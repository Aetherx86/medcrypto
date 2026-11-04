use medcrypto::compliance::AuditLedger;
use medcrypto::zkp::ZKPEngine;

#[test]
fn test_hipaa_minimum_necessary_zero_knowledge() {
    let actual_hba1c = 57; // 5.7% (normal)
    let threshold = 65; // 6.5% (diabetic threshold)
    let blinding = 81726354;

    // 1. Prover generates proof
    let proof = ZKPEngine::prove_threshold(actual_hba1c, blinding, threshold, true)
        .expect("Proof generation should succeed");

    // 2. Serialized proof sent to external institution
    let serialized_proof = serde_json::to_string(&proof).unwrap();

    // Verify Zero PHI Leakage: The serialized proof must NEVER contain the raw number 57
    assert!(
        !serialized_proof.contains("\"value\":57"),
        "HIPAA Violation: Exact clinical measurement exposed in proof wire format"
    );

    // 3. Verifier checks proof
    let verified = ZKPEngine::verify_threshold(&proof);
    assert!(verified, "Valid ZKP proof should verify successfully");

    // 4. Boundary enforcement: Value outside boundary must fail proof generation
    let diabetic_hba1c = 82; // 8.2%
    let invalid_attempt = ZKPEngine::prove_threshold(diabetic_hba1c, blinding, threshold, true);
    assert!(
        invalid_attempt.is_err(),
        "HIPAA Integrity Failure: False predicate was provable"
    );
}

#[test]
fn test_hipaa_audit_trail_tamper_resistance() {
    let mut ledger = AuditLedger::new();

    ledger.append(
        "did:med:doctor:kim",
        "did:med:hospital:snuh",
        "did:med:patient:p01",
        "EMERGENCY_CONSULT",
        "ZKP_VERIFY",
        "0x1234567890abcdef",
    );

    ledger.append(
        "did:med:researcher:lee",
        "did:med:hospital:amc",
        "did:med:patient:p01",
        "CLINICAL_TRIAL",
        "FHE_QUERY",
        "0xfedcba0987654321",
    );

    // 1. Unmodified chain must pass integrity check
    assert!(
        ledger.verify_integrity(),
        "Audit chain integrity failed on valid data"
    );

    // 2. Tampering test: Attacker modifies purpose of access retroactively
    ledger.entries[0].purpose = "UNAUTHORIZED_SNOOPING".to_string();

    // 3. Ledger verification MUST fail immediately
    assert!(
        !ledger.verify_integrity(),
        "HIPAA Audit Failure: Tampered audit record went undetected"
    );
}
