use medcrypto::blockchain::BlockchainConsentRegistry;
use medcrypto::compliance::KeyManager;

#[test]
fn test_gdpr_article_17_cryptographic_shredding() {
    let mut km = KeyManager::new();
    let patient_id = "patient-kr-9021";
    let raw_sensitive_phi =
        b"DIAGNOSIS: Type 2 Diabetes with Diabetic Nephropathy; GENOME: BRCA1 negative";

    // 1. Data encrypted in ephemeral envelope
    let envelope = km.encrypt(patient_id, raw_sensitive_phi);

    // 2. Verified that data can be legitimately decrypted while consent is active
    let decrypted = km
        .decrypt(&envelope)
        .expect("Decryption should succeed initially");
    assert_eq!(decrypted, raw_sensitive_phi);

    // 3. Patient revokes consent -> trigger Cryptographic Shredding
    let cert = km
        .shred_key(&envelope.key_id, patient_id)
        .expect("Key shredding should succeed");

    assert_eq!(cert.record_id, patient_id);
    assert_eq!(
        cert.regulatory_basis,
        "GDPR Article 17 - Right to Erasure / Cryptographic Shredding"
    );
    assert!(!cert.audit_signature.is_empty());

    // 4. Verifying post-erasure status: data must be mathematically unrecoverable
    let post_erasure_attempt = km.decrypt(&envelope);
    assert!(
        post_erasure_attempt.is_err(),
        "GDPR Violation: Plaintext was recoverable after shredding"
    );
}

#[test]
fn test_gdpr_article_25_zero_phi_on_blockchain() {
    let mut registry = BlockchainConsentRegistry::new();
    let leaves = vec![
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb".to_string(),
    ];

    let root = registry.compute_merkle_root(&leaves);

    // Assert that the on-chain root is purely a 32-byte cryptographic commitment
    assert_eq!(root.len(), 64); // 32 bytes in hex
    assert_eq!(registry.state_roots.len(), 1);

    // Assert no PHI keywords exist in on-chain state
    let serialized_state = serde_json::to_string(&registry.consents).unwrap();
    assert!(!serialized_state.contains("Diabetes"));
    assert!(!serialized_state.contains("Glucose"));
    assert!(!serialized_state.contains("BloodPressure"));
}
