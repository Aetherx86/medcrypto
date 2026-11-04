use medcrypto::quantum::QuantumAuditor;

#[test]
fn test_post_quantum_lattice_parameters() {
    let report = QuantumAuditor::evaluate_rlwe_security(128, 1_073_741_789, 3.2);

    // 1. Shor's algorithm resistance check
    assert!(
        report.shor_algorithm_resistant,
        "Post-Quantum Failure: FHE scheme must be immune to Shor's algorithm"
    );

    // 2. Grover's algorithm search security
    assert!(
        report.grover_security_bits >= 128,
        "Grover security bits must meet or exceed NIST Level 1 (128 bits)"
    );

    // 3. Ring LWE lattice security
    assert_eq!(
        report.hard_problem,
        "Ring Learning With Errors (Decisional RLWE over Cyclotomic Ring)"
    );

    // 4. Modulus bit length validation
    assert!(
        report.modulus_bits_q >= 30,
        "Modulus must be at least 30 bits for CKKS precision"
    );
}
