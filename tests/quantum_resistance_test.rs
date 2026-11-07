use medcrypto::fhe::{CKKSEngine, CkksPreset};
use medcrypto::quantum::QuantumAuditor;

#[test]
fn both_presets_meet_the_standard_at_128_post_quantum_bits() {
    for preset in [CkksPreset::N8192, CkksPreset::N16384] {
        let report = QuantumAuditor::evaluate_context(CKKSEngine::from_preset(preset).context());
        assert!(report.meets_quantum_128, "{report:?}");
        assert!(report.meets_classical_128);
        assert!(report.shor_algorithm_resistant);
        assert_eq!(report.grover_security_bits, 128);
        assert_eq!(
            report.hard_problem,
            "Ring Learning With Errors (Decisional RLWE over Cyclotomic Ring)"
        );
    }
}

#[test]
fn the_former_toy_parameters_are_reported_as_what_they_were() {
    // N = 128 is not in the standard at all, and it used to be reported as a pass.
    let report = QuantumAuditor::evaluate(128, 30);
    assert!(!report.meets_quantum_128 && !report.meets_classical_128);
    assert!(report.security_assessment.contains("Below 128 bits"));
}

#[test]
fn a_modulus_past_the_limit_loses_the_claim() {
    let report = QuantumAuditor::evaluate(8192, 210);
    assert!(!report.meets_quantum_128);
    assert!(report.meets_classical_128);
    assert!(!QuantumAuditor::evaluate(8192, 219).meets_classical_128);
    assert!(!report.zkp_commitment_quantum_safe);
}
