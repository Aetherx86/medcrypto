use medcrypto_fhe::params::{max_log_qp, SecurityLevel};
use medcrypto_fhe::CKKSContext;
use serde::{Deserialize, Serialize};

/// A check of the lattice parameters against the Homomorphic Encryption Standard's tables, along with where
/// the rest of the system stands against quantum computers.
///
/// This reads a published table. It does not run a lattice estimator, and it says nothing about
/// implementation attacks. The previous version computed a number from a formula that had no basis.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuantumSecurityReport {
    pub algorithm_family: String,
    pub hard_problem: String,
    pub ring_dimension_n: usize,
    pub modulus_bits_qp: u32,
    /// The standard's limit for this ring at 128 bits against quantum attacks.
    pub limit_bits_quantum_128: Option<u32>,
    /// The standard's limit for this ring at 128 bits against classical attacks.
    pub limit_bits_classical_128: Option<u32>,
    pub meets_quantum_128: bool,
    pub meets_classical_128: bool,
    pub shor_algorithm_resistant: bool,
    pub grover_security_bits: usize,
    pub security_assessment: String,
    pub zkp_commitment_quantum_safe: bool,
    pub post_quantum_recommendations: Vec<String>,
}

pub struct QuantumAuditor;

impl QuantumAuditor {
    /// The report for any ring degree and total modulus size.
    pub fn evaluate(degree: usize, modulus_bits_qp: u32) -> QuantumSecurityReport {
        let quantum = max_log_qp(degree, SecurityLevel::Quantum128);
        let classical = max_log_qp(degree, SecurityLevel::Classical128);
        let meets_quantum_128 = quantum.is_some_and(|limit| modulus_bits_qp <= limit);
        let meets_classical_128 = classical.is_some_and(|limit| modulus_bits_qp <= limit);
        let security_assessment = if meets_quantum_128 {
            "128 bits against quantum attacks, by the Homomorphic Encryption Standard's table"
        } else if meets_classical_128 {
            "128 bits against classical attacks only, by the Homomorphic Encryption Standard's table"
        } else {
            "Below 128 bits: not covered by the Homomorphic Encryption Standard's table"
        };
        QuantumSecurityReport {
            algorithm_family: "RNS-CKKS approximate homomorphic encryption".to_string(),
            hard_problem: "Ring Learning With Errors (Decisional RLWE over Cyclotomic Ring)".to_string(),
            ring_dimension_n: degree,
            modulus_bits_qp,
            limit_bits_quantum_128: quantum,
            limit_bits_classical_128: classical,
            meets_quantum_128,
            meets_classical_128,
            shor_algorithm_resistant: true,
            grover_security_bits: 128,
            security_assessment: security_assessment.to_string(),
            zkp_commitment_quantum_safe: false,
            post_quantum_recommendations: vec![
                "CKKS rests on RLWE, for which no efficient quantum attack is known.".to_string(),
                "SHA-256 chains keep about 128 bits against Grover's preimage search.".to_string(),
                "The Pedersen backend, Ed25519 signatures and TLS certificates all rest on elliptic curves, which Shor's algorithm breaks. Use a post-quantum runner for proofs in production, and treat the signatures and TLS as needing their own migration.".to_string(),
            ],
        }
    }

    pub fn evaluate_context(context: &CKKSContext) -> QuantumSecurityReport {
        Self::evaluate(context.poly_degree, context.total_modulus_bits())
    }
}
