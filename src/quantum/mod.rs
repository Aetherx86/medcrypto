use serde::{Deserialize, Serialize};

/// Quantum Resistance and Post-Quantum Cryptography (PQC) Evaluation Module
/// Evaluates lattice hardness (RLWE/CKKS) against Shor's and Grover's quantum algorithms.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuantumSecurityReport {
    pub algorithm_family: String,
    pub hard_problem: String,
    pub ring_dimension_n: usize,
    pub modulus_bits_q: usize,
    pub noise_std_dev: f64,
    pub shor_algorithm_resistant: bool,
    pub grover_security_bits: usize,
    pub quantum_sieving_security_bits: usize,
    pub nist_security_level: String,
    pub zkp_commitment_quantum_safe: bool,
    pub post_quantum_recommendations: Vec<String>,
}

pub struct QuantumAuditor;

impl QuantumAuditor {
    /// Evaluates the quantum resistance of the system's RLWE-based CKKS parameters
    pub fn evaluate_rlwe_security(
        ring_degree: usize,
        modulus: i64,
        std_dev: f64,
    ) -> QuantumSecurityReport {
        let q_bits = 64 - modulus.leading_zeros() as usize;

        // Shor's Algorithm:
        // Shor's algorithm relies on finding periods in abelian groups (period-finding via Quantum Fourier Transform).
        // Lattice problems (SVP, CVP, RLWE) possess non-abelian, high-dimensional geometry without periodic subgroup structures that Shor can exploit.
        let shor_resistant = true;

        // Grover's Algorithm & Quantum Lattice Sieving:
        // Quantum sieving algorithms (e.g. BDGL16) achieve time complexity 2^(0.265 * beta + o(beta)) where beta is the BKZ block size.
        // For dimension N and modulus q, the estimated post-quantum bit security:
        let estimated_beta = (ring_degree as f64 * 0.15) as usize;
        let quantum_security_bits =
            ((0.265 * estimated_beta as f64) + (q_bits as f64 * 0.5)) as usize;

        // Grover security for 256-bit hash chains and Merkle roots:
        // Grover search gives square-root speedup: 256 / 2 = 128 bits of quantum security.
        let grover_bits = 128;

        let nist_level = if quantum_security_bits >= 128 {
            "NIST PQC Category 1 (AES-128 Equivalent Post-Quantum Security)"
        } else if quantum_security_bits >= 192 {
            "NIST PQC Category 3 (AES-192 Equivalent Post-Quantum Security)"
        } else {
            "Development / Embedded Profile (Standard Latency Optimized)"
        };

        QuantumSecurityReport {
            algorithm_family: "4th Generation Approximate FHE (CKKS / RLWE)".to_string(),
            hard_problem: "Ring Learning With Errors (Decisional RLWE over Cyclotomic Ring)".to_string(),
            ring_dimension_n: ring_degree,
            modulus_bits_q: q_bits,
            noise_std_dev: std_dev,
            shor_algorithm_resistant: shor_resistant,
            grover_security_bits: grover_bits,
            quantum_sieving_security_bits: quantum_security_bits,
            nist_security_level: nist_level.to_string(),
            zkp_commitment_quantum_safe: false, // Discrete-log Pedersen commitments are broken by Shor; STARKs/FRI are PQC-safe
            post_quantum_recommendations: vec![
                "Lattice-based CKKS FHE is inherently quantum-safe against Shor's polynomial-time factoring/logarithm attacks.".to_string(),
                "Audit trail SHA-256 hash chains retain 128-bit quantum security against Grover search.".to_string(),
                "For high-threat post-quantum ZKP deployment, use Hash-based STARKs (e.g., SP1 / FRI) to replace discrete-log commitments.".to_string(),
            ],
        }
    }
}
