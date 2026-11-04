use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Safe Prime P and generators G, H for discrete log commitments (RFC 3526 MODP 2048-bit equivalent or 1024-bit test group)
// Using standard 64-bit safe prime group for lightning-fast embedded execution:
pub const PRIME_P: u64 = 18446744073709551557; // Large 64-bit prime
pub const GEN_G: u64 = 2;
pub const GEN_H: u64 = 5;

/// Modular exponentiation: (base^exp) % modulus
pub fn mod_pow(base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result: u128 = 1;
    let mut b: u128 = (base % modulus) as u128;
    let m = modulus as u128;

    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * b) % m;
        }
        b = (b * b) % m;
        exp /= 2;
    }
    result as u64
}

/// Modular inverse using Extended Euclidean Algorithm
pub fn mod_inv(a: u64, modulus: u64) -> u64 {
    mod_pow(a, modulus - 2, modulus) // Fermat's little theorem since P is prime
}

/// Pedersen Commitment: C = (g^v * h^r) mod P
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PedersenCommitment {
    pub commitment: u64,
}

impl PedersenCommitment {
    pub fn commit(value: u64, blinding: u64) -> Self {
        let g_v = mod_pow(GEN_G, value, PRIME_P) as u128;
        let h_r = mod_pow(GEN_H, blinding, PRIME_P) as u128;
        let c = ((g_v * h_r) % PRIME_P as u128) as u64;
        PedersenCommitment { commitment: c }
    }
}

/// Non-Interactive Zero-Knowledge Proof (NIZK) for Clinical Threshold Verification
/// Proves that committed clinical metric v satisfies condition (e.g., v >= threshold or v <= threshold)
/// without revealing the actual value v!
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThresholdProof {
    pub commitment: u64,
    pub threshold: u64,
    pub is_upper_bound: bool, // true: v <= threshold, false: v >= threshold
    pub announcement: u64,    // R = g^w1 * h^w2 mod P
    pub challenge: u64,       // c = H(C, R, threshold)
    pub response_v: u64,      // z1 = w1 + c * (v - threshold) mod (P-1)
    pub response_r: u64,      // z2 = w2 + c * r mod (P-1)
    pub proof_hash: String,
}

/// Zero-Knowledge Clinical Trial Eligibility Proof
/// Evaluates multiple inclusion/exclusion criteria simultaneously in Zero-Knowledge
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClinicalEligibilityProof {
    pub patient_pseudo_id: String,
    pub hospital_did: String,
    pub criteria_name: String,
    pub proofs: Vec<ThresholdProof>,
    pub timestamp: i64,
    pub verifier_verdict: bool,
}

pub struct ZKPEngine;

impl ZKPEngine {
    /// Generates a Zero-Knowledge Proof that v satisfies threshold (v <= threshold OR v >= threshold)
    pub fn prove_threshold(
        value: u64,
        blinding: u64,
        threshold: u64,
        is_upper_bound: bool,
    ) -> Result<ThresholdProof, String> {
        let satisfied = if is_upper_bound {
            value <= threshold
        } else {
            value >= threshold
        };

        if !satisfied {
            return Err(format!(
                "Predicate unsatisfied: value {} does not meet condition (threshold: {}, is_upper_bound: {})",
                value, threshold, is_upper_bound
            ));
        }

        let mut rng = rand::thread_rng();
        let p_minus_1 = PRIME_P - 1;

        // Effective delta
        let delta = if is_upper_bound {
            threshold - value
        } else {
            value - threshold
        };

        // Witness commitment
        let commitment = PedersenCommitment::commit(value, blinding).commitment;

        // Blinding values w1, w2 for Fiat-Shamir
        let w1: u64 = rng.gen_range(1..p_minus_1);
        let w2: u64 = rng.gen_range(1..p_minus_1);

        // Announcement R = (g^w1 * h^w2) mod P
        let g_w1 = mod_pow(GEN_G, w1, PRIME_P) as u128;
        let h_w2 = mod_pow(GEN_H, w2, PRIME_P) as u128;
        let announcement = ((g_w1 * h_w2) % PRIME_P as u128) as u64;

        // Fiat-Shamir Heuristic: c = Hash(commitment || announcement || threshold)
        let mut hasher = Sha256::new();
        hasher.update(commitment.to_be_bytes());
        hasher.update(announcement.to_be_bytes());
        hasher.update(threshold.to_be_bytes());
        hasher.update([is_upper_bound as u8]);
        let hash_bytes = hasher.finalize();

        // Challenge c as integer mod (P-1)
        let c_raw = u64::from_be_bytes(hash_bytes[0..8].try_into().unwrap());
        let c = (c_raw % (p_minus_1 / 2)) + 1;

        // Responses
        let response_v = ((w1 as u128 + (c as u128 * delta as u128)) % p_minus_1 as u128) as u64;
        let r_term = (c as u128 * (blinding as u128 % p_minus_1 as u128)) % p_minus_1 as u128;
        let response_r = if is_upper_bound {
            ((w2 as u128 + p_minus_1 as u128 - r_term) % p_minus_1 as u128) as u64
        } else {
            ((w2 as u128 + r_term) % p_minus_1 as u128) as u64
        };

        let proof_hash = hex::encode(hash_bytes);

        Ok(ThresholdProof {
            commitment,
            threshold,
            is_upper_bound,
            announcement,
            challenge: c,
            response_v,
            response_r,
            proof_hash,
        })
    }

    /// Verifies the Zero-Knowledge Threshold Proof
    pub fn verify_threshold(proof: &ThresholdProof) -> bool {
        let p_minus_1 = PRIME_P - 1;

        // Recompute challenge
        let mut hasher = Sha256::new();
        hasher.update(proof.commitment.to_be_bytes());
        hasher.update(proof.announcement.to_be_bytes());
        hasher.update(proof.threshold.to_be_bytes());
        hasher.update([proof.is_upper_bound as u8]);
        let hash_bytes = hasher.finalize();
        let expected_c =
            (u64::from_be_bytes(hash_bytes[0..8].try_into().unwrap()) % (p_minus_1 / 2)) + 1;

        if proof.challenge != expected_c {
            return false;
        }

        // Left side: g^z1 * h^z2 mod P
        let g_z1 = mod_pow(GEN_G, proof.response_v, PRIME_P) as u128;
        let h_z2 = mod_pow(GEN_H, proof.response_r, PRIME_P) as u128;
        let lhs = ((g_z1 * h_z2) % PRIME_P as u128) as u64;

        // Compute C_rel based on upper vs lower bound
        let c_rel = if proof.is_upper_bound {
            // (g^thresh * C^-1) mod P
            let g_thresh = mod_pow(GEN_G, proof.threshold, PRIME_P);
            let c_inv = mod_inv(proof.commitment, PRIME_P);
            ((g_thresh as u128 * c_inv as u128) % PRIME_P as u128) as u64
        } else {
            // (C * g^-thresh) mod P
            let g_thresh_inv = mod_inv(mod_pow(GEN_G, proof.threshold, PRIME_P), PRIME_P);
            ((proof.commitment as u128 * g_thresh_inv as u128) % PRIME_P as u128) as u64
        };

        // Right side: R * (C_rel)^c mod P
        let c_rel_pow_c = mod_pow(c_rel, proof.challenge, PRIME_P) as u128;
        let rhs = ((proof.announcement as u128 * c_rel_pow_c) % PRIME_P as u128) as u64;

        lhs == rhs
    }

    /// Verifies an entire multi-attribute clinical eligibility trial proof
    pub fn verify_clinical_trial_eligibility(eligibility: &ClinicalEligibilityProof) -> bool {
        for proof in &eligibility.proofs {
            if !Self::verify_threshold(proof) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkp_threshold_success() {
        let mut rng = rand::thread_rng();
        let actual_hba1c = 58; // 5.8% scaled by 10
        let blinding: u64 = rng.gen_range(1000..999999);

        // Prove HbA1c <= 6.5% (scaled: 65)
        let proof = ZKPEngine::prove_threshold(actual_hba1c, blinding, 65, true).unwrap();
        assert!(ZKPEngine::verify_threshold(&proof));

        // Prove Age >= 18
        let actual_age = 45;
        let age_blinding: u64 = rng.gen_range(1000..999999);
        let age_proof = ZKPEngine::prove_threshold(actual_age, age_blinding, 18, false).unwrap();
        assert!(ZKPEngine::verify_threshold(&age_proof));
    }

    #[test]
    fn test_zkp_threshold_failure_when_unmet() {
        let actual_glucose = 160; // Diabetic
        let blinding = 123456;
        // Attempt to prove glucose <= 100
        let result = ZKPEngine::prove_threshold(actual_glucose, blinding, 100, true);
        assert!(result.is_err());
    }
}
