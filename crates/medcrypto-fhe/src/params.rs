//! Parameter sets, and the check that they reach the security they claim.

use crate::arith::ntt_primes;
use crate::FheError;
use serde::{Deserialize, Serialize};

/// The security targets from the Homomorphic Encryption Standard, for ternary secrets and error of
/// standard deviation about 3.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// 128 bits against the best known quantum attacks.
    Quantum128,
    /// 128 bits against classical attacks only.
    Classical128,
}

/// The largest total modulus size, in bits, that the standard allows for a ring degree. These are the
/// tables of the standard as published in Microsoft SEAL's `hestdparms.h`.
pub fn max_log_qp(degree: usize, level: SecurityLevel) -> Option<u32> {
    let row = match degree {
        1024 => (27, 25),
        2048 => (54, 51),
        4096 => (109, 101),
        8192 => (218, 202),
        16384 => (438, 411),
        32768 => (881, 827),
        _ => return None,
    };
    Some(match level {
        SecurityLevel::Classical128 => row.0,
        SecurityLevel::Quantum128 => row.1,
    })
}

/// The ready-made parameter sets. Both reach 128 bits of post-quantum security under the standard's table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CkksPreset {
    /// `N = 8192`, 4096 slots, 200 modulus bits, two multiplications.
    N8192,
    /// `N = 16384`, 8192 slots, 400 modulus bits, seven multiplications.
    N16384,
}

impl CkksPreset {
    pub fn from_degree(degree: usize) -> Option<Self> {
        match degree {
            8192 => Some(Self::N8192),
            16384 => Some(Self::N16384),
            _ => None,
        }
    }

    pub fn params(self) -> CkksParams {
        let (degree, scale_primes) = match self {
            Self::N8192 => (8192, 2),
            Self::N16384 => (16384, 7),
        };
        // The largest 60-bit prime is the special prime, which has to be at least as large as any digit.
        let big = ntt_primes(60, degree, 2);
        let mut moduli_chain = vec![big[1]];
        moduli_chain.extend(ntt_primes(40, degree, scale_primes));
        CkksParams {
            poly_degree: degree,
            moduli_chain,
            special_prime: big[0],
            scale: (1u64 << 40) as f64,
            security: SecurityLevel::Quantum128,
        }
    }
}

/// A ring degree, RNS modulus chain and default scale.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CkksParams {
    pub poly_degree: usize,
    /// `q0, q1, ..., qL`. The first holds the final result, and each of the rest pays for one rescale.
    pub moduli_chain: Vec<u64>,
    /// `P`, used only inside key switching.
    pub special_prime: u64,
    pub scale: f64,
    pub security: SecurityLevel,
}

impl CkksParams {
    /// The size of the whole modulus `QP` in bits, rounded up, which is what security depends on.
    pub fn total_modulus_bits(&self) -> u32 {
        let bits: f64 = self
            .moduli_chain
            .iter()
            .chain(core::iter::once(&self.special_prime))
            .map(|&q| (q as f64).log2())
            .sum();
        bits.ceil() as u32
    }

    /// Refuses anything the standard does not cover, anything over its limit, and primes that do not work.
    pub fn validate(&self) -> Result<(), FheError> {
        let bad = |m: String| Err(FheError::InvalidParameters(m));
        let limit = match max_log_qp(self.poly_degree, self.security) {
            Some(limit) => limit,
            None => {
                return bad(format!(
                    "ring degree {} is not in the standard",
                    self.poly_degree
                ))
            }
        };
        let total = self.total_modulus_bits();
        if total > limit {
            return bad(format!(
                "{total} modulus bits exceeds the limit of {limit} for N = {} at {:?}",
                self.poly_degree, self.security
            ));
        }
        if self.moduli_chain.is_empty() {
            return bad("the modulus chain is empty".into());
        }
        let mut seen: Vec<u64> = Vec::new();
        for &q in self.moduli_chain.iter().chain([&self.special_prime]) {
            if seen.contains(&q) {
                return bad(format!("{q} appears twice"));
            }
            seen.push(q);
            let bits = 64 - q.leading_zeros();
            if !(20..=61).contains(&bits) {
                return bad(format!("{q} must have 20 to 61 bits"));
            }
            if q % (2 * self.poly_degree as u64) != 1 || !crate::arith::is_prime(q) {
                return bad(format!("{q} is not a prime that is 1 mod 2N"));
            }
        }
        if self.moduli_chain.iter().any(|&q| q > self.special_prime) {
            return bad("the special prime must be the largest".into());
        }
        if !(self.scale.is_finite() && self.scale >= 2.0) {
            return bad("the scale must be a finite number of at least 2".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_fit_the_post_quantum_table() {
        let p = CkksPreset::N8192.params();
        p.validate().unwrap();
        assert!(p.total_modulus_bits() <= 202);
        assert_eq!(p.moduli_chain.len(), 3);
        let p = CkksPreset::N16384.params();
        p.validate().unwrap();
        assert!(p.total_modulus_bits() <= 411);
        assert_eq!(p.moduli_chain.len(), 8);
    }

    #[test]
    fn the_old_toy_parameters_and_overlong_chains_are_refused() {
        let mut p = CkksPreset::N8192.params();
        p.poly_degree = 128;
        assert!(p.validate().is_err());

        let mut p = CkksPreset::N8192.params();
        p.moduli_chain
            .extend(ntt_primes(40, 8192, 4).into_iter().skip(2));
        assert!(matches!(p.validate(), Err(FheError::InvalidParameters(_))));
    }
}
