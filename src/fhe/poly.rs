// Polynomial arithmetic over R_q = Z_q[X] / (X^N + 1)
// Used in RLWE and CKKS homomorphic encryption schemes.

use rand::Rng;
use rand_distr::{Distribution, Normal};
use serde::{Deserialize, Serialize};

pub const DEFAULT_DEGREE: usize = 128; // Ring dimension N (power of two)
pub const DEFAULT_MODULUS: i64 = 1_073_741_789; // Prime modulus q ≈ 2^30 for CKKS arithmetic

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Polynomial {
    pub coeffs: Vec<i64>,
    pub modulus: i64,
}

impl Polynomial {
    pub fn new(coeffs: Vec<i64>, modulus: i64) -> Self {
        let mut p = Polynomial { coeffs, modulus };
        p.normalize();
        p
    }

    pub fn zero(degree: usize, modulus: i64) -> Self {
        Polynomial {
            coeffs: vec![0; degree],
            modulus,
        }
    }

    pub fn degree(&self) -> usize {
        self.coeffs.len()
    }

    /// Normalizes coefficients to [-q/2, q/2] or [0, q-1]
    pub fn normalize(&mut self) {
        let q = self.modulus;
        for c in &mut self.coeffs {
            *c = (*c % q + q) % q;
        }
    }

    /// Centered representation in [-q/2, q/2)
    pub fn centered_coeffs(&self) -> Vec<i64> {
        let q = self.modulus;
        let half_q = q / 2;
        self.coeffs
            .iter()
            .map(|&c| if c > half_q { c - q } else { c })
            .collect()
    }

    /// Uniform random polynomial sampling in R_q
    pub fn sample_uniform<R: Rng>(degree: usize, modulus: i64, rng: &mut R) -> Self {
        let coeffs: Vec<i64> = (0..degree).map(|_| rng.gen_range(0..modulus)).collect();
        Polynomial::new(coeffs, modulus)
    }

    /// Discrete Gaussian error sampling for LWE/RLWE noise
    pub fn sample_gaussian<R: Rng>(degree: usize, modulus: i64, std_dev: f64, rng: &mut R) -> Self {
        let normal = Normal::new(0.0, std_dev).unwrap();
        let coeffs: Vec<i64> = (0..degree)
            .map(|_| {
                let sample = normal.sample(rng).round() as i64;
                (sample % modulus + modulus) % modulus
            })
            .collect();
        Polynomial::new(coeffs, modulus)
    }

    /// Ternary secret key sampling {-1, 0, 1}
    pub fn sample_ternary<R: Rng>(degree: usize, modulus: i64, rng: &mut R) -> Self {
        let coeffs: Vec<i64> = (0..degree)
            .map(|_| {
                let r: i32 = rng.gen_range(-1..=1);
                (r as i64 + modulus) % modulus
            })
            .collect();
        Polynomial::new(coeffs, modulus)
    }

    /// Polynomial addition in R_q
    pub fn add(&self, other: &Polynomial) -> Self {
        assert_eq!(self.degree(), other.degree());
        assert_eq!(self.modulus, other.modulus);
        let q = self.modulus;
        let coeffs: Vec<i64> = self
            .coeffs
            .iter()
            .zip(other.coeffs.iter())
            .map(|(&a, &b)| (a + b) % q)
            .collect();
        Polynomial::new(coeffs, q)
    }

    /// Polynomial subtraction in R_q
    pub fn sub(&self, other: &Polynomial) -> Self {
        assert_eq!(self.degree(), other.degree());
        assert_eq!(self.modulus, other.modulus);
        let q = self.modulus;
        let coeffs: Vec<i64> = self
            .coeffs
            .iter()
            .zip(other.coeffs.iter())
            .map(|(&a, &b)| (a - b + q) % q)
            .collect();
        Polynomial::new(coeffs, q)
    }

    /// Scalar multiplication: P(X) * k mod q
    pub fn scalar_mul(&self, scalar: i64) -> Self {
        let q = self.modulus;
        let s = (scalar % q + q) % q;
        let coeffs: Vec<i64> = self
            .coeffs
            .iter()
            .map(|&a| ((a as i128 * s as i128) % q as i128) as i64)
            .collect();
        Polynomial::new(coeffs, q)
    }

    /// Polynomial multiplication in R_q = Z_q[X] / (X^N + 1) using negacyclic convolution
    pub fn mul_negacyclic(&self, other: &Polynomial) -> Self {
        let n = self.degree();
        assert_eq!(n, other.degree());
        assert_eq!(self.modulus, other.modulus);
        let q = self.modulus as i128;

        let mut res = vec![0i128; n];
        for i in 0..n {
            let a = self.coeffs[i] as i128;
            if a == 0 {
                continue;
            }
            for j in 0..n {
                let b = other.coeffs[j] as i128;
                let prod = (a * b) % q;
                if i + j < n {
                    res[i + j] = (res[i + j] + prod) % q;
                } else {
                    // X^N = -1 mod (X^N + 1)
                    res[i + j - n] = (res[i + j - n] - prod + q) % q;
                }
            }
        }

        let final_coeffs: Vec<i64> = res.into_iter().map(|c| (c % q) as i64).collect();
        Polynomial::new(final_coeffs, self.modulus)
    }
}
