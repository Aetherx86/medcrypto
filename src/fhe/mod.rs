pub mod poly;

use poly::{Polynomial, DEFAULT_DEGREE, DEFAULT_MODULUS};
use rand::thread_rng;
use serde::{Deserialize, Serialize};

/// 4th Generation Approximate Homomorphic Encryption (CKKS) Scheme
/// Suitable for floating-point and continuous biological/clinical data.
pub const DEFAULT_SCALE: f64 = 65536.0; // Delta = 2^16 scaling factor
pub const NOISE_STD_DEV: f64 = 3.2;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretKey {
    pub s: Polynomial,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey {
    pub b: Polynomial,
    pub a: Polynomial,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ciphertext {
    pub c0: Polynomial,
    pub c1: Polynomial,
    pub scale: f64,
    pub num_slots: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CKKSEngine {
    pub degree: usize,
    pub modulus: i64,
    pub scale: f64,
}

impl Default for CKKSEngine {
    fn default() -> Self {
        Self {
            degree: DEFAULT_DEGREE,
            modulus: DEFAULT_MODULUS,
            scale: DEFAULT_SCALE,
        }
    }
}

impl CKKSEngine {
    pub fn new(degree: usize, modulus: i64, scale: f64) -> Self {
        Self {
            degree,
            modulus,
            scale,
        }
    }

    /// Key Generation
    pub fn keygen(&self) -> (SecretKey, PublicKey) {
        let mut rng = thread_rng();
        let s = Polynomial::sample_ternary(self.degree, self.modulus, &mut rng);
        let a = Polynomial::sample_uniform(self.degree, self.modulus, &mut rng);
        let e = Polynomial::sample_gaussian(self.degree, self.modulus, NOISE_STD_DEV, &mut rng);

        // b = - (a * s + e) mod q
        let as_prod = a.mul_negacyclic(&s);
        let as_plus_e = as_prod.add(&e);
        let b = as_plus_e.scalar_mul(-1);

        (SecretKey { s }, PublicKey { b, a })
    }

    /// Encodes a vector of real numbers into a polynomial via fixed-point scaling
    pub fn encode(&self, values: &[f64]) -> Polynomial {
        let mut coeffs = vec![0i64; self.degree];
        for (i, &v) in values.iter().enumerate().take(self.degree) {
            let scaled = (v * self.scale).round() as i64;
            coeffs[i] = (scaled % self.modulus + self.modulus) % self.modulus;
        }
        Polynomial::new(coeffs, self.modulus)
    }

    /// Decodes a plaintext polynomial back into a vector of real numbers
    pub fn decode(&self, poly: &Polynomial, num_slots: usize) -> Vec<f64> {
        let centered = poly.centered_coeffs();
        centered
            .iter()
            .take(num_slots)
            .map(|&c| (c as f64) / self.scale)
            .collect()
    }

    /// Encrypts a real-valued vector into a CKKS Ciphertext
    pub fn encrypt(&self, pk: &PublicKey, values: &[f64]) -> Ciphertext {
        let mut rng = thread_rng();
        let m = self.encode(values);

        let v = Polynomial::sample_ternary(self.degree, self.modulus, &mut rng);
        let e0 = Polynomial::sample_gaussian(self.degree, self.modulus, NOISE_STD_DEV, &mut rng);
        let e1 = Polynomial::sample_gaussian(self.degree, self.modulus, NOISE_STD_DEV, &mut rng);

        // c0 = b * v + e0 + m mod q
        let bv = pk.b.mul_negacyclic(&v);
        let c0 = bv.add(&e0).add(&m);

        // c1 = a * v + e1 mod q
        let av = pk.a.mul_negacyclic(&v);
        let c1 = av.add(&e1);

        Ciphertext {
            c0,
            c1,
            scale: self.scale,
            num_slots: values.len(),
        }
    }

    /// Decrypts a Ciphertext using the secret key
    pub fn decrypt(&self, sk: &SecretKey, ct: &Ciphertext) -> Vec<f64> {
        // m_noisy = c0 + c1 * s mod q
        let c1s = ct.c1.mul_negacyclic(&sk.s);
        let m_poly = ct.c0.add(&c1s);
        let centered = m_poly.centered_coeffs();
        centered
            .iter()
            .take(ct.num_slots)
            .map(|&c| (c as f64) / ct.scale)
            .collect()
    }

    /// Homomorphic Addition: Enc(x) + Enc(y) = Enc(x + y)
    pub fn add(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
        assert_eq!(ct1.scale, ct2.scale);
        assert_eq!(ct1.num_slots, ct2.num_slots);
        Ciphertext {
            c0: ct1.c0.add(&ct2.c0),
            c1: ct1.c1.add(&ct2.c1),
            scale: ct1.scale,
            num_slots: ct1.num_slots,
        }
    }

    /// Homomorphic Scalar Multiplication: Enc(x) * k = Enc(k * x)
    pub fn scalar_mul(&self, ct: &Ciphertext, scalar: f64) -> Ciphertext {
        // Multiply by scaled integer or directly scale coefficients
        let s_int = scalar.round() as i64;
        if (scalar - s_int as f64).abs() < 1e-6 {
            Ciphertext {
                c0: ct.c0.scalar_mul(s_int),
                c1: ct.c1.scalar_mul(s_int),
                scale: ct.scale,
                num_slots: ct.num_slots,
            }
        } else {
            // Fractional scaling
            let factor = (scalar * 1024.0).round() as i64;
            let c0 = ct.c0.scalar_mul(factor);
            let c1 = ct.c1.scalar_mul(factor);
            Ciphertext {
                c0,
                c1,
                scale: ct.scale * 1024.0,
                num_slots: ct.num_slots,
            }
        }
    }

    /// Multi-Hospital Federated Average on Ciphertexts
    /// In CKKS approximate arithmetic, the homomorphic sum Enc(sum x_i) represents the mean
    /// with scaled factor N * Delta: (sum Delta * x_i) / (N * Delta) = mean(x).
    pub fn federated_average(&self, ciphertexts: &[Ciphertext]) -> Ciphertext {
        assert!(
            !ciphertexts.is_empty(),
            "Must provide at least one ciphertext"
        );
        let n = ciphertexts.len() as f64;
        let mut sum_c0 = ciphertexts[0].c0.clone();
        let mut sum_c1 = ciphertexts[0].c1.clone();

        for ct in ciphertexts.iter().skip(1) {
            sum_c0 = sum_c0.add(&ct.c0);
            sum_c1 = sum_c1.add(&ct.c1);
        }

        Ciphertext {
            c0: sum_c0,
            c1: sum_c1,
            scale: ciphertexts[0].scale * n,
            num_slots: ciphertexts[0].num_slots,
        }
    }

    /// Evaluates a Linear Health Risk Score model: Score = sum(weight_i * feature_i)
    pub fn evaluate_linear_risk_model(&self, ct: &Ciphertext, weights: &[f64]) -> Ciphertext {
        assert!(weights.len() <= ct.num_slots);
        // We encode weights as a plaintext vector polynomial
        let mut w_coeffs = vec![0i64; self.degree];
        for (i, &w) in weights.iter().enumerate() {
            w_coeffs[i] = (w * 1000.0).round() as i64;
        }
        let w_poly = Polynomial::new(w_coeffs, self.modulus);

        let c0 = ct.c0.mul_negacyclic(&w_poly);
        let c1 = ct.c1.mul_negacyclic(&w_poly);

        Ciphertext {
            c0,
            c1,
            scale: ct.scale * 1000.0,
            num_slots: ct.num_slots,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ckks_encrypt_decrypt() {
        let engine = CKKSEngine::default();
        let (sk, pk) = engine.keygen();

        let original = vec![120.5, 80.0, 5.7, 36.5, 24.2]; // Vitals: Systolic, Diastolic, HbA1c, Temp, BMI
        let ct = engine.encrypt(&pk, &original);
        let decrypted = engine.decrypt(&sk, &ct);

        for (orig, dec) in original.iter().zip(decrypted.iter()) {
            assert!(
                (orig - dec).abs() < 0.1,
                "Mismatch: orig={}, dec={}",
                orig,
                dec
            );
        }
    }

    #[test]
    fn test_ckks_homomorphic_addition() {
        let engine = CKKSEngine::default();
        let (sk, pk) = engine.keygen();

        let v1 = vec![10.0, 20.0, 30.0];
        let v2 = vec![5.0, 15.0, 25.0];

        let ct1 = engine.encrypt(&pk, &v1);
        let ct2 = engine.encrypt(&pk, &v2);

        let ct_sum = engine.add(&ct1, &ct2);
        let decrypted = engine.decrypt(&sk, &ct_sum);

        assert!((decrypted[0] - 15.0).abs() < 0.1);
        assert!((decrypted[1] - 35.0).abs() < 0.1);
        assert!((decrypted[2] - 55.0).abs() < 0.1);
    }
}
