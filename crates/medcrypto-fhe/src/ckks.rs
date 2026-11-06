//! The RNS-CKKS scheme: keys, encryption, arithmetic, relinearization, rescaling and rotation.

use crate::arith::Modulus;
use crate::encoder::Encoder;
use crate::ntt::{galois_permutation, NttTable};
use crate::params::{CkksParams, CkksPreset, SecurityLevel};
use crate::rns::RnsPoly;
use crate::FheError;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

/// Parameters and the tables computed from them.
#[derive(Debug)]
pub struct CKKSContext {
    pub poly_degree: usize,
    /// `q0, q1, ..., qL`.
    pub moduli_chain: Vec<u64>,
    pub special_prime: u64,
    pub scale: f64,
    pub security: SecurityLevel,
    pub(crate) tables: Vec<NttTable>,
    pub(crate) encoder: Encoder,
    pub(crate) param_id: u64,
}

impl CKKSContext {
    pub fn new(params: CkksParams) -> Result<Self, FheError> {
        params.validate()?;
        let n = params.poly_degree;
        let tables = params
            .moduli_chain
            .iter()
            .chain(core::iter::once(&params.special_prime))
            .map(|&q| NttTable::new(q, n))
            .collect();
        let mut hash = Sha256::new();
        hash.update(b"medcrypto-ckks-params-v1");
        hash.update((n as u64).to_le_bytes());
        for q in &params.moduli_chain {
            hash.update(q.to_le_bytes());
        }
        hash.update(params.special_prime.to_le_bytes());
        let digest = hash.finalize();
        Ok(Self {
            poly_degree: n,
            moduli_chain: params.moduli_chain,
            special_prime: params.special_prime,
            scale: params.scale,
            security: params.security,
            tables,
            encoder: Encoder::new(n),
            param_id: u64::from_le_bytes(digest[..8].try_into().expect("8 bytes")),
        })
    }

    pub fn slots(&self) -> usize {
        self.poly_degree / 2
    }

    /// The highest level, which is also how many times a ciphertext can be rescaled.
    pub fn max_level(&self) -> usize {
        self.moduli_chain.len() - 1
    }

    pub(crate) fn special_index(&self) -> usize {
        self.moduli_chain.len()
    }

    /// Identifies the ring and primes. Keys and ciphertexts carry it, so mixing parameter sets is an error.
    pub fn param_id(&self) -> u64 {
        self.param_id
    }

    /// The total modulus size in bits that security is measured on.
    pub fn total_modulus_bits(&self) -> u32 {
        let bits: f64 = self
            .moduli_chain
            .iter()
            .chain(core::iter::once(&self.special_prime))
            .map(|&q| (q as f64).log2())
            .sum();
        bits.ceil() as u32
    }
}

/// A ternary secret over all primes including `P`. It is wiped when dropped, and prints as nothing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretKey {
    pub(crate) s: RnsPoly,
    pub param_id: u64,
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.s.wipe();
    }
}

/// `(b, a)` with `b = -a * s + e`, over all ciphertext primes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PublicKey {
    pub b: RnsPoly,
    pub a: RnsPoly,
    pub param_id: u64,
}

/// Encryptions of a key under the secret, one per prime in the chain.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeySwitchKey {
    pub(crate) digits: Vec<(RnsPoly, RnsPoly)>,
}

/// Lets a degree-2 ciphertext be brought back to degree 1 after a multiplication.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RelinKey {
    pub(crate) key: KeySwitchKey,
    pub param_id: u64,
}

/// The rotations a holder is able to perform, by Galois element.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GaloisKey {
    pub(crate) keys: BTreeMap<u32, KeySwitchKey>,
    pub param_id: u64,
}

impl GaloisKey {
    pub fn elements(&self) -> Vec<u32> {
        self.keys.keys().copied().collect()
    }
}

/// A ciphertext: `c0 + c1 * s (+ c2 * s^2) = scale * message + noise`, in the NTT domain.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Ciphertext {
    pub polys: Vec<RnsPoly>,
    pub scale: f64,
    /// How many leading slots hold meaningful values.
    pub num_slots: usize,
    pub param_id: u64,
}

impl Ciphertext {
    /// The index of the last prime still in use.
    pub fn level(&self) -> usize {
        self.polys[0].limb_count() - 1
    }

    /// One less than the number of polynomials: 1 normally, and 2 straight after a multiplication.
    pub fn degree(&self) -> usize {
        self.polys.len() - 1
    }
}

/// A CSPRNG seeded from the operating system.
#[cfg(feature = "os-rng")]
pub fn os_seeded_rng() -> rand_chacha::ChaCha20Rng {
    use rand_core::SeedableRng;
    rand_chacha::ChaCha20Rng::from_rng(rand_core::OsRng).expect("the OS random source failed")
}

fn sample_ternary<R: RngCore>(degree: usize, rng: &mut R) -> Vec<i64> {
    (0..degree)
        .map(|_| loop {
            // Rejection on two random bits. What it reveals in timing says nothing of the accepted value.
            let x = rng.next_u32() >> 30;
            if x < 3 {
                break x as i64 - 1;
            }
        })
        .collect()
}

/// A centered binomial with 21 pairs of bits has variance 10.5, which is standard deviation 3.24, in line
/// with the 3.2 that the standard assumes. It involves no floating point and no secret-dependent branches.
pub(crate) fn sample_error<R: RngCore>(degree: usize, rng: &mut R) -> Vec<i64> {
    const MASK: u64 = (1 << 21) - 1;
    (0..degree)
        .map(|_| {
            let x = rng.next_u64();
            (x & MASK).count_ones() as i64 - ((x >> 21) & MASK).count_ones() as i64
        })
        .collect()
}

/// A cheap handle: the tables are shared.
#[derive(Clone, Debug)]
pub struct CKKSEngine {
    pub(crate) ctx: Arc<CKKSContext>,
}

impl Default for CKKSEngine {
    /// `N = 8192`, the smaller preset.
    fn default() -> Self {
        Self::from_preset(CkksPreset::N8192)
    }
}

impl CKKSEngine {
    pub fn new(params: CkksParams) -> Result<Self, FheError> {
        Ok(Self {
            ctx: Arc::new(CKKSContext::new(params)?),
        })
    }

    /// The tables for a preset are built once per process.
    pub fn from_preset(preset: CkksPreset) -> Self {
        static N8192: OnceLock<Arc<CKKSContext>> = OnceLock::new();
        static N16384: OnceLock<Arc<CKKSContext>> = OnceLock::new();
        let cell = match preset {
            CkksPreset::N8192 => &N8192,
            CkksPreset::N16384 => &N16384,
        };
        let ctx = cell.get_or_init(|| {
            Arc::new(CKKSContext::new(preset.params()).expect("the presets are valid"))
        });
        Self { ctx: ctx.clone() }
    }

    pub fn context(&self) -> &CKKSContext {
        &self.ctx
    }

    pub fn slots(&self) -> usize {
        self.ctx.slots()
    }

    fn modulus(&self, table: usize) -> Modulus {
        self.ctx.tables[table].modulus
    }

    // ---- Polynomials ----

    /// Reduces small signed coefficients modulo the given primes and transforms them.
    pub(crate) fn small_to_ntt(&self, coefficients: &[i64], tables: &[usize]) -> RnsPoly {
        let limbs = tables
            .iter()
            .map(|&t| {
                let m = self.modulus(t);
                let mut limb: Vec<u64> = coefficients
                    .iter()
                    .map(|&c| {
                        if c < 0 {
                            m.neg(m.reduce(c.unsigned_abs()))
                        } else {
                            m.reduce(c as u64)
                        }
                    })
                    .collect();
                self.ctx.tables[t].forward(&mut limb);
                limb
            })
            .collect();
        RnsPoly { limbs }
    }

    pub(crate) fn uniform<R: RngCore>(&self, tables: &[usize], rng: &mut R) -> RnsPoly {
        let n = self.ctx.poly_degree;
        let limbs = tables
            .iter()
            .map(|&t| {
                let q = self.modulus(t).q;
                let mask = u64::MAX >> q.leading_zeros();
                (0..n)
                    .map(|_| loop {
                        let x = rng.next_u64() & mask;
                        if x < q {
                            break x;
                        }
                    })
                    .collect()
            })
            .collect();
        RnsPoly { limbs }
    }

    pub(crate) fn ciphertext_tables(&self, level: usize) -> Vec<usize> {
        (0..=level).collect()
    }

    pub(crate) fn all_tables(&self) -> Vec<usize> {
        (0..=self.ctx.special_index()).collect()
    }

    pub(crate) fn add_into(&self, a: &mut RnsPoly, b: &RnsPoly, tables: &[usize]) {
        for ((x, y), &t) in a.limbs.iter_mut().zip(&b.limbs).zip(tables) {
            let m = self.modulus(t);
            for (p, &q) in x.iter_mut().zip(y) {
                *p = m.add(*p, q);
            }
        }
    }

    fn sub_into(&self, a: &mut RnsPoly, b: &RnsPoly, tables: &[usize]) {
        for ((x, y), &t) in a.limbs.iter_mut().zip(&b.limbs).zip(tables) {
            let m = self.modulus(t);
            for (p, &q) in x.iter_mut().zip(y) {
                *p = m.sub(*p, q);
            }
        }
    }

    pub(crate) fn negate(&self, a: &mut RnsPoly, tables: &[usize]) {
        for (x, &t) in a.limbs.iter_mut().zip(tables) {
            let m = self.modulus(t);
            for p in x.iter_mut() {
                *p = m.neg(*p);
            }
        }
    }

    pub(crate) fn pointwise(&self, a: &RnsPoly, b: &RnsPoly, tables: &[usize]) -> RnsPoly {
        let limbs = a
            .limbs
            .iter()
            .zip(&b.limbs)
            .zip(tables)
            .map(|((x, y), &t)| {
                let m = self.modulus(t);
                x.iter().zip(y).map(|(&p, &q)| m.mul(p, q)).collect()
            })
            .collect();
        RnsPoly { limbs }
    }

    /// The first `count` limbs of a polynomial.
    pub(crate) fn truncate(&self, p: &RnsPoly, count: usize) -> RnsPoly {
        RnsPoly {
            limbs: p.limbs[..count].to_vec(),
        }
    }

    /// Divides by the prime of the last limb, rounding, and removes that limb.
    fn divide_round_by_last(&self, poly: &mut RnsPoly, last_table: usize) {
        let mut last = poly.limbs.pop().expect("at least one limb");
        let table = &self.ctx.tables[last_table];
        table.inverse(&mut last);
        let p = table.modulus;
        let half = p.q >> 1;
        for x in &mut last {
            *x = p.add(*x, half);
        }
        for (j, limb) in poly.limbs.iter_mut().enumerate() {
            let m = self.modulus(j);
            let half_mod = m.reduce(half);
            let mut t: Vec<u64> = last.iter().map(|&x| m.sub(m.reduce(x), half_mod)).collect();
            self.ctx.tables[j].forward(&mut t);
            let inverse = m.inv(m.reduce(p.q));
            let inverse_shoup = m.shoup(inverse);
            for (x, &y) in limb.iter_mut().zip(&t) {
                *x = m.mul_shoup(m.sub(*x, y), inverse, inverse_shoup);
            }
        }
    }

    // ---- Keys ----

    pub fn keygen_with<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (SecretKey, PublicKey) {
        let n = self.ctx.poly_degree;
        let s = self.small_to_ntt(&sample_ternary(n, rng), &self.all_tables());
        let sk = SecretKey {
            s,
            param_id: self.ctx.param_id,
        };
        let pk = self.public_key_with(&sk, rng);
        (sk, pk)
    }

    #[cfg(feature = "os-rng")]
    pub fn keygen(&self) -> (SecretKey, PublicKey) {
        self.keygen_with(&mut os_seeded_rng())
    }

    fn public_key_with<R: RngCore + CryptoRng>(&self, sk: &SecretKey, rng: &mut R) -> PublicKey {
        let tables = self.ciphertext_tables(self.ctx.max_level());
        let a = self.uniform(&tables, rng);
        let b = self.rlwe_b(&a, &sk.s, &tables, rng);
        PublicKey {
            b,
            a,
            param_id: self.ctx.param_id,
        }
    }

    /// `b = -a * s + e`, using as many limbs of the secret as the sample has.
    pub(crate) fn rlwe_b<R: RngCore + CryptoRng>(
        &self,
        a: &RnsPoly,
        s: &RnsPoly,
        tables: &[usize],
        rng: &mut R,
    ) -> RnsPoly {
        let secret = RnsPoly {
            limbs: tables.iter().map(|&t| s.limbs[t].clone()).collect(),
        };
        let mut b = self.pointwise(a, &secret, tables);
        self.negate(&mut b, tables);
        let e = self.small_to_ntt(&sample_error(self.ctx.poly_degree, rng), tables);
        self.add_into(&mut b, &e, tables);
        b
    }

    /// One digit of a key-switching key: `b = -a * s + e + P * new_key` on the digit's own prime only.
    pub(crate) fn key_switch_digit<R: RngCore + CryptoRng>(
        &self,
        digit: usize,
        a: &RnsPoly,
        s: &RnsPoly,
        new_key: &RnsPoly,
        rng: &mut R,
    ) -> RnsPoly {
        let tables = self.all_tables();
        let mut b = self.rlwe_b(a, s, &tables, rng);
        let m = self.modulus(digit);
        let p = m.reduce(self.ctx.special_prime);
        for (x, &k) in b.limbs[digit].iter_mut().zip(&new_key.limbs[digit]) {
            *x = m.add(*x, m.mul(p, k));
        }
        b
    }

    fn key_switch_key<R: RngCore + CryptoRng>(
        &self,
        sk: &SecretKey,
        new_key: &RnsPoly,
        rng: &mut R,
    ) -> KeySwitchKey {
        let tables = self.all_tables();
        let digits = (0..=self.ctx.max_level())
            .map(|digit| {
                let a = self.uniform(&tables, rng);
                let b = self.key_switch_digit(digit, &a, &sk.s, new_key, rng);
                (b, a)
            })
            .collect();
        KeySwitchKey { digits }
    }

    pub fn relin_keygen_with<R: RngCore + CryptoRng>(
        &self,
        sk: &SecretKey,
        rng: &mut R,
    ) -> RelinKey {
        let mut square = self.pointwise(&sk.s, &sk.s, &self.all_tables());
        let key = self.key_switch_key(sk, &square, rng);
        square.wipe();
        RelinKey {
            key,
            param_id: self.ctx.param_id,
        }
    }

    #[cfg(feature = "os-rng")]
    pub fn relin_keygen(&self, sk: &SecretKey) -> RelinKey {
        self.relin_keygen_with(sk, &mut os_seeded_rng())
    }

    /// The Galois element for rotating left by `steps`, which may be negative.
    pub fn galois_element(&self, steps: i64) -> u32 {
        let slots = self.slots() as i64;
        let k = steps.rem_euclid(slots) as u64;
        let m = 2 * self.ctx.poly_degree as u64;
        let (mut result, mut base, mut e) = (1u64, 5u64, k);
        while e > 0 {
            if e & 1 == 1 {
                result = result * base % m;
            }
            base = base * base % m;
            e >>= 1;
        }
        result as u32
    }

    /// The rotations by powers of two, which is what [`CKKSEngine::sum_slots`] needs.
    pub fn sum_rotation_steps(&self) -> Vec<i64> {
        (0..self.slots().trailing_zeros())
            .map(|i| 1i64 << i)
            .collect()
    }

    pub(crate) fn automorphism(&self, p: &RnsPoly, permutation: &[u32]) -> RnsPoly {
        let limbs = p
            .limbs
            .iter()
            .map(|limb| permutation.iter().map(|&i| limb[i as usize]).collect())
            .collect();
        RnsPoly { limbs }
    }

    pub fn galois_keygen_with<R: RngCore + CryptoRng>(
        &self,
        sk: &SecretKey,
        steps: &[i64],
        rng: &mut R,
    ) -> GaloisKey {
        let mut keys = BTreeMap::new();
        for &step in steps {
            let g = self.galois_element(step);
            keys.entry(g).or_insert_with(|| {
                let permutation = galois_permutation(self.ctx.poly_degree, g as u64);
                let mut rotated = self.automorphism(&sk.s, &permutation);
                let key = self.key_switch_key(sk, &rotated, rng);
                rotated.wipe();
                key
            });
        }
        GaloisKey {
            keys,
            param_id: self.ctx.param_id,
        }
    }

    #[cfg(feature = "os-rng")]
    pub fn galois_keygen(&self, sk: &SecretKey, steps: &[i64]) -> GaloisKey {
        self.galois_keygen_with(sk, steps, &mut os_seeded_rng())
    }

    // ---- Encoding ----

    /// Slot values to a polynomial with the given scale, at the given level.
    pub fn encode(&self, values: &[f64], scale: f64, level: usize) -> Result<RnsPoly, FheError> {
        let slots = self.slots();
        if values.len() > slots {
            return Err(FheError::TooManyValues {
                given: values.len(),
                slots,
            });
        }
        if level > self.ctx.max_level() {
            return Err(FheError::OutOfLevels);
        }
        if let Some(bad) = values.iter().find(|v| !v.is_finite()) {
            return Err(FheError::ValueOutOfRange(format!("{bad} is not finite")));
        }
        if !(scale.is_finite() && scale > 0.0) {
            return Err(FheError::ValueOutOfRange(format!("bad scale {scale}")));
        }
        let coefficients = self.ctx.encoder.encode(values);
        let capacity: f64 = self.ctx.moduli_chain[..=level]
            .iter()
            .map(|&q| (q as f64).log2())
            .sum::<f64>()
            .min(126.0);
        let scaled: Vec<i128> = coefficients
            .iter()
            .map(|c| (c * scale).round() as i128)
            .collect();
        let largest = coefficients.iter().fold(0.0f64, |a, c| a.max(c.abs())) * scale;
        if largest >= 2f64.powf(capacity - 1.0) {
            return Err(FheError::ValueOutOfRange(format!(
                "a coefficient of about 2^{:.0} does not fit the {capacity:.0} bits at level {level}",
                largest.log2()
            )));
        }
        let limbs = (0..=level)
            .map(|t| {
                let m = self.modulus(t);
                let mut limb: Vec<u64> = scaled.iter().map(|&c| m.reduce_i128(c)).collect();
                self.ctx.tables[t].forward(&mut limb);
                limb
            })
            .collect();
        Ok(RnsPoly { limbs })
    }

    /// All slot values of a polynomial in the NTT domain whose coefficients are below half the modulus.
    pub(crate) fn decode_all(&self, mut poly: RnsPoly, scale: f64) -> Vec<f64> {
        for (t, limb) in poly.limbs.iter_mut().enumerate() {
            self.ctx.tables[t].inverse(limb);
        }
        let count = poly.limbs.len();
        let moduli: Vec<Modulus> = (0..count).map(|t| self.modulus(t)).collect();
        // Balanced mixed-radix digits: x = d0 + q0 * (d1 + q1 * (d2 + ...)), each digit centered. Evaluating
        // that from the inside out in floating point keeps full relative precision and needs no big integers.
        let mut coefficients = vec![0.0f64; self.ctx.poly_degree];
        let mut digits = vec![0i64; count];
        for (k, out) in coefficients.iter_mut().enumerate() {
            for i in 0..count {
                let m = moduli[i];
                let mut t = poly.limbs[i][k];
                let mut product = 1u64;
                for j in 0..i {
                    let digit = digits[j];
                    let reduced = if digit < 0 {
                        m.neg(m.reduce(digit.unsigned_abs()))
                    } else {
                        m.reduce(digit as u64)
                    };
                    t = m.sub(t, m.mul(reduced, product));
                    product = m.mul(product, m.reduce(moduli[j].q));
                }
                let d = m.mul(t, m.inv(product));
                digits[i] = if d > m.q / 2 {
                    d as i64 - m.q as i64
                } else {
                    d as i64
                };
            }
            let mut value = digits[count - 1] as f64;
            for i in (0..count - 1).rev() {
                value = digits[i] as f64 + moduli[i].q as f64 * value;
            }
            *out = value / scale;
        }
        self.ctx.encoder.decode(&coefficients)
    }

    // ---- Encryption ----

    pub fn encrypt_with<R: RngCore + CryptoRng>(
        &self,
        pk: &PublicKey,
        values: &[f64],
        rng: &mut R,
    ) -> Result<Ciphertext, FheError> {
        if pk.param_id != self.ctx.param_id {
            return Err(FheError::ParameterMismatch);
        }
        let level = self.ctx.max_level();
        let tables = self.ciphertext_tables(level);
        let message = self.encode(values, self.ctx.scale, level)?;
        let n = self.ctx.poly_degree;
        let v = self.small_to_ntt(&sample_ternary(n, rng), &tables);
        let e0 = self.small_to_ntt(&sample_error(n, rng), &tables);
        let e1 = self.small_to_ntt(&sample_error(n, rng), &tables);
        let mut c0 = self.pointwise(&pk.b, &v, &tables);
        self.add_into(&mut c0, &e0, &tables);
        self.add_into(&mut c0, &message, &tables);
        let mut c1 = self.pointwise(&pk.a, &v, &tables);
        self.add_into(&mut c1, &e1, &tables);
        Ok(Ciphertext {
            polys: vec![c0, c1],
            scale: self.ctx.scale,
            num_slots: values.len(),
            param_id: self.ctx.param_id,
        })
    }

    #[cfg(feature = "os-rng")]
    pub fn encrypt(&self, pk: &PublicKey, values: &[f64]) -> Result<Ciphertext, FheError> {
        self.encrypt_with(pk, values, &mut os_seeded_rng())
    }

    /// The values in the ciphertext's leading slots. Works on degree-2 ciphertexts as well.
    pub fn decrypt(&self, sk: &SecretKey, ct: &Ciphertext) -> Result<Vec<f64>, FheError> {
        self.check(ct)?;
        if sk.param_id != self.ctx.param_id {
            return Err(FheError::ParameterMismatch);
        }
        let tables = self.ciphertext_tables(ct.level());
        let secret = self.truncate(&sk.s, tables.len());
        let mut sum = ct.polys[0].clone();
        let mut power = secret.clone();
        for c in &ct.polys[1..] {
            let term = self.pointwise(c, &power, &tables);
            self.add_into(&mut sum, &term, &tables);
            power = self.pointwise(&power, &secret, &tables);
        }
        power.wipe();
        let mut values = self.decode_all(sum, ct.scale);
        values.truncate(ct.num_slots);
        Ok(values)
    }

    // ---- Checks ----

    fn check(&self, ct: &Ciphertext) -> Result<(), FheError> {
        if ct.param_id != self.ctx.param_id {
            return Err(FheError::ParameterMismatch);
        }
        if ct.polys.len() < 2 || ct.polys.len() > 3 {
            return Err(FheError::Malformed(format!(
                "{} polynomials in a ciphertext",
                ct.polys.len()
            )));
        }
        let limbs = ct.polys[0].limb_count();
        if limbs == 0 || limbs > self.ctx.moduli_chain.len() {
            return Err(FheError::Malformed(format!("{limbs} limbs")));
        }
        for p in &ct.polys {
            if p.limb_count() != limbs || p.limbs.iter().any(|l| l.len() != self.ctx.poly_degree) {
                return Err(FheError::Malformed("inconsistent polynomial shape".into()));
            }
        }
        if !(ct.scale.is_finite() && ct.scale > 0.0) {
            return Err(FheError::Malformed(format!("scale {}", ct.scale)));
        }
        if ct.num_slots > self.slots() {
            return Err(FheError::Malformed(format!("{} slots", ct.num_slots)));
        }
        Ok(())
    }

    fn check_ranges(&self, p: &RnsPoly, tables: &[usize]) -> Result<(), FheError> {
        if p.limb_count() != tables.len() {
            return Err(FheError::Malformed("wrong number of limbs".into()));
        }
        for (limb, &t) in p.limbs.iter().zip(tables) {
            if limb.len() != self.ctx.poly_degree {
                return Err(FheError::Malformed("wrong polynomial length".into()));
            }
            let q = self.modulus(t).q;
            if limb.iter().any(|&x| x >= q) {
                return Err(FheError::Malformed(
                    "a coefficient exceeds its prime".into(),
                ));
            }
        }
        Ok(())
    }

    /// The full check for a ciphertext from elsewhere: shape, and that every residue is below its prime.
    pub fn validate_ciphertext(&self, ct: &Ciphertext) -> Result<(), FheError> {
        self.check(ct)?;
        let tables = self.ciphertext_tables(ct.level());
        ct.polys
            .iter()
            .try_for_each(|p| self.check_ranges(p, &tables))
    }

    pub fn validate_public_key(&self, pk: &PublicKey) -> Result<(), FheError> {
        if pk.param_id != self.ctx.param_id {
            return Err(FheError::ParameterMismatch);
        }
        let tables = self.ciphertext_tables(self.ctx.max_level());
        self.check_ranges(&pk.b, &tables)?;
        self.check_ranges(&pk.a, &tables)
    }

    pub fn validate_secret_key(&self, sk: &SecretKey) -> Result<(), FheError> {
        if sk.param_id != self.ctx.param_id {
            return Err(FheError::ParameterMismatch);
        }
        self.check_ranges(&sk.s, &self.all_tables())
    }

    pub(crate) fn validate_switch_key(&self, key: &KeySwitchKey) -> Result<(), FheError> {
        if key.digits.len() != self.ctx.moduli_chain.len() {
            return Err(FheError::Malformed("wrong number of key digits".into()));
        }
        let tables = self.all_tables();
        for (b, a) in &key.digits {
            self.check_ranges(b, &tables)?;
            self.check_ranges(a, &tables)?;
        }
        Ok(())
    }

    pub fn validate_relin_key(&self, key: &RelinKey) -> Result<(), FheError> {
        if key.param_id != self.ctx.param_id {
            return Err(FheError::ParameterMismatch);
        }
        self.validate_switch_key(&key.key)
    }

    pub fn validate_galois_key(&self, key: &GaloisKey) -> Result<(), FheError> {
        if key.param_id != self.ctx.param_id {
            return Err(FheError::ParameterMismatch);
        }
        key.keys
            .values()
            .try_for_each(|k| self.validate_switch_key(k))
    }

    fn align(&self, a: &Ciphertext, b: &Ciphertext) -> Result<(), FheError> {
        self.check(a)?;
        self.check(b)?;
        if a.level() != b.level() {
            return Err(FheError::Malformed(format!(
                "levels differ: {} and {}; use mod_switch_to_level first",
                a.level(),
                b.level()
            )));
        }
        Ok(())
    }

    fn check_same_scale(&self, a: &Ciphertext, b: &Ciphertext) -> Result<(), FheError> {
        if (a.scale - b.scale).abs() > a.scale * 1e-9 {
            return Err(FheError::ScaleMismatch {
                left: a.scale,
                right: b.scale,
            });
        }
        Ok(())
    }

    // ---- Linear operations ----

    fn combine(
        &self,
        a: &Ciphertext,
        b: &Ciphertext,
        subtract: bool,
    ) -> Result<Ciphertext, FheError> {
        self.align(a, b)?;
        self.check_same_scale(a, b)?;
        let tables = self.ciphertext_tables(a.level());
        let (long, short, negate_extra) = if a.polys.len() >= b.polys.len() {
            (a, b, false)
        } else {
            (b, a, subtract)
        };
        let mut polys = long.polys.clone();
        for (x, y) in polys.iter_mut().zip(&short.polys) {
            if !subtract {
                self.add_into(x, y, &tables);
            } else if negate_extra {
                // polys holds b, and the result is a - b.
                self.negate(x, &tables);
                self.add_into(x, y, &tables);
            } else {
                self.sub_into(x, y, &tables);
            }
        }
        if negate_extra {
            for x in polys.iter_mut().skip(short.polys.len()) {
                self.negate(x, &tables);
            }
        }
        Ok(Ciphertext {
            polys,
            scale: a.scale,
            num_slots: a.num_slots.max(b.num_slots),
            param_id: a.param_id,
        })
    }

    /// `Enc(x) + Enc(y) = Enc(x + y)`.
    pub fn add(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext, FheError> {
        self.combine(a, b, false)
    }

    /// `Enc(x) - Enc(y) = Enc(x - y)`.
    pub fn sub(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext, FheError> {
        self.combine(a, b, true)
    }

    /// The same constant added to every slot.
    pub fn add_constant(&self, ct: &Ciphertext, value: f64) -> Result<Ciphertext, FheError> {
        self.check(ct)?;
        if !value.is_finite() {
            return Err(FheError::ValueOutOfRange(format!("{value} is not finite")));
        }
        let scaled = (value * ct.scale).round();
        if scaled.abs() >= 2f64.powi(120) {
            return Err(FheError::ValueOutOfRange(format!("{value} at this scale")));
        }
        let mut out = ct.clone();
        for (t, limb) in out.polys[0].limbs.iter_mut().enumerate() {
            let m = self.modulus(t);
            // A constant polynomial has the same value at every point, so the NTT leaves it as it is.
            let residue = m.reduce_i128(scaled as i128);
            for x in limb.iter_mut() {
                *x = m.add(*x, residue);
            }
        }
        Ok(out)
    }

    /// The sum of ciphertexts with the scale multiplied by their count, which reads as their average when
    /// decrypted. Nothing is divided in the ring, so this costs no level.
    pub fn federated_average(&self, cts: &[Ciphertext]) -> Result<Ciphertext, FheError> {
        let (first, rest) = cts
            .split_first()
            .ok_or_else(|| FheError::Malformed("no ciphertexts to average".into()))?;
        let mut sum = first.clone();
        for ct in rest {
            sum = self.add(&sum, ct)?;
        }
        sum.scale *= cts.len() as f64;
        Ok(sum)
    }

    /// Drops primes without changing the scale, to make two ciphertexts the same level.
    pub fn mod_switch_to_level(
        &self,
        ct: &Ciphertext,
        level: usize,
    ) -> Result<Ciphertext, FheError> {
        self.check(ct)?;
        if level > ct.level() {
            return Err(FheError::OutOfLevels);
        }
        let mut out = ct.clone();
        for p in &mut out.polys {
            p.limbs.truncate(level + 1);
        }
        Ok(out)
    }

    // ---- Rescaling and multiplication ----

    /// Divides by the last prime in the chain, which brings a product's scale back down and removes the
    /// noise that came with it. The ciphertext drops one level.
    pub fn rescale_to_next(&self, ct: &mut Ciphertext) -> Result<(), FheError> {
        self.check(ct)?;
        let level = ct.level();
        if level == 0 {
            return Err(FheError::OutOfLevels);
        }
        for p in &mut ct.polys {
            self.divide_round_by_last(p, level);
        }
        ct.scale /= self.ctx.moduli_chain[level] as f64;
        Ok(())
    }

    fn check_product_scale(&self, scale: f64, level: usize) -> Result<(), FheError> {
        let capacity: f64 = self.ctx.moduli_chain[..=level]
            .iter()
            .map(|&q| (q as f64).log2())
            .sum();
        // Leave room for the message itself as well as the scale.
        if scale.log2() + 10.0 >= capacity {
            return Err(FheError::ScaleOverflow);
        }
        Ok(())
    }

    /// The raw product, of degree 2 and with the scales multiplied. Follow it with
    /// [`CKKSEngine::relinearize`] and [`CKKSEngine::rescale_to_next`].
    pub fn multiply(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext, FheError> {
        self.align(a, b)?;
        if a.degree() != 1 || b.degree() != 1 {
            return Err(FheError::NotRelinearized);
        }
        self.check_product_scale(a.scale * b.scale, a.level())?;
        let tables = self.ciphertext_tables(a.level());
        let c0 = self.pointwise(&a.polys[0], &b.polys[0], &tables);
        let mut c1 = self.pointwise(&a.polys[0], &b.polys[1], &tables);
        let cross = self.pointwise(&a.polys[1], &b.polys[0], &tables);
        self.add_into(&mut c1, &cross, &tables);
        let c2 = self.pointwise(&a.polys[1], &b.polys[1], &tables);
        Ok(Ciphertext {
            polys: vec![c0, c1, c2],
            scale: a.scale * b.scale,
            num_slots: a.num_slots.max(b.num_slots),
            param_id: a.param_id,
        })
    }

    /// Hybrid key switching with one digit per prime: returns the pair that decrypts to `c * new_key`.
    fn key_switch(&self, c: &RnsPoly, key: &KeySwitchKey) -> (RnsPoly, RnsPoly) {
        let n = self.ctx.poly_degree;
        let level = c.limb_count() - 1;
        let special = self.ctx.special_index();
        let targets: Vec<usize> = (0..=level).chain(core::iter::once(special)).collect();
        let mut out0 = RnsPoly::zero(n, targets.len());
        let mut out1 = RnsPoly::zero(n, targets.len());
        for i in 0..=level {
            let mut coefficients = c.limbs[i].clone();
            self.ctx.tables[i].inverse(&mut coefficients);
            let (key_b, key_a) = &key.digits[i];
            for (position, &t) in targets.iter().enumerate() {
                let m = self.modulus(t);
                let lifted;
                let digit: &[u64] = if t == i {
                    &c.limbs[i]
                } else {
                    let mut l: Vec<u64> = coefficients.iter().map(|&x| m.reduce(x)).collect();
                    self.ctx.tables[t].forward(&mut l);
                    lifted = l;
                    &lifted
                };
                let (o0, o1) = (&mut out0.limbs[position], &mut out1.limbs[position]);
                let (kb, ka) = (&key_b.limbs[t], &key_a.limbs[t]);
                for (k, &d) in digit.iter().enumerate() {
                    o0[k] = m.add(o0[k], m.mul(d, kb[k]));
                    o1[k] = m.add(o1[k], m.mul(d, ka[k]));
                }
            }
        }
        self.divide_round_by_last(&mut out0, special);
        self.divide_round_by_last(&mut out1, special);
        (out0, out1)
    }

    /// Brings a degree-2 ciphertext back to degree 1.
    pub fn relinearize(
        &self,
        ct: &Ciphertext,
        relin_key: &RelinKey,
    ) -> Result<Ciphertext, FheError> {
        self.check(ct)?;
        if relin_key.param_id != self.ctx.param_id {
            return Err(FheError::ParameterMismatch);
        }
        if ct.degree() != 2 {
            return Ok(ct.clone());
        }
        let tables = self.ciphertext_tables(ct.level());
        let (d0, d1) = self.key_switch(&ct.polys[2], &relin_key.key);
        let mut c0 = ct.polys[0].clone();
        let mut c1 = ct.polys[1].clone();
        self.add_into(&mut c0, &d0, &tables);
        self.add_into(&mut c1, &d1, &tables);
        Ok(Ciphertext {
            polys: vec![c0, c1],
            ..ct.clone_header()
        })
    }

    /// Multiplies, relinearizes and rescales in one step.
    pub fn multiply_relin_rescale(
        &self,
        a: &Ciphertext,
        b: &Ciphertext,
        relin_key: &RelinKey,
    ) -> Result<Ciphertext, FheError> {
        let mut product = self.relinearize(&self.multiply(a, b)?, relin_key)?;
        self.rescale_to_next(&mut product)?;
        Ok(product)
    }

    /// Multiplies each slot by a plaintext value, and rescales. The weights are encoded at exactly the
    /// scale of the prime being dropped, so the scale comes out the same as it went in.
    pub fn multiply_plain_rescale(
        &self,
        ct: &Ciphertext,
        weights: &[f64],
    ) -> Result<Ciphertext, FheError> {
        self.check(ct)?;
        if ct.degree() != 1 {
            return Err(FheError::NotRelinearized);
        }
        let level = ct.level();
        if level == 0 {
            return Err(FheError::OutOfLevels);
        }
        let prime = self.ctx.moduli_chain[level] as f64;
        let plain = self.encode(weights, prime, level)?;
        let tables = self.ciphertext_tables(level);
        let polys = ct
            .polys
            .iter()
            .map(|c| self.pointwise(c, &plain, &tables))
            .collect();
        let mut out = Ciphertext {
            polys,
            ..ct.clone_header()
        };
        self.rescale_to_next(&mut out)?;
        out.scale = ct.scale;
        Ok(out)
    }

    /// Multiplies every limb by the integer `round(value * constant_scale)`.
    fn multiply_constant(
        &self,
        ct: &Ciphertext,
        value: f64,
        constant_scale: f64,
    ) -> Result<Ciphertext, FheError> {
        let scaled = (value * constant_scale).round();
        if !scaled.is_finite() || scaled.abs() >= 2f64.powi(100) {
            return Err(FheError::ValueOutOfRange(format!(
                "{value} at scale {constant_scale}"
            )));
        }
        let mut out = ct.clone();
        for p in &mut out.polys {
            for (t, limb) in p.limbs.iter_mut().enumerate() {
                let m = self.modulus(t);
                let residue = m.reduce_i128(scaled as i128);
                let shoup = m.shoup(residue);
                for x in limb.iter_mut() {
                    *x = m.mul_shoup(*x, residue, shoup);
                }
            }
        }
        out.scale *= constant_scale;
        Ok(out)
    }

    /// `Enc(x) * k = Enc(k * x)`. A whole number costs no level. Anything else costs one.
    pub fn scalar_mul(&self, ct: &Ciphertext, scalar: f64) -> Result<Ciphertext, FheError> {
        self.check(ct)?;
        if !scalar.is_finite() {
            return Err(FheError::ValueOutOfRange(format!("{scalar} is not finite")));
        }
        if scalar.fract() == 0.0 && scalar.abs() < 2f64.powi(31) {
            return self.multiply_constant(ct, scalar, 1.0);
        }
        let level = ct.level();
        if level == 0 {
            return Err(FheError::OutOfLevels);
        }
        let mut out = self.multiply_constant(ct, scalar, self.ctx.moduli_chain[level] as f64)?;
        self.rescale_to_next(&mut out)?;
        out.scale = ct.scale;
        Ok(out)
    }

    // ---- Rotation ----

    /// Rotates the slots left by `steps`, or right if that is negative.
    pub fn rotate(
        &self,
        ct: &Ciphertext,
        steps: i64,
        galois_key: &GaloisKey,
    ) -> Result<Ciphertext, FheError> {
        self.check(ct)?;
        if galois_key.param_id != self.ctx.param_id {
            return Err(FheError::ParameterMismatch);
        }
        if ct.degree() != 1 {
            return Err(FheError::NotRelinearized);
        }
        if steps.rem_euclid(self.slots() as i64) == 0 {
            return Ok(ct.clone());
        }
        let g = self.galois_element(steps);
        let key = galois_key
            .keys
            .get(&g)
            .ok_or(FheError::MissingGaloisKey { steps })?;
        let permutation = galois_permutation(self.ctx.poly_degree, g as u64);
        let mut c0 = self.automorphism(&ct.polys[0], &permutation);
        let c1 = self.automorphism(&ct.polys[1], &permutation);
        let (d0, d1) = self.key_switch(&c1, key);
        self.add_into(&mut c0, &d0, &self.ciphertext_tables(ct.level()));
        Ok(Ciphertext {
            polys: vec![c0, d1],
            ..ct.clone_header()
        })
    }

    /// Every slot becomes the sum of all slots, in `log2(slots)` rotations and no levels. Decrypting the
    /// result reveals the total but none of the individual values that went into it.
    pub fn sum_slots(
        &self,
        ct: &Ciphertext,
        galois_key: &GaloisKey,
    ) -> Result<Ciphertext, FheError> {
        let mut sum = ct.clone();
        for step in self.sum_rotation_steps() {
            let rotated = self.rotate(&sum, step, galois_key)?;
            sum = self.add(&sum, &rotated)?;
        }
        sum.num_slots = 1;
        Ok(sum)
    }

    // ---- Clinical scoring ----

    /// A linear score, `sum(weight[i] * feature[i])`, in the first slot. It costs one level.
    pub fn evaluate_linear_risk_model(
        &self,
        ct: &Ciphertext,
        weights: &[f64],
        bias: f64,
        galois_key: &GaloisKey,
    ) -> Result<Ciphertext, FheError> {
        if weights.len() > ct.num_slots {
            return Err(FheError::TooManyValues {
                given: weights.len(),
                slots: ct.num_slots,
            });
        }
        let weighted = self.multiply_plain_rescale(ct, weights)?;
        let total = self.sum_slots(&weighted, galois_key)?;
        self.add_constant(&total, bias)
    }

    /// `a0 + a1 x + a2 x^2 + a3 x^3` on every slot, in two levels. Each term is brought to exactly the
    /// final scale with a constant chosen for it, so that the terms can be added without a scale error.
    pub fn evaluate_cubic(
        &self,
        ct: &Ciphertext,
        coefficients: [f64; 4],
        relin_key: &RelinKey,
    ) -> Result<Ciphertext, FheError> {
        self.check(ct)?;
        let level = ct.level();
        if level < 2 {
            return Err(FheError::OutOfLevels);
        }
        let [a0, a1, a2, a3] = coefficients;
        let primes = &self.ctx.moduli_chain;
        let (top, next) = (primes[level] as f64, primes[level - 1] as f64);

        let x2 = self.multiply_relin_rescale(ct, ct, relin_key)?;
        let mut a3x = self.multiply_constant(ct, a3, top)?;
        self.rescale_to_next(&mut a3x)?;
        a3x.scale = ct.scale;
        let cubic = self.multiply_relin_rescale(&x2, &a3x, relin_key)?;
        let target = cubic.scale;

        let mut quadratic = self.multiply_constant(&x2, a2, target * next / x2.scale)?;
        self.rescale_to_next(&mut quadratic)?;
        quadratic.scale = target;

        let x_down = self.mod_switch_to_level(ct, level - 1)?;
        let mut linear = self.multiply_constant(&x_down, a1, target * next / ct.scale)?;
        self.rescale_to_next(&mut linear)?;
        linear.scale = target;

        let sum = self.add(&self.add(&cubic, &quadratic)?, &linear)?;
        self.add_constant(&sum, a0)
    }

    /// The logistic function on `[-8, 8]`, by the cubic least-squares fit from Kim et al. (2018),
    /// `0.5 + 0.15012 x - 0.001593 x^3`. Outside that interval the approximation is meaningless.
    pub fn evaluate_logistic(
        &self,
        ct: &Ciphertext,
        relin_key: &RelinKey,
    ) -> Result<Ciphertext, FheError> {
        self.evaluate_cubic(ct, [0.5, 0.15012, 0.0, -0.001593], relin_key)
    }
}

impl Ciphertext {
    /// The same metadata with no polynomials, for use with struct update syntax.
    fn clone_header(&self) -> Ciphertext {
        Ciphertext {
            polys: Vec::new(),
            scale: self.scale,
            num_slots: self.num_slots,
            param_id: self.param_id,
        }
    }
}
