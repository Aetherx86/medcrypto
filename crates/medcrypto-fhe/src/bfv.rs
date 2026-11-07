//! RNS-BFV: exact arithmetic on integers, modulo a plaintext modulus `t`.
//!
//! CKKS answers approximately, which suits lab values. BFV answers exactly, which suits counts, codes and
//! anything where 1234 must not come back as 1234.00002. It shares the ring, the primes, the NTT and the key
//! switching with CKKS, so the security argument is the same table in the HE Standard.
//!
//! A message `m` is held in the high bits, as `c0 + c1 * s = Delta * m + noise` with `Delta = floor(Q / t)`.
//! Decryption is correct while the noise stays below `Delta / 2`. There are no levels and no rescaling: the
//! noise grows until the budget in [`BfvEngine::noise_budget_bits`] runs out.
//!
//! # Exact scaling without big integers
//!
//! Multiplication needs `round(t * x / Q)`, for an `x` larger than `Q` can hold. The usual RNS methods
//! approximate this in floating point. Here it is exact, in word arithmetic only:
//!
//! 1. Lift each polynomial from `Q` to an auxiliary basis `B`, by converting to balanced mixed-radix digits and
//!    evaluating them modulo each prime of `B`. `B` is large enough that the tensor product cannot wrap around.
//! 2. Multiply in `Q * B`.
//! 3. Let `y = t * x + floor(Q / 2)`. Then `y = Q * z + r` with `r` in `[0, Q)` and `z` the wanted result. The
//!    residues of `y` modulo `Q` are exactly those of `r`, so `r` can be lifted to `B`, and then
//!    `z = (y - r) / Q` is a plain division in each prime of `B`.
//! 4. Lift `z` back from `B` to `Q`.
//!
//! The cost is quadratic in the number of primes per coefficient, which is small here.
//!
//! # Slots
//!
//! `t` is a prime that is 1 mod `2N`, so plaintexts batch into `N` slots, arranged as two rows of `N/2`.
//! [`BfvEngine::rotate_rows`] rotates both rows, and [`BfvEngine::swap_rows`] exchanges them.
//!
//! Slot arithmetic wraps around modulo `t`, as integers modulo `t` do. Nothing can detect that under
//! encryption, so choose `t` larger than any result the computation can reach.

use crate::arith::{largest_ntt_prime_excluding, ntt_primes, Modulus};
use crate::ckks::{
    sample_error, sample_ternary, CKKSEngine, GaloisKey, PublicKey, RelinKey, SecretKey,
};
use crate::ntt::{galois_permutation, NttTable};
use crate::params::CkksPreset;
use crate::rns::RnsPoly;
use crate::FheError;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// A polynomial in both bases: the residues modulo `Q`, then those modulo the auxiliary basis.
type TwoBases = (Vec<Vec<u64>>, Vec<Vec<u64>>);

/// A BFV ciphertext, in the NTT domain, always over the whole of `Q`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BfvCiphertext {
    pub polys: Vec<RnsPoly>,
    /// How many leading slots hold meaningful values.
    pub num_slots: usize,
    pub plain_modulus: u64,
    pub param_id: u64,
}

impl BfvCiphertext {
    /// One less than the number of polynomials: 1 normally, and 2 straight after a multiplication.
    pub fn degree(&self) -> usize {
        self.polys.len() - 1
    }
}

/// Converts a residue vector between two bases, exactly, through mixed-radix digits.
#[derive(Clone, Debug)]
struct Lifter {
    from: Vec<Modulus>,
    to: Vec<Modulus>,
    /// `partial[i][j]` is the product of the first `j` primes of `from`, modulo `from[i]`.
    partial: Vec<Vec<u64>>,
    /// The inverse of the product of the first `i` primes of `from`, modulo `from[i]`.
    inverse: Vec<u64>,
    /// `radix[t][i]` is `from[i]` modulo `to[t]`.
    radix: Vec<Vec<u64>>,
}

impl Lifter {
    fn new(from: Vec<Modulus>, to: Vec<Modulus>) -> Self {
        let partial: Vec<Vec<u64>> = from
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let mut row = vec![1u64];
                for f in &from[..i] {
                    row.push(m.mul(*row.last().expect("not empty"), m.reduce(f.q)));
                }
                row
            })
            .collect();
        let inverse = from
            .iter()
            .enumerate()
            .map(|(i, m)| m.inv(partial[i][i]))
            .collect();
        let radix = to
            .iter()
            .map(|t| from.iter().map(|f| t.reduce(f.q)).collect())
            .collect();
        Self {
            from,
            to,
            partial,
            inverse,
            radix,
        }
    }

    /// Digits such that `x = d0 + f0 * (d1 + f1 * (d2 + ...))`.
    fn digits(&self, residues: &[&[u64]], k: usize, centered: bool, out: &mut [i64]) {
        for i in 0..self.from.len() {
            let m = self.from[i];
            let mut t = residues[i][k];
            for (j, &d) in out[..i].iter().enumerate() {
                let reduced = if d < 0 {
                    m.neg(m.reduce(d.unsigned_abs()))
                } else {
                    m.reduce(d as u64)
                };
                t = m.sub(t, m.mul(reduced, self.partial[i][j]));
            }
            let d = m.mul(t, self.inverse[i]);
            out[i] = if centered && d > m.q / 2 {
                d as i64 - m.q as i64
            } else {
                d as i64
            };
        }
    }

    /// Lifts each coefficient to every prime of the target basis.
    fn lift(&self, input: &[Vec<u64>], centered: bool) -> Vec<Vec<u64>> {
        let n = input[0].len();
        let residues: Vec<&[u64]> = input.iter().map(Vec::as_slice).collect();
        let mut out = vec![vec![0u64; n]; self.to.len()];
        let mut digits = vec![0i64; self.from.len()];
        for k in 0..n {
            self.digits(&residues, k, centered, &mut digits);
            for (limb, (t, radix)) in out.iter_mut().zip(self.to.iter().zip(&self.radix)) {
                let mut value = 0u64;
                for i in (0..digits.len()).rev() {
                    let d = digits[i];
                    let reduced = if d < 0 {
                        t.neg(t.reduce(d.unsigned_abs()))
                    } else {
                        t.reduce(d as u64)
                    };
                    value = t.add(t.mul(value, radix[i]), reduced);
                }
                limb[k] = value;
            }
        }
        out
    }
}

/// The scheme, on one of the CKKS presets' parameter sets and a plaintext modulus.
#[derive(Clone, Debug)]
pub struct BfvEngine {
    ckks: CKKSEngine,
    t: NttTable,
    q: Vec<Modulus>,
    aux: Vec<NttTable>,
    q_to_aux: Lifter,
    aux_to_q: Lifter,
    aux_to_t: Lifter,
    /// `floor(Q / t)`, by prime of `Q`.
    delta: Vec<u64>,
    /// `floor(Q / 2)`, by prime of `Q` and then of the auxiliary basis.
    half_q_in_q: Vec<u64>,
    half_q_in_aux: Vec<u64>,
    /// The inverse of `Q`, by prime of the auxiliary basis.
    q_inverse_in_aux: Vec<u64>,
    /// `t`, by prime of `Q` and then of the auxiliary basis.
    t_in_q: Vec<u64>,
    t_in_aux: Vec<u64>,
    /// Slot to position in the NTT modulo `t`.
    slot_positions: Vec<u32>,
    log2_q: f64,
}

/// `floor(Q / 2)`, computed by long division over the mixed-radix form of `Q`, then reduced into each target.
fn half_of_product(primes: &[u64], targets: &[Modulus]) -> Vec<u64> {
    // Q is odd, so floor(Q / 2) = (Q - 1) / 2, and that is an exact division in each odd prime.
    targets
        .iter()
        .map(|m| {
            let mut q_mod = 1u64;
            for &p in primes {
                q_mod = m.mul(q_mod, m.reduce(p));
            }
            m.mul(m.sub(q_mod, 1), m.inv(2))
        })
        .collect()
}

impl BfvEngine {
    /// `plain_bits` is the size of `t`, from 20 to 40 bits. Larger values wrap around later, and leave less
    /// noise budget for multiplications.
    pub fn new(preset: CkksPreset, plain_bits: u32) -> Result<Self, FheError> {
        if !(20..=40).contains(&plain_bits) {
            return Err(FheError::InvalidParameters(format!(
                "plain_bits {plain_bits}: use 20 to 40"
            )));
        }
        let ckks = CKKSEngine::from_preset(preset);
        let context = ckks.context();
        let degree = context.poly_degree;
        // Distinct from the ciphertext primes, which only matters at 40 bits.
        let plain = largest_ntt_prime_excluding(plain_bits, degree, &context.moduli_chain)
            .ok_or_else(|| {
                FheError::InvalidParameters(format!(
                    "no {plain_bits}-bit plaintext modulus exists for N = {degree}"
                ))
            })?;
        let t = NttTable::new(plain, degree);

        let chain = &context.moduli_chain;
        let q: Vec<Modulus> = chain.iter().map(|&p| Modulus::new(p)).collect();
        let log2_q: f64 = chain.iter().map(|&p| (p as f64).log2()).sum();

        // The tensor product is at most N * Q^2 / 2, and the scaled result about t * N * Q / 2, so B has to
        // exceed t * N * Q. Two more bits, and one more prime, keep that from being a close call.
        let needed = log2_q + (degree as f64).log2() + plain_bits as f64 + 2.0;
        let count = (needed / 59.0).ceil() as usize + 1;
        // The first two 60-bit primes are the preset's q0 and special prime, so they are skipped.
        let aux_primes: Vec<u64> = ntt_primes(60, degree, count + 2)
            .into_iter()
            .filter(|p| !chain.contains(p) && *p != context.special_prime)
            .take(count)
            .collect();
        let aux: Vec<NttTable> = aux_primes
            .iter()
            .map(|&p| NttTable::new(p, degree))
            .collect();
        let aux_mod: Vec<Modulus> = aux.iter().map(|table| table.modulus).collect();

        // floor(Q / t) = (Q - (Q mod t)) / t, which modulo a prime of Q is -(Q mod t) / t.
        let mut q_mod_t = 1u64;
        for &p in chain {
            q_mod_t = t.modulus.mul(q_mod_t, t.modulus.reduce(p));
        }
        let delta = q
            .iter()
            .map(|m| m.mul(m.neg(m.reduce(q_mod_t)), m.inv(m.reduce(plain))))
            .collect();
        let q_inverse_in_aux = aux_mod
            .iter()
            .map(|m| {
                let mut product = 1u64;
                for &p in chain {
                    product = m.mul(product, m.reduce(p));
                }
                m.inv(product)
            })
            .collect();

        let half = degree / 2;
        let log_n = degree.trailing_zeros();
        let position = |k: u64| (((k - 1) / 2) as usize).reverse_bits() >> (usize::BITS - log_n);
        let mut slot_positions = vec![0u32; degree];
        let mut power = 1u64;
        let m = 2 * degree as u64;
        for j in 0..half {
            slot_positions[j] = position(power) as u32;
            slot_positions[j + half] = position(m - power) as u32;
            power = power * 5 % m;
        }

        Ok(Self {
            t_in_q: q.iter().map(|m| m.reduce(plain)).collect(),
            t_in_aux: aux_mod.iter().map(|m| m.reduce(plain)).collect(),
            half_q_in_q: half_of_product(chain, &q),
            half_q_in_aux: half_of_product(chain, &aux_mod),
            q_to_aux: Lifter::new(q.clone(), aux_mod.clone()),
            aux_to_q: Lifter::new(aux_mod.clone(), q.clone()),
            aux_to_t: Lifter::new(aux_mod, vec![t.modulus]),
            q_inverse_in_aux,
            delta,
            slot_positions,
            log2_q,
            ckks,
            t,
            q,
            aux,
        })
    }

    /// The plaintext modulus. Slot values are the integers in `(-t/2, t/2]`.
    pub fn plain_modulus(&self) -> u64 {
        self.t.modulus.q
    }

    /// `N`, as two rows of `N/2`.
    pub fn slots(&self) -> usize {
        self.ckks.context().poly_degree
    }

    fn q_tables(&self) -> Vec<usize> {
        self.ckks.ciphertext_tables(self.ckks.context().max_level())
    }

    // ---- Keys. These are the same keys as CKKS, from the same machinery ----

    pub fn keygen_with<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (SecretKey, PublicKey) {
        self.ckks.keygen_with(rng)
    }

    #[cfg(feature = "os-rng")]
    pub fn keygen(&self) -> (SecretKey, PublicKey) {
        self.ckks.keygen()
    }

    pub fn relin_keygen_with<R: RngCore + CryptoRng>(
        &self,
        sk: &SecretKey,
        rng: &mut R,
    ) -> RelinKey {
        self.ckks.relin_keygen_with(sk, rng)
    }

    #[cfg(feature = "os-rng")]
    pub fn relin_keygen(&self, sk: &SecretKey) -> RelinKey {
        self.ckks.relin_keygen(sk)
    }

    fn swap_element(&self) -> u32 {
        (2 * self.ckks.context().poly_degree - 1) as u32
    }

    /// The steps [`BfvEngine::sum_all`] needs, along with the row swap.
    pub fn sum_galois_keygen_with<R: RngCore + CryptoRng>(
        &self,
        sk: &SecretKey,
        rng: &mut R,
    ) -> GaloisKey {
        let mut elements: Vec<u32> = self
            .ckks
            .sum_rotation_steps()
            .iter()
            .map(|&s| self.ckks.galois_element(s))
            .collect();
        elements.push(self.swap_element());
        self.ckks.galois_keygen_for_elements(sk, &elements, rng)
    }

    #[cfg(feature = "os-rng")]
    pub fn sum_galois_keygen(&self, sk: &SecretKey) -> GaloisKey {
        self.sum_galois_keygen_with(sk, &mut crate::ckks::os_seeded_rng())
    }

    /// Keys for particular row rotations, and for the row swap if asked.
    pub fn galois_keygen_with<R: RngCore + CryptoRng>(
        &self,
        sk: &SecretKey,
        steps: &[i64],
        with_swap: bool,
        rng: &mut R,
    ) -> GaloisKey {
        let mut elements: Vec<u32> = steps.iter().map(|&s| self.ckks.galois_element(s)).collect();
        if with_swap {
            elements.push(self.swap_element());
        }
        self.ckks.galois_keygen_for_elements(sk, &elements, rng)
    }

    #[cfg(feature = "os-rng")]
    pub fn galois_keygen(&self, sk: &SecretKey, steps: &[i64], with_swap: bool) -> GaloisKey {
        self.galois_keygen_with(sk, steps, with_swap, &mut crate::ckks::os_seeded_rng())
    }

    // ---- Encoding ----

    /// Slot values to centered plaintext coefficients.
    fn encode(&self, values: &[i64]) -> Result<Vec<i64>, FheError> {
        let n = self.slots();
        if values.len() > n {
            return Err(FheError::TooManyValues {
                given: values.len(),
                slots: n,
            });
        }
        let t = self.t.modulus;
        let bound = (t.q / 2) as i64;
        let mut evaluations = vec![0u64; n];
        for (slot, &value) in values.iter().enumerate() {
            if value > bound || value < -bound {
                return Err(FheError::ValueOutOfRange(format!(
                    "{value} is outside the plaintext range of +/-{bound}"
                )));
            }
            evaluations[self.slot_positions[slot] as usize] = if value < 0 {
                t.q - value.unsigned_abs()
            } else {
                value as u64
            };
        }
        self.t.inverse(&mut evaluations);
        Ok(evaluations
            .iter()
            .map(|&c| {
                if c > t.q / 2 {
                    c as i64 - t.q as i64
                } else {
                    c as i64
                }
            })
            .collect())
    }

    fn decode(&self, mut coefficients: Vec<u64>, num_slots: usize) -> Vec<i64> {
        let t = self.t.modulus;
        self.t.forward(&mut coefficients);
        self.slot_positions[..num_slots]
            .iter()
            .map(|&position| {
                let c = coefficients[position as usize];
                if c > t.q / 2 {
                    c as i64 - t.q as i64
                } else {
                    c as i64
                }
            })
            .collect()
    }

    /// `Delta * m`, in the NTT domain over `Q`.
    fn scaled_message(&self, plain: &[i64]) -> RnsPoly {
        let limbs = self
            .q
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let delta = self.delta[i];
                let shoup = m.shoup(delta);
                let mut limb: Vec<u64> = plain
                    .iter()
                    .map(|&c| {
                        let r = if c < 0 {
                            m.neg(m.reduce(c.unsigned_abs()))
                        } else {
                            m.reduce(c as u64)
                        };
                        m.mul_shoup(r, delta, shoup)
                    })
                    .collect();
                self.ckks.context().tables[i].forward(&mut limb);
                limb
            })
            .collect();
        RnsPoly { limbs }
    }

    // ---- Encryption ----

    pub fn encrypt_with<R: RngCore + CryptoRng>(
        &self,
        pk: &PublicKey,
        values: &[i64],
        rng: &mut R,
    ) -> Result<BfvCiphertext, FheError> {
        self.ckks.validate_public_key(pk)?;
        let plain = self.encode(values)?;
        let tables = self.q_tables();
        let n = self.slots();
        let e = &self.ckks;
        let v = e.small_to_ntt(&sample_ternary(n, rng), &tables);
        let e0 = e.small_to_ntt(&sample_error(n, rng), &tables);
        let e1 = e.small_to_ntt(&sample_error(n, rng), &tables);
        let mut c0 = e.pointwise(&pk.b, &v, &tables);
        e.add_into(&mut c0, &e0, &tables);
        e.add_into(&mut c0, &self.scaled_message(&plain), &tables);
        let mut c1 = e.pointwise(&pk.a, &v, &tables);
        e.add_into(&mut c1, &e1, &tables);
        Ok(BfvCiphertext {
            polys: vec![c0, c1],
            num_slots: values.len(),
            plain_modulus: self.plain_modulus(),
            param_id: e.context().param_id(),
        })
    }

    #[cfg(feature = "os-rng")]
    pub fn encrypt(&self, pk: &PublicKey, values: &[i64]) -> Result<BfvCiphertext, FheError> {
        self.encrypt_with(pk, values, &mut crate::ckks::os_seeded_rng())
    }

    /// `c0 + c1 * s + ...`, in the coefficient domain.
    fn phase(&self, sk: &SecretKey, ct: &BfvCiphertext) -> Result<Vec<Vec<u64>>, FheError> {
        self.check(ct)?;
        self.ckks.validate_secret_key(sk)?;
        let tables = self.q_tables();
        let e = &self.ckks;
        let secret = e.truncate(&sk.s, tables.len());
        let mut sum = ct.polys[0].clone();
        let mut power = secret.clone();
        for c in &ct.polys[1..] {
            let term = e.pointwise(c, &power, &tables);
            e.add_into(&mut sum, &term, &tables);
            power = e.pointwise(&power, &secret, &tables);
        }
        power.wipe();
        for (i, limb) in sum.limbs.iter_mut().enumerate() {
            e.context().tables[i].inverse(limb);
        }
        Ok(sum.limbs)
    }

    /// `round(t * x / Q)` in the auxiliary basis, with `x` given in both bases in the coefficient domain.
    fn scale_down(&self, q_part: &[Vec<u64>], aux_part: &[Vec<u64>]) -> Vec<Vec<u64>> {
        let n = q_part[0].len();
        // y = t * x + floor(Q / 2), whose residues modulo Q are those of its remainder r.
        let remainder: Vec<Vec<u64>> = q_part
            .iter()
            .enumerate()
            .map(|(i, limb)| {
                let m = self.q[i];
                let (t, half) = (self.t_in_q[i], self.half_q_in_q[i]);
                limb.iter().map(|&x| m.add(m.mul(x, t), half)).collect()
            })
            .collect();
        let lifted = self.q_to_aux.lift(&remainder, false);
        aux_part
            .iter()
            .enumerate()
            .map(|(j, limb)| {
                let table = &self.aux[j];
                let m = table.modulus;
                let (t, half, inverse) = (
                    self.t_in_aux[j],
                    self.half_q_in_aux[j],
                    self.q_inverse_in_aux[j],
                );
                (0..n)
                    .map(|k| {
                        let y = m.add(m.mul(limb[k], t), half);
                        m.mul(m.sub(y, lifted[j][k]), inverse)
                    })
                    .collect()
            })
            .collect()
    }

    /// The slot values, as integers in the plaintext range. Works on degree-2 ciphertexts as well.
    pub fn decrypt(&self, sk: &SecretKey, ct: &BfvCiphertext) -> Result<Vec<i64>, FheError> {
        let phase = self.phase(sk, ct)?;
        let aux = self.q_to_aux.lift(&phase, true);
        let scaled = self.scale_down(&phase, &aux);
        let mut plain = self.aux_to_t.lift(&scaled, true);
        Ok(self.decode(plain.remove(0), ct.num_slots))
    }

    /// How many bits of noise room remain. Below 1, decryption gives wrong answers, since noise that has
    /// overrun the message reads as about half of `Q`. Each multiplication uses up a lot of this, and each
    /// addition very little.
    pub fn noise_budget_bits(&self, sk: &SecretKey, ct: &BfvCiphertext) -> Result<f64, FheError> {
        let mut phase = self.phase(sk, ct)?;
        for (i, limb) in phase.iter_mut().enumerate() {
            let m = self.q[i];
            for x in limb.iter_mut() {
                *x = m.mul(*x, self.t_in_q[i]);
            }
        }
        // t * phase modulo Q is t * noise, up to a term from Q mod t that is part of the noise too. Lift it
        // to the auxiliary basis exactly and read off its size in floating point.
        let residues: Vec<&[u64]> = phase.iter().map(Vec::as_slice).collect();
        let mut digits = vec![0i64; self.q.len()];
        let mut largest = 0f64;
        for k in 0..phase[0].len() {
            self.q_to_aux.digits(&residues, k, true, &mut digits);
            let mut value = digits[digits.len() - 1] as f64;
            for i in (0..digits.len() - 1).rev() {
                value = digits[i] as f64 + self.q[i].q as f64 * value;
            }
            largest = largest.max(value.abs());
        }
        Ok(self.log2_q - largest.max(1.0).log2() - 1.0)
    }

    // ---- Checks ----

    fn check(&self, ct: &BfvCiphertext) -> Result<(), FheError> {
        if ct.param_id != self.ckks.context().param_id() || ct.plain_modulus != self.plain_modulus()
        {
            return Err(FheError::ParameterMismatch);
        }
        if ct.polys.len() < 2 || ct.polys.len() > 3 {
            return Err(FheError::Malformed(format!(
                "{} polynomials in a ciphertext",
                ct.polys.len()
            )));
        }
        if ct.num_slots > self.slots() {
            return Err(FheError::Malformed(format!("{} slots", ct.num_slots)));
        }
        let n = self.slots();
        for p in &ct.polys {
            if p.limb_count() != self.q.len() || p.limbs.iter().any(|l| l.len() != n) {
                return Err(FheError::Malformed("inconsistent polynomial shape".into()));
            }
        }
        Ok(())
    }

    /// The full check for a ciphertext from elsewhere.
    pub fn validate_ciphertext(&self, ct: &BfvCiphertext) -> Result<(), FheError> {
        self.check(ct)?;
        for p in &ct.polys {
            for (limb, m) in p.limbs.iter().zip(&self.q) {
                if limb.iter().any(|&x| x >= m.q) {
                    return Err(FheError::Malformed(
                        "a coefficient exceeds its prime".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn check_pair(&self, a: &BfvCiphertext, b: &BfvCiphertext) -> Result<(), FheError> {
        self.check(a)?;
        self.check(b)
    }

    fn header(&self, ct: &BfvCiphertext, polys: Vec<RnsPoly>, num_slots: usize) -> BfvCiphertext {
        BfvCiphertext {
            polys,
            num_slots,
            plain_modulus: ct.plain_modulus,
            param_id: ct.param_id,
        }
    }

    // ---- Arithmetic ----

    pub fn add(&self, a: &BfvCiphertext, b: &BfvCiphertext) -> Result<BfvCiphertext, FheError> {
        self.check_pair(a, b)?;
        let tables = self.q_tables();
        let (long, short) = if a.polys.len() >= b.polys.len() {
            (a, b)
        } else {
            (b, a)
        };
        let mut polys = long.polys.clone();
        for (x, y) in polys.iter_mut().zip(&short.polys) {
            self.ckks.add_into(x, y, &tables);
        }
        Ok(self.header(a, polys, a.num_slots.max(b.num_slots)))
    }

    pub fn negate(&self, a: &BfvCiphertext) -> Result<BfvCiphertext, FheError> {
        self.check(a)?;
        let tables = self.q_tables();
        let mut polys = a.polys.clone();
        for p in &mut polys {
            self.ckks.negate(p, &tables);
        }
        Ok(self.header(a, polys, a.num_slots))
    }

    pub fn sub(&self, a: &BfvCiphertext, b: &BfvCiphertext) -> Result<BfvCiphertext, FheError> {
        self.add(a, &self.negate(b)?)
    }

    /// Adds plaintext values, slot by slot.
    pub fn add_plain(&self, a: &BfvCiphertext, values: &[i64]) -> Result<BfvCiphertext, FheError> {
        self.check(a)?;
        let tables = self.q_tables();
        let message = self.scaled_message(&self.encode(values)?);
        let mut polys = a.polys.clone();
        self.ckks.add_into(&mut polys[0], &message, &tables);
        Ok(self.header(a, polys, a.num_slots.max(values.len())))
    }

    /// Multiplies by plaintext values, slot by slot. Slots beyond `values` become zero.
    pub fn multiply_plain(
        &self,
        a: &BfvCiphertext,
        values: &[i64],
    ) -> Result<BfvCiphertext, FheError> {
        self.check(a)?;
        let tables = self.q_tables();
        let plain = self.ckks.small_to_ntt(&self.encode(values)?, &tables);
        let polys = a
            .polys
            .iter()
            .map(|c| self.ckks.pointwise(c, &plain, &tables))
            .collect();
        Ok(self.header(a, polys, a.num_slots))
    }

    /// The product of two ciphertexts, of degree 2. Follow it with [`BfvEngine::relinearize`].
    pub fn multiply(
        &self,
        a: &BfvCiphertext,
        b: &BfvCiphertext,
    ) -> Result<BfvCiphertext, FheError> {
        self.check_pair(a, b)?;
        if a.degree() != 1 || b.degree() != 1 {
            return Err(FheError::NotRelinearized);
        }
        let q_count = self.q.len();
        let context = self.ckks.context();
        // Each input polynomial in Q and in B, in the NTT domain of each.
        let expand = |p: &RnsPoly| -> TwoBases {
            let mut coefficients = p.limbs.clone();
            for (i, limb) in coefficients.iter_mut().enumerate() {
                context.tables[i].inverse(limb);
            }
            let mut aux = self.q_to_aux.lift(&coefficients, true);
            for (j, limb) in aux.iter_mut().enumerate() {
                self.aux[j].forward(limb);
            }
            (p.limbs.clone(), aux)
        };
        let (a0, a1) = (expand(&a.polys[0]), expand(&a.polys[1]));
        let (b0, b1) = (expand(&b.polys[0]), expand(&b.polys[1]));

        let n = self.slots();
        let mut tensor: Vec<TwoBases> = Vec::with_capacity(3);
        let product = |x: &[u64], y: &[u64], m: Modulus| -> Vec<u64> {
            x.iter().zip(y).map(|(&p, &q)| m.mul(p, q)).collect()
        };
        // c0 = a0 * b0, c1 = a0 * b1 + a1 * b0, c2 = a1 * b1.
        let mut combine = |terms: &[(&TwoBases, &TwoBases)]| {
            let mut q_part = vec![vec![0u64; n]; q_count];
            for (i, limb) in q_part.iter_mut().enumerate() {
                let m = self.q[i];
                for (x, y) in terms {
                    for (out, value) in limb.iter_mut().zip(product(&x.0[i], &y.0[i], m)) {
                        *out = m.add(*out, value);
                    }
                }
                context.tables[i].inverse(limb);
            }
            let mut aux_part = vec![vec![0u64; n]; self.aux.len()];
            for (j, limb) in aux_part.iter_mut().enumerate() {
                let m = self.aux[j].modulus;
                for (x, y) in terms {
                    for (out, value) in limb.iter_mut().zip(product(&x.1[j], &y.1[j], m)) {
                        *out = m.add(*out, value);
                    }
                }
                self.aux[j].inverse(limb);
            }
            tensor.push((q_part, aux_part));
        };
        combine(&[(&a0, &b0)]);
        combine(&[(&a0, &b1), (&a1, &b0)]);
        combine(&[(&a1, &b1)]);

        let polys = tensor
            .iter()
            .map(|(q_part, aux_part)| {
                let scaled = self.scale_down(q_part, aux_part);
                let mut limbs = self.aux_to_q.lift(&scaled, true);
                for (i, limb) in limbs.iter_mut().enumerate() {
                    context.tables[i].forward(limb);
                }
                RnsPoly { limbs }
            })
            .collect();
        Ok(self.header(a, polys, a.num_slots.max(b.num_slots)))
    }

    /// Brings a degree-2 ciphertext back to degree 1.
    pub fn relinearize(
        &self,
        ct: &BfvCiphertext,
        relin_key: &RelinKey,
    ) -> Result<BfvCiphertext, FheError> {
        self.check(ct)?;
        if relin_key.param_id != ct.param_id {
            return Err(FheError::ParameterMismatch);
        }
        if ct.degree() != 2 {
            return Ok(ct.clone());
        }
        let tables = self.q_tables();
        let (d0, d1) = self.ckks.key_switch(&ct.polys[2], &relin_key.key);
        let (mut c0, mut c1) = (ct.polys[0].clone(), ct.polys[1].clone());
        self.ckks.add_into(&mut c0, &d0, &tables);
        self.ckks.add_into(&mut c1, &d1, &tables);
        Ok(self.header(ct, vec![c0, c1], ct.num_slots))
    }

    /// Multiplies and relinearizes in one step.
    pub fn multiply_relin(
        &self,
        a: &BfvCiphertext,
        b: &BfvCiphertext,
        relin_key: &RelinKey,
    ) -> Result<BfvCiphertext, FheError> {
        self.relinearize(&self.multiply(a, b)?, relin_key)
    }

    fn apply_automorphism(
        &self,
        ct: &BfvCiphertext,
        element: u32,
        galois_key: &GaloisKey,
        missing: FheError,
    ) -> Result<BfvCiphertext, FheError> {
        self.check(ct)?;
        if galois_key.param_id != ct.param_id {
            return Err(FheError::ParameterMismatch);
        }
        if ct.degree() != 1 {
            return Err(FheError::NotRelinearized);
        }
        let key = galois_key.keys.get(&element).ok_or(missing)?;
        let permutation = galois_permutation(self.slots(), element as u64);
        let mut c0 = self.ckks.automorphism(&ct.polys[0], &permutation);
        let c1 = self.ckks.automorphism(&ct.polys[1], &permutation);
        let (d0, d1) = self.ckks.key_switch(&c1, key);
        self.ckks.add_into(&mut c0, &d0, &self.q_tables());
        Ok(self.header(ct, vec![c0, d1], ct.num_slots))
    }

    /// Rotates both rows left by `steps`, or right if that is negative.
    pub fn rotate_rows(
        &self,
        ct: &BfvCiphertext,
        steps: i64,
        galois_key: &GaloisKey,
    ) -> Result<BfvCiphertext, FheError> {
        if steps.rem_euclid((self.slots() / 2) as i64) == 0 {
            self.check(ct)?;
            return Ok(ct.clone());
        }
        let element = self.ckks.galois_element(steps);
        self.apply_automorphism(
            ct,
            element,
            galois_key,
            FheError::MissingGaloisKey { steps },
        )
    }

    /// Exchanges the two rows.
    pub fn swap_rows(
        &self,
        ct: &BfvCiphertext,
        galois_key: &GaloisKey,
    ) -> Result<BfvCiphertext, FheError> {
        self.apply_automorphism(
            ct,
            self.swap_element(),
            galois_key,
            FheError::MissingGaloisKey { steps: 0 },
        )
    }

    /// Every slot becomes the sum of all `N` slots, modulo `t`. Keys come from
    /// [`BfvEngine::sum_galois_keygen`].
    pub fn sum_all(
        &self,
        ct: &BfvCiphertext,
        galois_key: &GaloisKey,
    ) -> Result<BfvCiphertext, FheError> {
        let mut sum = ct.clone();
        for step in self.ckks.sum_rotation_steps() {
            let rotated = self.rotate_rows(&sum, step, galois_key)?;
            sum = self.add(&sum, &rotated)?;
        }
        let swapped = self.swap_rows(&sum, galois_key)?;
        let mut total = self.add(&sum, &swapped)?;
        total.num_slots = 1;
        Ok(total)
    }
}
