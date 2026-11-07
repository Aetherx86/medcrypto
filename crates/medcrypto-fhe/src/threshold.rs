//! k-of-n distributed key generation and threshold decryption for CKKS.
//!
//! Each party draws its own ternary secret `s_i`, and the collective secret `s` is their sum, which nobody
//! ever holds. The protocol has two parts, both one round:
//!
//! - Public: each party publishes `b_i = -a * s_i + e_i` for a common random `a`, and the same for each
//!   rotation. Those are linear in the secret, so summing them gives keys for `s`.
//! - Secret: each party Shamir-shares `s_i` to every other party. A party's final share is the sum of what
//!   it received, which is a Shamir share of `s`.
//!
//! To decrypt, `k` parties each publish `lambda_j * share_j * c1 + smudge`, where `lambda_j` is the Lagrange
//! coefficient for that set of parties. The sum of those plus `c0` is the message.
//!
//! The smudging noise matters: without it, a partial decryption reveals the error of the ciphertext, which
//! for CKKS can give away the key. Its size is a trade between precision and how well the ciphertext noise
//! is covered, and [`DEFAULT_SMUDGING_BITS`] does not reach a statistically negligible distance. Treat it
//! as defense in depth for parties that follow the protocol.
//!
//! Security model: parties are honest but curious. There is no verifiable secret sharing or proof of correct
//! partial decryption, so an actively malicious party can cause a wrong result, or deny service.

use crate::bfv::{BfvCiphertext, BfvEngine};
use crate::ckks::{CKKSEngine, Ciphertext, GaloisKey, KeySwitchKey, PublicKey};
use crate::ntt::galois_permutation;
use crate::rns::RnsPoly;
use crate::FheError;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Smudging noise is uniform in `[-2^b, 2^b)`. With a scale of `2^40` and `N = 8192`, 24 bits leaves about
/// `2^-9` of absolute noise per party in a decoded slot.
pub const DEFAULT_SMUDGING_BITS: u32 = 24;

/// BFV holds its message in the high bits, far above this noise, so unlike CKKS it can take the most that
/// [`partial_decrypt_bfv`] allows without losing any precision. The result is still exact.
pub const BFV_SMUDGING_BITS: u32 = 50;

/// How many parties there are, and how many it takes to decrypt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub n: u32,
    pub k: u32,
}

impl ThresholdConfig {
    pub fn new(n: u32, k: u32) -> Result<Self, FheError> {
        if k == 0 || k > n {
            return Err(FheError::Threshold(format!("{k}-of-{n} is not possible")));
        }
        Ok(Self { n, k })
    }

    fn check_party(&self, party: u32) -> Result<(), FheError> {
        if party == 0 || party > self.n {
            return Err(FheError::Threshold(format!(
                "party {party} is not in 1..={}",
                self.n
            )));
        }
        Ok(())
    }
}

/// One party's contribution to the public keys.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DkgPublicShare {
    pub party: u32,
    pub b: RnsPoly,
    /// By Galois element, then by digit.
    pub galois: BTreeMap<u32, Vec<RnsPoly>>,
}

/// What one party sends one other party, over a confidential channel. Wiped when dropped.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgSecretShare {
    pub from: u32,
    pub to: u32,
    pub(crate) share: RnsPoly,
}

impl Drop for DkgSecretShare {
    fn drop(&mut self) {
        self.share.wipe();
    }
}

/// A party's share of the collective secret. Wiped when dropped.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThresholdKeyShare {
    pub party: u32,
    pub config: ThresholdConfig,
    pub param_id: u64,
    pub(crate) share: RnsPoly,
}

impl Drop for ThresholdKeyShare {
    fn drop(&mut self) {
        self.share.wipe();
    }
}

/// The keys everybody can use once the protocol has finished.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CollectiveKeys {
    pub public_key: PublicKey,
    pub galois_key: GaloisKey,
}

/// One party's part of a decryption. It is only good for the exact set of parties it names.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PartialDecryption {
    pub party: u32,
    pub active_set: Vec<u32>,
    pub data: RnsPoly,
}

/// A party during key generation. It holds that party's additive secret, wiped when dropped.
pub struct DkgParty {
    engine: CKKSEngine,
    config: ThresholdConfig,
    party: u32,
    secret: RnsPoly,
}

impl Drop for DkgParty {
    fn drop(&mut self) {
        self.secret.wipe();
    }
}

/// A public random polynomial, derived from a seed that the parties have agreed on.
fn common_random(engine: &CKKSEngine, seed: &[u8; 32], label: &[u8], tables: &[usize]) -> RnsPoly {
    let mut hash = Sha256::new();
    hash.update(b"medcrypto-threshold-crs-v1");
    hash.update(seed);
    hash.update((label.len() as u64).to_le_bytes());
    hash.update(label);
    let mut rng = ChaCha20Rng::from_seed(hash.finalize().into());
    engine.uniform(tables, &mut rng)
}

fn galois_label(element: u32, digit: usize) -> Vec<u8> {
    let mut label = b"galois".to_vec();
    label.extend_from_slice(&element.to_le_bytes());
    label.extend_from_slice(&(digit as u32).to_le_bytes());
    label
}

impl DkgParty {
    pub fn new<R: RngCore + CryptoRng>(
        engine: &CKKSEngine,
        config: ThresholdConfig,
        party: u32,
        rng: &mut R,
    ) -> Result<Self, FheError> {
        config.check_party(party)?;
        let n = engine.context().poly_degree;
        let coefficients: Vec<i64> = (0..n)
            .map(|_| loop {
                let x = rng.next_u32() >> 30;
                if x < 3 {
                    break x as i64 - 1;
                }
            })
            .collect();
        let secret = engine.small_to_ntt(&coefficients, &engine.all_tables());
        Ok(Self {
            engine: engine.clone(),
            config,
            party,
            secret,
        })
    }

    /// The contribution to the public key and to a Galois key for each of the given rotations.
    pub fn public_share<R: RngCore + CryptoRng>(
        &self,
        crs_seed: &[u8; 32],
        steps: &[i64],
        rng: &mut R,
    ) -> DkgPublicShare {
        let engine = &self.engine;
        let top = engine.ciphertext_tables(engine.context().max_level());
        let a = common_random(engine, crs_seed, b"public-key", &top);
        let b = engine.rlwe_b(&a, &self.secret, &top, rng);
        let all = engine.all_tables();
        let mut galois = BTreeMap::new();
        for &step in steps {
            let element = engine.galois_element(step);
            galois.entry(element).or_insert_with(|| {
                let permutation = galois_permutation(engine.context().poly_degree, element as u64);
                let mut rotated = engine.automorphism(&self.secret, &permutation);
                let digits = (0..=engine.context().max_level())
                    .map(|digit| {
                        let a =
                            common_random(engine, crs_seed, &galois_label(element, digit), &all);
                        engine.key_switch_digit(digit, &a, &self.secret, &rotated, rng)
                    })
                    .collect();
                rotated.wipe();
                digits
            });
        }
        DkgPublicShare {
            party: self.party,
            b,
            galois,
        }
    }

    /// A Shamir share of this party's secret for every party including itself.
    pub fn secret_shares<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Vec<DkgSecretShare> {
        let engine = &self.engine;
        let tables = engine.ciphertext_tables(engine.context().max_level());
        let degree_terms: Vec<RnsPoly> = (1..self.config.k)
            .map(|_| engine.uniform(&tables, rng))
            .collect();
        let constant = engine.truncate(&self.secret, tables.len());
        let shares = (1..=self.config.n)
            .map(|to| {
                // Horner's rule in each residue, which works because Shamir sharing is linear and so
                // can be done on the evaluations of the polynomial just as well as on its coefficients.
                let mut share = RnsPoly::zero(engine.context().poly_degree, tables.len());
                for (t, limb) in share.limbs.iter_mut().enumerate() {
                    let m = engine.context().tables[t].modulus;
                    let x = m.reduce(to as u64);
                    let shoup = m.shoup(x);
                    for (i, out) in limb.iter_mut().enumerate() {
                        let mut value = 0;
                        for term in degree_terms.iter().rev() {
                            value = m.add(m.mul_shoup(value, x, shoup), term.limbs[t][i]);
                        }
                        *out = m.add(m.mul_shoup(value, x, shoup), constant.limbs[t][i]);
                    }
                }
                DkgSecretShare {
                    from: self.party,
                    to,
                    share,
                }
            })
            .collect();
        let mut wipe_constant = constant;
        wipe_constant.wipe();
        shares
    }
}

/// Sums every party's public shares into the collective keys.
pub fn aggregate_public(
    engine: &CKKSEngine,
    config: ThresholdConfig,
    crs_seed: &[u8; 32],
    shares: &[DkgPublicShare],
) -> Result<CollectiveKeys, FheError> {
    let mut parties: Vec<u32> = shares.iter().map(|s| s.party).collect();
    parties.sort_unstable();
    let expected: Vec<u32> = (1..=config.n).collect();
    if parties != expected {
        return Err(FheError::Threshold(format!(
            "public shares from {parties:?}, needed {expected:?}"
        )));
    }
    let top = engine.ciphertext_tables(engine.context().max_level());
    let all = engine.all_tables();
    let check = |p: &RnsPoly, tables: &[usize]| -> Result<(), FheError> {
        if p.limb_count() != tables.len() {
            return Err(FheError::Malformed(
                "wrong number of limbs in a share".into(),
            ));
        }
        for (limb, &t) in p.limbs.iter().zip(tables) {
            let q = engine.context().tables[t].modulus.q;
            if limb.len() != engine.context().poly_degree || limb.iter().any(|&x| x >= q) {
                return Err(FheError::Malformed("bad coefficients in a share".into()));
            }
        }
        Ok(())
    };
    let elements: Vec<u32> = shares[0].galois.keys().copied().collect();
    let mut b = RnsPoly::zero(engine.context().poly_degree, top.len());
    let mut galois: BTreeMap<u32, Vec<RnsPoly>> = elements
        .iter()
        .map(|&e| {
            let digits = engine.context().moduli_chain.len();
            (
                e,
                vec![RnsPoly::zero(engine.context().poly_degree, all.len()); digits],
            )
        })
        .collect();
    for share in shares {
        check(&share.b, &top)?;
        engine.add_into(&mut b, &share.b, &top);
        if share.galois.keys().copied().collect::<Vec<_>>() != elements {
            return Err(FheError::Threshold(
                "parties disagree on the rotations".into(),
            ));
        }
        for (element, digits) in &share.galois {
            let totals = galois.get_mut(element).expect("checked above");
            if digits.len() != totals.len() {
                return Err(FheError::Threshold(
                    "wrong number of digits in a share".into(),
                ));
            }
            for (total, digit) in totals.iter_mut().zip(digits) {
                check(digit, &all)?;
                engine.add_into(total, digit, &all);
            }
        }
    }
    let param_id = engine.context().param_id();
    let public_key = PublicKey {
        b,
        a: common_random(engine, crs_seed, b"public-key", &top),
        param_id,
    };
    let keys = galois
        .into_iter()
        .map(|(element, totals)| {
            let digits = totals
                .into_iter()
                .enumerate()
                .map(|(digit, b)| {
                    let a = common_random(engine, crs_seed, &galois_label(element, digit), &all);
                    (b, a)
                })
                .collect();
            (element, KeySwitchKey { digits })
        })
        .collect();
    Ok(CollectiveKeys {
        public_key,
        galois_key: GaloisKey { keys, param_id },
    })
}

/// Sums the Shamir shares a party received into its share of the collective secret.
pub fn aggregate_secret(
    engine: &CKKSEngine,
    config: ThresholdConfig,
    party: u32,
    shares: &[DkgSecretShare],
) -> Result<ThresholdKeyShare, FheError> {
    config.check_party(party)?;
    let mut from: Vec<u32> = shares.iter().map(|s| s.from).collect();
    from.sort_unstable();
    if from != (1..=config.n).collect::<Vec<_>>() {
        return Err(FheError::Threshold(format!(
            "shares received from {from:?}"
        )));
    }
    let tables = engine.ciphertext_tables(engine.context().max_level());
    let mut total = RnsPoly::zero(engine.context().poly_degree, tables.len());
    for s in shares {
        if s.to != party {
            return Err(FheError::Threshold(format!(
                "a share for party {} was given to party {party}",
                s.to
            )));
        }
        if s.share.limb_count() != tables.len() {
            return Err(FheError::Malformed(
                "wrong number of limbs in a share".into(),
            ));
        }
        for (limb, &t) in s.share.limbs.iter().zip(&tables) {
            let q = engine.context().tables[t].modulus.q;
            if limb.len() != engine.context().poly_degree || limb.iter().any(|&x| x >= q) {
                return Err(FheError::Malformed("bad coefficients in a share".into()));
            }
        }
        engine.add_into(&mut total, &s.share, &tables);
    }
    Ok(ThresholdKeyShare {
        party,
        config,
        param_id: engine.context().param_id(),
        share: total,
    })
}

fn check_active_set(config: ThresholdConfig, set: &[u32]) -> Result<(), FheError> {
    if set.len() != config.k as usize {
        return Err(FheError::Threshold(format!(
            "{} parties in the set, and the threshold is {}",
            set.len(),
            config.k
        )));
    }
    if !set.windows(2).all(|w| w[0] < w[1]) {
        return Err(FheError::Threshold(
            "the set must be sorted, with no repeats".into(),
        ));
    }
    set.iter().try_for_each(|&p| config.check_party(p))
}

/// The part of a decryption one party contributes. `active_set` is sorted, and must have exactly `k` members
/// including this party, since the Lagrange coefficient has to be applied before the noise is added.
pub fn partial_decrypt<R: RngCore + CryptoRng>(
    engine: &CKKSEngine,
    key: &ThresholdKeyShare,
    ct: &Ciphertext,
    active_set: &[u32],
    smudging_bits: u32,
    rng: &mut R,
) -> Result<PartialDecryption, FheError> {
    engine.validate_ciphertext(ct)?;
    if ct.degree() != 1 {
        return Err(FheError::NotRelinearized);
    }
    partial_on(engine, key, &ct.polys[1], active_set, smudging_bits, rng)
}

/// The same for a BFV ciphertext, which uses the same keys and the same shares.
pub fn partial_decrypt_bfv<R: RngCore + CryptoRng>(
    bfv: &BfvEngine,
    key: &ThresholdKeyShare,
    ct: &BfvCiphertext,
    active_set: &[u32],
    smudging_bits: u32,
    rng: &mut R,
) -> Result<PartialDecryption, FheError> {
    bfv.validate_ciphertext(ct)?;
    if ct.degree() != 1 {
        return Err(FheError::NotRelinearized);
    }
    partial_on(
        bfv.ckks(),
        key,
        &ct.polys[1],
        active_set,
        smudging_bits,
        rng,
    )
}

fn partial_on<R: RngCore + CryptoRng>(
    engine: &CKKSEngine,
    key: &ThresholdKeyShare,
    c1: &RnsPoly,
    active_set: &[u32],
    smudging_bits: u32,
    rng: &mut R,
) -> Result<PartialDecryption, FheError> {
    if key.param_id != engine.context().param_id() {
        return Err(FheError::ParameterMismatch);
    }
    check_active_set(key.config, active_set)?;
    if !active_set.contains(&key.party) {
        return Err(FheError::Threshold(format!(
            "party {} is not in the set {active_set:?}",
            key.party
        )));
    }
    if !(1..=50).contains(&smudging_bits) {
        return Err(FheError::Threshold("smudging must be 1 to 50 bits".into()));
    }
    let tables = engine.ciphertext_tables(c1.limb_count() - 1);
    let mut data = RnsPoly::zero(engine.context().poly_degree, tables.len());
    let noise: Vec<i64> = {
        let half = 1i64 << smudging_bits;
        let mask = (1u64 << (smudging_bits + 1)) - 1;
        (0..engine.context().poly_degree)
            .map(|_| (rng.next_u64() & mask) as i64 - half)
            .collect()
    };
    let noise = engine.small_to_ntt(&noise, &tables);
    for &t in &tables {
        let m = engine.context().tables[t].modulus;
        // lambda_j = product over the others of m / (m - j).
        let mut lambda = 1u64;
        for &other in active_set {
            if other != key.party {
                let numerator = m.reduce(other as u64);
                let denominator = m.sub(numerator, m.reduce(key.party as u64));
                lambda = m.mul(lambda, m.mul(numerator, m.inv(denominator)));
            }
        }
        let shoup = m.shoup(lambda);
        for i in 0..data.limbs[t].len() {
            let product = m.mul(c1.limbs[t][i], key.share.limbs[t][i]);
            data.limbs[t][i] = m.add(m.mul_shoup(product, lambda, shoup), noise.limbs[t][i]);
        }
    }
    Ok(PartialDecryption {
        party: key.party,
        active_set: active_set.to_vec(),
        data,
    })
}

/// `c0` plus all the partial decryptions, after checking that they fit together.
fn sum_partials(
    engine: &CKKSEngine,
    config: ThresholdConfig,
    c0: &RnsPoly,
    partials: &[PartialDecryption],
) -> Result<RnsPoly, FheError> {
    let first = partials
        .first()
        .ok_or_else(|| FheError::Threshold("no partial decryptions".into()))?;
    check_active_set(config, &first.active_set)?;
    let mut parties: Vec<u32> = partials.iter().map(|p| p.party).collect();
    parties.sort_unstable();
    if parties != first.active_set || partials.iter().any(|p| p.active_set != first.active_set) {
        return Err(FheError::Threshold(format!(
            "partial decryptions from {parties:?} for the set {:?}",
            first.active_set
        )));
    }
    let tables = engine.ciphertext_tables(c0.limb_count() - 1);
    let mut sum = c0.clone();
    for partial in partials {
        if partial.data.limb_count() != tables.len() {
            return Err(FheError::Malformed(
                "wrong number of limbs in a partial".into(),
            ));
        }
        for (limb, &t) in partial.data.limbs.iter().zip(&tables) {
            let q = engine.context().tables[t].modulus.q;
            if limb.len() != engine.context().poly_degree || limb.iter().any(|&x| x >= q) {
                return Err(FheError::Malformed("bad coefficients in a partial".into()));
            }
        }
        engine.add_into(&mut sum, &partial.data, &tables);
    }
    Ok(sum)
}

/// All slot values, from `k` partial decryptions by the same set of parties.
pub fn combine(
    engine: &CKKSEngine,
    config: ThresholdConfig,
    ct: &Ciphertext,
    partials: &[PartialDecryption],
) -> Result<Vec<f64>, FheError> {
    engine.validate_ciphertext(ct)?;
    if ct.degree() != 1 {
        return Err(FheError::NotRelinearized);
    }
    let sum = sum_partials(engine, config, &ct.polys[0], partials)?;
    let mut values = engine.decode_all(sum, ct.scale);
    values.truncate(ct.num_slots);
    Ok(values)
}

/// The same for a BFV ciphertext, with exact integers as the result.
pub fn combine_bfv(
    bfv: &BfvEngine,
    config: ThresholdConfig,
    ct: &BfvCiphertext,
    partials: &[PartialDecryption],
) -> Result<Vec<i64>, FheError> {
    bfv.validate_ciphertext(ct)?;
    if ct.degree() != 1 {
        return Err(FheError::NotRelinearized);
    }
    let sum = sum_partials(bfv.ckks(), config, &ct.polys[0], partials)?;
    Ok(bfv.decode_phase_ntt(sum, ct.num_slots))
}
