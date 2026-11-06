//! A range proof over ristretto255, built from bit commitments and one-of-two Schnorr proofs.
//!
//! To prove `min <= v <= max` for the `v` in a commitment `C = v*G + r*H`, the prover decomposes both
//! `a = v - min` and `b = max - v` into `n` bits, where `n` is enough for `max - min`. Each bit gets a
//! commitment and a proof that it opens to 0 or 1. The verifier checks that the bit commitments add up to
//! `C - min*G` and `max*G - C`. Since both sides are sums of bits, `a` and `b` are non-negative integers
//! far below the group order, which rules out wrapping around it, and that is what makes it a range proof.
//!
//! Earlier versions of this file proved only knowledge of an opening of `C / g^t`, which says nothing about
//! the sign of the difference, and did so in a 64-bit group where discrete logarithms are easy to compute.

use super::{CryptoError, ZkPredicateProver, ZkProof};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::sync::OnceLock;

const BACKEND_NAME: &str = "pedersen-ristretto255-v1";

/// The second generator, from a hash, so that nobody knows its discrete logarithm relative to `G`.
fn generator_h() -> RistrettoPoint {
    static H: OnceLock<RistrettoPoint> = OnceLock::new();
    *H.get_or_init(|| {
        RistrettoPoint::from_hash(Sha512::new().chain_update(b"medcrypto/pedersen/H/v1"))
    })
}

/// A commitment to a bit, with the proof that it is one.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct BitProof {
    commitment: [u8; 32],
    e0: [u8; 32],
    e1: [u8; 32],
    s0: [u8; 32],
    s1: [u8; 32],
}

/// The bits of `v - min` and of `max - v`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RangeProof {
    lower: Vec<BitProof>,
    upper: Vec<BitProof>,
}

fn transcript(commitment: &[u8; 32], min: u64, max: u64) -> Sha512 {
    Sha512::new()
        .chain_update(b"medcrypto/range-proof/v1")
        .chain_update(commitment)
        .chain_update(min.to_le_bytes())
        .chain_update(max.to_le_bytes())
}

fn bit_challenge(
    base: &Sha512,
    side: u8,
    index: usize,
    commitment: &[u8; 32],
    a0: &RistrettoPoint,
    a1: &RistrettoPoint,
) -> Scalar {
    Scalar::from_hash(
        base.clone()
            .chain_update([side])
            .chain_update((index as u64).to_le_bytes())
            .chain_update(commitment)
            .chain_update(a0.compress().as_bytes())
            .chain_update(a1.compress().as_bytes()),
    )
}

fn prove_bit(base: &Sha512, side: u8, index: usize, bit: bool, r: Scalar) -> BitProof {
    let h = generator_h();
    let c = if bit { G + r * h } else { r * h };
    let commitment = c.compress().to_bytes();
    let k = Scalar::random(&mut OsRng);
    // The branch that is false is simulated by choosing its challenge and response first.
    let simulated_e = Scalar::random(&mut OsRng);
    let simulated_s = Scalar::random(&mut OsRng);
    let (a0, a1) = if bit {
        (simulated_s * h - simulated_e * c, k * h)
    } else {
        (k * h, simulated_s * h - simulated_e * (c - G))
    };
    let e = bit_challenge(base, side, index, &commitment, &a0, &a1);
    let real_e = e - simulated_e;
    let real_s = k + real_e * r;
    let (e0, e1, s0, s1) = if bit {
        (simulated_e, real_e, simulated_s, real_s)
    } else {
        (real_e, simulated_e, real_s, simulated_s)
    };
    BitProof {
        commitment,
        e0: e0.to_bytes(),
        e1: e1.to_bytes(),
        s0: s0.to_bytes(),
        s1: s1.to_bytes(),
    }
}

fn canonical(bytes: &[u8; 32]) -> Option<Scalar> {
    Option::from(Scalar::from_canonical_bytes(*bytes))
}

fn verify_bit(base: &Sha512, side: u8, index: usize, proof: &BitProof) -> Option<RistrettoPoint> {
    let h = generator_h();
    let c = CompressedRistretto(proof.commitment).decompress()?;
    let (e0, e1) = (canonical(&proof.e0)?, canonical(&proof.e1)?);
    let (s0, s1) = (canonical(&proof.s0)?, canonical(&proof.s1)?);
    let (a0, a1) = (s0 * h - e0 * c, s1 * h - e1 * (c - G));
    // The two challenges have to add up to the hash, which leaves the prover free to choose only one.
    let e = bit_challenge(base, side, index, &proof.commitment, &a0, &a1);
    (e == e0 + e1).then_some(c)
}

fn bits_for(span: u64) -> usize {
    (u64::BITS - span.leading_zeros()).max(1) as usize
}

fn weighted_sum(points: &[RistrettoPoint]) -> RistrettoPoint {
    let mut total = RistrettoPoint::default();
    for p in points.iter().rev() {
        total = total + total + p;
    }
    total
}

/// Blindings for `n` bits whose weighted sum comes to `target`.
fn blindings(n: usize, target: Scalar) -> Vec<Scalar> {
    let mut r: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();
    let mut sum = Scalar::ZERO;
    let mut weight = Scalar::ONE;
    let two = Scalar::from(2u64);
    for x in &r[..n - 1] {
        sum += weight * x;
        weight *= two;
    }
    r[n - 1] = (target - sum) * weight.invert();
    r
}

/// The commitment `v*G + r*H`.
pub fn commit(value: u64, blinding: &Scalar) -> RistrettoPoint {
    Scalar::from(value) * G + blinding * generator_h()
}

/// The lightweight backend, for development and testing inside a hospital.
#[derive(Clone, Copy, Debug, Default)]
pub struct PedersenBackend;

impl PedersenBackend {
    pub const NAME: &'static str = BACKEND_NAME;
}

impl ZkPredicateProver for PedersenBackend {
    fn prove_range(&self, val: u64, min: u64, max: u64) -> Result<ZkProof, CryptoError> {
        if min > max {
            return Err(CryptoError::InvalidRange { min, max });
        }
        if val < min || val > max {
            return Err(CryptoError::PredicateUnsatisfied);
        }
        let r = Scalar::random(&mut OsRng);
        let commitment = commit(val, &r).compress().to_bytes();
        let base = transcript(&commitment, min, max);
        let n = bits_for(max - min);
        let prove_side = |side: u8, amount: u64, target: Scalar| -> Vec<BitProof> {
            blindings(n, target)
                .into_iter()
                .enumerate()
                .map(|(i, b)| prove_bit(&base, side, i, (amount >> i) & 1 == 1, b))
                .collect()
        };
        let proof = RangeProof {
            lower: prove_side(0, val - min, r),
            upper: prove_side(1, max - val, -r),
        };
        Ok(ZkProof {
            backend: BACKEND_NAME.to_string(),
            min,
            max,
            commitment: hex::encode(commitment),
            payload: hex::encode(
                postcard::to_allocvec(&proof).map_err(|e| CryptoError::Backend(e.to_string()))?,
            ),
        })
    }

    fn verify_range(&self, proof: &ZkProof, min: u64, max: u64) -> bool {
        verify(proof, min, max).unwrap_or(false)
    }
}

fn verify(proof: &ZkProof, min: u64, max: u64) -> Option<bool> {
    if proof.backend != BACKEND_NAME || proof.min != min || proof.max != max || min > max {
        return Some(false);
    }
    let commitment: [u8; 32] = hex::decode(&proof.commitment).ok()?.try_into().ok()?;
    let c = CompressedRistretto(commitment).decompress()?;
    let parsed: RangeProof = postcard::from_bytes(&hex::decode(&proof.payload).ok()?).ok()?;
    let n = bits_for(max - min);
    if parsed.lower.len() != n || parsed.upper.len() != n {
        return Some(false);
    }
    let base = transcript(&commitment, min, max);
    let check_side = |side: u8, bits: &[BitProof]| -> Option<Vec<RistrettoPoint>> {
        bits.iter()
            .enumerate()
            .map(|(i, b)| verify_bit(&base, side, i, b))
            .collect()
    };
    let lower = check_side(0, &parsed.lower)?;
    let upper = check_side(1, &parsed.upper)?;
    let min_point = Scalar::from(min) * G;
    let max_point = Scalar::from(max) * G;
    Some(weighted_sum(&lower) == c - min_point && weighted_sum(&upper) == max_point - c)
}
