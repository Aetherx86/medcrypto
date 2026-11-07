//! The built-in post-quantum backend: see [`medcrypto_pq::range_proof`] for how the proof works.

use super::{CryptoError, ZkPredicateProver, ZkProof};
use medcrypto_pq::range_proof::{self, RangeProof};
use rand::RngCore;

const BACKEND_NAME: &str = "mpc-in-the-head-sha256-v1";
const CONTEXT: &[u8] = b"medcrypto-zkp-range";

/// Range proofs that assume nothing but SHA-256, with no external program needed.
#[derive(Clone, Copy, Debug, Default)]
pub struct HashBasedBackend;

impl ZkPredicateProver for HashBasedBackend {
    fn prove_range(&self, val: u64, min: u64, max: u64) -> Result<ZkProof, CryptoError> {
        if min > max {
            return Err(CryptoError::InvalidRange { min, max });
        }
        let mut blinding = zeroize::Zeroizing::new([0u8; 32]);
        let mut randomness = zeroize::Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(blinding.as_mut());
        rand::rngs::OsRng.fill_bytes(randomness.as_mut());
        let (commitment, proof) =
            range_proof::prove(val, &blinding, min, max, CONTEXT, &randomness)
                .ok_or(CryptoError::PredicateUnsatisfied)?;
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
        (|| {
            if proof.backend != BACKEND_NAME || proof.min != min || proof.max != max {
                return None;
            }
            let commitment: [u8; 32] = hex::decode(&proof.commitment).ok()?.try_into().ok()?;
            let parsed: RangeProof =
                postcard::from_bytes(&hex::decode(&proof.payload).ok()?).ok()?;
            Some(range_proof::verify(&commitment, min, max, CONTEXT, &parsed))
        })()
        .unwrap_or(false)
    }
}
