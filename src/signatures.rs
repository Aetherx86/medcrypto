//! Hybrid signatures: Ed25519 and ML-DSA-65 (FIPS 204) over the same message, with both required to verify.
//!
//! ML-DSA is the part that survives a quantum computer, since Ed25519 falls to Shor's algorithm. Ed25519 is kept
//! because ML-DSA is young: if a flaw turns up in it, or in this implementation of it, forging a signature still
//! means breaking Ed25519 as well. An attacker has to break both, so dropping one signature gets nowhere.

use ed25519_compact::{KeyPair, Noise, PublicKey as EdPublicKey, Seed, Signature as EdSignature};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

mod hex_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            hex::encode(bytes).serialize(serializer)
        } else {
            serde_bytes::Bytes::new(bytes).serialize(serializer)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        if deserializer.is_human_readable() {
            hex::decode(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
        } else {
            Ok(serde_bytes::ByteBuf::deserialize(deserializer)?.into_vec())
        }
    }
}

/// Both public keys. Hexadecimal in JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridPublicKey {
    #[serde(with = "hex_bytes")]
    pub ed25519: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub ml_dsa_65: Vec<u8>,
}

/// Both signatures. Hexadecimal in JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSignature {
    #[serde(with = "hex_bytes")]
    pub ed25519: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub ml_dsa_65: Vec<u8>,
}

/// A signing key, made from one 32-byte seed, which is all that needs storing. It prints as nothing.
pub struct HybridSigningKey {
    ed25519: KeyPair,
    ml_dsa_65: ml_dsa_65::PrivateKey,
    public: HybridPublicKey,
    seed: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for HybridSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HybridSigningKey(public: {:?})", self.public)
    }
}

/// A sub-seed for one algorithm, so that the two keys are independent of each other.
fn derive(label: &[u8], seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(
        Sha256::new()
            .chain_update(b"medcrypto-hybrid-key-v1")
            .chain_update(label)
            .chain_update(seed)
            .finalize()
            .into(),
    )
}

/// What actually gets signed: the context is bound in, so that a signature made for one purpose cannot be
/// passed off as one for another, and with a length prefix, so that bytes cannot move between the two.
fn composite(context: &[u8], message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + context.len() + message.len());
    out.extend_from_slice(b"medcrypto-hybrid-signature-v1");
    out.extend_from_slice(&(context.len() as u64).to_le_bytes());
    out.extend_from_slice(context);
    out.extend_from_slice(message);
    out
}

impl HybridSigningKey {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let ed25519 = KeyPair::from_seed(Seed::new(*derive(b"ed25519", seed)));
        let (pq_public, pq_private) = ml_dsa_65::KG::keygen_from_seed(&derive(b"ml-dsa-65", seed));
        let public = HybridPublicKey {
            ed25519: ed25519.pk.to_vec(),
            ml_dsa_65: pq_public.into_bytes().to_vec(),
        };
        Self {
            ed25519,
            ml_dsa_65: pq_private,
            public,
            seed: Zeroizing::new(*seed),
        }
    }

    /// A new key, from the operating system's random source.
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(seed.as_mut());
        Self::from_seed(&seed)
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub fn public_key(&self) -> &HybridPublicKey {
        &self.public
    }

    pub fn sign(&self, context: &[u8], message: &[u8]) -> Result<HybridSignature, String> {
        let signed = composite(context, message);
        let mut noise = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut noise);
        Ok(HybridSignature {
            ed25519: self
                .ed25519
                .sk
                .sign(&signed, Some(Noise::new(noise)))
                .to_vec(),
            ml_dsa_65: self
                .ml_dsa_65
                .try_sign(&signed, b"")
                .map_err(str::to_string)?
                .to_vec(),
        })
    }
}

/// Whether both signatures hold. Anything malformed is simply not valid.
pub fn verify(
    public: &HybridPublicKey,
    context: &[u8],
    message: &[u8],
    signature: &HybridSignature,
) -> bool {
    let signed = composite(context, message);
    let classical = match (
        EdPublicKey::from_slice(&public.ed25519),
        EdSignature::from_slice(&signature.ed25519),
    ) {
        (Ok(key), Ok(sig)) => key.verify(&signed, &sig).is_ok(),
        _ => false,
    };
    let post_quantum = (|| {
        let key_bytes: [u8; ml_dsa_65::PK_LEN] = public.ml_dsa_65.as_slice().try_into().ok()?;
        let sig: [u8; ml_dsa_65::SIG_LEN] = signature.ml_dsa_65.as_slice().try_into().ok()?;
        let key = ml_dsa_65::PublicKey::try_from_bytes(key_bytes).ok()?;
        Some(key.verify(&signed, &sig, b""))
    })()
    .unwrap_or(false);
    classical && post_quantum
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> HybridSigningKey {
        HybridSigningKey::from_seed(&[7; 32])
    }

    /// ML-DSA-65 key generation test case 26 from NIST's ACVP vectors, as hashes of the expected keys.
    #[test]
    fn ml_dsa_key_generation_matches_nist() {
        let seed: [u8; 32] =
            hex::decode("A991FD42B071D49C48AE3E75C647459E0DAAD1E1BA356A04801912D3294BCFF8")
                .unwrap()
                .try_into()
                .unwrap();
        let (public, private) = ml_dsa_65::KG::keygen_from_seed(&seed);
        assert_eq!(
            hex::encode(Sha256::digest(public.into_bytes())),
            "b1a7d0d2f0d7a04b9d5ffccd9bd578864dab4a01cdd7f70a05cd1f4f0672e43a"
        );
        assert_eq!(
            hex::encode(Sha256::digest(private.into_bytes())),
            "56c53ac82fbff7d81b7a8cfbbc73011ceccad677e16dc53f2ece66d49aa11edd"
        );
    }

    #[test]
    fn a_signature_verifies_only_for_its_message_context_and_key() {
        let k = key();
        let sig = k.sign(b"audit", b"message").unwrap();
        assert!(verify(k.public_key(), b"audit", b"message", &sig));
        assert!(!verify(k.public_key(), b"audit", b"other", &sig));
        assert!(!verify(k.public_key(), b"other", b"message", &sig));
        // Moving bytes between the context and the message changes what was signed.
        assert!(!verify(k.public_key(), b"audi", b"tmessage", &sig));
        let other = HybridSigningKey::from_seed(&[8; 32]);
        assert!(!verify(other.public_key(), b"audit", b"message", &sig));
    }

    /// The point of a hybrid: each half is checked, so forging one and keeping the other gets nowhere.
    #[test]
    fn both_halves_are_required() {
        let k = key();
        let good = k.sign(b"c", b"m").unwrap();
        let forged_message = k.sign(b"c", b"forged").unwrap();

        let mut only_classical = good.clone();
        only_classical.ml_dsa_65 = forged_message.ml_dsa_65.clone();
        assert!(!verify(k.public_key(), b"c", b"m", &only_classical));

        let mut only_post_quantum = good.clone();
        only_post_quantum.ed25519 = forged_message.ed25519.clone();
        assert!(!verify(k.public_key(), b"c", b"m", &only_post_quantum));

        let mut stripped = good.clone();
        stripped.ml_dsa_65.clear();
        assert!(!verify(k.public_key(), b"c", b"m", &stripped));
        let mut stripped = good.clone();
        stripped.ed25519.clear();
        assert!(!verify(k.public_key(), b"c", b"m", &stripped));

        // A key with either half swapped for another key's does not verify either.
        let other = HybridSigningKey::from_seed(&[9; 32]);
        let mut mixed = k.public_key().clone();
        mixed.ml_dsa_65 = other.public_key().ml_dsa_65.clone();
        assert!(!verify(&mixed, b"c", b"m", &good));
        let mut mixed = k.public_key().clone();
        mixed.ed25519 = other.public_key().ed25519.clone();
        assert!(!verify(&mixed, b"c", b"m", &good));
    }

    #[test]
    fn flipping_any_bit_breaks_it_and_malformed_input_is_false() {
        let k = key();
        let good = k.sign(b"c", b"m").unwrap();
        for position in [0, 1000, good.ml_dsa_65.len() - 1] {
            let mut bad = good.clone();
            bad.ml_dsa_65[position] ^= 1;
            assert!(!verify(k.public_key(), b"c", b"m", &bad));
        }
        let mut bad = good.clone();
        bad.ed25519[0] ^= 1;
        assert!(!verify(k.public_key(), b"c", b"m", &bad));
        let empty = HybridPublicKey {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        };
        assert!(!verify(&empty, b"c", b"m", &good));
    }

    #[test]
    fn keys_come_from_the_seed_and_round_trip_through_json() {
        assert_eq!(
            key().public_key(),
            HybridSigningKey::from_seed(&[7; 32]).public_key()
        );
        assert_ne!(
            HybridSigningKey::generate().seed(),
            HybridSigningKey::generate().seed()
        );
        // The two algorithms must not share key material.
        assert_ne!(derive(b"ed25519", &[7; 32]), derive(b"ml-dsa-65", &[7; 32]));

        let k = key();
        let sig = k.sign(b"c", b"m").unwrap();
        let text = serde_json::to_string(&sig).unwrap();
        assert_eq!(serde_json::from_str::<HybridSignature>(&text).unwrap(), sig);
        let bytes = postcard::to_allocvec(&sig).unwrap();
        assert_eq!(
            postcard::from_bytes::<HybridSignature>(&bytes).unwrap(),
            sig
        );
        assert_eq!(sig.ml_dsa_65.len(), 3309);
        assert_eq!(k.public_key().ml_dsa_65.len(), 1952);
        assert!(!format!("{k:?}").contains("seed"));
    }
}
