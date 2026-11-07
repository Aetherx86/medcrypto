//! Hybrid signatures: Ed25519 and ML-DSA-65 (FIPS 204) over the same message, with both required to verify.
//!
//! ML-DSA is the part that survives a quantum computer, since Ed25519 falls to Shor's algorithm. Ed25519 is kept
//! because ML-DSA is young: if a flaw turns up in it, or in this implementation of it, forging a signature still
//! means breaking Ed25519 as well. An attacker has to break both, so dropping one signature gets nowhere.

use ed25519_compact::{KeyPair, PublicKey as EdPublicKey, Seed, Signature as EdSignature};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
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
        Self::with_ed25519_seed(seed, &derive(b"ed25519", seed))
    }

    /// For a node key from before 0.3.0, where the seed file held the Ed25519 seed itself. The Ed25519 key stays
    /// what it was, so that the node keeps its identity, and the ML-DSA key is derived from the same seed.
    pub fn from_legacy_ed25519_seed(seed: &[u8; 32]) -> Self {
        Self::with_ed25519_seed(seed, seed)
    }

    /// Whichever of the two derivations gives this Ed25519 public key. Keys of any version load through this.
    pub fn matching_ed25519(seed: &[u8; 32], ed25519_public: &[u8]) -> Option<Self> {
        [Self::from_seed(seed), Self::from_legacy_ed25519_seed(seed)]
            .into_iter()
            .find(|k| k.public.ed25519 == ed25519_public)
    }

    fn with_ed25519_seed(seed: &[u8; 32], ed25519_seed: &[u8; 32]) -> Self {
        let ed25519 = KeyPair::from_seed(Seed::new(*ed25519_seed));
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
    #[cfg(feature = "os-rng")]
    pub fn generate() -> Self {
        use rand_core::RngCore;
        let mut seed = Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(seed.as_mut());
        Self::from_seed(&seed)
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub fn public_key(&self) -> &HybridPublicKey {
        &self.public
    }

    /// Signs, with `entropy` hedging ML-DSA. It should be fresh, though a repeat does no harm beyond making
    /// the two signatures identical. Ed25519 here is the deterministic signature of RFC 8032.
    pub fn sign_with_entropy(
        &self,
        context: &[u8],
        message: &[u8],
        entropy: &[u8; 32],
    ) -> Result<HybridSignature, &'static str> {
        let signed = composite(context, message);
        Ok(HybridSignature {
            ed25519: self.ed25519.sk.sign(&signed, None).to_vec(),
            ml_dsa_65: self
                .ml_dsa_65
                .try_sign_with_seed(entropy, &signed, b"")?
                .to_vec(),
        })
    }

    #[cfg(feature = "os-rng")]
    pub fn sign(&self, context: &[u8], message: &[u8]) -> Result<HybridSignature, String> {
        use rand_core::RngCore;
        let mut entropy = Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(entropy.as_mut());
        self.sign_with_entropy(context, message, &entropy)
            .map_err(str::to_string)
    }

    /// An Ed25519 signature alone, for peers still on a roster with no ML-DSA key.
    pub fn sign_ed25519_only(&self, message: &[u8]) -> Vec<u8> {
        self.ed25519.sk.sign(message, None).to_vec()
    }
}

/// Checks an Ed25519 signature alone, for peers still on a roster with no ML-DSA key.
pub fn verify_ed25519_only(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    match (
        EdPublicKey::from_slice(public),
        EdSignature::from_slice(signature),
    ) {
        (Ok(key), Ok(sig)) => key.verify(message, &sig).is_ok(),
        _ => false,
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
    fn keys_of_every_version_load_and_keep_their_identity() {
        let seed = [11u8; 32];
        // Before 0.3.0 the file held the Ed25519 seed itself.
        let old_public = KeyPair::from_seed(Seed::new(seed)).pk.to_vec();
        let legacy = HybridSigningKey::matching_ed25519(&seed, &old_public).unwrap();
        assert_eq!(legacy.public_key().ed25519, old_public);
        assert_eq!(legacy.public_key().ml_dsa_65.len(), 1952);
        // In 0.3.0 the Ed25519 seed was derived.
        let current = HybridSigningKey::from_seed(&seed);
        let found =
            HybridSigningKey::matching_ed25519(&seed, &current.public_key().ed25519).unwrap();
        assert_eq!(found.public_key(), current.public_key());
        // Nothing else matches, so a wrong key file is noticed.
        assert!(HybridSigningKey::matching_ed25519(&[12; 32], &old_public).is_none());

        // The legacy path signs both ways.
        let message = b"message";
        assert!(verify_ed25519_only(
            &old_public,
            message,
            &legacy.sign_ed25519_only(message)
        ));
        assert!(!verify_ed25519_only(
            &old_public,
            b"other",
            &legacy.sign_ed25519_only(message)
        ));
        let hybrid = legacy.sign(b"c", message).unwrap();
        assert!(verify(legacy.public_key(), b"c", message, &hybrid));
    }

    #[test]
    fn signing_with_given_entropy_works_without_an_os() {
        let k = key();
        let one = k.sign_with_entropy(b"c", b"m", &[1; 32]).unwrap();
        assert_eq!(one, k.sign_with_entropy(b"c", b"m", &[1; 32]).unwrap());
        assert_ne!(
            one.ml_dsa_65,
            k.sign_with_entropy(b"c", b"m", &[2; 32]).unwrap().ml_dsa_65
        );
        assert!(verify(k.public_key(), b"c", b"m", &one));
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
