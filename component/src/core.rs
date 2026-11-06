//! The cryptography itself, which is plain Rust and is tested natively as well as through the component.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use ed25519_compact::{KeyPair, PublicKey, SecretKey, Seed, Signature};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BadLength,
    AuthenticationFailed,
    BadOutputLength,
    WeakSeed,
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

pub fn hkdf(input_key: &[u8], salt: &[u8], info: &[u8], length: u32) -> Result<Vec<u8>, Error> {
    // The limit is 255 hash outputs, checked first so that a huge request allocates nothing.
    if length > 255 * 32 {
        return Err(Error::BadOutputLength);
    }
    let mut out = vec![0u8; length as usize];
    Hkdf::<Sha256>::new(Some(salt), input_key)
        .expand(info, &mut out)
        .map_err(|_| Error::BadOutputLength)?;
    Ok(out)
}

fn cipher(key: &[u8], nonce: &[u8]) -> Result<Aes256Gcm, Error> {
    if key.len() != 32 || nonce.len() != 12 {
        return Err(Error::BadLength);
    }
    Ok(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key)))
}

pub fn seal(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    cipher(key, nonce)?
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| Error::AuthenticationFailed)
}

pub fn open(
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    cipher(key, nonce)?
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| Error::AuthenticationFailed)
}

/// Returns the public key and secret key.
pub fn keypair_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| Error::BadLength)?;
    // An all-zero seed is refused, and is what a broken random source tends to produce.
    let pair = KeyPair::try_from_seed(Seed::new(seed)).map_err(|_| Error::WeakSeed)?;
    Ok((pair.pk.to_vec(), pair.sk.to_vec()))
}

pub fn sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
    let secret = SecretKey::from_slice(secret_key).map_err(|_| Error::BadLength)?;
    // No noise, which makes this exactly the deterministic signature of RFC 8032.
    Ok(secret.sign(message, None).to_vec())
}

pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(public), Ok(signature)) = (
        PublicKey::from_slice(public_key),
        Signature::from_slice(signature),
    ) else {
        return false;
    };
    public.verify(message, &signature).is_ok()
}

fn leaf_hash(leaf: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update([0u8])
        .chain_update(leaf)
        .finalize()
        .into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update([1u8])
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

pub fn merkle_root(leaves: &[Vec<u8>]) -> Vec<u8> {
    if leaves.is_empty() {
        return sha256(b"");
    }
    // Working level by level with an iterative merge makes hostile input unable to deepen the stack. A
    // node left over at the end of a level moves up unchanged, which gives RFC 6962's shape.
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|l| leaf_hash(l)).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            next.push(match pair {
                [left, right] => node_hash(left, right),
                [odd] => *odd,
                _ => unreachable!(),
            });
        }
        level = next;
    }
    level[0].to_vec()
}

pub fn audit_link(previous: &[u8], entry: &[u8]) -> Vec<u8> {
    // Both lengths are hashed in, so that moving bytes from one side to the other changes the result.
    Sha256::new()
        .chain_update([2u8])
        .chain_update((previous.len() as u64).to_le_bytes())
        .chain_update(previous)
        .chain_update((entry.len() as u64).to_le_bytes())
        .chain_update(entry)
        .finalize()
        .to_vec()
}

pub fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
