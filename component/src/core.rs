//! The cryptography itself, which is plain Rust and is tested natively as well as through the component.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use ed25519_compact::{KeyPair, PublicKey, SecretKey, Seed, Signature};
use hkdf::Hkdf;
use medcrypto_fhe::{
    from_bytes, to_bytes, BfvCiphertext, BfvEngine, CKKSEngine, Ciphertext, CkksPreset, FheError,
    PublicKey as FhePublicKey, RelinKey, SecretKey as FheSecretKey,
};
use medcrypto_pq::signatures::{HybridPublicKey, HybridSignature, HybridSigningKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
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

/// What a homomorphic operation can report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FheOpError {
    BadEntropy,
    BadEncoding,
    ParameterMismatch,
    ValueOutOfRange,
    ScaleMismatch,
    OutOfLevels,
}

/// A ciphertext as the interface passes it around. `data` is what counts: the other two are for convenience,
/// and have to agree with it.
#[derive(Clone, Debug, PartialEq)]
pub struct FheCiphertext {
    pub data: Vec<u8>,
    pub degree: u32,
    pub scale: f64,
}

impl From<FheError> for FheOpError {
    fn from(e: FheError) -> Self {
        match e {
            FheError::ParameterMismatch => Self::ParameterMismatch,
            FheError::TooManyValues { .. } | FheError::ValueOutOfRange(_) => Self::ValueOutOfRange,
            FheError::ScaleMismatch { .. } => Self::ScaleMismatch,
            FheError::OutOfLevels | FheError::ScaleOverflow => Self::OutOfLevels,
            _ => Self::BadEncoding,
        }
    }
}

/// A generator from the caller's entropy, under a domain label so that one use cannot repeat another's stream.
fn entropy_rng(entropy: &[u8], label: &[u8]) -> Result<ChaCha20Rng, FheOpError> {
    if entropy.len() != 32 || entropy.iter().all(|&b| b == 0) {
        return Err(FheOpError::BadEntropy);
    }
    let seed: [u8; 32] = Sha256::new()
        .chain_update(b"medcrypto-component-fhe-v1")
        .chain_update(label)
        .chain_update(entropy)
        .finalize()
        .into();
    Ok(ChaCha20Rng::from_seed(seed))
}

fn engine_for(param_id: u64) -> Result<CKKSEngine, FheOpError> {
    [CkksPreset::N8192, CkksPreset::N16384]
        .into_iter()
        .map(CKKSEngine::from_preset)
        .find(|e| e.context().param_id() == param_id)
        .ok_or(FheOpError::ParameterMismatch)
}

fn parse_ciphertext(input: &FheCiphertext) -> Result<(CKKSEngine, Ciphertext), FheOpError> {
    let ct: Ciphertext = from_bytes(&input.data).map_err(|_| FheOpError::BadEncoding)?;
    let engine = engine_for(ct.param_id)?;
    engine
        .validate_ciphertext(&ct)
        .map_err(|_| FheOpError::BadEncoding)?;
    if ct.degree() as u32 != input.degree || ct.scale != input.scale {
        return Err(FheOpError::BadEncoding);
    }
    Ok((engine, ct))
}

fn package_ciphertext(ct: &Ciphertext) -> Result<FheCiphertext, FheOpError> {
    Ok(FheCiphertext {
        data: to_bytes(ct).map_err(|_| FheOpError::BadEncoding)?,
        degree: ct.degree() as u32,
        scale: ct.scale,
    })
}

/// Returns the public key and the secret key, at N = 8192.
pub fn fhe_keygen(entropy: &[u8]) -> Result<(Vec<u8>, Vec<u8>), FheOpError> {
    let mut rng = entropy_rng(entropy, b"keygen")?;
    let (secret, public) = CKKSEngine::from_preset(CkksPreset::N8192).keygen_with(&mut rng);
    Ok((
        to_bytes(&public).map_err(|_| FheOpError::BadEncoding)?,
        to_bytes(&secret).map_err(|_| FheOpError::BadEncoding)?,
    ))
}

pub fn fhe_encrypt(
    public_key: &[u8],
    values: &[f64],
    entropy: &[u8],
) -> Result<FheCiphertext, FheOpError> {
    let mut rng = entropy_rng(entropy, b"encrypt")?;
    let public: FhePublicKey = from_bytes(public_key).map_err(|_| FheOpError::BadEncoding)?;
    let engine = engine_for(public.param_id)?;
    engine
        .validate_public_key(&public)
        .map_err(|_| FheOpError::BadEncoding)?;
    package_ciphertext(&engine.encrypt_with(&public, values, &mut rng)?)
}

pub fn fhe_decrypt(secret_key: &[u8], ciphertext: &FheCiphertext) -> Result<Vec<f64>, FheOpError> {
    let secret: FheSecretKey = from_bytes(secret_key).map_err(|_| FheOpError::BadEncoding)?;
    let (engine, ct) = parse_ciphertext(ciphertext)?;
    engine.validate_secret_key(&secret).map_err(|e| match e {
        FheError::ParameterMismatch => FheOpError::ParameterMismatch,
        _ => FheOpError::BadEncoding,
    })?;
    Ok(engine.decrypt(&secret, &ct)?)
}

pub fn fhe_add(a: &FheCiphertext, b: &FheCiphertext) -> Result<FheCiphertext, FheOpError> {
    let (engine, x) = parse_ciphertext(a)?;
    let (_, y) = parse_ciphertext(b)?;
    if x.param_id != y.param_id {
        return Err(FheOpError::ParameterMismatch);
    }
    if x.level() != y.level() {
        return Err(FheOpError::ScaleMismatch);
    }
    package_ciphertext(&engine.add(&x, &y)?)
}

pub fn fhe_scalar_mul(a: &FheCiphertext, scalar: f64) -> Result<FheCiphertext, FheOpError> {
    let (engine, x) = parse_ciphertext(a)?;
    package_ciphertext(&engine.scalar_mul(&x, scalar)?)
}

/// A BFV ciphertext as the interface passes it around, with `data` being what counts.
#[derive(Clone, Debug, PartialEq)]
pub struct BfvWire {
    pub data: Vec<u8>,
    pub degree: u32,
    pub plain_modulus: u64,
}

fn bfv_engine(param_id: u64, plain_bits: u32) -> Result<BfvEngine, FheOpError> {
    let preset = [CkksPreset::N8192, CkksPreset::N16384]
        .into_iter()
        .find(|p| CKKSEngine::from_preset(*p).context().param_id() == param_id)
        .ok_or(FheOpError::ParameterMismatch)?;
    BfvEngine::new(preset, plain_bits).map_err(|_| FheOpError::ValueOutOfRange)
}

fn parse_bfv(input: &BfvWire) -> Result<(BfvEngine, BfvCiphertext), FheOpError> {
    let ct: BfvCiphertext = from_bytes(&input.data).map_err(|_| FheOpError::BadEncoding)?;
    if ct.plain_modulus != input.plain_modulus
        || ct.polys.is_empty()
        || ct.degree() as u32 != input.degree
    {
        return Err(FheOpError::BadEncoding);
    }
    let engine = bfv_engine(ct.param_id, 64 - ct.plain_modulus.leading_zeros())
        .map_err(|_| FheOpError::BadEncoding)?;
    engine
        .validate_ciphertext(&ct)
        .map_err(|_| FheOpError::BadEncoding)?;
    Ok((engine, ct))
}

fn package_bfv(ct: &BfvCiphertext) -> Result<BfvWire, FheOpError> {
    Ok(BfvWire {
        data: to_bytes(ct).map_err(|_| FheOpError::BadEncoding)?,
        degree: ct.degree() as u32,
        plain_modulus: ct.plain_modulus,
    })
}

/// Returns the public key and the secret key, at N = 8192.
pub fn bfv_keygen(entropy: &[u8]) -> Result<(Vec<u8>, Vec<u8>), FheOpError> {
    let mut rng = entropy_rng(entropy, b"bfv-keygen")?;
    let (secret, public) = CKKSEngine::from_preset(CkksPreset::N8192).keygen_with(&mut rng);
    Ok((
        to_bytes(&public).map_err(|_| FheOpError::BadEncoding)?,
        to_bytes(&secret).map_err(|_| FheOpError::BadEncoding)?,
    ))
}

fn parse_secret(secret_key: &[u8]) -> Result<FheSecretKey, FheOpError> {
    from_bytes(secret_key).map_err(|_| FheOpError::BadEncoding)
}

pub fn bfv_relin_keygen(secret_key: &[u8], entropy: &[u8]) -> Result<Vec<u8>, FheOpError> {
    let mut rng = entropy_rng(entropy, b"bfv-relin")?;
    let secret = parse_secret(secret_key)?;
    let engine = engine_for(secret.param_id)?;
    engine
        .validate_secret_key(&secret)
        .map_err(|_| FheOpError::BadEncoding)?;
    to_bytes(&engine.relin_keygen_with(&secret, &mut rng)).map_err(|_| FheOpError::BadEncoding)
}

pub fn bfv_encrypt(
    public_key: &[u8],
    plain_bits: u32,
    values: &[i64],
    entropy: &[u8],
) -> Result<BfvWire, FheOpError> {
    let mut rng = entropy_rng(entropy, b"bfv-encrypt")?;
    let public: FhePublicKey = from_bytes(public_key).map_err(|_| FheOpError::BadEncoding)?;
    let engine = bfv_engine(public.param_id, plain_bits)?;
    package_bfv(&engine.encrypt_with(&public, values, &mut rng)?)
}

pub fn bfv_decrypt(secret_key: &[u8], ciphertext: &BfvWire) -> Result<Vec<i64>, FheOpError> {
    let secret = parse_secret(secret_key)?;
    let (engine, ct) = parse_bfv(ciphertext)?;
    Ok(engine.decrypt(&secret, &ct)?)
}

pub fn bfv_add(a: &BfvWire, b: &BfvWire) -> Result<BfvWire, FheOpError> {
    let (engine, x) = parse_bfv(a)?;
    let (_, y) = parse_bfv(b)?;
    if x.param_id != y.param_id || x.plain_modulus != y.plain_modulus {
        return Err(FheOpError::ParameterMismatch);
    }
    package_bfv(&engine.add(&x, &y)?)
}

pub fn bfv_multiply(a: &BfvWire, b: &BfvWire, relin_key: &[u8]) -> Result<BfvWire, FheOpError> {
    let (engine, x) = parse_bfv(a)?;
    let (_, y) = parse_bfv(b)?;
    if x.param_id != y.param_id || x.plain_modulus != y.plain_modulus {
        return Err(FheOpError::ParameterMismatch);
    }
    let key: RelinKey = from_bytes(relin_key).map_err(|_| FheOpError::BadEncoding)?;
    engine
        .ckks()
        .validate_relin_key(&key)
        .map_err(|_| FheOpError::BadEncoding)?;
    package_bfv(&engine.multiply_relin(&x, &y, &key)?)
}

pub fn bfv_noise_budget(secret_key: &[u8], ciphertext: &BfvWire) -> Result<f64, FheOpError> {
    let secret = parse_secret(secret_key)?;
    let (engine, ct) = parse_bfv(ciphertext)?;
    Ok(engine.noise_budget_bits(&secret, &ct)?)
}

fn seed_of(seed: &[u8]) -> Result<[u8; 32], Error> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| Error::BadLength)?;
    // All zeros is what a broken random source tends to produce.
    if seed == [0; 32] {
        return Err(Error::WeakSeed);
    }
    Ok(seed)
}

/// Both public keys, as Ed25519 then ML-DSA-65.
pub fn hybrid_public_key(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let key = HybridSigningKey::from_seed(&seed_of(seed)?);
    let public = key.public_key();
    Ok((public.ed25519.clone(), public.ml_dsa_65.clone()))
}

/// Both signatures, as Ed25519 then ML-DSA-65.
pub fn hybrid_sign(
    seed: &[u8],
    context: &[u8],
    message: &[u8],
    entropy: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let entropy: [u8; 32] = entropy.try_into().map_err(|_| Error::BadLength)?;
    let signature = HybridSigningKey::from_seed(&seed_of(seed)?)
        .sign_with_entropy(context, message, &entropy)
        .map_err(|_| Error::BadLength)?;
    Ok((signature.ed25519, signature.ml_dsa_65))
}

pub fn hybrid_verify(
    public: (&[u8], &[u8]),
    context: &[u8],
    message: &[u8],
    signature: (&[u8], &[u8]),
) -> bool {
    medcrypto_pq::signatures::verify(
        &HybridPublicKey {
            ed25519: public.0.to_vec(),
            ml_dsa_65: public.1.to_vec(),
        },
        context,
        message,
        &HybridSignature {
            ed25519: signature.0.to_vec(),
            ml_dsa_65: signature.1.to_vec(),
        },
    )
}
