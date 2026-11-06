//! RNS-CKKS approximate homomorphic encryption, written from scratch in safe Rust.
//!
//! The scheme works on vectors of real numbers packed into `N/2` slots. Everything is stored in the
//! Residue Number System, one 64-bit word per prime per coefficient, so no multi-precision arithmetic
//! is needed. The modules, from the bottom up:
//!
//! - [`arith`]: modular arithmetic and NTT-friendly prime search
//! - [`ntt`]: the negacyclic number theoretic transform
//! - [`params`]: parameter sets checked against the Homomorphic Encryption Standard
//! - [`encoder`]: the canonical embedding between slots and polynomial coefficients
//! - [`ckks`]: keys, encryption, multiplication, relinearization, rescaling and rotation
//! - [`threshold`]: k-of-n distributed key generation and threshold decryption
//!
//! This crate has not had an independent cryptographic audit.

#![forbid(unsafe_code)]

pub mod arith;
pub mod ckks;
pub mod encoder;
pub mod ntt;
pub mod params;
pub mod rns;
pub mod threshold;

pub use ckks::{CKKSContext, CKKSEngine, Ciphertext, GaloisKey, PublicKey, RelinKey, SecretKey};
pub use params::{CkksParams, CkksPreset, SecurityLevel};
pub use rns::RnsPoly;

/// What can go wrong in homomorphic operations.
#[derive(Clone, Debug, PartialEq)]
pub enum FheError {
    /// The parameters are unusable, or do not reach the requested security level.
    InvalidParameters(String),
    /// More values than slots.
    TooManyValues { given: usize, slots: usize },
    /// NaN or infinity, or a magnitude that does not fit the modulus at this scale.
    ValueOutOfRange(String),
    /// Key or ciphertext made under other parameters.
    ParameterMismatch,
    /// A ciphertext with the wrong shape, or coefficients outside their modulus.
    Malformed(String),
    /// Two ciphertexts whose scales differ, so adding them would give a wrong answer.
    ScaleMismatch { left: f64, right: f64 },
    /// No more primes to rescale with.
    OutOfLevels,
    /// The product's scale would not fit the remaining modulus.
    ScaleOverflow,
    /// The Galois key for this rotation was not generated.
    MissingGaloisKey { steps: i64 },
    /// An operation that needs a degree-1 ciphertext got one that has not been relinearized.
    NotRelinearized,
    /// Threshold protocol input that is inconsistent.
    Threshold(String),
    /// Bytes that do not decode.
    Codec(String),
}

impl core::fmt::Display for FheError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidParameters(m) => write!(f, "invalid parameters: {m}"),
            Self::TooManyValues { given, slots } => {
                write!(f, "{given} values do not fit in {slots} slots")
            }
            Self::ValueOutOfRange(m) => write!(f, "value out of range: {m}"),
            Self::ParameterMismatch => write!(f, "made under different parameters"),
            Self::Malformed(m) => write!(f, "malformed input: {m}"),
            Self::ScaleMismatch { left, right } => write!(f, "scales differ: {left} and {right}"),
            Self::OutOfLevels => write!(f, "no levels left"),
            Self::ScaleOverflow => write!(f, "the scale would overflow the remaining modulus"),
            Self::MissingGaloisKey { steps } => write!(f, "no Galois key for rotation by {steps}"),
            Self::NotRelinearized => write!(f, "the ciphertext must be relinearized first"),
            Self::Threshold(m) => write!(f, "threshold protocol: {m}"),
            Self::Codec(m) => write!(f, "decoding failed: {m}"),
        }
    }
}

impl std::error::Error for FheError {}

/// Compact binary form of any serializable value here, used on the wire and in the Wasm component.
pub fn to_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, FheError> {
    postcard::to_allocvec(value).map_err(|e| FheError::Codec(e.to_string()))
}

/// Reverses [`to_bytes`]. Check what comes out with the engine's `validate_*` functions if the bytes
/// came from anyone else.
pub fn from_bytes<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, FheError> {
    postcard::from_bytes(bytes).map_err(|e| FheError::Codec(e.to_string()))
}
