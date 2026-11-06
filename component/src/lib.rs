//! MedCrypto's core cryptography and homomorphic encryption as a WebAssembly Component.
//!
//! The one `.wasm` file works from any language with a component runtime, with no bindings written by
//! hand. It imports nothing at all, so what it can do is limited to computing on what it is given.

pub mod core;

#[cfg(target_arch = "wasm32")]
mod component {
    wit_bindgen::generate!({ path: "wit", world: "medcrypto" });

    use self::exports::medcrypto::crypto::api::{CryptoError, Guest, Keypair};
    use self::exports::medcrypto::crypto::fhe_ops::{
        self, Ciphertext, FheError, FheKeypair, Guest as FheGuest,
    };
    use crate::core::{self, Error, FheCiphertext, FheOpError};

    impl From<FheOpError> for FheError {
        fn from(e: FheOpError) -> Self {
            match e {
                FheOpError::BadEntropy => FheError::BadEntropy,
                FheOpError::BadEncoding => FheError::BadEncoding,
                FheOpError::ParameterMismatch => FheError::ParameterMismatch,
                FheOpError::ValueOutOfRange => FheError::ValueOutOfRange,
                FheOpError::ScaleMismatch => FheError::ScaleMismatch,
                FheOpError::OutOfLevels => FheError::OutOfLevels,
            }
        }
    }

    fn inward(c: fhe_ops::Ciphertext) -> FheCiphertext {
        FheCiphertext {
            data: c.data,
            degree: c.degree,
            scale: c.scale,
        }
    }

    fn outward(c: FheCiphertext) -> Ciphertext {
        Ciphertext {
            data: c.data,
            degree: c.degree,
            scale: c.scale,
        }
    }

    impl From<Error> for CryptoError {
        fn from(e: Error) -> Self {
            match e {
                Error::BadLength => CryptoError::BadLength,
                Error::AuthenticationFailed => CryptoError::AuthenticationFailed,
                Error::BadOutputLength => CryptoError::BadOutputLength,
                Error::WeakSeed => CryptoError::WeakSeed,
            }
        }
    }

    struct Medcrypto;

    impl Guest for Medcrypto {
        fn sha256(data: Vec<u8>) -> Vec<u8> {
            core::sha256(&data)
        }

        fn hkdf(
            input_key: Vec<u8>,
            salt: Vec<u8>,
            info: Vec<u8>,
            length: u32,
        ) -> Result<Vec<u8>, CryptoError> {
            Ok(core::hkdf(&input_key, &salt, &info, length)?)
        }

        fn seal(
            key: Vec<u8>,
            nonce: Vec<u8>,
            associated_data: Vec<u8>,
            plaintext: Vec<u8>,
        ) -> Result<Vec<u8>, CryptoError> {
            Ok(core::seal(&key, &nonce, &associated_data, &plaintext)?)
        }

        fn open(
            key: Vec<u8>,
            nonce: Vec<u8>,
            associated_data: Vec<u8>,
            ciphertext: Vec<u8>,
        ) -> Result<Vec<u8>, CryptoError> {
            Ok(core::open(&key, &nonce, &associated_data, &ciphertext)?)
        }

        fn keypair_from_seed(seed: Vec<u8>) -> Result<Keypair, CryptoError> {
            let (public_key, secret_key) = core::keypair_from_seed(&seed)?;
            Ok(Keypair {
                public_key,
                secret_key,
            })
        }

        fn sign(secret_key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
            Ok(core::sign(&secret_key, &message)?)
        }

        fn verify(public_key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
            core::verify(&public_key, &message, &signature)
        }

        fn merkle_root(leaves: Vec<Vec<u8>>) -> Vec<u8> {
            core::merkle_root(&leaves)
        }

        fn audit_link(previous: Vec<u8>, entry: Vec<u8>) -> Vec<u8> {
            core::audit_link(&previous, &entry)
        }

        fn constant_time_equal(a: Vec<u8>, b: Vec<u8>) -> bool {
            core::constant_time_equal(&a, &b)
        }
    }

    impl FheGuest for Medcrypto {
        fn keygen(entropy: Vec<u8>) -> Result<FheKeypair, FheError> {
            let (public_key, secret_key) = core::fhe_keygen(&entropy)?;
            Ok(FheKeypair {
                public_key,
                secret_key,
            })
        }

        fn encrypt_vector(
            pk: Vec<u8>,
            values: Vec<f64>,
            entropy: Vec<u8>,
        ) -> Result<Ciphertext, FheError> {
            Ok(outward(core::fhe_encrypt(&pk, &values, &entropy)?))
        }

        fn decrypt_vector(sk: Vec<u8>, a: Ciphertext) -> Result<Vec<f64>, FheError> {
            Ok(core::fhe_decrypt(&sk, &inward(a))?)
        }

        fn homomorphic_add(a: Ciphertext, b: Ciphertext) -> Result<Ciphertext, FheError> {
            Ok(outward(core::fhe_add(&inward(a), &inward(b))?))
        }

        fn homomorphic_scalar_mul(a: Ciphertext, scalar: f64) -> Result<Ciphertext, FheError> {
            Ok(outward(core::fhe_scalar_mul(&inward(a), scalar)?))
        }
    }

    export!(Medcrypto);
}
