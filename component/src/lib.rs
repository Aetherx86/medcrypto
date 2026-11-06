//! MedCrypto's core cryptography as a WebAssembly Component.
//!
//! The one `.wasm` file works from any language with a component runtime, with no bindings written by
//! hand. It imports nothing at all, so what it can do is limited to computing on what it is given.

pub mod core;

#[cfg(target_arch = "wasm32")]
mod component {
    wit_bindgen::generate!({ path: "wit", world: "medcrypto" });

    use self::exports::medcrypto::crypto::api::{CryptoError, Guest, Keypair};
    use crate::core::{self, Error};

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

    export!(Medcrypto);
}
