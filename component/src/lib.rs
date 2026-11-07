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

    use self::exports::medcrypto::crypto::bfv_ops::{self, BfvCiphertext, Guest as BfvGuest};
    use self::exports::medcrypto::crypto::pq_signatures::{
        self, Guest as PqGuest, HybridPublicKey, HybridSignature,
    };
    use crate::core::BfvWire;

    fn bfv_in(c: bfv_ops::BfvCiphertext) -> BfvWire {
        BfvWire {
            data: c.data,
            degree: c.degree,
            plain_modulus: c.plain_modulus,
        }
    }

    fn bfv_out(c: BfvWire) -> BfvCiphertext {
        BfvCiphertext {
            data: c.data,
            degree: c.degree,
            plain_modulus: c.plain_modulus,
        }
    }

    impl BfvGuest for Medcrypto {
        fn keygen(entropy: Vec<u8>) -> Result<bfv_ops::FheKeypair, bfv_ops::FheError> {
            let (public_key, secret_key) = core::bfv_keygen(&entropy)?;
            Ok(FheKeypair {
                public_key,
                secret_key,
            })
        }

        fn relin_keygen(sk: Vec<u8>, entropy: Vec<u8>) -> Result<Vec<u8>, bfv_ops::FheError> {
            Ok(core::bfv_relin_keygen(&sk, &entropy)?)
        }

        fn encrypt(
            pk: Vec<u8>,
            plain_bits: u32,
            values: Vec<i64>,
            entropy: Vec<u8>,
        ) -> Result<BfvCiphertext, bfv_ops::FheError> {
            Ok(bfv_out(core::bfv_encrypt(
                &pk, plain_bits, &values, &entropy,
            )?))
        }

        fn decrypt(sk: Vec<u8>, a: BfvCiphertext) -> Result<Vec<i64>, bfv_ops::FheError> {
            Ok(core::bfv_decrypt(&sk, &bfv_in(a))?)
        }

        fn add(a: BfvCiphertext, b: BfvCiphertext) -> Result<BfvCiphertext, bfv_ops::FheError> {
            Ok(bfv_out(core::bfv_add(&bfv_in(a), &bfv_in(b))?))
        }

        fn multiply(
            a: BfvCiphertext,
            b: BfvCiphertext,
            relin_key: Vec<u8>,
        ) -> Result<BfvCiphertext, bfv_ops::FheError> {
            Ok(bfv_out(core::bfv_multiply(
                &bfv_in(a),
                &bfv_in(b),
                &relin_key,
            )?))
        }

        fn noise_budget(sk: Vec<u8>, a: BfvCiphertext) -> Result<f64, bfv_ops::FheError> {
            Ok(core::bfv_noise_budget(&sk, &bfv_in(a))?)
        }
    }

    impl PqGuest for Medcrypto {
        fn public_key_from_seed(
            seed: Vec<u8>,
        ) -> Result<HybridPublicKey, pq_signatures::CryptoError> {
            let (ed25519, ml_dsa65) = core::hybrid_public_key(&seed)?;
            Ok(HybridPublicKey { ed25519, ml_dsa65 })
        }

        fn sign(
            seed: Vec<u8>,
            context: Vec<u8>,
            message: Vec<u8>,
            entropy: Vec<u8>,
        ) -> Result<HybridSignature, pq_signatures::CryptoError> {
            let (ed25519, ml_dsa65) = core::hybrid_sign(&seed, &context, &message, &entropy)?;
            Ok(HybridSignature { ed25519, ml_dsa65 })
        }

        fn verify(
            public_key: HybridPublicKey,
            context: Vec<u8>,
            message: Vec<u8>,
            signature: HybridSignature,
        ) -> bool {
            core::hybrid_verify(
                (&public_key.ed25519, &public_key.ml_dsa65),
                &context,
                &message,
                (&signature.ed25519, &signature.ml_dsa65),
            )
        }
    }

    export!(Medcrypto);
}
