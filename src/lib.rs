pub mod blockchain;
pub mod clinical_ai;
pub mod compliance;
pub mod consortium;
pub mod gui;
pub mod models;
pub mod packing;
pub mod quantum;
pub mod signatures;
pub mod zkp;

/// The homomorphic encryption engine, which lives in its own crate so that the Wasm component can use it.
pub use medcrypto_fhe as fhe;
/// FHIR ingestion, which lives in its own crate and knows nothing of encryption.
pub use medcrypto_fhir as fhir;
