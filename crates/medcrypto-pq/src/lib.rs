//! Post-quantum building blocks that need no operating system, so that the Wasm component can use them too.
//!
//! - [`signatures`]: ML-DSA-65 (FIPS 204) and Ed25519 together, with both required.
//! - [`range_proof`]: zero-knowledge range proofs resting only on SHA-256, by MPC-in-the-head.

#![forbid(unsafe_code)]

pub mod range_proof;
pub mod signatures;
