//! Runs inside the prover. Commits publicly to `SHA-256(value, blinding)`, `min` and `max`, and fails unless
//! `min <= value <= max`. Hash-based, so that nothing here depends on discrete logarithms.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};

pub fn main() {
    let value: u64 = sp1_zkvm::io::read();
    let blinding: [u8; 32] = sp1_zkvm::io::read();
    let min: u64 = sp1_zkvm::io::read();
    let max: u64 = sp1_zkvm::io::read();
    assert!(min <= value && value <= max);
    let commitment: [u8; 32] = Sha256::new()
        .chain_update(b"medcrypto/guest-range/v1")
        .chain_update(value.to_le_bytes())
        .chain_update(blinding)
        .finalize()
        .into();
    sp1_zkvm::io::commit(&commitment);
    sp1_zkvm::io::commit(&min);
    sp1_zkvm::io::commit(&max);
}
