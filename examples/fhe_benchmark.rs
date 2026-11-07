// Times the homomorphic operations and prints a Markdown table. Run it in release mode:
//   cargo run --release --example fhe_benchmark

use medcrypto::fhe::{to_bytes, BfvEngine, CKKSEngine, CkksPreset};
use medcrypto::signatures::{verify, HybridSigningKey};
use medcrypto::zkp::{HashBasedBackend, PedersenBackend, ZkPredicateProver};
use std::time::Instant;

fn time<T>(runs: u32, mut f: impl FnMut() -> T) -> f64 {
    let start = Instant::now();
    for _ in 0..runs {
        std::hint::black_box(f());
    }
    start.elapsed().as_secs_f64() * 1000.0 / runs as f64
}

fn main() {
    for preset in [CkksPreset::N8192, CkksPreset::N16384] {
        let engine = CKKSEngine::from_preset(preset);
        let context = engine.context();
        println!(
            "\n## N = {}, {} slots, {} modulus bits\n",
            context.poly_degree,
            context.slots(),
            context.total_modulus_bits()
        );
        let (secret, public) = engine.keygen();
        let values: Vec<f64> = (0..engine.slots()).map(|i| (i % 300) as f64).collect();
        let ct = engine.encrypt(&public, &values).unwrap();
        println!("| Operation | Time (ms) |\n|---|---:|");
        let row = |name: &str, ms: f64| println!("| {name} | {ms:.2} |");
        row("Key generation", time(5, || engine.keygen()));
        row(
            "Relinearization key",
            time(3, || engine.relin_keygen(&secret)),
        );
        row(
            "Rotation key, one",
            time(3, || engine.galois_keygen(&secret, &[1])),
        );
        row(
            "Encrypt, all slots",
            time(10, || engine.encrypt(&public, &values).unwrap()),
        );
        row(
            "Decrypt",
            time(10, || engine.decrypt(&secret, &ct).unwrap()),
        );
        row("Add", time(200, || engine.add(&ct, &ct).unwrap()));
        let raw = engine.multiply(&ct, &ct).unwrap();
        row("Multiply", time(50, || engine.multiply(&ct, &ct).unwrap()));
        let relin = engine.relin_keygen(&secret);
        row(
            "Relinearize",
            time(10, || engine.relinearize(&raw, &relin).unwrap()),
        );
        let relinearized = engine.relinearize(&raw, &relin).unwrap();
        row(
            "Rescale",
            time(20, || {
                let mut c = relinearized.clone();
                engine.rescale_to_next(&mut c).unwrap();
                c
            }),
        );
        let galois = engine.galois_keygen(&secret, &engine.sum_rotation_steps());
        row(
            "Rotate",
            time(10, || engine.rotate(&ct, 1, &galois).unwrap()),
        );
        row(
            "Sum all slots",
            time(3, || engine.sum_slots(&ct, &galois).unwrap()),
        );
        println!(
            "\nCiphertext: {:.0} KiB. Public key: {:.0} KiB. Relinearization key: {:.1} MiB. Rotation keys for summing: {:.1} MiB.",
            to_bytes(&ct).unwrap().len() as f64 / 1024.0,
            to_bytes(&public).unwrap().len() as f64 / 1024.0,
            to_bytes(&relin).unwrap().len() as f64 / 1048576.0,
            to_bytes(&galois).unwrap().len() as f64 / 1048576.0,
        );
    }

    for (preset, bits) in [(CkksPreset::N8192, 20u32), (CkksPreset::N16384, 20)] {
        let engine = BfvEngine::new(preset, bits).unwrap();
        println!("\n## BFV at N = {}, {bits}-bit t\n", engine.slots());
        let (secret, public) = engine.keygen();
        let relin = engine.relin_keygen(&secret);
        let galois = engine.sum_galois_keygen(&secret);
        let values: Vec<i64> = (0..engine.slots() as i64).map(|i| i % 300).collect();
        let ct = engine.encrypt(&public, &values).unwrap();
        println!("| Operation | Time (ms) |\n|---|---:|");
        let row = |name: &str, ms: f64| println!("| {name} | {ms:.2} |");
        row(
            "Encrypt, all slots",
            time(10, || engine.encrypt(&public, &values).unwrap()),
        );
        row("Decrypt", time(5, || engine.decrypt(&secret, &ct).unwrap()));
        row("Add", time(200, || engine.add(&ct, &ct).unwrap()));
        row(
            "Multiply plain",
            time(20, || engine.multiply_plain(&ct, &values).unwrap()),
        );
        let raw = engine.multiply(&ct, &ct).unwrap();
        row("Multiply", time(5, || engine.multiply(&ct, &ct).unwrap()));
        row(
            "Relinearize",
            time(10, || engine.relinearize(&raw, &relin).unwrap()),
        );
        row(
            "Sum all slots",
            time(3, || engine.sum_all(&ct, &galois).unwrap()),
        );
    }

    println!("\n## Hybrid signatures\n");
    let signer = HybridSigningKey::generate();
    let signature = signer.sign(b"bench", b"message").unwrap();
    println!("| Operation | Time (ms) |\n|---|---:|");
    println!(
        "| Key generation | {:.2} |",
        time(20, HybridSigningKey::generate)
    );
    println!(
        "| Sign | {:.2} |",
        time(20, || signer.sign(b"bench", b"message").unwrap())
    );
    println!(
        "| Verify | {:.2} |",
        time(20, || verify(
            signer.public_key(),
            b"bench",
            b"message",
            &signature
        ))
    );

    println!("\n## Range proofs (Pedersen backend)\n");
    println!("| Range | Prove (ms) | Verify (ms) | Size (bytes) |\n|---|---:|---:|---:|");
    for (min, max, value) in [(0u64, 65u64, 58u64), (18, 18 + (1u64 << 32) - 1, 45)] {
        let proof = PedersenBackend.prove_range(value, min, max).unwrap();
        println!(
            "| [{min}, {max}] | {:.2} | {:.2} | {} |",
            time(20, || PedersenBackend.prove_range(value, min, max).unwrap()),
            time(20, || PedersenBackend.verify_range(&proof, min, max)),
            proof.payload.len() / 2
        );
    }

    println!("\n## Range proofs (hash-based backend)\n");
    let proof = HashBasedBackend.prove_range(58, 0, 65).unwrap();
    println!("| Prove (ms) | Verify (ms) | Size (bytes) |\n|---:|---:|---:|");
    println!(
        "| {:.0} | {:.0} | {} |",
        time(3, || HashBasedBackend.prove_range(58, 0, 65).unwrap()),
        time(3, || HashBasedBackend.verify_range(&proof, 0, 65)),
        proof.payload.len() / 2
    );
}
