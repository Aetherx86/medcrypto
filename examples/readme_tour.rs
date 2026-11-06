// The library tour from the README, kept here so that it is compiled and run.
//   cargo run --release --example readme_tour

use medcrypto::compliance::KeyManager;
use medcrypto::fhe::{CKKSEngine, CkksPreset};
use medcrypto::packing::RecordEnvelope;
use medcrypto::zkp::{PedersenBackend, ZKPEngine, ZkPredicateProver};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // N = 8192: 4096 slots, two multiplications, 128 post-quantum bits by the HE Standard's table.
    let fhe = CKKSEngine::from_preset(CkksPreset::N8192);
    let (secret, public) = fhe.keygen();
    let relin = fhe.relin_keygen(&secret);
    let galois = fhe.galois_keygen(&secret, &fhe.sum_rotation_steps());

    // Slot-wise arithmetic on encrypted vectors.
    let a = fhe.encrypt(&public, &[1.5, 2.5, 3.5, 4.5])?;
    let b = fhe.encrypt(&public, &[2.0, 2.0, 2.0, 2.0])?;
    let product = fhe.multiply_relin_rescale(&a, &b, &relin)?;
    println!("product: {:.3?}", fhe.decrypt(&secret, &product)?); // [3.0, 5.0, 7.0, 9.0]

    // Rotation moves slots left, and a negative step moves them right.
    let rotated = fhe.rotate(&a, 1, &galois)?;
    println!("rotated: {:.3}", fhe.decrypt(&secret, &rotated)?[0]); // 2.5

    // A linear score: sum(weight * feature) + bias, all under encryption.
    let features = fhe.encrypt(&public, &[54.0, 128.0, 5.8])?;
    let score = fhe.evaluate_linear_risk_model(&features, &[0.02, 0.01, 0.3], -1.5, &galois)?;
    println!("score: {:.3}", fhe.decrypt(&secret, &score)?[0]); // 2.6

    // A nonlinear score: a logistic curve, by a cubic approximation.
    let inputs = fhe.encrypt(&public, &[-2.0, 0.0, 2.0])?;
    let probability = fhe.evaluate_logistic(&inputs, &relin)?;
    println!("logistic: {:.3?}", fhe.decrypt(&secret, &probability)?); // About 0.21, 0.5, 0.79

    // A range proof: the verifier learns that the value is in the range, and nothing else about it.
    let proof = PedersenBackend.prove_range(58, 0, 65)?;
    assert!(PedersenBackend.verify_range(&proof, 0, 65));
    let threshold = ZKPEngine::prove_threshold(58, 65, true)?;
    assert!(ZKPEngine::verify_threshold(&threshold));

    // An envelope that can be erased by destroying its key.
    let mut keys = KeyManager::new();
    let names = vec!["hba1c".to_string(), "glucose".to_string()];
    let envelope =
        RecordEnvelope::seal(&fhe, &public, &mut keys, "patient-1", names, &[5.9, 108.0])?;
    assert!(envelope.open(&fhe, &keys).is_ok());
    keys.shred_key(&envelope.envelope.key_id, "patient-1")?;
    assert!(envelope.open(&fhe, &keys).is_err());
    println!("erased: the envelope no longer opens");
    Ok(())
}
