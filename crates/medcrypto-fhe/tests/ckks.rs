use medcrypto_fhe::ckks::os_seeded_rng;
use medcrypto_fhe::threshold::{
    aggregate_public, aggregate_secret, combine, partial_decrypt, DkgParty, ThresholdConfig,
    ThresholdKeyShare, DEFAULT_SMUDGING_BITS,
};
use medcrypto_fhe::{
    from_bytes, to_bytes, CKKSEngine, Ciphertext, CkksPreset, FheError, PublicKey,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn close(actual: &[f64], expected: &[f64], tolerance: f64) {
    assert_eq!(actual.len(), expected.len());
    for (i, (a, e)) in actual.iter().zip(expected).enumerate() {
        assert!((a - e).abs() < tolerance, "slot {i}: got {a}, expected {e}");
    }
}

fn engine() -> CKKSEngine {
    CKKSEngine::from_preset(CkksPreset::N8192)
}

#[test]
fn encrypt_decrypt_uses_all_slots() {
    let e = engine();
    let (sk, pk) = e.keygen();
    let values: Vec<f64> = (0..e.slots())
        .map(|i| (i % 300) as f64 * 0.5 - 40.0)
        .collect();
    let ct = e.encrypt(&pk, &values).unwrap();
    close(&e.decrypt(&sk, &ct).unwrap(), &values, 1e-5);
}

#[test]
fn addition_subtraction_and_scalars() {
    let e = engine();
    let (sk, pk) = e.keygen();
    let (a, b) = (vec![10.0, 20.5, -30.0], vec![5.0, 15.25, 25.0]);
    let (ca, cb) = (e.encrypt(&pk, &a).unwrap(), e.encrypt(&pk, &b).unwrap());
    close(
        &e.decrypt(&sk, &e.add(&ca, &cb).unwrap()).unwrap(),
        &[15.0, 35.75, -5.0],
        1e-5,
    );
    close(
        &e.decrypt(&sk, &e.sub(&ca, &cb).unwrap()).unwrap(),
        &[5.0, 5.25, -55.0],
        1e-5,
    );
    close(
        &e.decrypt(&sk, &e.scalar_mul(&ca, 3.0).unwrap()).unwrap(),
        &[30.0, 61.5, -90.0],
        1e-4,
    );

    // A fractional scalar costs a level, and the scale comes back exactly.
    let half = e.scalar_mul(&ca, 0.5).unwrap();
    assert_eq!(half.level(), ca.level() - 1);
    assert_eq!(half.scale, ca.scale);
    close(&e.decrypt(&sk, &half).unwrap(), &[5.0, 10.25, -15.0], 1e-4);

    close(
        &e.decrypt(&sk, &e.add_constant(&ca, 1.5).unwrap()).unwrap(),
        &[11.5, 22.0, -28.5],
        1e-5,
    );
}

#[test]
fn multiplication_relinearization_and_rescaling() {
    let e = engine();
    let (sk, pk) = e.keygen();
    let rlk = e.relin_keygen(&sk);
    let (a, b) = (vec![1.5, -2.0, 3.25, 10.0], vec![4.0, 0.5, -2.0, 7.5]);
    let (ca, cb) = (e.encrypt(&pk, &a).unwrap(), e.encrypt(&pk, &b).unwrap());
    let expected: Vec<f64> = a.iter().zip(&b).map(|(x, y)| x * y).collect();

    let raw = e.multiply(&ca, &cb).unwrap();
    assert_eq!(raw.degree(), 2);
    close(&e.decrypt(&sk, &raw).unwrap(), &expected, 1e-3);

    let relinearized = e.relinearize(&raw, &rlk).unwrap();
    assert_eq!(relinearized.degree(), 1);
    close(&e.decrypt(&sk, &relinearized).unwrap(), &expected, 1e-3);

    let mut rescaled = relinearized;
    e.rescale_to_next(&mut rescaled).unwrap();
    assert_eq!(rescaled.level(), ca.level() - 1);
    assert!((rescaled.scale.log2() - 40.0).abs() < 0.01);
    close(&e.decrypt(&sk, &rescaled).unwrap(), &expected, 1e-3);

    // Multiplying again spends the second and last level of this preset.
    let c2 = e.mod_switch_to_level(&ca, 1).unwrap();
    let again = e.multiply_relin_rescale(&rescaled, &c2, &rlk).unwrap();
    assert_eq!(again.level(), 0);
    let expected: Vec<f64> = expected.iter().zip(&a).map(|(x, y)| x * y).collect();
    close(&e.decrypt(&sk, &again).unwrap(), &expected, 1e-2);

    // There is nothing left to pay for another rescale.
    let mut spent = again;
    assert_eq!(e.rescale_to_next(&mut spent), Err(FheError::OutOfLevels));
}

#[test]
fn rotation_moves_slots_in_both_directions() {
    let e = engine();
    let (sk, pk) = e.keygen();
    let gk = e.galois_keygen(&sk, &[1, -3, 256]);
    let mut values = vec![0.0; e.slots()];
    for (i, v) in values.iter_mut().enumerate() {
        *v = i as f64;
    }
    let ct = e.encrypt(&pk, &values).unwrap();
    for steps in [1i64, -3, 256] {
        let rotated = e.rotate(&ct, steps, &gk).unwrap();
        let expected: Vec<f64> = (0..e.slots() as i64)
            .map(|i| (i + steps).rem_euclid(e.slots() as i64) as f64)
            .collect();
        close(&e.decrypt(&sk, &rotated).unwrap(), &expected, 1e-3);
    }
    assert_eq!(
        e.rotate(&ct, 2, &gk),
        Err(FheError::MissingGaloisKey { steps: 2 })
    );
    // A rotation after a level has gone still works, since the key covers every level.
    let lower = e.mod_switch_to_level(&ct, 1).unwrap();
    let rotated = e.rotate(&lower, 1, &gk).unwrap();
    assert!((e.decrypt(&sk, &rotated).unwrap()[10] - 11.0).abs() < 1e-3);
}

#[test]
fn sum_slots_reveals_only_the_total() {
    let e = engine();
    let (sk, pk) = e.keygen();
    let gk = e.galois_keygen(&sk, &e.sum_rotation_steps());
    let values: Vec<f64> = (0..4096).map(|i| 5.0 + (i % 7) as f64 * 0.1).collect();
    let total: f64 = values.iter().sum();
    let ct = e.encrypt(&pk, &values).unwrap();
    let sum = e.sum_slots(&ct, &gk).unwrap();
    assert!((e.decrypt(&sk, &sum).unwrap()[0] - total).abs() < 1e-2);
}

#[test]
fn linear_and_nonlinear_clinical_scores() {
    let e = engine();
    let (sk, pk) = e.keygen();
    let gk = e.galois_keygen(&sk, &e.sum_rotation_steps());
    let rlk = e.relin_keygen(&sk);

    let features = vec![54.0, 128.0, 5.8, 110.0];
    let weights = vec![0.02, 0.01, 0.3, -0.005];
    let ct = e.encrypt(&pk, &features).unwrap();
    let score = e
        .evaluate_linear_risk_model(&ct, &weights, -1.5, &gk)
        .unwrap();
    let expected: f64 = features
        .iter()
        .zip(&weights)
        .map(|(x, w)| x * w)
        .sum::<f64>()
        - 1.5;
    assert!((e.decrypt(&sk, &score).unwrap()[0] - expected).abs() < 1e-3);

    let inputs: Vec<f64> = vec![-6.0, -2.5, 0.0, 1.0, 4.0, 7.5];
    let ct = e.encrypt(&pk, &inputs).unwrap();
    let out = e.evaluate_logistic(&ct, &rlk).unwrap();
    assert_eq!(out.level(), 0);
    let expected: Vec<f64> = inputs
        .iter()
        .map(|x| 0.5 + 0.15012 * x - 0.001593 * x * x * x)
        .collect();
    close(&e.decrypt(&sk, &out).unwrap(), &expected, 1e-3);

    let out = e.evaluate_cubic(&ct, [1.0, 2.0, -0.5, 0.25], &rlk).unwrap();
    let expected: Vec<f64> = inputs
        .iter()
        .map(|x| 1.0 + 2.0 * x - 0.5 * x * x + 0.25 * x * x * x)
        .collect();
    close(&e.decrypt(&sk, &out).unwrap(), &expected, 1e-2);
}

#[test]
fn federated_average_costs_no_level() {
    let e = engine();
    let (sk, pk) = e.keygen();
    let cts: Vec<Ciphertext> = [[90.0, 120.0], [110.0, 130.0], [100.0, 140.0]]
        .iter()
        .map(|v| e.encrypt(&pk, v).unwrap())
        .collect();
    let average = e.federated_average(&cts).unwrap();
    assert_eq!(average.level(), cts[0].level());
    close(&e.decrypt(&sk, &average).unwrap(), &[100.0, 130.0], 1e-5);
}

#[test]
fn the_larger_preset_supports_seven_multiplications() {
    let e = CKKSEngine::from_preset(CkksPreset::N16384);
    assert_eq!(e.slots(), 8192);
    assert!(e.context().total_modulus_bits() <= 411);
    let (sk, pk) = e.keygen();
    let rlk = e.relin_keygen(&sk);
    let mut ct = e.encrypt(&pk, &[1.1, 0.9]).unwrap();
    let mut expected = [1.1f64, 0.9];
    for _ in 0..7 {
        ct = e.multiply_relin_rescale(&ct, &ct, &rlk).unwrap();
        expected = [expected[0] * expected[0], expected[1] * expected[1]];
    }
    assert_eq!(ct.level(), 0);
    // Noise grows along with the value through squarings, so what matters here is the relative error.
    let decrypted = e.decrypt(&sk, &ct).unwrap();
    for (d, x) in decrypted.iter().zip(&expected) {
        assert!((d - x).abs() / x.abs().max(1e-3) < 1e-3, "{d} vs {x}");
    }
}

#[test]
fn bad_input_is_an_error_and_never_a_panic() {
    let e = engine();
    let (sk, pk) = e.keygen();
    assert!(matches!(
        e.encrypt(&pk, &[f64::NAN]),
        Err(FheError::ValueOutOfRange(_))
    ));
    assert!(matches!(
        e.encrypt(&pk, &[1e30]),
        Err(FheError::ValueOutOfRange(_))
    ));
    assert!(matches!(
        e.encrypt(&pk, &vec![0.0; 4097]),
        Err(FheError::TooManyValues { .. })
    ));

    let ct = e.encrypt(&pk, &[1.0]).unwrap();
    let mut tampered = ct.clone();
    tampered.param_id ^= 1;
    assert_eq!(e.decrypt(&sk, &tampered), Err(FheError::ParameterMismatch));

    // Different scales would add up to a wrong answer, so they are refused.
    let mut rescaled = e.multiply(&ct, &ct).unwrap();
    e.rescale_to_next(&mut rescaled).unwrap();
    let down = e.mod_switch_to_level(&ct, 1).unwrap();
    let mut other = down.clone();
    other.scale *= 2.0;
    assert!(matches!(
        e.add(&down, &other),
        Err(FheError::ScaleMismatch { .. })
    ));

    // A product that cannot fit is refused rather than silently wrapping around.
    let bottom = e.mod_switch_to_level(&ct, 0).unwrap();
    assert_eq!(e.multiply(&bottom, &bottom), Err(FheError::ScaleOverflow));

    // A residue at or above its prime is caught by the full check.
    let bytes = to_bytes(&ct).unwrap();
    let parsed: Ciphertext = from_bytes(&bytes).unwrap();
    assert_eq!(parsed, ct);
    e.validate_ciphertext(&parsed).unwrap();
    let mut json: serde_json::Value = serde_json::to_value(&ct).unwrap();
    let limb = json["polys"][0][0].as_str().unwrap().to_string();
    json["polys"][0][0] = serde_json::Value::String(format!("ffffffffffffffff{}", &limb[16..]));
    let bad: Ciphertext = serde_json::from_value(json).unwrap();
    assert!(matches!(
        e.validate_ciphertext(&bad),
        Err(FheError::Malformed(_))
    ));

    assert!(from_bytes::<Ciphertext>(&bytes[..bytes.len() / 2]).is_err());
    let _: PublicKey = from_bytes(&to_bytes(&pk).unwrap()).unwrap();
}

#[test]
fn seeded_encryption_is_deterministic_for_the_wasm_component() {
    let e = engine();
    let (_, pk) = e.keygen_with(&mut ChaCha20Rng::from_seed([7; 32]));
    let (_, again) = e.keygen_with(&mut ChaCha20Rng::from_seed([7; 32]));
    assert_eq!(pk, again);
    let one = e
        .encrypt_with(&pk, &[1.0], &mut ChaCha20Rng::from_seed([9; 32]))
        .unwrap();
    let two = e
        .encrypt_with(&pk, &[1.0], &mut ChaCha20Rng::from_seed([9; 32]))
        .unwrap();
    assert_eq!(one, two);
}

fn run_dkg(
    e: &CKKSEngine,
    config: ThresholdConfig,
    steps: &[i64],
) -> (
    medcrypto_fhe::threshold::CollectiveKeys,
    Vec<ThresholdKeyShare>,
) {
    let mut rng = os_seeded_rng();
    let seed = [42u8; 32];
    let parties: Vec<DkgParty> = (1..=config.n)
        .map(|i| DkgParty::new(e, config, i, &mut rng).unwrap())
        .collect();
    let public: Vec<_> = parties
        .iter()
        .map(|p| p.public_share(&seed, steps, &mut rng))
        .collect();
    let keys = aggregate_public(e, config, &seed, &public).unwrap();
    let all_shares: Vec<_> = parties.iter().map(|p| p.secret_shares(&mut rng)).collect();
    let shares = (1..=config.n)
        .map(|to| {
            let mine: Vec<_> = all_shares
                .iter()
                .map(|from| from[to as usize - 1].clone())
                .collect();
            aggregate_secret(e, config, to, &mine).unwrap()
        })
        .collect();
    (keys, shares)
}

#[test]
fn any_k_of_n_parties_decrypt_and_fewer_do_not() {
    let e = engine();
    let config = ThresholdConfig::new(5, 3).unwrap();
    let (keys, shares) = run_dkg(&e, config, &[]);
    let mut rng = os_seeded_rng();
    let values = vec![120.5, 80.25, 5.7];
    let ct = e.encrypt(&keys.public_key, &values).unwrap();

    for set in [[1u32, 2, 3], [2, 4, 5], [1, 3, 5]] {
        let partials: Vec<_> = set
            .iter()
            .map(|&p| {
                partial_decrypt(
                    &e,
                    &shares[p as usize - 1],
                    &ct,
                    &set,
                    DEFAULT_SMUDGING_BITS,
                    &mut rng,
                )
                .unwrap()
            })
            .collect();
        close(&combine(&e, config, &ct, &partials).unwrap(), &values, 0.02);
    }

    // Only two parties: the set is refused outright.
    assert!(partial_decrypt(&e, &shares[0], &ct, &[1, 2], 24, &mut rng).is_err());

    // Partials for one set cannot be mixed with another set's.
    let a = partial_decrypt(&e, &shares[0], &ct, &[1, 2, 3], 24, &mut rng).unwrap();
    let b = partial_decrypt(&e, &shares[1], &ct, &[1, 2, 3], 24, &mut rng).unwrap();
    let c = partial_decrypt(&e, &shares[2], &ct, &[1, 3, 4], 24, &mut rng).unwrap();
    assert!(combine(&e, config, &ct, &[a.clone(), b.clone()]).is_err());
    assert!(combine(&e, config, &ct, &[a, b, c]).is_err());
}

#[test]
fn fewer_than_k_partials_with_a_forged_set_give_garbage() {
    // The two real parties of a 3-of-5 claim a set including a third, and leave that one out by supplying
    // a zero share. The Lagrange reconstruction fails, so the output has nothing to do with the message.
    let e = engine();
    let config = ThresholdConfig::new(5, 3).unwrap();
    let (keys, shares) = run_dkg(&e, config, &[]);
    let mut rng = os_seeded_rng();
    let values = vec![120.5, 80.25, 5.7];
    let ct = e.encrypt(&keys.public_key, &values).unwrap();
    let set = [1u32, 2, 3];
    let mut partials: Vec<_> = set[..2]
        .iter()
        .map(|&p| partial_decrypt(&e, &shares[p as usize - 1], &ct, &set, 24, &mut rng).unwrap())
        .collect();
    let mut fake = partials[0].clone();
    fake.party = 3;
    fake.data = medcrypto_fhe::RnsPoly::zero(fake.data.degree(), fake.data.limb_count());
    partials.push(fake);
    let out = combine(&e, config, &ct, &partials).unwrap();
    assert!((out[0] - values[0]).abs() > 1000.0, "{}", out[0]);
}

#[test]
fn threshold_sum_over_hospitals_with_collective_rotation_keys() {
    let e = engine();
    let config = ThresholdConfig::new(3, 2).unwrap();
    let (keys, shares) = run_dkg(&e, config, &e.sum_rotation_steps());
    let mut rng = os_seeded_rng();

    let hospital_a: Vec<f64> = (0..1000).map(|i| 5.0 + (i % 10) as f64 * 0.1).collect();
    let hospital_b: Vec<f64> = (0..2000).map(|i| 6.0 + (i % 5) as f64 * 0.2).collect();
    let total: f64 = hospital_a.iter().chain(&hospital_b).sum();
    let ca = e.encrypt(&keys.public_key, &hospital_a).unwrap();
    let cb = e.encrypt(&keys.public_key, &hospital_b).unwrap();
    let sum = e
        .sum_slots(&e.add(&ca, &cb).unwrap(), &keys.galois_key)
        .unwrap();

    let set = [1u32, 3];
    let partials: Vec<_> = set
        .iter()
        .map(|&p| partial_decrypt(&e, &shares[p as usize - 1], &sum, &set, 24, &mut rng).unwrap())
        .collect();
    let out = combine(&e, config, &sum, &partials).unwrap();
    assert!((out[0] - total).abs() < 0.05, "{} vs {total}", out[0]);
}

#[test]
fn threshold_config_rejects_impossible_values() {
    assert!(ThresholdConfig::new(3, 0).is_err());
    assert!(ThresholdConfig::new(3, 4).is_err());
    let e = engine();
    let mut rng = os_seeded_rng();
    assert!(DkgParty::new(&e, ThresholdConfig::new(3, 2).unwrap(), 4, &mut rng).is_err());
}

#[test]
fn threshold_decryption_of_bfv_is_exact_under_the_same_keys() {
    use medcrypto_fhe::threshold::{combine_bfv, partial_decrypt_bfv, BFV_SMUDGING_BITS};
    use medcrypto_fhe::BfvEngine;
    let e = engine();
    let config = ThresholdConfig::new(3, 2).unwrap();
    let (keys, shares) = run_dkg(&e, config, &e.sum_rotation_steps());
    let bfv = BfvEngine::new(CkksPreset::N8192, 50).unwrap();
    let mut rng = os_seeded_rng();

    let site_a: Vec<i64> = (0..4096).map(|i| 1000 + i % 500).collect();
    let site_b: Vec<i64> = (0..1000).map(|i| 2000 + i % 300).collect();
    let total: i64 = site_a.iter().chain(&site_b).sum();
    let ca = bfv.encrypt(&keys.public_key, &site_a).unwrap();
    let cb = bfv.encrypt(&keys.public_key, &site_b).unwrap();
    let sum = bfv
        .sum_rows(&bfv.add(&ca, &cb).unwrap(), &keys.galois_key)
        .unwrap();

    for set in [[1u32, 2], [2, 3], [1, 3]] {
        let partials: Vec<_> = set
            .iter()
            .map(|&p| {
                partial_decrypt_bfv(
                    &bfv,
                    &shares[p as usize - 1],
                    &sum,
                    &set,
                    BFV_SMUDGING_BITS,
                    &mut rng,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(combine_bfv(&bfv, config, &sum, &partials).unwrap(), [total]);
    }
    let one = partial_decrypt_bfv(&bfv, &shares[0], &sum, &[1, 2], 50, &mut rng).unwrap();
    assert!(combine_bfv(&bfv, config, &sum, &[one]).is_err());
}
