use medcrypto_fhe::{from_bytes, to_bytes, BfvCiphertext, BfvEngine, CkksPreset, FheError};

fn engine() -> BfvEngine {
    BfvEngine::new(CkksPreset::N8192, 20).unwrap()
}

/// Slot values as the plaintext ring sees them, for comparing with computed results.
fn centered(value: i128, t: u64) -> i64 {
    let t = t as i128;
    let r = value.rem_euclid(t);
    (if r > t / 2 { r - t } else { r }) as i64
}

#[test]
fn parameters_are_checked() {
    assert!(BfvEngine::new(CkksPreset::N8192, 19).is_err());
    assert!(BfvEngine::new(CkksPreset::N8192, 41).is_err());
    let e = engine();
    assert_eq!(e.slots(), 8192);
    assert_eq!(e.plain_modulus() % (2 * 8192), 1);
    assert_eq!(64 - e.plain_modulus().leading_zeros(), 20);
}

#[test]
fn every_slot_round_trips_exactly_including_negatives() {
    let e = engine();
    let (sk, pk) = e.keygen();
    let t = e.plain_modulus() as i64;
    let values: Vec<i64> = (0..e.slots() as i64)
        .map(|i| (i * 37) % t - t / 2 + 1)
        .collect();
    let ct = e.encrypt(&pk, &values).unwrap();
    assert_eq!(e.decrypt(&sk, &ct).unwrap(), values);
    assert!(e.noise_budget_bits(&sk, &ct).unwrap() > 80.0);
}

#[test]
fn linear_operations_are_exact() {
    let e = engine();
    let (sk, pk) = e.keygen();
    let (a, b) = (vec![1000, -2000, 3, 70000], vec![5, 60, -700, 8]);
    let (ca, cb) = (e.encrypt(&pk, &a).unwrap(), e.encrypt(&pk, &b).unwrap());
    assert_eq!(
        e.decrypt(&sk, &e.add(&ca, &cb).unwrap()).unwrap(),
        [1005, -1940, -697, 70008]
    );
    assert_eq!(
        e.decrypt(&sk, &e.sub(&ca, &cb).unwrap()).unwrap(),
        [995, -2060, 703, 69992]
    );
    assert_eq!(
        e.decrypt(&sk, &e.negate(&ca).unwrap()).unwrap(),
        [-1000, 2000, -3, -70000]
    );
    assert_eq!(
        e.decrypt(&sk, &e.add_plain(&ca, &[1, 2, 3, 4]).unwrap())
            .unwrap(),
        [1001, -1998, 6, 70004]
    );
    assert_eq!(
        e.decrypt(&sk, &e.multiply_plain(&ca, &[2, -3, 4, 5]).unwrap())
            .unwrap(),
        [2000, 6000, 12, 350000]
    );
}

#[test]
fn multiplication_is_exact_and_relinearization_keeps_it() {
    let e = engine();
    let (sk, pk) = e.keygen();
    let rlk = e.relin_keygen(&sk);
    let t = e.plain_modulus();
    let a: Vec<i64> = (0..e.slots() as i64).map(|i| i % 1000 - 500).collect();
    let b: Vec<i64> = (0..e.slots() as i64).map(|i| (i * 7) % 900 - 450).collect();
    let expected: Vec<i64> = a
        .iter()
        .zip(&b)
        .map(|(&x, &y)| centered(x as i128 * y as i128, t))
        .collect();
    let (ca, cb) = (e.encrypt(&pk, &a).unwrap(), e.encrypt(&pk, &b).unwrap());

    let raw = e.multiply(&ca, &cb).unwrap();
    assert_eq!(raw.degree(), 2);
    assert_eq!(e.decrypt(&sk, &raw).unwrap(), expected);

    let relinearized = e.relinearize(&raw, &rlk).unwrap();
    assert_eq!(relinearized.degree(), 1);
    assert_eq!(e.decrypt(&sk, &relinearized).unwrap(), expected);
    assert!(
        e.noise_budget_bits(&sk, &relinearized).unwrap() < e.noise_budget_bits(&sk, &ca).unwrap()
    );
}

#[test]
fn repeated_multiplication_until_the_budget_says_stop() {
    let e = engine();
    let (sk, pk) = e.keygen();
    let rlk = e.relin_keygen(&sk);
    let t = e.plain_modulus();
    let base = vec![3i64, -5, 7, 2];
    let mut expected: Vec<i128> = base.iter().map(|&x| x as i128).collect();
    let fresh = e.encrypt(&pk, &base).unwrap();
    let mut ct = fresh.clone();
    let mut depth = 0;
    loop {
        let next = e.multiply_relin(&ct, &fresh, &rlk).unwrap();
        let budget = e.noise_budget_bits(&sk, &next).unwrap();
        // Noise that has overrun the message reads as about half of Q, which is a budget just above zero.
        if budget < 1.0 {
            break;
        }
        for (x, b) in expected.iter_mut().zip(&base) {
            *x = (*x * *b as i128).rem_euclid(t as i128);
        }
        let want: Vec<i64> = expected.iter().map(|&x| centered(x, t)).collect();
        assert_eq!(
            e.decrypt(&sk, &next).unwrap(),
            want,
            "depth {depth}, budget {budget}"
        );
        ct = next;
        depth += 1;
        assert!(depth < 20, "the budget should run out long before this");
    }
    assert!(
        depth >= 2,
        "only {depth} multiplications before the budget ran out"
    );
}

#[test]
fn the_larger_preset_goes_deeper_with_a_larger_modulus() {
    let e = BfvEngine::new(CkksPreset::N16384, 30).unwrap();
    assert_eq!(e.slots(), 16384);
    let (sk, pk) = e.keygen();
    let rlk = e.relin_keygen(&sk);
    let t = e.plain_modulus();
    let value = 1_000_003i64;
    let fresh = e.encrypt(&pk, &[value]).unwrap();
    let mut ct = fresh.clone();
    let mut expected = value as i128;
    for _ in 0..5 {
        ct = e.multiply_relin(&ct, &fresh, &rlk).unwrap();
        expected = (expected * value as i128).rem_euclid(t as i128);
    }
    assert_eq!(e.decrypt(&sk, &ct).unwrap(), [centered(expected, t)]);
    assert!(e.noise_budget_bits(&sk, &ct).unwrap() > 0.0);
}

#[test]
fn rotation_moves_each_row_and_swap_exchanges_them() {
    let e = engine();
    let (sk, pk) = e.keygen();
    let gk = e.galois_keygen(&sk, &[1, -3], true);
    let half = e.slots() / 2;
    let values: Vec<i64> = (0..e.slots() as i64).map(|i| i + 1).collect();
    let ct = e.encrypt(&pk, &values).unwrap();

    let rotated = e
        .decrypt(&sk, &e.rotate_rows(&ct, 1, &gk).unwrap())
        .unwrap();
    for i in 0..half {
        assert_eq!(rotated[i], values[(i + 1) % half]);
        assert_eq!(rotated[half + i], values[half + (i + 1) % half]);
    }
    let right = e
        .decrypt(&sk, &e.rotate_rows(&ct, -3, &gk).unwrap())
        .unwrap();
    assert_eq!(right[3], values[0]);

    let swapped = e.decrypt(&sk, &e.swap_rows(&ct, &gk).unwrap()).unwrap();
    assert_eq!(swapped[0], values[half]);
    assert_eq!(swapped[half], values[0]);

    assert_eq!(
        e.rotate_rows(&ct, 2, &gk),
        Err(FheError::MissingGaloisKey { steps: 2 })
    );
}

#[test]
fn sum_all_gives_the_exact_total_in_every_slot() {
    let e = engine();
    let (sk, pk) = e.keygen();
    let gk = e.sum_galois_keygen(&sk);
    let values: Vec<i64> = (0..e.slots() as i64).map(|i| (i % 3 == 0) as i64).collect();
    let total: i64 = values.iter().sum();
    let sum = e.sum_all(&e.encrypt(&pk, &values).unwrap(), &gk).unwrap();
    assert_eq!(e.decrypt(&sk, &sum).unwrap(), [total]);

    // Counting patients across two hospitals: both add a column of ones and zeros.
    let other: Vec<i64> = (0..100).map(|i| (i % 2) as i64).collect();
    let both = e
        .add(
            &e.encrypt(&pk, &values).unwrap(),
            &e.encrypt(&pk, &other).unwrap(),
        )
        .unwrap();
    assert_eq!(
        e.decrypt(&sk, &e.sum_all(&both, &gk).unwrap()).unwrap(),
        [total + 50]
    );
}

#[test]
fn results_past_the_modulus_wrap_around_exactly() {
    let e = engine();
    let (sk, pk) = e.keygen();
    let t = e.plain_modulus();
    let bound = (t / 2) as i64;
    let ct = e.encrypt(&pk, &[bound]).unwrap();
    assert_eq!(
        e.decrypt(&sk, &e.add_plain(&ct, &[1]).unwrap()).unwrap(),
        [centered(bound as i128 + 1, t)]
    );
}

#[test]
fn bad_input_is_an_error_and_never_a_panic() {
    let e = engine();
    let (sk, pk) = e.keygen();
    let t = e.plain_modulus() as i64;
    assert!(matches!(
        e.encrypt(&pk, &[t]),
        Err(FheError::ValueOutOfRange(_))
    ));
    assert!(matches!(
        e.encrypt(&pk, &vec![0; 8193]),
        Err(FheError::TooManyValues { .. })
    ));

    let ct = e.encrypt(&pk, &[1]).unwrap();
    let other = BfvEngine::new(CkksPreset::N8192, 24).unwrap();
    assert_eq!(other.decrypt(&sk, &ct), Err(FheError::ParameterMismatch));
    let larger = BfvEngine::new(CkksPreset::N16384, 20).unwrap();
    assert_eq!(larger.decrypt(&sk, &ct), Err(FheError::ParameterMismatch));

    let parsed: BfvCiphertext = from_bytes(&to_bytes(&ct).unwrap()).unwrap();
    assert_eq!(parsed, ct);
    e.validate_ciphertext(&parsed).unwrap();
    let mut json: serde_json::Value = serde_json::to_value(&ct).unwrap();
    let limb = json["polys"][0][0].as_str().unwrap().to_string();
    json["polys"][0][0] = serde_json::Value::String(format!("ffffffffffffffff{}", &limb[16..]));
    let bad: BfvCiphertext = serde_json::from_value(json).unwrap();
    assert!(matches!(
        e.validate_ciphertext(&bad),
        Err(FheError::Malformed(_))
    ));

    let raw = e.multiply(&ct, &ct).unwrap();
    assert_eq!(e.multiply(&raw, &ct), Err(FheError::NotRelinearized));
}

#[test]
#[ignore = "prints the measurements quoted in the README"]
fn measure_budgets() {
    for (preset, name) in [(CkksPreset::N8192, "N8192"), (CkksPreset::N16384, "N16384")] {
        for bits in [20u32, 30, 40] {
            let Ok(e) = BfvEngine::new(preset, bits) else {
                println!("{name} t={bits}: no such modulus");
                continue;
            };
            let (sk, pk) = e.keygen();
            let rlk = e.relin_keygen(&sk);
            let fresh = e.encrypt(&pk, &[3, -5, 7]).unwrap();
            let mut ct = fresh.clone();
            let mut budgets = vec![e.noise_budget_bits(&sk, &fresh).unwrap() as i64];
            let mut sq = fresh.clone();
            let mut squares = vec![budgets[0]];
            for _ in 0..12 {
                ct = e.multiply_relin(&ct, &fresh, &rlk).unwrap();
                let b = e.noise_budget_bits(&sk, &ct).unwrap();
                budgets.push(b as i64);
                if b <= 0.0 {
                    break;
                }
            }
            for _ in 0..12 {
                sq = e.multiply_relin(&sq, &sq, &rlk).unwrap();
                let b = e.noise_budget_bits(&sk, &sq).unwrap();
                squares.push(b as i64);
                if b <= 0.0 {
                    break;
                }
            }
            println!(
                "{name} t={bits} ({}): product chain {budgets:?}, squaring {squares:?}",
                e.plain_modulus()
            );
        }
    }
}
