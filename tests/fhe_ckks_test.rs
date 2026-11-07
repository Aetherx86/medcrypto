use medcrypto::fhe::CKKSEngine;

#[test]
fn test_ckks_vector_multi_slot_accuracy() {
    let engine = CKKSEngine::default();
    let (sk, pk) = engine.keygen();

    // 8 continuous clinical variables:
    // [Age, Systolic BP, Diastolic BP, Glucose, HbA1c, BMI, eGFR, LDL]
    let vitals = vec![58.0, 134.5, 84.0, 105.0, 5.9, 26.2, 88.0, 125.0];

    let ct = engine.encrypt(&pk, &vitals).unwrap();
    let decrypted = engine.decrypt(&sk, &ct).unwrap();

    for (i, (&orig, &dec)) in vitals.iter().zip(decrypted.iter()).enumerate() {
        assert!((orig - dec).abs() < 1e-5, "slot {i}: {orig} and {dec}");
    }
}

#[test]
fn test_ckks_multi_hospital_federated_average() {
    let engine = CKKSEngine::default();
    let (sk, pk) = engine.keygen();

    let ct1 = engine.encrypt(&pk, &[90.0, 120.0]).unwrap();
    let ct2 = engine.encrypt(&pk, &[110.0, 130.0]).unwrap();
    let ct3 = engine.encrypt(&pk, &[100.0, 140.0]).unwrap();

    let ct_avg = engine.federated_average(&[ct1, ct2, ct3]).unwrap();
    let decrypted = engine.decrypt(&sk, &ct_avg).unwrap();

    assert!((decrypted[0] - 100.0).abs() < 1e-5);
    assert!((decrypted[1] - 130.0).abs() < 1e-5);
}
