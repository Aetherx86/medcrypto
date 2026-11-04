use medcrypto::fhe::CKKSEngine;

#[test]
fn test_ckks_vector_multi_slot_accuracy() {
    let engine = CKKSEngine::default();
    let (sk, pk) = engine.keygen();

    // 8 continuous clinical variables:
    // [Age, Systolic BP, Diastolic BP, Glucose, HbA1c, BMI, eGFR, LDL]
    let vitals = vec![58.0, 134.5, 84.0, 105.0, 5.9, 26.2, 88.0, 125.0];

    let ct = engine.encrypt(&pk, &vitals);
    let decrypted = engine.decrypt(&sk, &ct);

    for (i, (&orig, &dec)) in vitals.iter().zip(decrypted.iter()).enumerate() {
        let diff = (orig - dec).abs();
        assert!(
            diff < 0.1,
            "Slot {} exceeded approximate error bound: orig={}, dec={}, diff={}",
            i,
            orig,
            dec,
            diff
        );
    }
}

#[test]
fn test_ckks_multi_hospital_federated_average() {
    let engine = CKKSEngine::default();
    let (sk, pk) = engine.keygen();

    // 3 hospital cohorts for mean glucose study
    let hospital_1 = vec![90.0, 120.0];
    let hospital_2 = vec![110.0, 130.0];
    let hospital_3 = vec![100.0, 140.0];

    let ct1 = engine.encrypt(&pk, &hospital_1);
    let ct2 = engine.encrypt(&pk, &hospital_2);
    let ct3 = engine.encrypt(&pk, &hospital_3);

    // Compute average on encrypted vectors
    let ct_avg = engine.federated_average(&[ct1, ct2, ct3]);
    let decrypted = engine.decrypt(&sk, &ct_avg);

    // Expected: [ (90+110+100)/3, (120+130+140)/3 ] = [100.0, 130.0]
    assert!((decrypted[0] - 100.0).abs() < 0.2);
    assert!((decrypted[1] - 130.0).abs() < 0.2);
}
