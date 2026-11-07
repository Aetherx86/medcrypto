use medcrypto::compliance::KeyManager;
use medcrypto::fhe::CKKSEngine;
use medcrypto::fhir::pipeline::{Column, ColumnQuality, Row};
use medcrypto::fhir::CohortTable;
use medcrypto::packing::vertical::AnalyteStatistics;
use medcrypto::packing::{CohortFile, PackingError, RecordEnvelope};

fn column(name: &str) -> Column {
    Column {
        analyte: name.into(),
        display: name.into(),
        unit: "mg/dL".into(),
    }
}

fn table(values: &[Option<f64>]) -> CohortTable {
    CohortTable {
        columns: vec![column("glucose")],
        rows: values
            .iter()
            .enumerate()
            .map(|(i, v)| Row {
                pseudo_id: format!("p{i}"),
                values: vec![*v],
            })
            .collect(),
        quality: vec![ColumnQuality {
            analyte: "glucose".into(),
            observations: values.len(),
            ..Default::default()
        }],
    }
}

fn statistics(
    engine: &CKKSEngine,
    keys: &(medcrypto::fhe::SecretKey, medcrypto::fhe::GaloisKey),
    cohort: &CohortFile,
) -> AnalyteStatistics {
    let aggregate = &cohort.aggregate(engine, &keys.1).unwrap()[0];
    let open = |ct| engine.decrypt(&keys.0, ct).unwrap()[0];
    AnalyteStatistics::from_totals(
        &aggregate.column,
        open(&aggregate.sum),
        open(&aggregate.sum_of_squares),
        open(&aggregate.count),
    )
}

fn keys(
    engine: &CKKSEngine,
) -> (
    medcrypto::fhe::SecretKey,
    medcrypto::fhe::GaloisKey,
    medcrypto::fhe::PublicKey,
) {
    let (secret, public) = engine.keygen();
    let galois = engine.galois_keygen(&secret, &engine.sum_rotation_steps());
    (secret, galois, public)
}

#[test]
fn vertical_statistics_match_plaintext_and_skip_missing_values() {
    let engine = CKKSEngine::default();
    let (secret, galois, public) = keys(&engine);
    let values: Vec<Option<f64>> = (0..500)
        .map(|i| {
            if i % 5 == 0 {
                None
            } else {
                Some(80.0 + (i % 40) as f64)
            }
        })
        .collect();
    let (cohort, slots) = CohortFile::pack(&engine, &public, &table(&values), 4096).unwrap();
    cohort.validate(&engine).unwrap();
    assert_eq!(slots.pseudo_ids.len(), 500);
    assert!(!serde_json::to_string(&cohort.columns[0].column)
        .unwrap()
        .contains("p0"));

    let present: Vec<f64> = values.iter().flatten().copied().collect();
    let n = present.len() as f64;
    let mean = present.iter().sum::<f64>() / n;
    let variance = present.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);

    let stats = statistics(&engine, &(secret, galois), &cohort);
    assert_eq!(stats.count, 400, "missing values must not count as zeros");
    assert!((stats.mean - mean).abs() < 1e-3);
    assert!((stats.variance.unwrap() - variance).abs() < 1e-2);
    assert_eq!(stats.unit, "mg/dL");
}

#[test]
fn a_cohort_larger_than_a_ciphertext_spans_batches() {
    let engine = CKKSEngine::default();
    let (secret, galois, public) = keys(&engine);
    let values: Vec<Option<f64>> = (0..250).map(|i| Some(i as f64)).collect();
    let (cohort, _) = CohortFile::pack(&engine, &public, &table(&values), 100).unwrap();
    assert_eq!(cohort.columns[0].batches.len(), 3);
    let stats = statistics(&engine, &(secret, galois), &cohort);
    assert_eq!(stats.count, 250);
    assert!((stats.mean - 124.5).abs() < 1e-3);
}

#[test]
fn merging_sites_collects_batches_and_refuses_what_does_not_match() {
    let engine = CKKSEngine::default();
    let (secret, galois, public) = keys(&engine);
    let (a, _) =
        CohortFile::pack(&engine, &public, &table(&[Some(100.0), Some(200.0)]), 4096).unwrap();
    let (b, _) = CohortFile::pack(&engine, &public, &table(&[Some(400.0)]), 4096).unwrap();
    let merged = a.clone().merge(b).unwrap();
    assert_eq!(merged.quality[0].observations, 3);
    let stats = statistics(&engine, &(secret, galois), &merged);
    assert_eq!(stats.count, 3);
    assert!((stats.mean - 700.0 / 3.0).abs() < 1e-3);

    let mut other = table(&[Some(1.0)]);
    other.columns[0].analyte = "hba1c".into();
    let (c, _) = CohortFile::pack(&engine, &public, &other, 4096).unwrap();
    assert!(matches!(a.clone().merge(c), Err(PackingError::Mismatch(_))));

    let mut other_unit = table(&[Some(1.0)]);
    other_unit.columns[0].unit = "mmol/L".into();
    let (d, _) = CohortFile::pack(&engine, &public, &other_unit, 4096).unwrap();
    assert!(matches!(a.merge(d), Err(PackingError::Mismatch(_))));
}

#[test]
fn packing_rejects_impossible_requests() {
    let engine = CKKSEngine::default();
    let (_, public) = engine.keygen();
    let one = table(&[Some(1.0)]);
    assert!(matches!(
        CohortFile::pack(&engine, &public, &one, 0),
        Err(PackingError::BatchSize { .. })
    ));
    assert!(matches!(
        CohortFile::pack(&engine, &public, &one, 4097),
        Err(PackingError::BatchSize { .. })
    ));
    assert!(matches!(
        CohortFile::pack(&engine, &public, &table(&[]), 4096),
        Err(PackingError::NoData)
    ));
}

#[test]
fn horizontal_envelope_opens_until_the_key_is_shredded() {
    let engine = CKKSEngine::default();
    let (secret, public) = engine.keygen();
    let directory = tempfile::tempdir().unwrap();
    let store = directory.path().join("keys.json");

    let mut keys = KeyManager::open(&store).unwrap();
    let names = vec!["hba1c".to_string(), "glucose".to_string()];
    let envelope = RecordEnvelope::seal(
        &engine,
        &public,
        &mut keys,
        "p1",
        names.clone(),
        &[5.9, 108.0],
    )
    .unwrap();
    let second = RecordEnvelope::seal(
        &engine,
        &public,
        &mut keys,
        "p1",
        names.clone(),
        &[6.0, 110.0],
    )
    .unwrap();
    let other =
        RecordEnvelope::seal(&engine, &public, &mut keys, "p2", names, &[7.0, 150.0]).unwrap();
    keys.save().unwrap();
    assert_ne!(envelope.envelope.nonce, second.envelope.nonce);

    // In a later run, from the file, an earlier envelope for the same record still opens.
    let mut keys = KeyManager::open(&store).unwrap();
    let opened = envelope.open(&engine, &keys).unwrap();
    assert!((engine.decrypt(&secret, &opened).unwrap()[0] - 5.9).abs() < 1e-5);
    assert!(second.open(&engine, &keys).is_ok());

    keys.shred_key(&envelope.envelope.key_id, "p1").unwrap();
    assert!(envelope.open(&engine, &keys).is_err());
    assert!(
        second.open(&engine, &keys).is_err(),
        "both envelopes used the record's key"
    );
    assert!(
        other.open(&engine, &keys).is_ok(),
        "other patients are unaffected"
    );

    // The erasure holds in a new process, and the key is gone from the file.
    let keys = KeyManager::open(&store).unwrap();
    assert!(!keys.has_key_for_record("p1"));
    assert!(envelope.open(&engine, &keys).is_err());
    assert!(!std::fs::read_to_string(&store)
        .unwrap()
        .contains("key:envelope:p1"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&store).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn shredding_twice_is_an_error_rather_than_a_second_certificate() {
    let mut keys = KeyManager::new();
    let envelope = keys.encrypt("p1", b"data");
    keys.shred_key(&envelope.key_id, "p1").unwrap();
    assert!(keys.shred_key(&envelope.key_id, "p1").is_err());
}
