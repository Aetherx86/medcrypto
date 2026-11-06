use medcrypto_fhir::bundle::parse_bundle;
use medcrypto_fhir::pipeline::{
    build_table, percentile, pseudonym, Imputation, PipelineOptions, Winsorization,
};
use medcrypto_fhir::FhirError;

const KEY: &[u8] = b"sixteen byte key for the tests!!";

fn options(winsorization: Winsorization, imputation: Imputation) -> PipelineOptions {
    PipelineOptions {
        winsorization,
        imputation,
        pseudonym_key: KEY.to_vec(),
    }
}

fn observation(
    id: &str,
    patient: &str,
    code: &str,
    value: f64,
    unit: &str,
    when: &str,
    status: &str,
) -> serde_json::Value {
    serde_json::json!({"resource": {
        "resourceType": "Observation", "id": id, "status": status,
        "code": {"coding": [{"system": "http://loinc.org", "code": code}]},
        "subject": {"reference": format!("Patient/{patient}")},
        "effectiveDateTime": when,
        "valueQuantity": {"value": value, "unit": unit, "system": "http://unitsofmeasure.org", "code": unit}
    }})
}

fn bundle(entries: Vec<serde_json::Value>) -> String {
    serde_json::json!({"resourceType": "Bundle", "type": "searchset", "entry": entries}).to_string()
}

fn filter(codes: &[&str]) -> Vec<String> {
    codes.iter().map(|c| c.to_string()).collect()
}

#[test]
fn parses_the_three_resources_and_a_blood_pressure_panel() {
    let json = bundle(vec![
        serde_json::json!({"resource": {"resourceType": "Patient", "id": "a", "birthDate": "1970-03-02", "gender": "female"}}),
        serde_json::json!({"resource": {"resourceType": "Practitioner", "id": "x"}}),
        serde_json::json!({"resource": {
            "resourceType": "Condition", "id": "c1",
            "clinicalStatus": {"coding": [{"code": "active"}]},
            "code": {"coding": [{"system": "http://snomed.info/sct", "code": "44054006"}]},
            "subject": {"reference": "Patient/a"}
        }}),
        serde_json::json!({"resource": {
            "resourceType": "Observation", "id": "bp", "status": "final",
            "code": {"coding": [{"system": "http://loinc.org", "code": "85354-9"}]},
            "subject": {"reference": "https://emr.example/fhir/R4/Patient/a"},
            "effectiveDateTime": "2026-01-02T03:04:05Z",
            "component": [
                {"code": {"coding": [{"system": "http://loinc.org", "code": "8480-6"}]},
                 "valueQuantity": {"value": 128, "code": "mm[Hg]"}},
                {"code": {"coding": [{"system": "http://loinc.org", "code": "8462-4"}]},
                 "valueQuantity": {"value": 82, "code": "mm[Hg]"}}
            ]
        }}),
    ]);
    let parsed = parse_bundle(&json).unwrap();
    assert_eq!(parsed.patients.len(), 1);
    assert_eq!(
        parsed.patients[0].birth_date.unwrap().to_string(),
        "1970-03-02"
    );
    assert_eq!(parsed.conditions.len(), 1);
    assert!(parsed.conditions[0].active);
    assert_eq!(parsed.skipped_other, 1);
    let codes: Vec<&str> = parsed
        .observations
        .iter()
        .map(|o| o.loinc.as_str())
        .collect();
    assert_eq!(codes, ["8480-6", "8462-4"]);
    assert_eq!(parsed.observations[0].patient_id, "a");
}

#[test]
fn unreliable_observations_are_left_out_and_counted() {
    let mut censored = observation("c", "a", "2339-0", 40.0, "mg/dL", "2026-01-01", "final");
    censored["resource"]["valueQuantity"]["comparator"] = "<".into();
    let json = bundle(vec![
        observation(
            "e",
            "a",
            "2339-0",
            999.0,
            "mg/dL",
            "2026-01-01",
            "entered-in-error",
        ),
        observation(
            "p",
            "a",
            "2339-0",
            999.0,
            "mg/dL",
            "2026-01-01",
            "preliminary",
        ),
        censored,
        serde_json::json!({"resource": {"resourceType": "Observation", "status": "final",
            "code": {"coding": [{"system": "http://loinc.org", "code": "2339-0"}]},
            "subject": {"reference": "Group/1"}, "valueQuantity": {"value": 5, "code": "mg/dL"}}}),
    ]);
    let parsed = parse_bundle(&json).unwrap();
    assert!(parsed.observations.is_empty());
    assert_eq!(parsed.skipped_status, 2);
    assert_eq!(parsed.skipped_incomplete, 2);
}

#[test]
fn not_a_bundle_is_an_error() {
    assert!(matches!(
        parse_bundle("{"),
        Err(FhirError::InvalidBundle(_))
    ));
    assert!(matches!(
        parse_bundle(r#"{"resourceType":"Patient"}"#),
        Err(FhirError::InvalidBundle(_))
    ));
}

#[test]
fn the_latest_result_wins_and_units_are_unified() {
    let json = bundle(vec![
        observation("1", "a", "2339-0", 200.0, "mg/dL", "2025-01-01", "final"),
        observation("2", "a", "15074-8", 5.5, "mmol/L", "2026-06-01", "final"),
        observation("3", "b", "2339-0", 90.0, "mg/dL", "2026-02-01", "final"),
    ]);
    let table = build_table(
        &parse_bundle(&json).unwrap(),
        &filter(&["2339-0", "15074-8"]),
        &options(Winsorization::Off, Imputation::None),
    )
    .unwrap();
    assert_eq!(
        table.columns.len(),
        1,
        "two codes for one analyte make one column"
    );
    assert_eq!(table.columns[0].unit, "mg/dL");
    assert_eq!(table.rows.len(), 2);
    let a = table
        .rows
        .iter()
        .find(|r| r.pseudo_id == pseudonym(KEY, "a"))
        .unwrap();
    let b = table
        .rows
        .iter()
        .find(|r| r.pseudo_id == pseudonym(KEY, "b"))
        .unwrap();
    assert!((a.values[0].unwrap() - 99.09).abs() < 0.01);
    assert_eq!(b.values[0], Some(90.0));
}

#[test]
fn implausible_values_are_dropped_and_extreme_ones_clamped() {
    let json = bundle(vec![
        observation("1", "a", "8480-6", 900.0, "mm[Hg]", "2026-01-01", "final"),
        observation("2", "b", "8480-6", 280.0, "mm[Hg]", "2026-01-01", "final"),
        observation("3", "c", "8480-6", 120.0, "furlongs", "2026-01-01", "final"),
        observation("4", "d", "8480-6", 120.0, "mm[Hg]", "2026-01-01", "final"),
    ]);
    let table = build_table(
        &parse_bundle(&json).unwrap(),
        &filter(&["8480-6"]),
        &options(Winsorization::Clinical, Imputation::None),
    )
    .unwrap();
    let q = &table.quality[0];
    assert_eq!((q.implausible, q.unknown_unit, q.winsorized), (1, 1, 1));
    let values: Vec<_> = table.rows.iter().filter_map(|r| r.values[0]).collect();
    assert!(values.contains(&250.0) && values.contains(&120.0));
    assert_eq!(q.missing, 2);
}

#[test]
fn percentile_winsorization_and_imputation() {
    let mut entries: Vec<_> = (0..101)
        .map(|i| {
            observation(
                &format!("o{i}"),
                &format!("p{i}"),
                "2339-0",
                50.0 + i as f64,
                "mg/dL",
                "2026-01-01",
                "final",
            )
        })
        .collect();
    entries.push(observation(
        "x",
        "q",
        "4548-4",
        6.0,
        "%",
        "2026-01-01",
        "final",
    ));
    let parsed = parse_bundle(&bundle(entries)).unwrap();
    let table = build_table(
        &parsed,
        &filter(&["2339-0", "4548-4"]),
        &options(
            Winsorization::Percentile {
                lower: 5.0,
                upper: 95.0,
            },
            Imputation::Median,
        ),
    )
    .unwrap();
    let glucose: Vec<f64> = table.rows.iter().map(|r| r.values[0].unwrap()).collect();
    assert_eq!(glucose.iter().cloned().fold(f64::MAX, f64::min), 55.0);
    assert_eq!(glucose.iter().cloned().fold(f64::MIN, f64::max), 145.0);
    assert_eq!(table.quality[0].imputed, 1);
    assert_eq!(table.quality[1].imputed, 101);
    assert!(table.rows.iter().all(|r| r.values[1] == Some(6.0)));

    assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 50.0), 2.5);
}

#[test]
fn pseudonyms_depend_on_the_site_key_and_rows_are_not_in_record_order() {
    assert_ne!(
        pseudonym(KEY, "a"),
        pseudonym(b"another key of 16 bytes or more", "a")
    );
    assert_eq!(pseudonym(KEY, "a"), pseudonym(KEY, "a"));
    let parsed = parse_bundle(&bundle(vec![
        observation("1", "a", "2339-0", 90.0, "mg/dL", "2026-01-01", "final"),
        observation("2", "b", "2339-0", 91.0, "mg/dL", "2026-01-01", "final"),
    ]))
    .unwrap();
    let table = build_table(
        &parsed,
        &filter(&["2339-0"]),
        &options(Winsorization::Off, Imputation::None),
    )
    .unwrap();
    assert!(table
        .rows
        .windows(2)
        .all(|w| w[0].pseudo_id < w[1].pseudo_id));
    assert!(!serde_json::to_string(&table).unwrap().contains("Patient/a"));
}

#[test]
fn bad_options_are_refused() {
    let parsed = medcrypto_fhir::ParsedBundle::default();
    let mut short = options(Winsorization::Off, Imputation::None);
    short.pseudonym_key = b"short".to_vec();
    assert!(build_table(&parsed, &filter(&["2339-0"]), &short).is_err());
    assert_eq!(
        build_table(
            &parsed,
            &filter(&["0000-0"]),
            &options(Winsorization::Off, Imputation::None)
        ),
        Err(FhirError::UnknownLoinc("0000-0".into()))
    );
    assert!(build_table(
        &parsed,
        &filter(&["2339-0"]),
        &options(
            Winsorization::Percentile {
                lower: 99.0,
                upper: 1.0
            },
            Imputation::None
        )
    )
    .is_err());
}
