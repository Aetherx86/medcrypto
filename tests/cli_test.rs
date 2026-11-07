//! The commands exactly as the documentation shows them, through the real binary.

use std::path::Path;
use std::process::{Command, Output};

fn medcrypto(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_medcrypto"))
        .current_dir(cwd)
        .env("AETHER_AUTHOR_OVERRIDE", "1")
        .args(args)
        .output()
        .unwrap()
}

fn succeed(cwd: &Path, args: &[&str]) -> String {
    let output = medcrypto(cwd, args);
    assert!(
        output.status.success(),
        "{args:?}:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn sample_bundle(count: usize) -> String {
    let mut entries = Vec::new();
    for i in 0..count {
        entries.push(serde_json::json!({"resource": {"resourceType": "Patient", "id": format!("p{i}"), "birthDate": "1970-01-01"}}));
        for (code, value, unit) in [
            ("8480-6", 120.0 + i as f64, "mm[Hg]"),
            ("4548-4", 5.0 + (i % 10) as f64 * 0.1, "%"),
            ("15074-8", 5.5, "mmol/L"),
        ] {
            entries.push(serde_json::json!({"resource": {
                "resourceType": "Observation", "id": format!("{code}-{i}"), "status": "final",
                "code": {"coding": [{"system": "http://loinc.org", "code": code}]},
                "subject": {"reference": format!("Patient/p{i}")},
                "effectiveDateTime": "2026-01-01",
                "valueQuantity": {"value": value, "code": unit}
            }}));
        }
    }
    serde_json::json!({"resourceType": "Bundle", "type": "searchset", "entry": entries}).to_string()
}

#[test]
fn batch_pack_and_cohort_stats_on_patient_records() {
    let directory = tempfile::tempdir().unwrap();
    let cwd = directory.path();
    let records = cwd.join("patient_records");
    std::fs::create_dir(&records).unwrap();
    for i in 0..15 {
        let record = medcrypto::models::PatientRecord::mock_patient(
            &format!("P{i}"),
            50.0,
            5.5,
            100.0,
            120.0 + i as f64,
        );
        std::fs::write(
            records.join(format!("{i}.json")),
            serde_json::to_string(&record).unwrap(),
        )
        .unwrap();
    }
    succeed(
        cwd,
        &[
            "batch-pack",
            "--input-dir",
            "./patient_records/",
            "--batch-size",
            "4096",
            "--output",
            "./cohort_vertical_ct.json",
        ],
    );
    assert!(cwd.join("cohort_vertical_ct.json").exists());
    assert!(cwd.join("cohort_vertical_ct.json.slots").exists());
    let keys = cwd.join("cohort_vertical_ct.json.keys");
    assert!(keys.join("secret-key.json").exists());

    // The slot map and the identifiers stay out of the shareable file.
    let shared = std::fs::read_to_string(cwd.join("cohort_vertical_ct.json")).unwrap();
    assert!(!shared.contains("did:med:patient"));

    let out = succeed(
        cwd,
        &[
            "cohort-stats",
            "--input",
            "cohort_vertical_ct.json",
            "--keys",
            "cohort_vertical_ct.json.keys",
        ],
    );
    assert!(out.contains("127.000"), "{out}");
    assert!(out.contains("15"), "{out}");

    // The same cohort, with a minimum cell size above its size.
    let out = succeed(
        cwd,
        &[
            "cohort-stats",
            "--input",
            "cohort_vertical_ct.json",
            "--keys",
            "cohort_vertical_ct.json.keys",
            "--min-cell-size",
            "16",
        ],
    );
    assert!(
        out.contains("withheld") && !out.contains("127.000"),
        "{out}"
    );
}

#[test]
fn ingest_fhir_from_a_bundle_in_both_modes() {
    let directory = tempfile::tempdir().unwrap();
    let cwd = directory.path();
    std::fs::write(cwd.join("bundle.json"), sample_bundle(20)).unwrap();
    succeed(cwd, &["keygen", "--output-dir", "keys"]);
    let out = succeed(
        cwd,
        &[
            "ingest-fhir",
            "--bundle",
            "bundle.json",
            "--loinc-filter",
            "8480-6,4548-4,15074-8",
            "--mode",
            "vertical",
            "--public-key",
            "keys/public-key.json",
            "--output",
            "./encrypted_cohort.json",
        ],
    );
    assert!(out.contains("systolic_bp"), "{out}");
    let out = succeed(
        cwd,
        &[
            "cohort-stats",
            "--input",
            "encrypted_cohort.json",
            "--keys",
            "keys",
        ],
    );
    assert!(out.contains("129.500"), "{out}");
    // 5.5 mmol/L of glucose comes out in mg/dL.
    assert!(out.contains("99.086"), "{out}");

    succeed(
        cwd,
        &[
            "ingest-fhir",
            "--bundle",
            "bundle.json",
            "--loinc-filter",
            "8480-6",
            "--mode",
            "horizontal",
            "--public-key",
            "keys/public-key.json",
            "--output",
            "envelopes.json",
        ],
    );
    let envelopes: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(cwd.join("envelopes.json")).unwrap())
            .unwrap();
    assert_eq!(envelopes.as_array().unwrap().len(), 20);
    let store = std::fs::read_to_string(cwd.join("medcrypto-keystore.json")).unwrap();
    assert_eq!(store.matches("key:envelope:").count(), 20);
}

#[test]
fn ingest_fhir_with_the_documented_endpoint_form() {
    // A refused request shows that it reached the point of talking to the server, without needing one.
    let directory = tempfile::tempdir().unwrap();
    let output = medcrypto(
        directory.path(),
        &[
            "ingest-fhir",
            "--endpoint",
            "http://emr.hospital.org/fhir/R4",
            "--loinc-filter",
            "8480-6,4548-4,2339-0",
            "--mode",
            "vertical",
            "--output",
            "./encrypted_cohort.json",
        ],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("needs https"));
}

#[test]
fn prove_verify_and_a_tampered_proof() {
    let directory = tempfile::tempdir().unwrap();
    let cwd = directory.path();
    succeed(
        cwd,
        &[
            "prove",
            "--metric",
            "hba1c",
            "--value",
            "58",
            "--threshold",
            "65",
            "--output",
            "proof.json",
        ],
    );
    let out = succeed(cwd, &["verify", "--proof-file", "proof.json"]);
    assert!(out.contains("VERIFIED"));

    let mut proof: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(cwd.join("proof.json")).unwrap()).unwrap();
    proof["threshold"] = 60.into();
    std::fs::write(cwd.join("forged.json"), proof.to_string()).unwrap();
    assert!(!medcrypto(cwd, &["verify", "--proof-file", "forged.json"])
        .status
        .success());

    // A false statement gets no proof, and the exit status says so.
    assert!(
        !medcrypto(cwd, &["prove", "--value", "82", "--threshold", "65"])
            .status
            .success()
    );
    let out = medcrypto(
        cwd,
        &[
            "prove",
            "--value",
            "30",
            "--threshold",
            "18",
            "--lower-bound",
        ],
    );
    assert!(out.status.success());

    // Production refuses the Pedersen backend, even when asked for it.
    let refused = medcrypto(
        cwd,
        &[
            "prove",
            "--value",
            "58",
            "--threshold",
            "65",
            "--profile",
            "production",
        ],
    );
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("post-quantum"));
}

#[test]
fn shredding_really_destroys_the_key_across_processes() {
    let directory = tempfile::tempdir().unwrap();
    let cwd = directory.path();
    succeed(cwd, &["keygen", "--output-dir", "keys"]);
    succeed(
        cwd,
        &[
            "pack-record",
            "--record-id",
            "P-8001",
            "--values",
            "52,5.8,105",
            "--features",
            "age,hba1c,glucose",
            "--public-key",
            "keys/public-key.json",
            "--output",
            "record.json",
        ],
    );
    let out = succeed(
        cwd,
        &[
            "open-record",
            "--input",
            "record.json",
            "--secret-key",
            "keys/secret-key.json",
        ],
    );
    assert!(out.contains("hba1c: 5.8000"), "{out}");

    succeed(cwd, &["shred", "--record-id", "P-8001"]);
    let blocked = medcrypto(
        cwd,
        &[
            "open-record",
            "--input",
            "record.json",
            "--secret-key",
            "keys/secret-key.json",
        ],
    );
    assert!(!blocked.status.success());

    // There is no key left to shred, and no certificate gets issued for one.
    assert!(!medcrypto(cwd, &["shred", "--record-id", "P-8001"])
        .status
        .success());
    assert!(!medcrypto(cwd, &["shred", "--record-id", "never-existed"])
        .status
        .success());
}

#[test]
fn hybrid_signatures_through_the_command_line() {
    let directory = tempfile::tempdir().unwrap();
    let cwd = directory.path();
    succeed(cwd, &["sign-keygen", "--output-dir", "sign"]);
    std::fs::write(cwd.join("result.json"), b"{\"count\": 1500}").unwrap();
    succeed(
        cwd,
        &[
            "sign",
            "--key",
            "sign/signing-key.hex",
            "--input",
            "result.json",
            "--output",
            "result.sig",
        ],
    );
    let verify = [
        "verify-signature",
        "--public-key",
        "sign/signing-public.json",
        "--input",
        "result.json",
        "--signature",
        "result.sig",
    ];
    assert!(succeed(cwd, &verify).contains("VERIFIED"));

    std::fs::write(cwd.join("result.json"), b"{\"count\": 1501}").unwrap();
    assert!(!medcrypto(cwd, &verify).status.success());
    std::fs::write(cwd.join("result.json"), b"{\"count\": 1500}").unwrap();

    // Removing the post-quantum half does not leave a valid signature.
    let mut signature: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(cwd.join("result.sig")).unwrap()).unwrap();
    signature["ml_dsa_65"] = "".into();
    std::fs::write(cwd.join("result.sig"), signature.to_string()).unwrap();
    assert!(!medcrypto(cwd, &verify).status.success());
}

#[test]
fn encrypt_decrypt_and_quantum_audit() {
    let directory = tempfile::tempdir().unwrap();
    let cwd = directory.path();
    succeed(
        cwd,
        &["encrypt", "--patient-id", "P-1", "--output", "ct.json"],
    );
    let out = succeed(
        cwd,
        &[
            "decrypt",
            "--input",
            "ct.json",
            "--secret-key",
            "ct.json.keys/secret-key.json",
        ],
    );
    assert!(out.starts_with("54.0000"), "{out}");
    let out = succeed(cwd, &["quantum-audit"]);
    assert!(
        out.contains("202 bits") && out.contains("128 bits against quantum attacks"),
        "{out}"
    );
    let out = succeed(cwd, &["quantum-audit", "--poly-degree", "16384"]);
    assert!(out.contains("411 bits"), "{out}");
    assert!(!medcrypto(cwd, &["quantum-audit", "--poly-degree", "128"])
        .status
        .success());
}

#[test]
fn consortium_init_writes_what_a_daemon_needs() {
    let directory = tempfile::tempdir().unwrap();
    let cwd = directory.path();
    succeed(cwd, &[
        "consortium-init", "--out", "consortium", "--threshold", "2",
        "--nodes", "hospital-a=https://127.0.0.1:7443,hospital-b=https://127.0.0.1:7444,hospital-c=https://127.0.0.1:7445",
    ]);
    for path in [
        "ca.pem",
        "roster.json",
        "studies.json",
        "consent.json",
        "hospital-b/node.json",
        "hospital-b/cert.pem",
        "hospital-b/key.pem",
    ] {
        assert!(cwd.join("consortium").join(path).exists(), "{path}");
    }
    assert!(!medcrypto(
        cwd,
        &[
            "consortium-init",
            "--out",
            "x",
            "--threshold",
            "5",
            "--nodes",
            "a=https://h:1"
        ]
    )
    .status
    .success());
    assert!(!medcrypto(
        cwd,
        &[
            "consortium-init",
            "--out",
            "x",
            "--threshold",
            "1",
            "--nodes",
            "Bad_Name=https://h:1"
        ]
    )
    .status
    .success());
}
