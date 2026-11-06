// Writes a FHIR R4 Bundle of made-up patients to standard output, for trying things out. All of it is random.
//   cargo run --example make_sample_bundle -- PATIENTS SEED > bundle.json

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let patients: usize = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(100);
    let seed: u64 = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(1);
    let mut rng = StdRng::seed_from_u64(seed);
    let mut entries = Vec::new();
    for i in 0..patients {
        let id = format!("s{seed}-{i}");
        entries.push(serde_json::json!({"resource": {
            "resourceType": "Patient", "id": id,
            "birthDate": format!("{}-01-15", rng.gen_range(1940..2005)),
        }}));
        let mut add = |code: &str, value: f64, unit: &str| {
            entries.push(serde_json::json!({"resource": {
                "resourceType": "Observation", "id": format!("{id}-{code}"), "status": "final",
                "code": {"coding": [{"system": "http://loinc.org", "code": code}]},
                "subject": {"reference": format!("Patient/{id}")},
                "effectiveDateTime": "2026-06-01",
                "valueQuantity": {"value": value, "system": "http://unitsofmeasure.org", "code": unit},
            }}));
        };
        add("8480-6", rng.gen_range(100.0..170.0), "mm[Hg]");
        add("4548-4", rng.gen_range(4.8..9.5), "%");
        // Half of the sites' glucose results are in mg/dL and half in mmol/L, as in real multi-site data.
        if i % 2 == 0 {
            add("2339-0", rng.gen_range(70.0..200.0), "mg/dL");
        } else {
            add("15074-8", rng.gen_range(3.9..11.0), "mmol/L");
        }
    }
    let bundle =
        serde_json::json!({"resourceType": "Bundle", "type": "searchset", "entry": entries});
    println!("{bundle}");
}
