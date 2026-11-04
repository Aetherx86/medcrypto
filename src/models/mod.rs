use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Standard Clinical Vitals & Lab Measurements for Cross-Hospital Sharing
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PatientRecord {
    pub patient_id: String,
    pub pseudo_id: String, // Anonymized DID / Hash
    pub age: f64,
    pub systolic_bp: f64,     // mmHg
    pub diastolic_bp: f64,    // mmHg
    pub fasting_glucose: f64, // mg/dL
    pub hba1c: f64,           // %
    pub bmi: f64,             // kg/m^2
    pub egfr: f64,            // mL/min/1.73m^2 (Kidney function)
    pub ldl_cholesterol: f64, // mg/dL
    pub recorded_at: DateTime<Utc>,
}

impl PatientRecord {
    /// Creates a mock test patient record
    pub fn mock_patient(id: &str, age: f64, hba1c: f64, glucose: f64, systolic: f64) -> Self {
        use sha2::{Digest, Sha256};
        let hash = hex::encode(Sha256::digest(id.as_bytes()));
        Self {
            patient_id: id.to_string(),
            pseudo_id: format!("did:med:patient:{}", &hash[..8]),
            age,
            systolic_bp: systolic,
            diastolic_bp: 80.0,
            fasting_glucose: glucose,
            hba1c,
            bmi: 24.5,
            egfr: 92.0,
            ldl_cholesterol: 110.0,
            recorded_at: Utc::now(),
        }
    }

    /// Converts clinical metrics into a normalized vector for CKKS FHE and ZKP
    /// Order: [age, systolic_bp, diastolic_bp, fasting_glucose, hba1c, bmi, egfr, ldl_cholesterol]
    pub fn to_vector(&self) -> Vec<f64> {
        vec![
            self.age,
            self.systolic_bp,
            self.diastolic_bp,
            self.fasting_glucose,
            self.hba1c,
            self.bmi,
            self.egfr,
            self.ldl_cholesterol,
        ]
    }

    pub fn feature_names() -> &'static [&'static str] {
        &[
            "Age (years)",
            "Systolic BP (mmHg)",
            "Diastolic BP (mmHg)",
            "Fasting Glucose (mg/dL)",
            "HbA1c (%)",
            "BMI (kg/m²)",
            "eGFR (mL/min)",
            "LDL Cholesterol (mg/dL)",
        ]
    }
}

/// HL7 FHIR Observation representation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FHIRObservation {
    pub resource_type: String,
    pub id: String,
    pub status: String,
    pub code_text: String,
    pub subject_reference: String,
    pub value_quantity: f64,
    pub unit: String,
    pub effective_date_time: DateTime<Utc>,
}
