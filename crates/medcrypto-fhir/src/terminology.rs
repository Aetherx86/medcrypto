//! LOINC codes and UCUM units.
//!
//! Each analyte has one canonical unit. Conversions between mass and molar concentration depend on the
//! molecule, so they are per analyte rather than a general unit table. The limits are of two kinds:
//! `plausible` values outside which a result is taken to be an error, such as a unit recorded wrongly, and
//! `clinical` values to which a real but extreme result can be clamped. They are engineering defaults
//! for data cleaning, not clinical reference ranges, and a deployment should review them.

/// A measurable quantity with a canonical unit.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Analyte {
    pub id: &'static str,
    pub display: &'static str,
    pub unit: &'static str,
    pub plausible: (f64, f64),
    pub clinical: (f64, f64),
    /// `(unit as written, multiply by, add)`, in UCUM with the common spellings folded by [`normalize_unit`].
    conversions: &'static [(&'static str, f64, f64)],
}

const SAME_PRESSURE: &[(&str, f64, f64)] = &[
    ("mm[hg]", 1.0, 0.0),
    ("mmhg", 1.0, 0.0),
    ("kpa", 7.50062, 0.0),
];
// NGSP % = 0.09148 * IFCC mmol/mol + 2.152, the published master equation.
const HBA1C: &[(&str, f64, f64)] = &[
    ("%", 1.0, 0.0),
    ("{percent}", 1.0, 0.0),
    ("mmol/mol", 0.09148, 2.152),
];
// Glucose has a molar mass of 180.156 g/mol.
const GLUCOSE: &[(&str, f64, f64)] = &[
    ("mg/dl", 1.0, 0.0),
    ("mmol/l", 18.0156, 0.0),
    ("g/l", 100.0, 0.0),
];
// Cholesterol has a molar mass of 386.65 g/mol.
const CHOLESTEROL: &[(&str, f64, f64)] = &[
    ("mg/dl", 1.0, 0.0),
    ("mmol/l", 38.665, 0.0),
    ("g/l", 100.0, 0.0),
];
// Triglycerides are conventionally taken as triolein, 885.7 g/mol.
const TRIGLYCERIDE: &[(&str, f64, f64)] = &[
    ("mg/dl", 1.0, 0.0),
    ("mmol/l", 88.57, 0.0),
    ("g/l", 100.0, 0.0),
];
// Creatinine has a molar mass of 113.12 g/mol.
const CREATININE: &[(&str, f64, f64)] = &[
    ("mg/dl", 1.0, 0.0),
    ("umol/l", 0.011312, 0.0),
    ("mmol/l", 11.312, 0.0),
];
const EGFR: &[(&str, f64, f64)] = &[
    ("ml/min/{1.73_m2}", 1.0, 0.0),
    ("ml/min/1.73m2", 1.0, 0.0),
    ("ml/min", 1.0, 0.0),
];
const BMI: &[(&str, f64, f64)] = &[("kg/m2", 1.0, 0.0)];
const WEIGHT: &[(&str, f64, f64)] = &[
    ("kg", 1.0, 0.0),
    ("g", 0.001, 0.0),
    ("[lb_av]", 0.45359237, 0.0),
    ("lb", 0.45359237, 0.0),
];
const HEIGHT: &[(&str, f64, f64)] = &[
    ("cm", 1.0, 0.0),
    ("m", 100.0, 0.0),
    ("[in_i]", 2.54, 0.0),
    ("in", 2.54, 0.0),
];
const RATE: &[(&str, f64, f64)] = &[
    ("/min", 1.0, 0.0),
    ("{beats}/min", 1.0, 0.0),
    ("{beat}/min", 1.0, 0.0),
    ("bpm", 1.0, 0.0),
];
const TEMPERATURE: &[(&str, f64, f64)] = &[
    ("cel", 1.0, 0.0),
    ("c", 1.0, 0.0),
    ("[degf]", 5.0 / 9.0, -160.0 / 9.0),
    ("f", 5.0 / 9.0, -160.0 / 9.0),
];

const fn analyte(
    id: &'static str,
    display: &'static str,
    unit: &'static str,
    plausible: (f64, f64),
    clinical: (f64, f64),
    conversions: &'static [(&'static str, f64, f64)],
) -> Analyte {
    Analyte {
        id,
        display,
        unit,
        plausible,
        clinical,
        conversions,
    }
}

pub const SYSTOLIC_BP: Analyte = analyte(
    "systolic_bp",
    "Systolic blood pressure",
    "mm[Hg]",
    (30.0, 320.0),
    (70.0, 250.0),
    SAME_PRESSURE,
);
pub const DIASTOLIC_BP: Analyte = analyte(
    "diastolic_bp",
    "Diastolic blood pressure",
    "mm[Hg]",
    (10.0, 220.0),
    (40.0, 150.0),
    SAME_PRESSURE,
);
pub const HBA1C_A: Analyte = analyte(
    "hba1c",
    "Hemoglobin A1c (NGSP)",
    "%",
    (2.0, 25.0),
    (3.5, 18.0),
    HBA1C,
);
pub const GLUCOSE_A: Analyte = analyte(
    "glucose",
    "Glucose",
    "mg/dL",
    (5.0, 2500.0),
    (40.0, 600.0),
    GLUCOSE,
);
pub const FASTING_GLUCOSE: Analyte = analyte(
    "fasting_glucose",
    "Fasting glucose",
    "mg/dL",
    (5.0, 2500.0),
    (40.0, 500.0),
    GLUCOSE,
);
pub const TOTAL_CHOLESTEROL: Analyte = analyte(
    "total_cholesterol",
    "Total cholesterol",
    "mg/dL",
    (20.0, 1500.0),
    (80.0, 500.0),
    CHOLESTEROL,
);
pub const LDL: Analyte = analyte(
    "ldl_cholesterol",
    "LDL cholesterol",
    "mg/dL",
    (5.0, 1000.0),
    (20.0, 400.0),
    CHOLESTEROL,
);
pub const HDL: Analyte = analyte(
    "hdl_cholesterol",
    "HDL cholesterol",
    "mg/dL",
    (3.0, 300.0),
    (10.0, 150.0),
    CHOLESTEROL,
);
pub const TRIGLYCERIDES: Analyte = analyte(
    "triglycerides",
    "Triglycerides",
    "mg/dL",
    (5.0, 15000.0),
    (30.0, 1500.0),
    TRIGLYCERIDE,
);
pub const CREATININE_A: Analyte = analyte(
    "creatinine",
    "Creatinine",
    "mg/dL",
    (0.05, 40.0),
    (0.2, 20.0),
    CREATININE,
);
pub const EGFR_A: Analyte = analyte(
    "egfr",
    "Estimated GFR",
    "mL/min/{1.73_m2}",
    (1.0, 250.0),
    (3.0, 180.0),
    EGFR,
);
pub const BMI_A: Analyte = analyte(
    "bmi",
    "Body mass index",
    "kg/m2",
    (5.0, 150.0),
    (12.0, 70.0),
    BMI,
);
pub const WEIGHT_A: Analyte = analyte(
    "body_weight",
    "Body weight",
    "kg",
    (0.3, 700.0),
    (2.0, 300.0),
    WEIGHT,
);
pub const HEIGHT_A: Analyte = analyte(
    "body_height",
    "Body height",
    "cm",
    (20.0, 280.0),
    (40.0, 220.0),
    HEIGHT,
);
pub const HEART_RATE: Analyte = analyte(
    "heart_rate",
    "Heart rate",
    "/min",
    (5.0, 350.0),
    (25.0, 220.0),
    RATE,
);
pub const TEMPERATURE_A: Analyte = analyte(
    "body_temperature",
    "Body temperature",
    "Cel",
    (15.0, 46.0),
    (30.0, 43.0),
    TEMPERATURE,
);

/// The catalog, from LOINC code to what it measures.
pub const LOINC: &[(&str, Analyte)] = &[
    ("8480-6", SYSTOLIC_BP),
    ("8462-4", DIASTOLIC_BP),
    ("4548-4", HBA1C_A),
    ("17856-6", HBA1C_A),
    ("59261-8", HBA1C_A),
    ("2339-0", GLUCOSE_A),
    ("2345-7", GLUCOSE_A),
    ("15074-8", GLUCOSE_A),
    ("14749-6", GLUCOSE_A),
    ("1558-6", FASTING_GLUCOSE),
    ("14771-0", FASTING_GLUCOSE),
    ("2093-3", TOTAL_CHOLESTEROL),
    ("14647-2", TOTAL_CHOLESTEROL),
    ("2089-1", LDL),
    ("13457-7", LDL),
    ("18262-6", LDL),
    ("22748-8", LDL),
    ("2085-9", HDL),
    ("14646-4", HDL),
    ("2571-8", TRIGLYCERIDES),
    ("14927-8", TRIGLYCERIDES),
    ("2160-0", CREATININE_A),
    ("14682-9", CREATININE_A),
    ("33914-3", EGFR_A),
    ("48642-3", EGFR_A),
    ("48643-1", EGFR_A),
    ("62238-1", EGFR_A),
    ("98979-8", EGFR_A),
    ("39156-5", BMI_A),
    ("29463-7", WEIGHT_A),
    ("3141-9", WEIGHT_A),
    ("8302-2", HEIGHT_A),
    ("8306-3", HEIGHT_A),
    ("8867-4", HEART_RATE),
    ("8310-5", TEMPERATURE_A),
];

pub fn analyte_for_loinc(code: &str) -> Option<Analyte> {
    LOINC.iter().find(|(c, _)| *c == code).map(|(_, a)| *a)
}

/// Folds case, whitespace and the micro sign so that the spellings seen in real data compare equal.
pub fn normalize_unit(unit: &str) -> String {
    unit.trim()
        .replace(['µ', 'μ'], "u")
        .replace("mcmol", "umol")
        .replace(' ', "")
        .to_lowercase()
}

/// The value in the analyte's canonical unit, or `None` if there is no known conversion. Guessing here
/// would silently corrupt a study, by a factor of 18 for glucose, so an unknown unit is never assumed.
pub fn convert_to_canonical(analyte: &Analyte, value: f64, unit: &str) -> Option<f64> {
    let normalized = normalize_unit(unit);
    analyte
        .conversions
        .iter()
        .find(|(u, _, _)| *u == normalized)
        .map(|(_, factor, offset)| value * factor + offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn near(a: f64, b: f64) {
        assert!((a - b).abs() < 0.01, "{a} vs {b}");
    }

    #[test]
    fn molar_and_mass_units_convert_per_analyte() {
        near(
            convert_to_canonical(&GLUCOSE_A, 5.5, "mmol/L").unwrap(),
            99.09,
        );
        near(convert_to_canonical(&LDL, 2.6, "mmol/L").unwrap(), 100.53);
        near(
            convert_to_canonical(&TRIGLYCERIDES, 1.7, "mmol/L").unwrap(),
            150.57,
        );
        near(
            convert_to_canonical(&CREATININE_A, 88.4, "µmol/L").unwrap(),
            1.0,
        );
        near(
            convert_to_canonical(&CREATININE_A, 88.4, "umol/L").unwrap(),
            1.0,
        );
    }

    #[test]
    fn hba1c_uses_the_ngsp_ifcc_master_equation() {
        near(
            convert_to_canonical(&HBA1C_A, 48.0, "mmol/mol").unwrap(),
            6.54,
        );
        near(convert_to_canonical(&HBA1C_A, 6.5, "%").unwrap(), 6.5);
    }

    #[test]
    fn other_units_and_spellings() {
        near(
            convert_to_canonical(&SYSTOLIC_BP, 120.0, "mm[Hg]").unwrap(),
            120.0,
        );
        near(
            convert_to_canonical(&SYSTOLIC_BP, 120.0, "mmHg").unwrap(),
            120.0,
        );
        near(
            convert_to_canonical(&SYSTOLIC_BP, 16.0, "kPa").unwrap(),
            120.01,
        );
        near(
            convert_to_canonical(&TEMPERATURE_A, 98.6, "[degF]").unwrap(),
            37.0,
        );
        near(
            convert_to_canonical(&WEIGHT_A, 154.0, "[lb_av]").unwrap(),
            69.85,
        );
        near(
            convert_to_canonical(&HEIGHT_A, 70.0, "[in_i]").unwrap(),
            177.8,
        );
    }

    #[test]
    fn an_unknown_unit_is_never_guessed() {
        assert_eq!(convert_to_canonical(&GLUCOSE_A, 100.0, "mg/L"), None);
        assert_eq!(convert_to_canonical(&GLUCOSE_A, 100.0, ""), None);
        assert_eq!(convert_to_canonical(&HBA1C_A, 6.0, "mg/dL"), None);
    }
}
