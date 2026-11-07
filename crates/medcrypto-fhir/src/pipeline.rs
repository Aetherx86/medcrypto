//! From parsed resources to a clean table with one row per patient and one column per analyte.

use crate::bundle::ParsedBundle;
use crate::terminology::{analyte_for_loinc, convert_to_canonical, Analyte};
use crate::FhirError;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;

/// What to do with results that are real but extreme.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Winsorization {
    Off,
    /// Clamp to the catalog's clinical limits for the analyte.
    Clinical,
    /// Clamp to the given lower and upper percentiles of this cohort, such as 1 and 99.
    Percentile {
        lower: f64,
        upper: f64,
    },
}

/// What to do when a patient has no usable result for an analyte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Imputation {
    /// Leave it missing, which is the right default for federated statistics.
    None,
    Median,
    Mean,
}

#[derive(Debug, Clone)]
pub struct PipelineOptions {
    pub winsorization: Winsorization,
    pub imputation: Imputation,
    /// The site's secret for pseudonyms. See [`pseudonym`].
    pub pseudonym_key: Vec<u8>,
}

/// The analyte each column holds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Column {
    pub analyte: String,
    pub display: String,
    pub unit: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Row {
    pub pseudo_id: String,
    pub values: Vec<Option<f64>>,
}

/// How a column was cleaned, so that a study can report it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ColumnQuality {
    pub analyte: String,
    /// Usable results, taken before choosing the latest for each patient.
    pub observations: usize,
    pub unknown_unit: usize,
    /// Outside plausible limits, and dropped.
    pub implausible: usize,
    pub winsorized: usize,
    pub missing: usize,
    pub imputed: usize,
}

/// One row per patient, one column per analyte, ready to be packed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CohortTable {
    pub columns: Vec<Column>,
    pub rows: Vec<Row>,
    pub quality: Vec<ColumnQuality>,
}

/// An HMAC of the patient's identifier under a secret the site keeps. A plain hash would not do: anybody
/// could hash every medical record number and match them up.
pub fn pseudonym(key: &[u8], patient_id: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(b"medcrypto-patient-pseudonym-v1\0");
    mac.update(patient_id.as_bytes());
    format!(
        "did:med:patient:{}",
        hex::encode(&mac.finalize().into_bytes()[..16])
    )
}

/// The value at a percentile, interpolating linearly between the two nearest.
pub fn percentile(sorted: &[f64], p: f64) -> f64 {
    let position = (p / 100.0).clamp(0.0, 1.0) * (sorted.len() - 1) as f64;
    let (low, high) = (position.floor() as usize, position.ceil() as usize);
    sorted[low] + (sorted[high] - sorted[low]) * (position - low as f64)
}

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    percentile(&sorted, 50.0)
}

/// Builds the table for the given LOINC codes. Codes for the same analyte become a single column.
pub fn build_table(
    parsed: &ParsedBundle,
    loinc_filter: &[String],
    options: &PipelineOptions,
) -> Result<CohortTable, FhirError> {
    if options.pseudonym_key.len() < 16 {
        return Err(FhirError::InvalidOption(
            "the pseudonym key must be at least 16 bytes".into(),
        ));
    }
    if let Winsorization::Percentile { lower, upper } = options.winsorization {
        if !(0.0..=100.0).contains(&lower) || !(0.0..=100.0).contains(&upper) || lower >= upper {
            return Err(FhirError::InvalidOption(format!(
                "percentiles {lower} and {upper}"
            )));
        }
    }
    let mut analytes: Vec<Analyte> = Vec::new();
    for code in loinc_filter {
        let a = analyte_for_loinc(code).ok_or_else(|| FhirError::UnknownLoinc(code.clone()))?;
        if !analytes.iter().any(|x| x.id == a.id) {
            analytes.push(a);
        }
    }
    if analytes.is_empty() {
        return Err(FhirError::InvalidOption("no LOINC codes given".into()));
    }

    let mut quality: Vec<ColumnQuality> = analytes
        .iter()
        .map(|a| ColumnQuality {
            analyte: a.id.to_string(),
            ..ColumnQuality::default()
        })
        .collect();

    // For each patient and column, the latest usable result. Results with no time sort first, so they
    // only get used if there is nothing else.
    type Latest = (Option<chrono::DateTime<chrono::Utc>>, f64);
    let mut latest: BTreeMap<&str, Vec<Option<Latest>>> = BTreeMap::new();
    for patient in &parsed.patients {
        latest
            .entry(&patient.id)
            .or_insert_with(|| vec![None; analytes.len()]);
    }
    for o in &parsed.observations {
        if !loinc_filter.iter().any(|c| c == &o.loinc) {
            continue;
        }
        // A patient with only unusable results still counts, as a row with missing values.
        let cells = latest
            .entry(&o.patient_id)
            .or_insert_with(|| vec![None; analytes.len()]);
        let analyte = analyte_for_loinc(&o.loinc).expect("the filter was checked");
        let column = analytes
            .iter()
            .position(|a| a.id == analyte.id)
            .expect("added above");
        let Some(value) = convert_to_canonical(&analyte, o.value, &o.unit) else {
            quality[column].unknown_unit += 1;
            continue;
        };
        if value < analyte.plausible.0 || value > analyte.plausible.1 {
            quality[column].implausible += 1;
            continue;
        }
        quality[column].observations += 1;
        let cell = &mut cells[column];
        if cell.as_ref().is_none_or(|(t, _)| o.effective >= *t) {
            *cell = Some((o.effective, value));
        }
    }

    let mut rows: Vec<Row> = latest
        .iter()
        .map(|(id, cells)| Row {
            pseudo_id: pseudonym(&options.pseudonym_key, id),
            values: cells.iter().map(|c| c.map(|(_, v)| v)).collect(),
        })
        .collect();
    // Sorted by pseudonym, so that slot order says nothing about record number or admission order.
    rows.sort_by(|a, b| a.pseudo_id.cmp(&b.pseudo_id));

    for (column, analyte) in analytes.iter().enumerate() {
        let mut present: Vec<f64> = rows.iter().filter_map(|r| r.values[column]).collect();
        present.sort_by(f64::total_cmp);
        let limits = match options.winsorization {
            Winsorization::Off => None,
            Winsorization::Clinical => Some(analyte.clinical),
            Winsorization::Percentile { lower, upper } if !present.is_empty() => {
                Some((percentile(&present, lower), percentile(&present, upper)))
            }
            Winsorization::Percentile { .. } => None,
        };
        if let Some((low, high)) = limits {
            for row in &mut rows {
                if let Some(v) = &mut row.values[column] {
                    let clamped = v.clamp(low, high);
                    if clamped != *v {
                        quality[column].winsorized += 1;
                        *v = clamped;
                    }
                }
            }
        }
        let present: Vec<f64> = rows.iter().filter_map(|r| r.values[column]).collect();
        let missing = rows.len() - present.len();
        quality[column].missing = missing;
        let fill = match options.imputation {
            Imputation::None => None,
            _ if present.is_empty() => None,
            Imputation::Median => Some(median(&present)),
            Imputation::Mean => Some(present.iter().sum::<f64>() / present.len() as f64),
        };
        if let Some(fill) = fill {
            for row in &mut rows {
                if row.values[column].is_none() {
                    row.values[column] = Some(fill);
                    quality[column].imputed += 1;
                }
            }
        }
    }

    Ok(CohortTable {
        columns: analytes
            .iter()
            .map(|a| Column {
                analyte: a.id.to_string(),
                display: a.display.to_string(),
                unit: a.unit.to_string(),
            })
            .collect(),
        rows,
        quality,
    })
}
