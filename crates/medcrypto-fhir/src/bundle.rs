//! Parsing FHIR R4 Bundles. Unknown resources and fields are skipped, because real servers send many.

use crate::FhirError;
use chrono::{DateTime, NaiveDate, Utc};
use serde_json::Value;

const LOINC_SYSTEM: &str = "http://loinc.org";

#[derive(Debug, Clone, PartialEq)]
pub struct FhirPatient {
    pub id: String,
    pub birth_date: Option<NaiveDate>,
    pub gender: Option<String>,
}

/// One measurement. A blood pressure panel with two components comes out as two of these.
#[derive(Debug, Clone, PartialEq)]
pub struct FhirObservation {
    pub id: String,
    pub patient_id: String,
    pub loinc: String,
    pub value: f64,
    pub unit: String,
    pub effective: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FhirCondition {
    pub id: String,
    pub patient_id: String,
    /// `(system, code)` for each coding.
    pub codes: Vec<(String, String)>,
    pub active: bool,
}

/// What came out of a bundle, and a count of what was left out and why.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParsedBundle {
    pub patients: Vec<FhirPatient>,
    pub observations: Vec<FhirObservation>,
    pub conditions: Vec<FhirCondition>,
    /// Observations marked as entered in error, cancelled or not yet resulted.
    pub skipped_status: usize,
    /// Observations with no numeric quantity, no LOINC code or no subject.
    pub skipped_incomplete: usize,
    /// Resource types other than the three understood here.
    pub skipped_other: usize,
    /// The URL of the next page, if the server sent one.
    pub next_link: Option<String>,
}

impl ParsedBundle {
    pub fn merge(&mut self, other: ParsedBundle) {
        self.patients.extend(other.patients);
        self.observations.extend(other.observations);
        self.conditions.extend(other.conditions);
        self.skipped_status += other.skipped_status;
        self.skipped_incomplete += other.skipped_incomplete;
        self.skipped_other += other.skipped_other;
        self.next_link = other.next_link;
    }
}

fn subject_id(resource: &Value) -> Option<String> {
    let reference = resource.pointer("/subject/reference")?.as_str()?;
    // "Patient/123", or an absolute URL ending in it. Other subjects, like Group, are not patients.
    let mut parts = reference.rsplit('/');
    let id = parts.next()?;
    match parts.next() {
        Some("Patient") if !id.is_empty() => Some(id.to_string()),
        _ => None,
    }
}

fn effective_time(resource: &Value) -> Option<DateTime<Utc>> {
    let text = resource
        .get("effectiveDateTime")
        .or_else(|| resource.pointer("/effectivePeriod/end"))
        .or_else(|| resource.pointer("/effectivePeriod/start"))
        .or_else(|| resource.get("effectiveInstant"))
        .or_else(|| resource.get("issued"))?
        .as_str()?;
    parse_fhir_time(text)
}

/// FHIR allows partial dates such as `2024` and `2024-03`, which are taken as the start of that period.
pub fn parse_fhir_time(text: &str) -> Option<DateTime<Utc>> {
    if let Ok(t) = DateTime::parse_from_rfc3339(text) {
        return Some(t.with_timezone(&Utc));
    }
    let date = match text.len() {
        4 => NaiveDate::from_ymd_opt(text.parse().ok()?, 1, 1)?,
        7 => NaiveDate::parse_from_str(&format!("{text}-01"), "%Y-%m-%d").ok()?,
        10 => NaiveDate::parse_from_str(text, "%Y-%m-%d").ok()?,
        _ => return None,
    };
    Some(date.and_hms_opt(0, 0, 0)?.and_utc())
}

fn loinc_codes(code: &Value) -> Vec<String> {
    code.get("coding")
        .and_then(Value::as_array)
        .map(|codings| {
            codings
                .iter()
                .filter(|c| c.get("system").and_then(Value::as_str) == Some(LOINC_SYSTEM))
                .filter_map(|c| c.get("code").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The value and the UCUM unit. The coded unit is preferred, since the display text is free form.
fn quantity(holder: &Value) -> Option<(f64, String)> {
    let q = holder.get("valueQuantity")?;
    let value = q.get("value")?.as_f64()?;
    // A comparator such as "<" means the real value is not this number.
    if q.get("comparator").is_some() || !value.is_finite() {
        return None;
    }
    let unit = q
        .get("code")
        .or_else(|| q.get("unit"))
        .and_then(Value::as_str)?;
    Some((value, unit.to_string()))
}

fn parse_observation(resource: &Value, out: &mut ParsedBundle) {
    match resource.get("status").and_then(Value::as_str) {
        Some("final" | "amended" | "corrected") => {}
        _ => {
            out.skipped_status += 1;
            return;
        }
    }
    let id = resource
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let Some(patient_id) = subject_id(resource) else {
        out.skipped_incomplete += 1;
        return;
    };
    let effective = effective_time(resource);
    let before = out.observations.len();
    let mut push = |loinc: String, (value, unit): (f64, String)| {
        out.observations.push(FhirObservation {
            id: id.clone(),
            patient_id: patient_id.clone(),
            loinc,
            value,
            unit,
            effective,
        });
    };
    if let (Some(code), Some(q)) = (resource.get("code"), quantity(resource)) {
        for loinc in loinc_codes(code) {
            push(loinc, q.clone());
        }
    }
    if let Some(components) = resource.get("component").and_then(Value::as_array) {
        for component in components {
            if let (Some(code), Some(q)) = (component.get("code"), quantity(component)) {
                for loinc in loinc_codes(code) {
                    push(loinc, q.clone());
                }
            }
        }
    }
    if out.observations.len() == before {
        out.skipped_incomplete += 1;
    }
}

fn parse_condition(resource: &Value) -> Option<FhirCondition> {
    let codes = resource
        .pointer("/code/coding")?
        .as_array()?
        .iter()
        .filter_map(|c| {
            Some((
                c.get("system")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                c.get("code")?.as_str()?.to_string(),
            ))
        })
        .collect();
    let active = resource
        .pointer("/clinicalStatus/coding")
        .and_then(Value::as_array)
        .is_none_or(|c| {
            c.iter()
                .any(|x| x.get("code").and_then(Value::as_str) == Some("active"))
        });
    Some(FhirCondition {
        id: resource
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        patient_id: subject_id(resource)?,
        codes,
        active,
    })
}

/// Parses a `Bundle` of any type, as a JSON string.
pub fn parse_bundle(json: &str) -> Result<ParsedBundle, FhirError> {
    let root: Value =
        serde_json::from_str(json).map_err(|e| FhirError::InvalidBundle(e.to_string()))?;
    if root.get("resourceType").and_then(Value::as_str) != Some("Bundle") {
        return Err(FhirError::InvalidBundle(
            "the resourceType is not Bundle".into(),
        ));
    }
    let mut out = ParsedBundle {
        next_link: root
            .get("link")
            .and_then(Value::as_array)
            .and_then(|links| {
                links
                    .iter()
                    .find(|l| l.get("relation").and_then(Value::as_str) == Some("next"))
            })
            .and_then(|l| l.get("url"))
            .and_then(Value::as_str)
            .map(str::to_string),
        ..ParsedBundle::default()
    };
    let empty = Vec::new();
    for entry in root
        .get("entry")
        .and_then(Value::as_array)
        .unwrap_or(&empty)
    {
        let Some(resource) = entry.get("resource") else {
            continue;
        };
        match resource.get("resourceType").and_then(Value::as_str) {
            Some("Patient") => {
                if let Some(id) = resource.get("id").and_then(Value::as_str) {
                    out.patients.push(FhirPatient {
                        id: id.to_string(),
                        birth_date: resource
                            .get("birthDate")
                            .and_then(Value::as_str)
                            .and_then(parse_fhir_time)
                            .map(|t| t.date_naive()),
                        gender: resource
                            .get("gender")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                    });
                }
            }
            Some("Observation") => parse_observation(resource, &mut out),
            Some("Condition") => {
                if let Some(c) = parse_condition(resource) {
                    out.conditions.push(c);
                }
            }
            _ => out.skipped_other += 1,
        }
    }
    Ok(out)
}
