//! HL7 FHIR R4 ingestion with no external scripts.
//!
//! The path from a hospital's EMR to a table ready for encryption:
//!
//! 1. [`client`] pages through a FHIR server, or a bundle comes from a file.
//! 2. [`bundle`] parses `Patient`, `Observation` and `Condition` resources, tolerating what it does not know.
//! 3. [`terminology`] maps LOINC codes to analytes and converts UCUM units to one canonical unit for each.
//! 4. [`pipeline`] picks the latest result per patient, handles outliers and missing values, and pseudonymizes.
//!
//! This crate knows nothing of encryption. Its output is a plain [`pipeline::CohortTable`].

#![forbid(unsafe_code)]

pub mod bundle;
#[cfg(feature = "http")]
pub mod client;
pub mod pipeline;
pub mod terminology;

pub use bundle::{parse_bundle, ParsedBundle};
pub use pipeline::{build_table, CohortTable, Imputation, PipelineOptions, Winsorization};
pub use terminology::{analyte_for_loinc, convert_to_canonical, Analyte};

/// Everything that can stop ingestion.
#[derive(Debug, Clone, PartialEq)]
pub enum FhirError {
    /// Not JSON, or not a FHIR Bundle.
    InvalidBundle(String),
    /// A filter names a LOINC code that is not in the catalog, so it could not be normalized.
    UnknownLoinc(String),
    /// A unit with no known conversion to the analyte's canonical unit.
    UnknownUnit { analyte: String, unit: String },
    /// A refused or failed request to the FHIR server.
    Http(String),
    /// A setting that makes no sense.
    InvalidOption(String),
}

impl std::fmt::Display for FhirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBundle(m) => write!(f, "invalid FHIR bundle: {m}"),
            Self::UnknownLoinc(c) => write!(f, "LOINC code {c} is not in the catalog"),
            Self::UnknownUnit { analyte, unit } => {
                write!(f, "no conversion from '{unit}' for {analyte}")
            }
            Self::Http(m) => write!(f, "FHIR request failed: {m}"),
            Self::InvalidOption(m) => write!(f, "invalid option: {m}"),
        }
    }
}

impl std::error::Error for FhirError {}
