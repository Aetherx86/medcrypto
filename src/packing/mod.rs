//! Two ways of packing clinical data into ciphertexts, for two different needs.
//!
//! | | Horizontal: [`RecordEnvelope`] | Vertical: [`CohortFile`] |
//! |---|---|---|
//! | One ciphertext holds | Many analytes of one patient | One analyte of up to 4096 or 8192 patients |
//! | Good for | Scoring one patient, and erasure on request | Statistics over a whole cohort |
//! | Erasure | Destroy that patient's key | Rebuild the batch without them |

pub mod horizontal;
pub mod vertical;

pub use horizontal::RecordEnvelope;
pub use vertical::{
    AnalyteStatistics, BfvAggregate, BfvCohortFile, CohortBatch, CohortFile, EncryptedAggregate,
    SlotMap, BFV_FORMAT, CURRENT_FORMAT,
};

/// What can go wrong while packing.
#[derive(Debug)]
pub enum PackingError {
    Fhe(medcrypto_fhe::FheError),
    /// A batch size that is zero or more than the slots available.
    BatchSize {
        given: usize,
        slots: usize,
    },
    /// Cohorts that cannot be combined.
    Mismatch(String),
    Envelope(String),
    NoData,
}

impl std::fmt::Display for PackingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fhe(e) => write!(f, "{e}"),
            Self::BatchSize { given, slots } => {
                write!(
                    f,
                    "a batch size of {given} does not fit: the limit is {slots} slots"
                )
            }
            Self::Mismatch(m) => write!(f, "cohorts do not match: {m}"),
            Self::Envelope(m) => write!(f, "envelope: {m}"),
            Self::NoData => write!(f, "there are no patient records to pack"),
        }
    }
}

impl std::error::Error for PackingError {}

impl From<medcrypto_fhe::FheError> for PackingError {
    fn from(e: medcrypto_fhe::FheError) -> Self {
        Self::Fhe(e)
    }
}
