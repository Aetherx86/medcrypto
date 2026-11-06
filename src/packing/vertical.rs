//! Many patients' results for one analyte in one ciphertext, which is what makes federated statistics cheap.
//!
//! For each analyte and batch there are three ciphertexts: the values, their squares and a presence mask.
//! Summing their slots gives the sum, the sum of squares and the count, which is enough for the mean and
//! the variance, and the count excludes missing results rather than treating them as zeros.
//!
//! Only the sums are ever decrypted in the consortium flow, because [`CKKSEngine::sum_slots`] replaces each
//! slot with the total before decryption. The mapping from slots to patients stays at the hospital that made
//! it, as a separate [`SlotMap`] file.

use super::PackingError;
use medcrypto_fhe::{CKKSEngine, Ciphertext, FheError, GaloisKey, PublicKey};
use medcrypto_fhir::pipeline::{Column, ColumnQuality};
use medcrypto_fhir::CohortTable;
use serde::{Deserialize, Serialize};

pub const CURRENT_FORMAT: &str = "medcrypto-cohort-v1";

/// Up to a batch's worth of patients, for one analyte.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CohortBatch {
    pub values: Ciphertext,
    pub squares: Ciphertext,
    pub presence: Ciphertext,
}

/// All batches of one analyte.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CohortColumn {
    pub column: Column,
    pub batches: Vec<CohortBatch>,
}

/// A vertically packed cohort. It holds no patient identifier and may leave the hospital.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CohortFile {
    pub format: String,
    pub param_id: u64,
    pub batch_size: usize,
    pub columns: Vec<CohortColumn>,
    /// How the data was cleaned, summed over the sites merged so far.
    pub quality: Vec<ColumnQuality>,
}

/// Which pseudonym is in which slot. This one stays inside the hospital: it is what would let somebody
/// holding a decrypted batch tell whose results they are, and what a re-pack after an erasure starts from.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SlotMap {
    pub batch_size: usize,
    pub pseudo_ids: Vec<String>,
}

impl CohortFile {
    /// Transposes rows into columns and encrypts them.
    pub fn pack(
        engine: &CKKSEngine,
        public_key: &PublicKey,
        table: &CohortTable,
        batch_size: usize,
    ) -> Result<(Self, SlotMap), PackingError> {
        let slots = engine.slots();
        if batch_size == 0 || batch_size > slots {
            return Err(PackingError::BatchSize {
                given: batch_size,
                slots,
            });
        }
        if table.rows.is_empty() {
            return Err(PackingError::NoData);
        }
        let mut columns = Vec::with_capacity(table.columns.len());
        for (index, column) in table.columns.iter().enumerate() {
            let mut batches = Vec::new();
            for chunk in table.rows.chunks(batch_size) {
                let values: Vec<f64> = chunk
                    .iter()
                    .map(|r| r.values[index].unwrap_or(0.0))
                    .collect();
                let squares: Vec<f64> = values.iter().map(|v| v * v).collect();
                let presence: Vec<f64> = chunk
                    .iter()
                    .map(|r| if r.values[index].is_some() { 1.0 } else { 0.0 })
                    .collect();
                batches.push(CohortBatch {
                    values: engine.encrypt(public_key, &values)?,
                    squares: engine.encrypt(public_key, &squares)?,
                    presence: engine.encrypt(public_key, &presence)?,
                });
            }
            columns.push(CohortColumn {
                column: column.clone(),
                batches,
            });
        }
        Ok((
            Self {
                format: CURRENT_FORMAT.to_string(),
                param_id: engine.context().param_id(),
                batch_size,
                columns,
                quality: table.quality.clone(),
            },
            SlotMap {
                batch_size,
                pseudo_ids: table.rows.iter().map(|r| r.pseudo_id.clone()).collect(),
            },
        ))
    }

    /// The full check for a file from elsewhere.
    pub fn validate(&self, engine: &CKKSEngine) -> Result<(), PackingError> {
        if self.format != CURRENT_FORMAT {
            return Err(PackingError::Mismatch(format!("format {}", self.format)));
        }
        if self.param_id != engine.context().param_id() {
            return Err(FheError::ParameterMismatch.into());
        }
        for column in &self.columns {
            for batch in &column.batches {
                engine.validate_ciphertext(&batch.values)?;
                engine.validate_ciphertext(&batch.squares)?;
                engine.validate_ciphertext(&batch.presence)?;
            }
        }
        Ok(())
    }

    /// Homomorphic per-analyte totals: `[sum, sum of squares, count]`, each in every slot of one
    /// ciphertext. Whoever computes this needs only public keys.
    pub fn aggregate(
        &self,
        engine: &CKKSEngine,
        galois_key: &GaloisKey,
    ) -> Result<Vec<EncryptedAggregate>, PackingError> {
        self.columns
            .iter()
            .map(|column| {
                let mut sums: Option<[Ciphertext; 3]> = None;
                for batch in &column.batches {
                    let parts = [&batch.values, &batch.squares, &batch.presence];
                    let totals = [
                        engine.sum_slots(parts[0], galois_key)?,
                        engine.sum_slots(parts[1], galois_key)?,
                        engine.sum_slots(parts[2], galois_key)?,
                    ];
                    sums = Some(match sums {
                        None => totals,
                        Some([a, b, c]) => [
                            engine.add(&a, &totals[0])?,
                            engine.add(&b, &totals[1])?,
                            engine.add(&c, &totals[2])?,
                        ],
                    });
                }
                let [sum, sum_of_squares, count] = sums.ok_or_else(|| {
                    PackingError::Mismatch(format!("{} has no batches", column.column.analyte))
                })?;
                Ok(EncryptedAggregate {
                    column: column.column.clone(),
                    sum,
                    sum_of_squares,
                    count,
                })
            })
            .collect()
    }

    /// Puts two sites' cohorts together. No slot arithmetic happens, since patients are not the same people
    /// and adding their slots would be meaningless: this only collects batches.
    pub fn merge(mut self, other: CohortFile) -> Result<CohortFile, PackingError> {
        if self.param_id != other.param_id {
            return Err(FheError::ParameterMismatch.into());
        }
        let names = |f: &CohortFile| -> Vec<String> {
            f.columns.iter().map(|c| c.column.analyte.clone()).collect()
        };
        if names(&self) != names(&other) {
            return Err(PackingError::Mismatch(format!(
                "analytes {:?} and {:?}",
                names(&self),
                names(&other)
            )));
        }
        for (mine, theirs) in self.columns.iter_mut().zip(other.columns) {
            if mine.column.unit != theirs.column.unit {
                return Err(PackingError::Mismatch(format!(
                    "{} is in {} and in {}",
                    mine.column.analyte, mine.column.unit, theirs.column.unit
                )));
            }
            mine.batches.extend(theirs.batches);
        }
        for (mine, theirs) in self.quality.iter_mut().zip(other.quality) {
            mine.observations += theirs.observations;
            mine.unknown_unit += theirs.unknown_unit;
            mine.implausible += theirs.implausible;
            mine.winsorized += theirs.winsorized;
            mine.missing += theirs.missing;
            mine.imputed += theirs.imputed;
        }
        Ok(self)
    }
}

/// The encrypted totals for one analyte. Every slot holds the same total, so decrypting reveals only that.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EncryptedAggregate {
    pub column: Column,
    pub sum: Ciphertext,
    pub sum_of_squares: Ciphertext,
    pub count: Ciphertext,
}

/// The released statistics for one analyte, in its canonical unit.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AnalyteStatistics {
    pub analyte: String,
    pub unit: String,
    pub count: u64,
    pub mean: f64,
    /// The sample variance. Absent with fewer than two results.
    pub variance: Option<f64>,
    pub standard_deviation: Option<f64>,
}

impl AnalyteStatistics {
    /// From decrypted totals. Rounding the count is safe because the noise is far below one half.
    pub fn from_totals(column: &Column, sum: f64, sum_of_squares: f64, count: f64) -> Self {
        let n = count.round().max(0.0);
        let mean = if n > 0.0 { sum / n } else { 0.0 };
        let variance = (n >= 2.0).then(|| ((sum_of_squares - sum * sum / n) / (n - 1.0)).max(0.0));
        Self {
            analyte: column.analyte.clone(),
            unit: column.unit.clone(),
            count: n as u64,
            mean,
            variance,
            standard_deviation: variance.map(f64::sqrt),
        }
    }
}
