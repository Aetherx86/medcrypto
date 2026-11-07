//! Zero-knowledge range predicates behind one interface, with the proof system chosen at run time.
//!
//! - [`PedersenBackend`]: a real range proof over ristretto255. Fast, needs nothing external, and sound as
//!   long as discrete logarithms are hard, which a large quantum computer would end.
//! - [`HashBasedBackend`]: a built-in range proof resting only on SHA-256, which is post-quantum. Slower to
//!   check and much larger, at about 1.4 MB a proof.
//! - [`StarkCoprocessorBackend`]: hands the statement to an external hash-based prover. The prover
//!   has to declare that it is post-quantum and zero-knowledge, or this backend refuses to use it.

pub mod hash_based;
pub mod pedersen;
pub mod stark;

pub use hash_based::HashBasedBackend;
pub use pedersen::{PedersenBackend, RangeProof};
pub use stark::{ProverCapabilities, StarkCoprocessorBackend};

use serde::{Deserialize, Serialize};

/// What can stop a proof from being made.
#[derive(Clone, Debug, PartialEq)]
pub enum CryptoError {
    /// The value does not satisfy the statement, so an honest proof cannot exist.
    PredicateUnsatisfied,
    /// A range with its minimum above its maximum.
    InvalidRange { min: u64, max: u64 },
    /// The external prover is missing, failed, or does not offer what is required.
    Backend(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PredicateUnsatisfied => write!(f, "the value does not satisfy the predicate"),
            Self::InvalidRange { min, max } => write!(f, "invalid range [{min}, {max}]"),
            Self::Backend(m) => write!(f, "proof backend: {m}"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// A proof from any backend. The value itself appears nowhere in it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ZkProof {
    /// Which proof system made this, so that it cannot be checked by the wrong one.
    pub backend: String,
    pub min: u64,
    pub max: u64,
    /// The binding commitment to the value, as hexadecimal.
    pub commitment: String,
    /// The backend's own proof bytes, as hexadecimal.
    pub payload: String,
}

/// The adapter that the rest of the system uses.
pub trait ZkPredicateProver {
    /// Proves `min <= val <= max` for a value that stays hidden.
    fn prove_range(&self, val: u64, min: u64, max: u64) -> Result<ZkProof, CryptoError>;
    /// Whether a proof holds for exactly this range. Anything malformed or unexpected is simply `false`.
    fn verify_range(&self, proof: &ZkProof, min: u64, max: u64) -> bool;
}

/// The size of a lower-bound statement's range: `value >= threshold` is proved as being within this much.
pub const LOWER_BOUND_SPAN: u64 = (1 << 32) - 1;

/// A clinical threshold claim: `value <= threshold`, or `value >= threshold`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThresholdProof {
    pub threshold: u64,
    pub is_upper_bound: bool,
    pub proof: ZkProof,
    /// A fingerprint for audit logs.
    pub proof_hash: String,
}

impl ThresholdProof {
    pub fn commitment(&self) -> &str {
        &self.proof.commitment
    }
}

/// Several criteria for one patient, each proved separately.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClinicalEligibilityProof {
    pub patient_pseudo_id: String,
    pub hospital_did: String,
    pub criteria_name: String,
    pub proofs: Vec<ThresholdProof>,
    pub timestamp: i64,
}

fn threshold_range(threshold: u64, is_upper_bound: bool) -> (u64, u64) {
    if is_upper_bound {
        (0, threshold)
    } else {
        (threshold, threshold.saturating_add(LOWER_BOUND_SPAN))
    }
}

/// Threshold statements on top of the Pedersen backend, which is what the demo and the GUI use.
pub struct ZKPEngine;

impl ZKPEngine {
    pub fn prove_threshold(
        value: u64,
        threshold: u64,
        is_upper_bound: bool,
    ) -> Result<ThresholdProof, CryptoError> {
        let (min, max) = threshold_range(threshold, is_upper_bound);
        Self::wrap(
            PedersenBackend.prove_range(value, min, max)?,
            threshold,
            is_upper_bound,
        )
    }

    pub fn prove_threshold_with(
        backend: &dyn ZkPredicateProver,
        value: u64,
        threshold: u64,
        is_upper_bound: bool,
    ) -> Result<ThresholdProof, CryptoError> {
        let (min, max) = threshold_range(threshold, is_upper_bound);
        Self::wrap(
            backend.prove_range(value, min, max)?,
            threshold,
            is_upper_bound,
        )
    }

    fn wrap(
        proof: ZkProof,
        threshold: u64,
        is_upper_bound: bool,
    ) -> Result<ThresholdProof, CryptoError> {
        use sha2::{Digest, Sha256};
        let proof_hash = hex::encode(Sha256::digest(proof.payload.as_bytes()));
        Ok(ThresholdProof {
            threshold,
            is_upper_bound,
            proof,
            proof_hash,
        })
    }

    pub fn verify_threshold(proof: &ThresholdProof) -> bool {
        Self::verify_threshold_with(&PedersenBackend, proof)
    }

    pub fn verify_threshold_with(backend: &dyn ZkPredicateProver, proof: &ThresholdProof) -> bool {
        let (min, max) = threshold_range(proof.threshold, proof.is_upper_bound);
        backend.verify_range(&proof.proof, min, max)
    }

    /// All criteria have to hold.
    pub fn verify_clinical_trial_eligibility(eligibility: &ClinicalEligibilityProof) -> bool {
        !eligibility.proofs.is_empty() && eligibility.proofs.iter().all(Self::verify_threshold)
    }
}

/// The deployment profile, which decides what a proof backend has to offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// Hospital-internal development and testing: the Pedersen backend is fine.
    Development,
    /// Regulatory audit and production: a post-quantum backend is required.
    Production,
}

/// Which proof system to use.
pub enum ProofChoice {
    Pedersen,
    /// Hash-based, built in, and needing no external program.
    HashBased,
    Stark(StarkCoprocessorBackend),
}

/// Refuses to give a production deployment a backend that a quantum computer could break.
pub fn backend_for_profile(
    profile: Profile,
    choice: ProofChoice,
) -> Result<Box<dyn ZkPredicateProver>, CryptoError> {
    match (profile, choice) {
        (_, ProofChoice::Stark(backend)) => {
            backend.require_capabilities()?;
            Ok(Box::new(backend))
        }
        (_, ProofChoice::HashBased) => Ok(Box::new(HashBasedBackend)),
        (Profile::Development, ProofChoice::Pedersen) => Ok(Box::new(PedersenBackend)),
        (Profile::Production, ProofChoice::Pedersen) => Err(CryptoError::Backend(
            "the production profile refuses the Pedersen backend, which is not post-quantum: use the hash backend"
                .into(),
        )),
    }
}
