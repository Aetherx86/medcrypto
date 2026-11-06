//! One patient's vector in one ciphertext, wrapped under a key that belongs to that patient alone.
//!
//! The AES-GCM layer on the outside is what makes erasure possible: destroying the patient's key leaves
//! nothing to decrypt, even for someone who holds the FHE secret key and a copy of the envelope.

use super::PackingError;
use crate::compliance::{EncryptedEnvelope, KeyManager};
use medcrypto_fhe::{from_bytes, to_bytes, CKKSEngine, Ciphertext, PublicKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordEnvelope {
    pub record_id: String,
    /// The meaning of each slot.
    pub features: Vec<String>,
    pub envelope: EncryptedEnvelope,
}

impl RecordEnvelope {
    pub fn seal(
        engine: &CKKSEngine,
        public_key: &PublicKey,
        keys: &mut KeyManager,
        record_id: &str,
        features: Vec<String>,
        values: &[f64],
    ) -> Result<Self, PackingError> {
        if features.len() != values.len() {
            return Err(PackingError::Mismatch(format!(
                "{} feature names for {} values",
                features.len(),
                values.len()
            )));
        }
        let ciphertext = engine.encrypt(public_key, values)?;
        Ok(Self {
            record_id: record_id.to_string(),
            features,
            envelope: keys.encrypt(record_id, &to_bytes(&ciphertext)?),
        })
    }

    /// Removes the outer layer, if the patient's key still exists.
    pub fn open(&self, engine: &CKKSEngine, keys: &KeyManager) -> Result<Ciphertext, PackingError> {
        let bytes = keys
            .decrypt(&self.envelope)
            .map_err(PackingError::Envelope)?;
        let ciphertext: Ciphertext = from_bytes(&bytes)?;
        engine.validate_ciphertext(&ciphertext)?;
        Ok(ciphertext)
    }
}
