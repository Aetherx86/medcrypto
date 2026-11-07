use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// GDPR Article 17 - Right to Erasure via Cryptographic Shredding
/// An encrypted envelope whose key can be irrevocably destroyed to render data permanently unrecoverable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub record_id: String,
    pub ciphertext_payload: Vec<u8>,
    pub nonce: [u8; 12],
    pub key_id: String,
    pub is_shredded: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShreddingCertificate {
    pub record_id: String,
    pub key_id: String,
    pub timestamp: DateTime<Utc>,
    pub regulatory_basis: String, // "GDPR Article 17 - Right to Erasure / Cryptographic Shredding"
    pub audit_signature: String,
}

/// Keys held in memory, and optionally in a file so that erasure works across runs.
///
/// A file is only as strong as the disk it is on. An erasure removes the key from the current file, but
/// cannot reach backups, and a journaling file system or SSD may keep old blocks. A real deployment should
/// keep these keys in an HSM or KMS, whose deletion it can trust.
pub struct KeyManager {
    keys: std::collections::HashMap<String, [u8; 32]>,
    path: Option<std::path::PathBuf>,
}

impl Drop for KeyManager {
    fn drop(&mut self) {
        for key in self.keys.values_mut() {
            zeroize::Zeroize::zeroize(key);
        }
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyManager {
    pub fn new() -> Self {
        Self {
            keys: std::collections::HashMap::new(),
            path: None,
        }
    }

    /// Uses a key file, which is created on the first save if it does not exist yet.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self, String> {
        let path = path.into();
        let mut keys = std::collections::HashMap::new();
        if path.exists() {
            let text = std::fs::read_to_string(&path).map_err(|e| format!("{path:?}: {e}"))?;
            let stored: std::collections::HashMap<String, String> =
                serde_json::from_str(&text).map_err(|e| format!("{path:?}: {e}"))?;
            for (id, value) in stored {
                let bytes: [u8; 32] = hex::decode(&value)
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| format!("{path:?}: the key {id} is not 32 bytes of hex"))?;
                keys.insert(id, bytes);
            }
        }
        Ok(Self {
            keys,
            path: Some(path),
        })
    }

    fn write_file(
        path: &std::path::Path,
        keys: &std::collections::HashMap<String, [u8; 32]>,
    ) -> Result<(), String> {
        let stored: std::collections::HashMap<&String, String> =
            keys.iter().map(|(id, k)| (id, hex::encode(k))).collect();
        let text = serde_json::to_string_pretty(&stored).map_err(|e| e.to_string())?;
        crate::consortium::write_private_file(path, text.as_bytes())
            .map_err(|e| format!("{path:?}: {e}"))
    }

    /// Writes the keys to the file, if there is one. Do this before relying on a new envelope.
    pub fn save(&self) -> Result<(), String> {
        match &self.path {
            Some(path) => Self::write_file(path, &self.keys),
            None => Ok(()),
        }
    }

    /// Whether a key exists for this record.
    pub fn has_key_for_record(&self, record_id: &str) -> bool {
        self.keys.contains_key(&Self::key_id_for(record_id))
    }

    pub fn key_id_for(record_id: &str) -> String {
        format!("key:envelope:{record_id}")
    }

    /// The symmetric key for an id, generated if it does not exist yet. An existing key has to be kept:
    /// replacing it would make earlier envelopes for the same record undecryptable.
    pub fn create_key(&mut self, key_id: &str) -> [u8; 32] {
        *self.keys.entry(key_id.to_string()).or_insert_with(|| {
            let key = Aes256Gcm::generate_key(&mut OsRng);
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&key);
            key_bytes
        })
    }

    /// Encrypts raw data with ephemeral key
    pub fn encrypt(&mut self, record_id: &str, plaintext: &[u8]) -> EncryptedEnvelope {
        let key_id = Self::key_id_for(record_id);
        let key_bytes = self.create_key(&key_id);

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let mut nonce_bytes = [0u8; 12];
        rand::Rng::fill(&mut rand::thread_rng(), &mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext_payload = cipher
            .encrypt(nonce, plaintext)
            .expect("encryption failure");

        EncryptedEnvelope {
            record_id: record_id.to_string(),
            ciphertext_payload,
            nonce: nonce_bytes,
            key_id,
            is_shredded: false,
            created_at: Utc::now(),
        }
    }

    /// Decrypts data envelope if key has not been shredded
    pub fn decrypt(&self, envelope: &EncryptedEnvelope) -> Result<Vec<u8>, String> {
        if envelope.is_shredded {
            return Err(
                "Cryptographic Shredding Error: Key has been destroyed (GDPR Art. 17)".to_string(),
            );
        }

        let key_bytes = self
            .keys
            .get(&envelope.key_id)
            .ok_or_else(|| "Key not found or already shredded".to_string())?;

        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&envelope.nonce);

        cipher
            .decrypt(nonce, envelope.ciphertext_payload.as_ref())
            .map_err(|e| format!("Decryption failed: {:?}", e))
    }

    /// Irrevocably destroys (shreds) the key, satisfying GDPR Article 17 without modifying the immutable blockchain
    pub fn shred_key(
        &mut self,
        key_id: &str,
        record_id: &str,
    ) -> Result<ShreddingCertificate, String> {
        if !self.keys.contains_key(key_id) {
            return Err("Key already destroyed or non-existent".to_string());
        }
        // The file goes first, so that a failure cannot report an erasure which did not happen.
        if let Some(path) = &self.path {
            let mut remaining = self.keys.clone();
            remaining.remove(key_id);
            let written = Self::write_file(path, &remaining);
            for key in remaining.values_mut() {
                zeroize::Zeroize::zeroize(key);
            }
            written?;
        }
        if let Some(mut key) = self.keys.remove(key_id) {
            zeroize::Zeroize::zeroize(&mut key);

            let now = Utc::now();
            let mut hasher = Sha256::new();
            hasher.update(record_id.as_bytes());
            hasher.update(key_id.as_bytes());
            hasher.update(now.to_rfc3339().as_bytes());
            let audit_signature = hex::encode(hasher.finalize());

            Ok(ShreddingCertificate {
                record_id: record_id.to_string(),
                key_id: key_id.to_string(),
                timestamp: now,
                regulatory_basis: "GDPR Article 17 - Right to Erasure / Cryptographic Shredding"
                    .to_string(),
                audit_signature,
            })
        } else {
            Err("Key already destroyed or non-existent".to_string())
        }
    }
}

/// HIPAA §164.528 - Accounting of Disclosures: Tamper-Proof Audit Trail
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub index: u64,
    pub timestamp: DateTime<Utc>,
    pub requestor_did: String,
    pub hospital_did: String,
    pub patient_pseudo_id: String,
    pub purpose: String, // e.g. "EMERGENCY_ACCESS", "MULTI_CENTER_STUDY", "CLINICAL_TRIAL_SCREENING"
    pub operation: String, // "ZKP_VERIFY", "FHE_EVALUATE", "CONSENT_REVOKE"
    pub proof_hash: String,
    pub previous_hash: String,
    pub entry_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditLedger {
    pub entries: Vec<AuditEntry>,
}

impl Default for AuditLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLedger {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn append(
        &mut self,
        requestor_did: &str,
        hospital_did: &str,
        patient_pseudo_id: &str,
        purpose: &str,
        operation: &str,
        proof_hash: &str,
    ) -> &AuditEntry {
        let index = self.entries.len() as u64;
        let prev_hash = if let Some(last) = self.entries.last() {
            last.entry_hash.clone()
        } else {
            "0000000000000000000000000000000000000000000000000000000000000000".to_string()
        };

        let now = Utc::now();
        let mut hasher = Sha256::new();
        hasher.update(index.to_be_bytes());
        hasher.update(now.to_rfc3339().as_bytes());
        hasher.update(requestor_did.as_bytes());
        hasher.update(hospital_did.as_bytes());
        hasher.update(patient_pseudo_id.as_bytes());
        hasher.update(purpose.as_bytes());
        hasher.update(operation.as_bytes());
        hasher.update(proof_hash.as_bytes());
        hasher.update(prev_hash.as_bytes());
        let entry_hash = hex::encode(hasher.finalize());

        let entry = AuditEntry {
            index,
            timestamp: now,
            requestor_did: requestor_did.to_string(),
            hospital_did: hospital_did.to_string(),
            patient_pseudo_id: patient_pseudo_id.to_string(),
            purpose: purpose.to_string(),
            operation: operation.to_string(),
            proof_hash: proof_hash.to_string(),
            previous_hash: prev_hash,
            entry_hash,
        };

        self.entries.push(entry);
        self.entries.last().unwrap()
    }

    /// Verifies the cryptographic integrity of the entire audit trail
    pub fn verify_integrity(&self) -> bool {
        for (i, entry) in self.entries.iter().enumerate() {
            let prev_hash = if i == 0 {
                "0000000000000000000000000000000000000000000000000000000000000000"
            } else {
                &self.entries[i - 1].entry_hash
            };

            if entry.previous_hash != prev_hash {
                return false;
            }

            let mut hasher = Sha256::new();
            hasher.update(entry.index.to_be_bytes());
            hasher.update(entry.timestamp.to_rfc3339().as_bytes());
            hasher.update(entry.requestor_did.as_bytes());
            hasher.update(entry.hospital_did.as_bytes());
            hasher.update(entry.patient_pseudo_id.as_bytes());
            hasher.update(entry.purpose.as_bytes());
            hasher.update(entry.operation.as_bytes());
            hasher.update(entry.proof_hash.as_bytes());
            hasher.update(entry.previous_hash.as_bytes());
            let computed = hex::encode(hasher.finalize());

            if entry.entry_hash != computed {
                return false;
            }
        }
        true
    }
}
