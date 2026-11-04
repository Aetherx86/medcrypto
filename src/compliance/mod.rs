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

pub struct KeyManager {
    // In-memory / secure enclave key store
    keys: std::collections::HashMap<String, [u8; 32]>,
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
        }
    }

    /// Generates a new ephemeral symmetric key for a patient's data envelope
    pub fn create_key(&mut self, key_id: &str) -> [u8; 32] {
        let key = Aes256Gcm::generate_key(&mut OsRng);
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&key);
        self.keys.insert(key_id.to_string(), key_bytes);
        key_bytes
    }

    /// Encrypts raw data with ephemeral key
    pub fn encrypt(&mut self, record_id: &str, plaintext: &[u8]) -> EncryptedEnvelope {
        let key_id = format!("key:envelope:{}", record_id);
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
        if let Some(mut key) = self.keys.remove(key_id) {
            // Overwrite key memory with zeros / CSPRNG (zeroize)
            key.fill(0);

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
