use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// W3C DID Standard Representation for Healthcare Entities
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DIDDocument {
    pub id: String, // e.g. "did:med:hospital:seoul-national"
    pub role: EntityRole,
    pub public_key_hex: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum EntityRole {
    Patient,
    Physician,
    HospitalNode,
    Researcher,
}

/// Dynamic Consent Object (Controlled by the Patient)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub patient_did: String,
    pub grantee_did: String,         // Doctor or Hospital permitted to access
    pub allowed_scopes: Vec<String>, // e.g., ["VITALS_ZKP", "CARDIAC_FHE_EVAL", "DIABETES_STATISTICS"]
    pub valid_until: DateTime<Utc>,
    pub is_active: bool,
    pub patient_signature: String,
}

/// Smart Contract Registry Simulator (Runs locally and outputs EVM calldata)
pub struct BlockchainConsentRegistry {
    pub did_registry: HashMap<String, DIDDocument>,
    pub consents: HashMap<String, ConsentRecord>, // key: format!("{}:{}", patient, grantee)
    pub state_roots: Vec<String>,
}

impl Default for BlockchainConsentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockchainConsentRegistry {
    pub fn new() -> Self {
        Self {
            did_registry: HashMap::new(),
            consents: HashMap::new(),
            state_roots: Vec::new(),
        }
    }

    pub fn register_did(&mut self, id: &str, role: EntityRole, pubkey: &str) {
        let doc = DIDDocument {
            id: id.to_string(),
            role,
            public_key_hex: pubkey.to_string(),
            created_at: Utc::now(),
        };
        self.did_registry.insert(id.to_string(), doc);
    }

    pub fn grant_consent(
        &mut self,
        patient_did: &str,
        grantee_did: &str,
        scopes: Vec<String>,
        valid_until: DateTime<Utc>,
    ) -> ConsentRecord {
        let key = format!("{}:{}", patient_did, grantee_did);
        let mut hasher = Sha256::new();
        hasher.update(patient_did.as_bytes());
        hasher.update(grantee_did.as_bytes());
        hasher.update(valid_until.to_rfc3339().as_bytes());
        let signature = hex::encode(hasher.finalize());

        let record = ConsentRecord {
            patient_did: patient_did.to_string(),
            grantee_did: grantee_did.to_string(),
            allowed_scopes: scopes,
            valid_until,
            is_active: true,
            patient_signature: signature,
        };

        self.consents.insert(key, record.clone());
        record
    }

    pub fn revoke_consent(&mut self, patient_did: &str, grantee_did: &str) -> bool {
        let key = format!("{}:{}", patient_did, grantee_did);
        if let Some(record) = self.consents.get_mut(&key) {
            record.is_active = false;
            true
        } else {
            false
        }
    }

    pub fn is_authorized(&self, patient_did: &str, grantee_did: &str, scope: &str) -> bool {
        let key = format!("{}:{}", patient_did, grantee_did);
        if let Some(record) = self.consents.get(&key) {
            record.is_active
                && record.valid_until > Utc::now()
                && record.allowed_scopes.iter().any(|s| s == scope)
        } else {
            false
        }
    }

    /// Computes Merkle Root of current commitments (Zero-PHI on-chain)
    pub fn compute_merkle_root(&mut self, leaf_hashes: &[String]) -> String {
        if leaf_hashes.is_empty() {
            return "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        }

        let mut current_level = leaf_hashes.to_vec();
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(chunk[0].as_bytes());
                if chunk.len() > 1 {
                    hasher.update(chunk[1].as_bytes());
                } else {
                    hasher.update(chunk[0].as_bytes());
                }
                next_level.push(hex::encode(hasher.finalize()));
            }
            current_level = next_level;
        }

        let root = current_level[0].clone();
        self.state_roots.push(root.clone());
        root
    }

    /// Generates EVM-compatible ABI function calldata for on-chain audit or verification
    /// Method: recordAudit(bytes32 rootHash, bytes32 proofHash)
    pub fn generate_evm_audit_calldata(root_hash: &str, proof_hash: &str) -> String {
        let selector = hex::encode(function_selector("recordAudit(bytes32,bytes32)"));
        let param1 = format!("{:0>64}", root_hash.trim_start_matches("0x"));
        let param2 = format!("{:0>64}", proof_hash.trim_start_matches("0x"));
        format!("0x{}{}{}", selector, param1, param2)
    }
}

/// The first four bytes of the Keccak-256 of a function signature, which is how the EVM picks a function.
pub fn function_selector(signature: &str) -> [u8; 4] {
    use sha3::Keccak256;
    let digest = Keccak256::digest(signature.as_bytes());
    [digest[0], digest[1], digest[2], digest[3]]
}
