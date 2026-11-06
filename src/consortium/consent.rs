//! Where the daemon learns about consent. A source that cannot answer returns an error, and the caller
//! treats that the same as no: nothing is shared on the strength of a failed lookup.

use crate::blockchain::function_selector;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::path::PathBuf;
use std::time::Duration;

pub trait ConsentSource: Send {
    /// Whether this epoch of a study is approved to run.
    fn study_active(&mut self, study_id: &str, epoch: u64) -> Result<bool, String>;
    /// Whether this patient's consent covers this scope right now.
    fn patient_authorized(&mut self, pseudo_id: &str, scope: &str) -> Result<bool, String>;
}

/// One patient's consent for one scope.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConsentEntry {
    pub patient: String,
    pub scope: String,
    /// Seconds since the Unix epoch.
    pub valid_until: i64,
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StudyEntry {
    pub id: String,
    pub epoch: u64,
    pub active: bool,
}

/// The contents of a consent ledger file.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ConsentLedger {
    pub studies: Vec<StudyEntry>,
    pub consents: Vec<ConsentEntry>,
}

/// A JSON file, read fresh on each lookup, so that a revocation takes effect at once. For deployments with no
/// chain, and for tests. Whoever can write to this file controls consent.
pub struct FileConsentLedger {
    path: PathBuf,
}

impl FileConsentLedger {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn read(&self) -> Result<ConsentLedger, String> {
        let text =
            std::fs::read_to_string(&self.path).map_err(|e| format!("{:?}: {e}", self.path))?;
        serde_json::from_str(&text).map_err(|e| format!("{:?}: {e}", self.path))
    }
}

impl ConsentSource for FileConsentLedger {
    fn study_active(&mut self, study_id: &str, epoch: u64) -> Result<bool, String> {
        Ok(self
            .read()?
            .studies
            .iter()
            .any(|s| s.id == study_id && s.epoch == epoch && s.active))
    }

    fn patient_authorized(&mut self, pseudo_id: &str, scope: &str) -> Result<bool, String> {
        let now = chrono::Utc::now().timestamp();
        Ok(self
            .read()?
            .consents
            .iter()
            .any(|c| c.patient == pseudo_id && c.scope == scope && c.active && c.valid_until > now))
    }
}

/// Reads `contracts/ConsentRegistry.sol` through a node's JSON-RPC endpoint. It only ever makes `eth_call`,
/// so it needs no wallet. Identifiers go on chain as their Keccak-256 hash.
pub struct EvmConsentSource {
    rpc_url: String,
    contract: String,
    agent: ureq::Agent,
}

/// An identifier as the contract sees it.
pub fn chain_id(text: &str) -> [u8; 32] {
    Keccak256::digest(text.as_bytes()).into()
}

impl EvmConsentSource {
    pub fn new(rpc_url: &str, contract: &str) -> Result<Self, String> {
        let address = contract.trim_start_matches("0x");
        if address.len() != 40 || hex::decode(address).is_err() {
            return Err(format!("{contract} is not an address"));
        }
        let loopback = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
            .iter()
            .any(|p| rpc_url.starts_with(p));
        if !rpc_url.starts_with("https://") && !loopback {
            return Err(format!("{rpc_url}: an RPC endpoint needs https"));
        }
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .max_redirects(0)
            .build()
            .into();
        Ok(Self {
            rpc_url: rpc_url.to_string(),
            contract: format!("0x{address}"),
            agent,
        })
    }

    fn call_bool(&self, signature: &str, words: [[u8; 32]; 2]) -> Result<bool, String> {
        let mut data = function_selector(signature).to_vec();
        data.extend_from_slice(&words[0]);
        data.extend_from_slice(&words[1]);
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [{"to": self.contract, "data": format!("0x{}", hex::encode(data))}, "latest"],
        });
        let mut response = self
            .agent
            .post(&self.rpc_url)
            .header("Content-Type", "application/json")
            .send(request.to_string())
            .map_err(|e| e.to_string())?;
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|e| e.to_string())?;
        let value: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        if let Some(error) = value.get("error") {
            return Err(format!("the node returned an error: {error}"));
        }
        let result = value
            .get("result")
            .and_then(|r| r.as_str())
            .ok_or_else(|| "no result in the response".to_string())?;
        let word = hex::decode(result.trim_start_matches("0x")).map_err(|e| e.to_string())?;
        // A contract that is not there returns empty bytes. That is not a yes.
        if word.len() != 32 {
            return Err(format!("expected one word, got {} bytes", word.len()));
        }
        Ok(word[31] == 1 && word[..31].iter().all(|&b| b == 0))
    }
}

impl ConsentSource for EvmConsentSource {
    fn study_active(&mut self, study_id: &str, epoch: u64) -> Result<bool, String> {
        let mut number = [0u8; 32];
        number[24..].copy_from_slice(&epoch.to_be_bytes());
        self.call_bool(
            "isStudyActive(bytes32,uint64)",
            [chain_id(study_id), number],
        )
    }

    fn patient_authorized(&mut self, pseudo_id: &str, scope: &str) -> Result<bool, String> {
        self.call_bool(
            "isAuthorized(bytes32,bytes32)",
            [chain_id(pseudo_id), chain_id(scope)],
        )
    }
}
