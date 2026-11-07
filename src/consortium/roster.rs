//! Membership, and the bootstrap that creates certificates and keys.

use super::write_private_file;
use crate::signatures::{HybridPublicKey, HybridSigningKey};
use medcrypto_fhe::threshold::DEFAULT_SMUDGING_BITS;
use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// One member, as everybody else sees it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RosterNode {
    /// Also the DNS name in its certificate, so limited to lowercase letters, digits and hyphens.
    pub id: String,
    /// The threshold party number, from 1.
    pub party: u32,
    /// Such as `https://10.0.0.5:7443`.
    pub endpoint: String,
    /// SHA-256 of its certificate, so that the CA alone cannot add a member.
    pub cert_sha256: String,
    /// Its hybrid message-signing keys, Ed25519 and ML-DSA-65.
    pub signing_public_key: HybridPublicKey,
}

/// The shared description of the consortium. Every node needs the same one.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Roster {
    pub consortium_id: String,
    pub threshold_k: u32,
    pub poly_degree: usize,
    /// A public seed for the common random polynomials of key generation.
    pub crs_seed: String,
    pub smudging_bits: u32,
    pub nodes: Vec<RosterNode>,
}

impl Roster {
    pub fn node(&self, id: &str) -> Option<&RosterNode> {
        self.nodes.iter().find(|n| n.id == id)
    }

    pub fn by_party(&self, party: u32) -> Option<&RosterNode> {
        self.nodes.iter().find(|n| n.party == party)
    }

    pub fn crs_seed_bytes(&self) -> Result<[u8; 32], String> {
        hex::decode(&self.crs_seed)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| "the roster's seed is not 32 bytes of hex".to_string())
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path:?}: {e}"))?;
        let roster: Self = serde_json::from_str(&text).map_err(|e| format!("{path:?}: {e}"))?;
        let n = roster.nodes.len() as u32;
        if roster.threshold_k == 0 || roster.threshold_k > n {
            return Err(format!("{}-of-{n} is not possible", roster.threshold_k));
        }
        let mut parties: Vec<u32> = roster.nodes.iter().map(|x| x.party).collect();
        parties.sort_unstable();
        if parties != (1..=n).collect::<Vec<_>>() {
            return Err("party numbers must run from 1 to n".to_string());
        }
        roster.crs_seed_bytes()?;
        Ok(roster)
    }
}

/// Where consent comes from.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ConsentConfig {
    File { path: PathBuf },
    Evm { rpc_url: String, contract: String },
}

/// One node's own settings.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_id: String,
    /// Such as `0.0.0.0:7443`.
    pub listen: String,
    pub roster: PathBuf,
    pub ca_cert: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub signing_key: PathBuf,
    /// For key shares, cohort tables and results.
    pub data_dir: PathBuf,
    /// The study definitions.
    pub studies: PathBuf,
    pub consent: ConsentConfig,
    pub poll_seconds: u64,
}

impl NodeConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path:?}: {e}"))?;
        serde_json::from_str(&text).map_err(|e| format!("{path:?}: {e}"))
    }
}

/// A member to create.
#[derive(Clone, Debug)]
pub struct BootstrapNode {
    pub id: String,
    pub endpoint: String,
    pub listen: String,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 63
        && !id.starts_with('-')
        && !id.ends_with('-')
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Creates a certificate authority and everything each member needs, under `out`.
///
/// The convenience here has a cost: whoever runs this has seen every node's private keys. It suits a pilot,
/// or one organization's testbed. Across real institutions, each should generate its own keys and have only a
/// certificate request signed, so treat this as a starting point. The threshold secret is not created here:
/// it comes from the key generation that the daemons run among themselves.
pub fn bootstrap_consortium(
    out: &Path,
    consortium_id: &str,
    nodes: &[BootstrapNode],
    threshold_k: u32,
    poly_degree: usize,
) -> Result<Roster, String> {
    let fail = |e: rcgen::Error| e.to_string();
    if nodes.is_empty() || threshold_k == 0 || threshold_k as usize > nodes.len() {
        return Err(format!("{threshold_k}-of-{} is not possible", nodes.len()));
    }
    for (i, node) in nodes.iter().enumerate() {
        if !valid_id(&node.id) {
            return Err(format!(
                "{}: a node id must be a DNS label of lowercase letters, digits and hyphens",
                node.id
            ));
        }
        if nodes[..i].iter().any(|n| n.id == node.id) {
            return Err(format!("{} appears twice", node.id));
        }
    }
    medcrypto_fhe::CkksPreset::from_degree(poly_degree)
        .ok_or_else(|| format!("poly degree {poly_degree}: use 8192 or 16384"))?;

    let ca_key = KeyPair::generate().map_err(fail)?;
    let mut ca_params = CertificateParams::new(Vec::new()).map_err(fail)?;
    ca_params
        .distinguished_name
        .push(DnType::CommonName, format!("{consortium_id} consortium CA"));
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).map_err(fail)?;
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    std::fs::write(out.join("ca.pem"), ca_cert.pem()).map_err(|e| e.to_string())?;
    write_private_file(&out.join("ca-key.pem"), ca_key.serialize_pem().as_bytes())
        .map_err(|e| e.to_string())?;
    let issuer = Issuer::new(ca_params, ca_key);

    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let mut roster = Roster {
        consortium_id: consortium_id.to_string(),
        threshold_k,
        poly_degree,
        crs_seed: hex::encode(seed),
        smudging_bits: DEFAULT_SMUDGING_BITS,
        nodes: Vec::new(),
    };
    let absolute = |p: PathBuf| std::path::absolute(&p).unwrap_or(p);
    for (index, node) in nodes.iter().enumerate() {
        let directory = out.join(&node.id);
        std::fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
        let key = KeyPair::generate().map_err(fail)?;
        let mut params = CertificateParams::new(vec![node.id.clone()]).map_err(fail)?;
        params
            .distinguished_name
            .push(DnType::CommonName, node.id.clone());
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let cert = params.signed_by(&key, &issuer).map_err(fail)?;
        std::fs::write(directory.join("cert.pem"), cert.pem()).map_err(|e| e.to_string())?;
        write_private_file(&directory.join("key.pem"), key.serialize_pem().as_bytes())
            .map_err(|e| e.to_string())?;

        let signing = HybridSigningKey::generate();
        write_private_file(
            &directory.join("signing.key"),
            hex::encode(signing.seed()).as_bytes(),
        )
        .map_err(|e| e.to_string())?;

        roster.nodes.push(RosterNode {
            id: node.id.clone(),
            party: index as u32 + 1,
            endpoint: node.endpoint.clone(),
            cert_sha256: hex::encode(Sha256::digest(cert.der())),
            signing_public_key: signing.public_key().clone(),
        });
        let config = NodeConfig {
            node_id: node.id.clone(),
            listen: node.listen.clone(),
            roster: absolute(out.join("roster.json")),
            ca_cert: absolute(out.join("ca.pem")),
            cert: absolute(directory.join("cert.pem")),
            key: absolute(directory.join("key.pem")),
            signing_key: absolute(directory.join("signing.key")),
            data_dir: absolute(directory.join("data")),
            studies: absolute(out.join("studies.json")),
            consent: ConsentConfig::File {
                path: absolute(out.join("consent.json")),
            },
            poll_seconds: 5,
        };
        std::fs::write(
            directory.join("node.json"),
            serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    }
    let text = serde_json::to_string_pretty(&roster).map_err(|e| e.to_string())?;
    std::fs::write(out.join("roster.json"), text).map_err(|e| e.to_string())?;
    if !out.join("studies.json").exists() {
        std::fs::write(out.join("studies.json"), "[]").map_err(|e| e.to_string())?;
    }
    if !out.join("consent.json").exists() {
        let empty = serde_json::to_string_pretty(&super::consent::ConsentLedger::default())
            .map_err(|e| e.to_string())?;
        std::fs::write(out.join("consent.json"), empty).map_err(|e| e.to_string())?;
    }
    Ok(roster)
}
