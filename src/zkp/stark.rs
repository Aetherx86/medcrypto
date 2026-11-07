//! The adapter to an external hash-based prover such as an SP1 host program.
//!
//! The prover is a separate executable, spoken to with JSON over pipes. The witness goes over standard
//! input and never on a command line, where other processes could read it.
//!
//! ```text
//! runner info                     -> {"system": "...", "post_quantum": true, "zero_knowledge": true}
//! runner prove  --elf GUEST.elf   <- {"value": 58, "min": 0, "max": 65}
//!                                 -> {"commitment": "hex", "proof": "hex"}
//! runner verify --elf GUEST.elf   <- {"commitment": "hex", "proof": "hex", "min": 0, "max": 65}
//!                                 -> {"valid": true}
//! ```
//!
//! Being a STARK does not by itself make a proof zero-knowledge, and many zkVM proofs are only succinct, so
//! a proof could leak the very value it is about. That is why a runner has to declare both properties, and
//! why this backend refuses one that does not. The declaration is only as honest as the runner: choosing
//! and reviewing it is on whoever deploys it.

use super::{CryptoError, ZkPredicateProver, ZkProof};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BACKEND_PREFIX: &str = "stark-coprocessor-v1";

/// What a runner says about itself.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProverCapabilities {
    pub system: String,
    pub post_quantum: bool,
    pub zero_knowledge: bool,
}

/// The high-assurance backend. Nothing here works until a runner has been installed.
#[derive(Clone, Debug)]
pub struct StarkCoprocessorBackend {
    /// The guest program that checks the predicate inside the prover.
    pub guest_elf_path: PathBuf,
    /// The runner executable.
    pub runner: PathBuf,
    pub timeout: Duration,
}

#[derive(Serialize)]
struct ProveRequest {
    value: u64,
    min: u64,
    max: u64,
}

#[derive(Deserialize)]
struct ProveResponse {
    commitment: String,
    proof: String,
}

#[derive(Serialize)]
struct VerifyRequest<'a> {
    commitment: &'a str,
    proof: &'a str,
    min: u64,
    max: u64,
}

#[derive(Deserialize)]
struct VerifyResponse {
    valid: bool,
}

impl StarkCoprocessorBackend {
    pub fn new(guest_elf_path: impl Into<PathBuf>, runner: impl Into<PathBuf>) -> Self {
        Self {
            guest_elf_path: guest_elf_path.into(),
            runner: runner.into(),
            timeout: Duration::from_secs(1800),
        }
    }

    fn run(&self, args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>, CryptoError> {
        let mut child = Command::new(&self.runner)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| CryptoError::Backend(format!("cannot start {:?}: {e}", self.runner)))?;
        let mut stdin = child.stdin.take().expect("stdin was piped");
        let bytes = input.unwrap_or_default().to_vec();
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
        });
        let mut stdout = child.stdout.take().expect("stdout was piped");
        let reader = std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = std::io::Read::read_to_end(&mut stdout, &mut out);
            out
        });
        let start = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if start.elapsed() > self.timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(CryptoError::Backend("the runner timed out".into()));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => return Err(CryptoError::Backend(e.to_string())),
            }
        };
        let _ = writer.join();
        let output = reader.join().unwrap_or_default();
        if !status.success() {
            return Err(CryptoError::Backend(format!(
                "the runner exited with {status}"
            )));
        }
        Ok(output)
    }

    pub fn capabilities(&self) -> Result<ProverCapabilities, CryptoError> {
        let output = self.run(&["info"], None)?;
        serde_json::from_slice(&output)
            .map_err(|e| CryptoError::Backend(format!("unreadable capabilities: {e}")))
    }

    /// Fails unless the runner declares itself both post-quantum and zero-knowledge.
    pub fn require_capabilities(&self) -> Result<ProverCapabilities, CryptoError> {
        let capabilities = self.capabilities()?;
        if !capabilities.post_quantum {
            return Err(CryptoError::Backend(format!(
                "{} does not declare itself post-quantum",
                capabilities.system
            )));
        }
        if !capabilities.zero_knowledge {
            return Err(CryptoError::Backend(format!(
                "{} does not declare itself zero-knowledge, so its proofs could leak the value",
                capabilities.system
            )));
        }
        Ok(capabilities)
    }

    /// Ties a proof to one exact guest program, so that a different program cannot stand in for it.
    fn backend_id(&self) -> Result<String, CryptoError> {
        let elf = std::fs::read(&self.guest_elf_path).map_err(|e| {
            CryptoError::Backend(format!("cannot read {:?}: {e}", self.guest_elf_path))
        })?;
        Ok(format!(
            "{BACKEND_PREFIX}:{}",
            hex::encode(Sha256::digest(elf))
        ))
    }

    fn elf_arg(&self) -> Result<&str, CryptoError> {
        self.guest_elf_path
            .to_str()
            .ok_or_else(|| CryptoError::Backend("the guest path is not valid text".into()))
    }

    fn verify_checked(&self, proof: &ZkProof, min: u64, max: u64) -> Result<bool, CryptoError> {
        if proof.min != min || proof.max != max || proof.backend != self.backend_id()? {
            return Ok(false);
        }
        self.require_capabilities()?;
        let input = serde_json::to_vec(&VerifyRequest {
            commitment: &proof.commitment,
            proof: &proof.payload,
            min,
            max,
        })
        .map_err(|e| CryptoError::Backend(e.to_string()))?;
        let output = self.run(&["verify", "--elf", self.elf_arg()?], Some(&input))?;
        let response: VerifyResponse = serde_json::from_slice(&output)
            .map_err(|e| CryptoError::Backend(format!("unreadable response: {e}")))?;
        Ok(response.valid)
    }
}

impl ZkPredicateProver for StarkCoprocessorBackend {
    fn prove_range(&self, val: u64, min: u64, max: u64) -> Result<ZkProof, CryptoError> {
        if min > max {
            return Err(CryptoError::InvalidRange { min, max });
        }
        if val < min || val > max {
            return Err(CryptoError::PredicateUnsatisfied);
        }
        self.require_capabilities()?;
        let backend = self.backend_id()?;
        let input = serde_json::to_vec(&ProveRequest {
            value: val,
            min,
            max,
        })
        .map_err(|e| CryptoError::Backend(e.to_string()))?;
        let output = self.run(&["prove", "--elf", self.elf_arg()?], Some(&input))?;
        let response: ProveResponse = serde_json::from_slice(&output)
            .map_err(|e| CryptoError::Backend(format!("unreadable response: {e}")))?;
        Ok(ZkProof {
            backend,
            min,
            max,
            commitment: response.commitment,
            payload: response.proof,
        })
    }

    /// Fails closed: if the runner is missing, broken or undeclared, the proof does not verify.
    fn verify_range(&self, proof: &ZkProof, min: u64, max: u64) -> bool {
        self.verify_checked(proof, min, max).unwrap_or(false)
    }
}
