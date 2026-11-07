//! The consortium daemon: hospitals computing statistics together, with no central server and no single
//! party able to decrypt.
//!
//! - [`roster`]: who is in the consortium, their certificates and keys, and the bootstrap that creates them.
//! - [`consent`]: where consent and study approvals are read from, a file or an EVM contract.
//! - [`core`]: the protocol as a plain state machine: messages in, messages out, with no networking.
//! - [`network`]: gRPC over mutual TLS around that state machine.

pub mod consent;
pub mod core;
pub mod network;
pub mod roster;

pub use self::core::{ConsortiumCore, JobResult, Message, Study, StudyScheme};
pub use consent::{ConsentSource, EvmConsentSource, FileConsentLedger};
pub use network::{install_post_quantum_tls, query_status, run_daemon, DaemonHandle};
pub use roster::{
    bootstrap_consortium, export_node_keys, import_node_keys, BootstrapNode, ConsentConfig,
    NodeConfig, NodeKeyRecord, Roster,
};

/// Writes a file readable only by its owner, atomically, so that a crash cannot leave half a key behind.
pub fn write_private_file(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let directory = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(directory) = directory {
        std::fs::create_dir_all(directory)?;
    }
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(format!(".tmp{}", std::process::id()));
    let temporary = std::path::PathBuf::from(temporary);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temporary, path)
}
