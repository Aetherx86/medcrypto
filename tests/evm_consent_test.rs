use medcrypto::blockchain::{function_selector, BlockchainConsentRegistry};
use medcrypto::consortium::consent::{
    chain_id, ConsentSource, EvmConsentSource, FileConsentLedger,
};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

#[test]
fn selectors_are_computed_and_match_published_values() {
    // The well-known ERC-20 selector, as a check on the hash function.
    assert_eq!(
        hex::encode(function_selector("transfer(address,uint256)")),
        "a9059cbb"
    );
    let calldata = BlockchainConsentRegistry::generate_evm_audit_calldata("0xaa", "bb");
    let expected = hex::encode(function_selector("recordAudit(bytes32,bytes32)"));
    assert!(calldata.starts_with(&format!("0x{expected}")));
    assert_eq!(calldata.len(), 2 + 8 + 64 + 64);
    assert!(calldata.ends_with("bb"));
}

/// Answers each JSON-RPC call with the next canned result, and records the request bodies.
fn fake_node(results: Vec<String>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for result in results {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some(v) = line.to_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            log.lock().unwrap().push(String::from_utf8(body).unwrap());
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{result}",
                result.len()
            )
            .unwrap();
        }
    });
    (url, seen)
}

fn word(value: u8) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}{:02x}"}}"#,
        "00".repeat(31),
        value
    )
}

const CONTRACT: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

#[test]
fn calls_are_encoded_by_the_abi_and_only_a_true_word_is_a_yes() {
    let (url, seen) = fake_node(vec![
        word(1),
        word(0),
        word(1),
        r#"{"jsonrpc":"2.0","id":1,"result":"0x"}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"execution reverted"}}"#
            .to_string(),
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}"}}"#,
            "ff".repeat(32)
        ),
    ]);
    let mut source = EvmConsentSource::new(&url, CONTRACT).unwrap();

    assert_eq!(source.patient_authorized("patient", "scope"), Ok(true));
    assert_eq!(source.patient_authorized("patient", "other"), Ok(false));
    assert_eq!(source.study_active("study", 7), Ok(true));

    let log = seen.lock().unwrap().clone();
    let expected = format!(
        "0x{}{}{}",
        hex::encode(function_selector("isAuthorized(bytes32,bytes32)")),
        hex::encode(chain_id("patient")),
        hex::encode(chain_id("scope"))
    );
    assert!(log[0].contains(&expected), "{}", log[0]);
    assert!(log[0].contains("eth_call"));
    let expected = format!(
        "0x{}{}{}07",
        hex::encode(function_selector("isStudyActive(bytes32,uint64)")),
        hex::encode(chain_id("study")),
        "00".repeat(31)
    );
    assert!(log[2].contains(&expected), "{}", log[2]);

    // No contract at the address, a revert, and a strange value are not answers at all, or are no.
    assert!(source.patient_authorized("patient", "scope").is_err());
    assert!(source.patient_authorized("patient", "scope").is_err());
    assert_eq!(source.patient_authorized("patient", "scope"), Ok(false));
}

#[test]
fn a_node_that_is_unreachable_or_on_plain_http_is_not_a_yes() {
    let mut source = EvmConsentSource::new("http://127.0.0.1:9", CONTRACT).unwrap();
    assert!(source.study_active("s", 1).is_err());
    assert!(EvmConsentSource::new("http://rpc.example", CONTRACT).is_err());
    assert!(EvmConsentSource::new("https://rpc.example", "0x1234").is_err());
}

#[test]
fn the_file_ledger_honours_expiry_and_revocation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("consent.json");
    let now = chrono::Utc::now().timestamp();
    std::fs::write(&path, format!(r#"{{
        "studies": [{{"id": "s", "epoch": 2, "active": true}}, {{"id": "t", "epoch": 1, "active": false}}],
        "consents": [
            {{"patient": "live", "scope": "x", "valid_until": {}, "active": true}},
            {{"patient": "expired", "scope": "x", "valid_until": {}, "active": true}},
            {{"patient": "revoked", "scope": "x", "valid_until": {}, "active": false}}
        ]}}"#, now + 1000, now - 1, now + 1000)).unwrap();
    let mut ledger = FileConsentLedger::new(&path);
    assert_eq!(ledger.patient_authorized("live", "x"), Ok(true));
    assert_eq!(ledger.patient_authorized("live", "y"), Ok(false));
    assert_eq!(ledger.patient_authorized("expired", "x"), Ok(false));
    assert_eq!(ledger.patient_authorized("revoked", "x"), Ok(false));
    assert_eq!(ledger.study_active("s", 2), Ok(true));
    assert_eq!(ledger.study_active("s", 1), Ok(false));
    assert_eq!(ledger.study_active("t", 1), Ok(false));
    std::fs::write(&path, "not json").unwrap();
    assert!(ledger.patient_authorized("live", "x").is_err());
}

/// The contract on a real local chain. This needs Foundry, and is skipped where that is not installed.
#[test]
fn the_contract_on_a_local_chain() {
    use std::process::{Command, Stdio};
    let have = |tool: &str| {
        Command::new(tool)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    if !(have("anvil") && have("forge") && have("cast")) {
        eprintln!("skipped: Foundry is not installed");
        return;
    }
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let rpc = format!("http://127.0.0.1:{port}");
    let mut anvil = Command::new("anvil")
        .args(["--port", &port.to_string(), "--silent"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    struct Stop(std::process::Child);
    impl Drop for Stop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _anvil_guard = Stop(std::mem::replace(
        &mut anvil,
        Command::new("true").spawn().unwrap(),
    ));
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // Anvil's first well-known development account, which holds nothing outside a local test chain.
    let key = [
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478",
        "cbed5efcae784d7bf4f2ff80",
    ]
    .concat();
    let out_dir = tempfile::tempdir().unwrap();
    let deployed = Command::new("forge")
        .args([
            "create",
            "contracts/ConsentRegistry.sol:ConsentRegistry",
            "--broadcast",
            "--json",
        ])
        .args(["--rpc-url", &rpc, "--private-key", &key, "--out"])
        .arg(out_dir.path().join("out"))
        .arg("--cache-path")
        .arg(out_dir.path().join("cache"))
        .output()
        .unwrap();
    if !deployed.status.success() {
        // Compiling needs a solc download, which offline machines cannot do. That is not a contract failure.
        let error = String::from_utf8_lossy(&deployed.stderr);
        assert!(
            error.to_lowercase().contains("solc")
                || error.contains("dns")
                || error.contains("network"),
            "{error}"
        );
        eprintln!("skipped: could not compile: {error}");
        return;
    }
    let output: serde_json::Value = serde_json::from_slice(&deployed.stdout).unwrap();
    let address = output["deployedTo"].as_str().unwrap().to_string();

    let send = |signature: &str, args: &[String]| {
        let status = Command::new("cast")
            .args(["send", &address, signature])
            .args(args)
            .args(["--rpc-url", &rpc, "--private-key", &key])
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "{signature}");
    };
    let hexed = |text: &str| format!("0x{}", hex::encode(chain_id(text)));
    let me = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string();

    let mut source = EvmConsentSource::new(&rpc, &address).unwrap();
    assert_eq!(source.patient_authorized("patient", "scope"), Ok(false));
    assert_eq!(source.study_active("study", 1), Ok(false));

    send("setController(bytes32,address)", &[hexed("patient"), me]);
    let until = (chrono::Utc::now().timestamp() + 100_000).to_string();
    send(
        "grantConsent(bytes32,bytes32,uint64)",
        &[hexed("patient"), hexed("scope"), until],
    );
    assert_eq!(source.patient_authorized("patient", "scope"), Ok(true));
    assert_eq!(source.patient_authorized("patient", "other"), Ok(false));
    send(
        "revokeConsent(bytes32,bytes32)",
        &[hexed("patient"), hexed("scope")],
    );
    assert_eq!(source.patient_authorized("patient", "scope"), Ok(false));

    send(
        "setStudy(bytes32,uint64,bool)",
        &[hexed("study"), "1".into(), "true".into()],
    );
    assert_eq!(source.study_active("study", 1), Ok(true));
    assert_eq!(source.study_active("study", 2), Ok(false));
}
