//! Three real daemons talking gRPC over mutual TLS on the loopback interface.

use medcrypto::consortium::consent::{ConsentEntry, ConsentLedger, StudyEntry};
use medcrypto::consortium::core::{result_path, ReleasedAnalyte};
use medcrypto::consortium::{
    bootstrap_consortium, query_status, run_daemon, BootstrapNode, JobResult, NodeConfig, Study,
};
use medcrypto::fhir::pipeline::{Column, Row};
use medcrypto::fhir::CohortTable;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const SCOPE: &str = "DIABETES_STATISTICS";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn bootstrap(root: &Path, ids: &[&str], k: u32) -> Vec<NodeConfig> {
    let nodes: Vec<BootstrapNode> = ids
        .iter()
        .map(|id| {
            let port = free_port();
            BootstrapNode {
                id: id.to_string(),
                endpoint: format!("https://127.0.0.1:{port}"),
                listen: format!("127.0.0.1:{port}"),
            }
        })
        .collect();
    bootstrap_consortium(root, "test-consortium", &nodes, k, 8192).unwrap();
    ids.iter()
        .map(|id| {
            let mut config = NodeConfig::load(&root.join(id).join("node.json")).unwrap();
            config.poll_seconds = 1;
            config
        })
        .collect()
}

fn write_table(
    config: &NodeConfig,
    study: &str,
    prefix: &str,
    glucose: &[Option<f64>],
    hba1c: &[Option<f64>],
) {
    let table = CohortTable {
        columns: vec![
            Column {
                analyte: "glucose".into(),
                display: "Glucose".into(),
                unit: "mg/dL".into(),
            },
            Column {
                analyte: "hba1c".into(),
                display: "HbA1c".into(),
                unit: "%".into(),
            },
        ],
        rows: glucose
            .iter()
            .zip(hba1c)
            .enumerate()
            .map(|(i, (g, h))| Row {
                pseudo_id: format!("{prefix}-{i}"),
                values: vec![*g, *h],
            })
            .collect(),
        quality: Vec::new(),
    };
    let directory = config.data_dir.join("cohorts");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join(format!("{study}.json")),
        serde_json::to_string(&table).unwrap(),
    )
    .unwrap();
}

fn consents(ledger: &mut ConsentLedger, prefix: &str, count: usize) {
    for i in 0..count {
        ledger.consents.push(ConsentEntry {
            patient: format!("{prefix}-{i}"),
            scope: SCOPE.into(),
            valid_until: chrono::Utc::now().timestamp() + 3600,
            active: true,
        });
    }
}

fn write_ledger(root: &Path, ledger: &ConsentLedger) {
    std::fs::write(
        root.join("consent.json"),
        serde_json::to_string(ledger).unwrap(),
    )
    .unwrap();
}

fn write_studies(root: &Path, studies: &[Study]) {
    std::fs::write(
        root.join("studies.json"),
        serde_json::to_string(studies).unwrap(),
    )
    .unwrap();
}

async fn wait_for_result(config: &NodeConfig, job: &str) -> JobResult {
    let path: PathBuf = result_path(&config.data_dir, job);
    let start = Instant::now();
    while !path.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(180),
            "no result at {path:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

async fn wait_for_keys(config: &NodeConfig) {
    let start = Instant::now();
    while !config.data_dir.join("threshold-share.bin").exists() {
        assert!(
            start.elapsed() < Duration::from_secs(180),
            "key generation did not finish"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn released(result: &JobResult, analyte: &str) -> medcrypto::packing::vertical::AnalyteStatistics {
    result
        .analytes
        .iter()
        .find_map(|a| match a {
            ReleasedAnalyte::Released(s) if s.analyte == analyte => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{analyte} was not released: {result:?}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_hospitals_get_the_right_statistics_with_a_node_down_at_the_end() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let configs = bootstrap(root, &["hospital-a", "hospital-b", "hospital-c"], 2);

    // Nobody can see any approved study yet, so the daemons only run key generation.
    let mut ledger = ConsentLedger::default();
    let study = Study {
        id: "study-1".into(),
        epoch: 1,
        scope: SCOPE.into(),
        analytes: vec!["glucose".into(), "hba1c".into()],
        participants: vec!["hospital-a".into(), "hospital-b".into()],
        min_cell_size: 11,
    };
    write_studies(root, std::slice::from_ref(&study));
    write_ledger(root, &ledger);

    let glucose_a: Vec<Option<f64>> = (0..30).map(|i| Some(90.0 + i as f64)).collect();
    // Hospital B has a missing glucose result, and one patient who has not consented.
    let mut glucose_b: Vec<Option<f64>> = (0..20).map(|i| Some(150.0 + i as f64)).collect();
    glucose_b[3] = None;
    // Only five patients have an HbA1c at all, which is below the minimum cell size.
    let hba1c_a: Vec<Option<f64>> = (0..30)
        .map(|i| if i < 5 { Some(6.0) } else { None })
        .collect();
    let hba1c_b: Vec<Option<f64>> = vec![None; 20];
    write_table(&configs[0], "study-1", "a", &glucose_a, &hba1c_a);
    write_table(&configs[1], "study-1", "b", &glucose_b, &hba1c_b);
    consents(&mut ledger, "a", 30);
    consents(&mut ledger, "b", 19); // b-19 never consented.
    write_ledger(root, &ledger);

    let mut handles = Vec::new();
    for config in &configs {
        handles.push(run_daemon(config.clone()).await.unwrap());
    }
    for config in &configs {
        wait_for_keys(config).await;
    }

    let status = query_status(&configs[0], "hospital-b").await.unwrap();
    assert_eq!(status.node_id, "hospital-b");

    // The chain side says go. Everything from here on happens by itself.
    ledger.studies.push(StudyEntry {
        id: "study-1".into(),
        epoch: 1,
        active: true,
    });
    write_ledger(root, &ledger);

    let job = study.job_id();
    let results = [
        wait_for_result(&configs[0], &job).await,
        wait_for_result(&configs[1], &job).await,
        wait_for_result(&configs[2], &job).await,
    ];

    let included: Vec<f64> = glucose_a
        .iter()
        .chain(&glucose_b[..19])
        .flatten()
        .copied()
        .collect();
    let n = included.len() as f64;
    let mean = included.iter().sum::<f64>() / n;
    let variance = included.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);

    for result in &results {
        assert_eq!(result.aggregate_digest, results[0].aggregate_digest);
        let glucose = released(result, "glucose");
        assert_eq!(
            glucose.count, 48,
            "the missing result and the unconsented patient are out"
        );
        assert!(
            (glucose.mean - mean).abs() < 0.01,
            "{} vs {mean}",
            glucose.mean
        );
        assert!(
            (glucose.variance.unwrap() - variance).abs() < 2.0,
            "{:?} vs {variance}",
            glucose.variance
        );
        assert!(
            result.analytes.iter().any(
                |a| matches!(a, ReleasedAnalyte::Suppressed { analyte, .. } if analyte == "hba1c")
            ),
            "five patients is below the minimum cell size"
        );
    }

    // The plain values never appear in what crossed the network: the result holds only aggregates.
    let text = std::fs::read_to_string(result_path(&configs[0].data_dir, &job)).unwrap();
    assert!(!text.contains("a-0") && !text.contains("b-0"));

    // Each node has its own intact audit trail for this.
    let audit: medcrypto::compliance::AuditLedger = serde_json::from_str(
        &std::fs::read_to_string(configs[0].data_dir.join("audit.json")).unwrap(),
    )
    .unwrap();
    assert!(audit.verify_integrity());
    assert!(audit
        .entries
        .iter()
        .any(|e| e.operation == "FHE_THRESHOLD_RELEASE"));

    // With one hospital switched off, the other two are still enough to decrypt a new study's result.
    let c = handles.pop().unwrap();
    c.stop().await.unwrap();
    let second = Study {
        id: "study-2".into(),
        epoch: 1,
        ..study.clone()
    };
    write_table(&configs[0], "study-2", "a", &glucose_a, &hba1c_a);
    write_table(&configs[1], "study-2", "b", &glucose_b, &hba1c_b);
    write_studies(root, &[study.clone(), second.clone()]);
    ledger.studies.push(StudyEntry {
        id: "study-2".into(),
        epoch: 1,
        active: true,
    });
    write_ledger(root, &ledger);
    let job2 = second.job_id();
    let (one, two) = (
        wait_for_result(&configs[0], &job2).await,
        wait_for_result(&configs[1], &job2).await,
    );
    assert_eq!(released(&one, "glucose").count, 48);
    assert_eq!(released(&two, "glucose").count, 48);
    assert!(!result_path(&configs[2].data_dir, &job2).exists());

    for handle in handles {
        handle.stop().await.unwrap();
    }

    // A restart comes back from disk with the same keys, and does not run key generation again.
    let keys_before = std::fs::read(configs[0].data_dir.join("collective-keys.bin")).unwrap();
    let handle = run_daemon(configs[0].clone()).await.unwrap();
    let start = Instant::now();
    while !handle.status().keys_ready {
        assert!(start.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        keys_before,
        std::fs::read(configs[0].data_dir.join("collective-keys.bin")).unwrap()
    );
    handle.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_outside_certificate_is_refused_and_an_unapproved_study_does_not_start() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let configs = bootstrap(root, &["node-one", "node-two"], 2);
    write_studies(root, &[]);
    write_ledger(root, &ConsentLedger::default());
    let one = run_daemon(configs[0].clone()).await.unwrap();
    let two = run_daemon(configs[1].clone()).await.unwrap();
    wait_for_keys(&configs[0]).await;
    wait_for_keys(&configs[1]).await;

    // A separate consortium's certificate does not chain to this CA, so the handshake itself fails.
    let outside_root = tempfile::tempdir().unwrap();
    let outsiders = bootstrap(outside_root.path(), &["node-one", "node-two"], 2);
    let mut impostor = outsiders[0].clone();
    impostor.roster = configs[0].roster.clone();
    assert!(query_status(&impostor, "node-two").await.is_err());

    // The same CA's certificate is not enough either: this one is signed by the right CA, and the roster
    // has a different hash for it.
    let mut tampered: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&configs[1].roster).unwrap()).unwrap();
    tampered["nodes"][0]["cert_sha256"] = "00".repeat(32).into();
    let forged_roster = root.join("tampered-roster.json");
    std::fs::write(&forged_roster, tampered.to_string()).unwrap();
    let mut forged_two = configs[1].clone();
    forged_two.roster = forged_roster;
    forged_two.data_dir = root.join("forged-data");
    forged_two.listen = format!("127.0.0.1:{}", free_port());
    let strict = run_daemon(forged_two.clone()).await.unwrap();
    let mut asker = configs[0].clone();
    asker.roster = forged_two.roster.clone();
    let reply_from_strict = query_status_at(&asker, &forged_two).await;
    assert!(
        reply_from_strict.is_err(),
        "a certificate that is not in the roster must be refused"
    );
    strict.stop().await.unwrap();

    // A study that has not been approved does not start, even with its definition and data in place.
    let study = Study {
        id: "unapproved".into(),
        epoch: 1,
        scope: SCOPE.into(),
        analytes: vec!["glucose".into()],
        participants: vec!["node-one".into(), "node-two".into()],
        min_cell_size: 1,
    };
    write_table(&configs[0], "unapproved", "a", &[Some(100.0)], &[None]);
    let mut ledger = ConsentLedger::default();
    consents(&mut ledger, "a", 1);
    write_studies(root, std::slice::from_ref(&study));
    write_ledger(root, &ledger);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !configs[0]
            .data_dir
            .join("jobs")
            .join(format!("{}.started", study.job_id()))
            .exists(),
        "nothing happens before the study is approved"
    );

    one.stop().await.unwrap();
    two.stop().await.unwrap();
}

/// A status query to the endpoint of a node that was moved, with its roster.
async fn query_status_at(asker: &NodeConfig, target: &NodeConfig) -> Result<(), String> {
    let mut roster: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&asker.roster).unwrap()).unwrap();
    for node in roster["nodes"].as_array_mut().unwrap() {
        if node["id"] == target.node_id.as_str() {
            node["endpoint"] = format!("https://{}", target.listen).into();
        }
    }
    let path = asker.data_dir.join("asker-roster.json");
    std::fs::create_dir_all(&asker.data_dir).unwrap();
    std::fs::write(&path, roster.to_string()).unwrap();
    let mut config = asker.clone();
    config.roster = path;
    query_status(&config, &target.node_id).await.map(|_| ())
}

mod protocol_without_a_network {
    use super::*;
    use medcrypto::consortium::consent::FileConsentLedger;
    use medcrypto::consortium::core::Outgoing;
    use medcrypto::consortium::{ConsortiumCore, Message, Roster};

    /// Two nodes, wired together by hand, so that a test can stop between any two steps.
    fn pair(root: &Path) -> (ConsortiumCore, ConsortiumCore, Vec<NodeConfig>) {
        let configs = bootstrap(root, &["node-one", "node-two"], 2);
        let build = |config: &NodeConfig| {
            ConsortiumCore::new(
                Roster::load(&config.roster).unwrap(),
                &config.node_id,
                config.data_dir.clone(),
                config.studies.clone(),
                Box::new(FileConsentLedger::new(root.join("consent.json"))),
            )
            .unwrap()
        };
        (build(&configs[0]), build(&configs[1]), configs)
    }

    /// Delivers everything both ways until nothing is left, optionally dropping what a filter rejects.
    fn pump(
        a: &mut ConsortiumCore,
        b: &mut ConsortiumCore,
        keep: impl Fn(&Message) -> bool,
    ) -> usize {
        let mut delivered = 0;
        loop {
            let to_b: Vec<Outgoing> = a.take_outgoing();
            let to_a: Vec<Outgoing> = b.take_outgoing();
            if to_a.is_empty() && to_b.is_empty() {
                return delivered;
            }
            for o in to_b.into_iter().filter(|o| keep(&o.message)) {
                b.handle("node-one", o.message).unwrap();
                delivered += 1;
            }
            for o in to_a.into_iter().filter(|o| keep(&o.message)) {
                a.handle("node-two", o.message).unwrap();
                delivered += 1;
            }
        }
    }

    fn setup(
        root: &Path,
    ) -> (
        ConsortiumCore,
        ConsortiumCore,
        Vec<NodeConfig>,
        Study,
        ConsentLedger,
    ) {
        let (mut a, mut b, configs) = pair(root);
        let study = Study {
            id: "s".into(),
            epoch: 1,
            scope: SCOPE.into(),
            analytes: vec!["glucose".into()],
            participants: vec!["node-one".into(), "node-two".into()],
            min_cell_size: 1,
        };
        let values: Vec<Option<f64>> = (0..5).map(|i| Some(100.0 + i as f64)).collect();
        let nones = vec![None; 5];
        write_table(&configs[0], "s", "a", &values, &nones);
        write_table(&configs[1], "s", "b", &values, &nones);
        let mut ledger = ConsentLedger::default();
        consents(&mut ledger, "a", 5);
        consents(&mut ledger, "b", 5);
        ledger.studies.push(StudyEntry {
            id: "s".into(),
            epoch: 1,
            active: true,
        });
        write_ledger(root, &ledger);
        write_studies(root, std::slice::from_ref(&study));
        a.start().unwrap();
        b.start().unwrap();
        pump(&mut a, &mut b, |_| true);
        assert!(a.status().keys_ready && b.status().keys_ready);
        (a, b, configs, study, ledger)
    }

    #[test]
    fn a_study_withdrawn_after_contributions_is_never_decrypted() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let (mut a, mut b, configs, study, mut ledger) = setup(root);
        a.tick();
        b.tick();
        // The ciphertexts cross, and each node computes the totals and queues its announcement.
        let (to_b, to_a) = (a.take_outgoing(), b.take_outgoing());
        for o in to_b {
            b.handle("node-one", o.message).unwrap();
        }
        for o in to_a {
            a.handle("node-two", o.message).unwrap();
        }
        let (ready_for_b, ready_for_a) = (a.take_outgoing(), b.take_outgoing());
        let digest = |m: &Message| match m {
            Message::Ready { digest, .. } => digest.clone(),
            other => panic!("expected an announcement, got {other:?}"),
        };
        assert_eq!(
            digest(&ready_for_b[0].message),
            digest(&ready_for_a[0].message),
            "the aggregation is deterministic, so honest nodes get identical bytes"
        );

        // The approval is taken away, and then the announcements that would lead to decryption arrive.
        ledger.studies[0].active = false;
        write_ledger(root, &ledger);
        for o in ready_for_b {
            b.handle("node-one", o.message).unwrap();
        }
        for o in ready_for_a {
            a.handle("node-two", o.message).unwrap();
        }
        let partials = a
            .take_outgoing()
            .into_iter()
            .chain(b.take_outgoing())
            .filter(|o| matches!(o.message, Message::Partial { .. }))
            .count();
        assert_eq!(partials, 0, "no partial decryption after a withdrawal");
        let job = study.job_id();
        assert!(a.status().failed.contains(&job) && b.status().failed.contains(&job));
        assert!(!result_path(&configs[0].data_dir, &job).exists());
        assert!(!result_path(&configs[1].data_dir, &job).exists());
    }

    #[test]
    fn nodes_that_compute_different_aggregates_do_not_release() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let (mut a, mut b, configs, study, _) = setup(root);
        a.tick();
        b.tick();
        pump(&mut a, &mut b, |m| {
            matches!(m, Message::Contribution { .. })
        });
        // Node two claims to have a different total, which is what a tampered cohort would produce.
        let job = study.job_id();
        for o in b.take_outgoing() {
            drop(o);
        }
        a.take_outgoing();
        a.handle(
            "node-two",
            Message::Ready {
                job: job.clone(),
                digest: "f".repeat(64),
            },
        )
        .unwrap();
        a.tick();
        let partials = a
            .take_outgoing()
            .into_iter()
            .filter(|o| matches!(o.message, Message::Partial { .. }))
            .count();
        assert_eq!(
            partials, 0,
            "with only one node agreeing, a 2-of-2 threshold is not reached"
        );
        assert!(!result_path(&configs[0].data_dir, &job).exists());
    }

    #[test]
    fn messages_from_outsiders_or_for_the_wrong_party_are_refused() {
        let directory = tempfile::tempdir().unwrap();
        let (mut a, mut b, _) = pair(directory.path());
        a.start().unwrap();
        b.start().unwrap();
        let outgoing = b.take_outgoing();
        let public = outgoing
            .iter()
            .find(|o| matches!(o.message, Message::DkgPublic(_)))
            .unwrap();
        assert!(a.handle("stranger", public.message.clone()).is_err());
        // Node one cannot pass off a share as coming from node two.
        let mine = a.take_outgoing();
        let own_public = mine
            .iter()
            .find(|o| matches!(o.message, Message::DkgPublic(_)))
            .unwrap();
        assert!(b.handle("node-two", own_public.message.clone()).is_err());
    }
}
