use medcrypto::zkp::{
    backend_for_profile, CryptoError, PedersenBackend, Profile, StarkCoprocessorBackend,
    ThresholdProof, ZKPEngine, ZkPredicateProver, ZkProof,
};

#[test]
fn honest_proofs_verify_across_the_range() {
    for (val, min, max) in [
        (58, 0, 65),
        (65, 0, 65),
        (0, 0, 65),
        (7, 7, 7),
        (u64::MAX, 0, u64::MAX),
        (u64::MAX - 3, u64::MAX - 10, u64::MAX),
    ] {
        let proof = PedersenBackend.prove_range(val, min, max).unwrap();
        assert!(
            PedersenBackend.verify_range(&proof, min, max),
            "{val} in [{min}, {max}]"
        );
    }
}

#[test]
fn a_false_statement_cannot_be_proved_and_a_proof_is_for_one_range() {
    assert_eq!(
        PedersenBackend.prove_range(66, 0, 65),
        Err(CryptoError::PredicateUnsatisfied)
    );
    assert_eq!(
        PedersenBackend.prove_range(1, 5, 65),
        Err(CryptoError::PredicateUnsatisfied)
    );
    assert_eq!(
        PedersenBackend.prove_range(1, 5, 2),
        Err(CryptoError::InvalidRange { min: 5, max: 2 })
    );

    let proof = PedersenBackend.prove_range(58, 0, 65).unwrap();
    assert!(!PedersenBackend.verify_range(&proof, 0, 60));
    let mut relabeled = proof.clone();
    relabeled.max = 60;
    assert!(!PedersenBackend.verify_range(&relabeled, 0, 60));
}

/// The attack that the old proof allowed: a dishonest prover commits to a value above the threshold and
/// proves it anyway. Here the prover takes valid parts from a real proof and points them at a commitment to
/// a different value, which breaks the sum of the bit commitments.
#[test]
fn a_proof_cannot_be_moved_to_another_commitment() {
    let good = PedersenBackend.prove_range(58, 0, 65).unwrap();
    let other = PedersenBackend.prove_range(60, 0, 65).unwrap();
    let mut forged = good.clone();
    forged.commitment = other.commitment;
    assert!(!PedersenBackend.verify_range(&forged, 0, 65));
}

#[test]
fn tampered_or_malformed_proofs_are_simply_false() {
    let good = PedersenBackend.prove_range(58, 0, 65).unwrap();
    let mut flipped = good.clone();
    let mut bytes = hex::decode(&flipped.payload).unwrap();
    for position in [1, bytes.len() / 2, bytes.len() - 1] {
        bytes[position] ^= 1;
        flipped.payload = hex::encode(&bytes);
        assert!(!PedersenBackend.verify_range(&flipped, 0, 65));
        bytes[position] ^= 1;
    }
    for payload in ["", "zz", "00"] {
        let mut bad = good.clone();
        bad.payload = payload.to_string();
        assert!(!PedersenBackend.verify_range(&bad, 0, 65));
    }
    let mut bad = good.clone();
    bad.commitment = "00".into();
    assert!(!PedersenBackend.verify_range(&bad, 0, 65));
    let mut bad = good;
    bad.backend = "something-else".into();
    assert!(!PedersenBackend.verify_range(&bad, 0, 65));
}

#[test]
fn the_same_value_gives_unlinkable_commitments_and_the_value_is_absent() {
    let a = PedersenBackend.prove_range(58, 0, 65).unwrap();
    let b = PedersenBackend.prove_range(58, 0, 65).unwrap();
    assert_ne!(a.commitment, b.commitment);
    let text = serde_json::to_string(&a).unwrap();
    assert!(!text.contains("\"value\""));
}

#[test]
fn threshold_statements_in_both_directions() {
    let upper = ZKPEngine::prove_threshold(58, 65, true).unwrap();
    assert!(ZKPEngine::verify_threshold(&upper));
    let lower = ZKPEngine::prove_threshold(45, 18, false).unwrap();
    assert!(ZKPEngine::verify_threshold(&lower));
    assert!(ZKPEngine::prove_threshold(160, 100, true).is_err());
    assert!(ZKPEngine::prove_threshold(17, 18, false).is_err());

    // A proof made for one direction says nothing about the other.
    let flipped = ThresholdProof {
        is_upper_bound: false,
        ..upper
    };
    assert!(!ZKPEngine::verify_threshold(&flipped));
}

#[test]
fn production_refuses_the_quantum_vulnerable_backend() {
    assert!(backend_for_profile(Profile::Development, None).is_ok());
    assert!(matches!(
        backend_for_profile(Profile::Production, None),
        Err(CryptoError::Backend(_))
    ));
}

#[test]
fn a_missing_runner_fails_closed() {
    let backend = StarkCoprocessorBackend::new("/nonexistent/guest.elf", "/nonexistent/runner");
    assert!(backend.prove_range(1, 0, 2).is_err());
    let proof = ZkProof {
        backend: "stark-coprocessor-v1:00".into(),
        min: 0,
        max: 2,
        commitment: "00".into(),
        payload: "00".into(),
    };
    assert!(!backend.verify_range(&proof, 0, 2));
}

#[cfg(unix)]
mod with_a_runner {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A stand-in for a real prover, to test the plumbing. It proves nothing: its "proof" is a marker that
    /// says what it was given. The tests here are about what the adapter does with a runner.
    fn write_runner(
        dir: &std::path::Path,
        post_quantum: bool,
        zero_knowledge: bool,
    ) -> std::path::PathBuf {
        let path = dir.join("runner.sh");
        std::fs::write(
            &path,
            format!(
                r#"#!/bin/sh
input=$(cat)
case "$1" in
  info) echo '{{"system":"stand-in","post_quantum":{post_quantum},"zero_knowledge":{zero_knowledge}}}' ;;
  prove) echo "$input" > "$(dirname "$0")/stdin.txt"; echo '{{"commitment":"abcd","proof":"beef"}}' ;;
  verify) case "$input" in *beef*) echo '{{"valid":true}}' ;; *) echo '{{"valid":false}}' ;; esac ;;
  *) exit 3 ;;
esac
"#
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn guest(dir: &std::path::Path, name: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn the_adapter_speaks_the_protocol_and_keeps_the_value_off_the_command_line() {
        let dir = tempfile::tempdir().unwrap();
        let runner = write_runner(dir.path(), true, true);
        let elf = guest(dir.path(), "guest.elf", b"guest program");
        let backend = StarkCoprocessorBackend::new(&elf, &runner);

        let proof = backend.prove_range(58, 0, 65).unwrap();
        assert_eq!(proof.commitment, "abcd");
        assert!(proof.backend.starts_with("stark-coprocessor-v1:"));
        assert!(backend.verify_range(&proof, 0, 65));
        assert!(!backend.verify_range(&proof, 0, 64));
        let received = std::fs::read_to_string(dir.path().join("stdin.txt")).unwrap();
        assert!(received.contains("\"value\":58"));

        let mut bad = proof.clone();
        bad.payload = "dead".into();
        assert!(!backend.verify_range(&bad, 0, 65));

        // Nothing about a false statement reaches the runner.
        assert_eq!(
            backend.prove_range(66, 0, 65),
            Err(CryptoError::PredicateUnsatisfied)
        );

        // A proof is tied to one exact guest program.
        let other = guest(dir.path(), "other.elf", b"a different program");
        assert!(!StarkCoprocessorBackend::new(&other, &runner).verify_range(&proof, 0, 65));

        assert!(backend_for_profile(Profile::Production, Some(backend)).is_ok());
    }

    #[test]
    fn a_runner_that_is_not_post_quantum_or_not_zero_knowledge_is_refused() {
        for (pq, zk, expected) in [
            (false, true, "post-quantum"),
            (true, false, "zero-knowledge"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let runner = write_runner(dir.path(), pq, zk);
            let elf = guest(dir.path(), "guest.elf", b"guest program");
            let backend = StarkCoprocessorBackend::new(&elf, &runner);
            assert!(
                matches!(backend.prove_range(1, 0, 2), Err(CryptoError::Backend(m)) if m.contains(expected))
            );
            assert!(backend_for_profile(Profile::Production, Some(backend)).is_err());
        }
    }
}
