# Developer Guide

For people changing the code. For what the system does and how to use it, read [README.md](README.md) or
[README.ko.md](README.ko.md) first.

## Invariants to keep

These are what a change must not break, and most have a test that will fail if it does.

1. **Secrets never reach a shared artifact.** A cohort file has no identifiers, and the slot map stays local. Keys and shares print as
   nothing in `Debug`.
2. **Only totals are decrypted in the consortium.** A partial decryption is made only over the output of `sum_slots`.
3. **A failed lookup is a no.** Consent errors, a missing runner and unparsable proofs all count as refusal.
4. **Bad input is an error.** Nothing from a file or the network may reach a panic. Use `validate_*`, and return `FheError`.
5. **Aggregation is deterministic.** Honest nodes must get identical bytes, since agreement on the hash gates decryption. Do not add
   randomness or depend on map order there.
6. **Lagrange before noise.** In `partial_decrypt`, the coefficient has to be applied before smudging.
7. **No imports in the component.** Nothing in `medcrypto-fhe` may reach the OS unless behind the `os-rng` feature. CI checks the WIT.
8. **Claims in documents match the code.** If a measurement or property changes, update both READMEs. Say what is not done.

## Layout

| Crate or path | Purpose | Depends on |
| :--- | :--- | :--- |
| `crates/medcrypto-fhe` | RNS-CKKS and threshold decryption | Nothing from this repository |
| `crates/medcrypto-fhir` | FHIR ingestion | Nothing from this repository |
| `crates/medcrypto-pq` | Hybrid signatures, hash-based range proofs | Nothing from this repository |
| `component` | The Wasm Component | `medcrypto-fhe` and `medcrypto-pq`, without `os-rng` |
| `.` (`medcrypto`) | Everything else, and the binary | All three crates |

## Everyday commands

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
cargo audit
python3 .github/scripts/repo_guard.py .

# One area
cargo test -p medcrypto-fhe
cargo test -p medcrypto --test consortium_test

# Measurements quoted in the READMEs
cargo run --release --example fhe_benchmark
```

The binary checks for a license at startup, including when tests run it. `tests/cli_test.rs` sets what it needs for that.

## Building the component

You need the `wasm32-unknown-unknown` target and `wasm-tools`.

```bash
sh component/build.sh
wasm-tools component wit component/dist/medcrypto.wasm | grep -E '^\s*(import|export) '
```

The output must show exports only. When the WIT changes, update all three hosts and `component/hosts/expected.txt`, and bump the package
version in the WIT, which also appears in `hosts/python/run.py` and `hosts/go/main.go`. Compare output with `diff` against `expected.txt`.
Do not put a ciphertext's bytes in there, since floating-point differences between platforms can change them.

## Adding things

**A LOINC code.** Add it to `LOINC` in `crates/medcrypto-fhir/src/terminology.rs`. A new unit needs its factor in that analyte's conversion
table, with the molar mass in a comment if one is involved. Add a conversion test, and update the catalog in both READMEs.

**A homomorphic operation.** Start from `check`, keep the level and scale accounting explicit, return `FheError`, and test against
plaintext at both presets. Update the operations table in both READMEs.

**A consortium message.** Add a `Message` variant, handle it in `ConsortiumCore::handle`, and check the sender's right to send it there.
Messages are authenticated by the time they reach the core, but what they claim is not. The tests in `protocol_without_a_network` let
you stop between any two steps, without sockets.

**A proof backend.** Implement `ZkPredicateProver`, return `false` for anything unexpected in `verify_range`, and bind proofs to the
backend's name and the statement.

**A parameter preset.** Add it to `CkksPreset`, and check that it validates against `max_log_qp`. Then check the depth you claim with a test,
and that `P` is the largest prime.

## The level budget, when changing clinical scoring

Every `multiply`, and every fractional constant, costs a rescale. `N8192` has two. See the worked example in the README under "Keeping scales
straight" before adding terms to `evaluate_cubic`.

## Releasing

1. Set the version in `Cargo.toml`, `crates/*/Cargo.toml` and `component/Cargo.toml`. A fix increments `0.0.X`, and new functionality or
   platform support increments `0.X.0`.
2. Write the `CHANGELOG.md` section under `## <version>`. That text becomes the release notes.
3. Update both READMEs.
4. Push to `main`, and wait for CI to pass.
5. Tag it `v<version>` and push the tag. `component.yml` builds everything and publishes, and refuses a tag that does not match the version.
6. Sync the portal, `aetherx86.github.io`, when a batch of work is finished.

## Not in CI

- The contract test on `anvil` runs only where Foundry is installed. Run it locally when touching `ConsentRegistry.sol` or `consent.rs`.
- Nothing tests `StarkCoprocessorBackend` against a real prover, and nothing compiles `zk/guest-range`.
- `commercial/` holds contract templates, and is ignored by Git and Docker on purpose.
- The GUI is compiled, and never launched.
