# Changelog

Versions follow this rule: a bug or security fix increments `0.0.X`, and new functionality or new platform
support increments `0.X.0`.

## 0.4.0

BFV everywhere, post-quantum key exchange and range proofs, and seamless key migration from earlier versions.

| Area | Before (0.3.0) | After (0.4.0) |
| :--- | :--- | :--- |
| BFV reach | Library and demo | Threshold decryption, the daemon (`scheme` in a study), the command line, the GUI and Wasm |
| TLS key exchange | Classical (ring) | Hybrid X25519 and ML-KEM-768 (aws-lc-rs), between nodes and to FHIR and RPC servers |
| Production range proofs | External prover required | Built in: `--backend hash`, MPC in the head on SHA-256, 128 post-quantum bits |
| Wasm interfaces | `api`, `fhe-ops` | Also `bfv-ops` and `pq-signatures` |
| Wasm package version | `@0.2.0` | `@0.4.0` |
| Rosters from 0.2.x | Recreated on upgrade | Compatible directly, and upgradable in place with `consortium-export-key` and `consortium-import-keys` |
| `plain_bits` for BFV | 20 to 40 | 20 to 50 |
| Hybrid signature code | In the main crate | Extracted to `crates/medcrypto-pq` for shared native and Wasm compilation |
| Build toolchain | Rust | Rust and a C compiler for the hybrid post-quantum TLS stack |

## 0.3.0

Adds the exact-integer RNS-BFV homomorphic encryption scheme and FIPS 204 post-quantum hybrid signatures.

| Area | Before (0.2.2) | After (0.3.0) |
| :--- | :--- | :--- |
| Homomorphic schemes | CKKS (approximate real vectors) | CKKS and RNS-BFV (exact integers modulo `t` across `N` slots) |
| BFV multiplication | Not available | Exact scaling in word arithmetic through an auxiliary RNS basis |
| Signatures on daemon messages | Ed25519 | Hybrid Ed25519 and ML-DSA-65 (FIPS 204), with both required |
| Roster | Ed25519 public key per node | Ed25519 and ML-DSA-65 public keys per node |
| `signing.key` | Ed25519 seed | Unified seed deriving both classical and post-quantum signing keys |
| Signing commands | Not available | `sign-keygen`, `sign`, `verify-signature` |
| Packages | Release archives and Wasm | Also a container image at `ghcr.io/aetherx86/medcrypto` |
| License | CC BY-ND 4.0 | CC BY-NC-ND 4.0 |

## 0.2.2

- License updated to Creative Commons Attribution-NoDerivatives 4.0 International (CC BY-ND 4.0).

## 0.2.1

- License updated to proprietary licensing under Jeong Hoon Kim.

## 0.2.0

Multi-hospital federated analytics architecture with Homomorphic Encryption Standard RNS-CKKS parameters, distributed threshold decryption, HL7 FHIR R4 ingestion, and zero-knowledge range proofs.

### Highlights

| Area | Capability |
| :--- | :--- |
| Ring degree and modulus | `N = 8192` (200-bit RNS chain) and `N = 16384` (400-bit RNS chain) validated against the HE Standard |
| Encoding and arithmetic | Canonical embedding over `4096` or `8192` slots with negacyclic NTT (`O(N log N)`), Barrett, and Shoup reduction |
| Homomorphic operations | `multiply`, `relinearize`, `rescale_to_next`, `rotate` with Galois keys, `sum_slots`, `evaluate_linear_risk_model`, `evaluate_cubic`, and `evaluate_logistic` |
| Key custody | k-of-n distributed key generation and threshold decryption across hospital nodes |
| Range proofs | Bit-decomposition range proofs over `ristretto255` via `ZkPredicateProver` (`PedersenBackend` and `StarkCoprocessorBackend`) |
| EMR ingestion | `crates/medcrypto-fhir` for HL7 FHIR R4 bundles and servers with LOINC and UCUM normalization, winsorization, and HMAC-SHA256 pseudonymization |
| Dual-slot packing | Horizontal `RecordEnvelope` (per-patient AES-256-GCM cryptographic shredding) and vertical `CohortBatch` (multi-thousand patient cohort statistics) |
| Consortium daemon | Decentralized gRPC over mutual TLS with signed messages, cell-size suppression, and hash-chained audit logs |
| Consent verification | File-backed ledger and Solidity smart contract (`contracts/ConsentRegistry.sol`) via JSON-RPC |
| WebAssembly Component | `fhe-ops` added alongside `api` for cross-language execution in Python, TypeScript, and Go |

### Added commands

`keygen`, `decrypt`, `batch-pack`, `ingest-fhir`, `cohort-merge`, `cohort-stats`, `pack-record`, `open-record`,
`consortium-init`, `daemon run` and `daemon status`.

## 0.1.0

- Added `medcrypto.wasm`, a zero-import WebAssembly Component implementing SHA-256, HKDF, AES-256-GCM, Ed25519, Merkle roots, and audit chain links across Python, TypeScript, and Go, distributed with SHA-256 checksums and build provenance attestations.
- Added supply-chain repository guard checks, least-privilege workflow permissions, and commit-pinned GitHub Actions workflows.

## 0.0.1-beta

First release.
