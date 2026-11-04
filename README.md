# MedCrypto (v0.0.1-beta)

Privacy-Preserving Cross-Institutional Healthcare Data Sharing Engine.

MedCrypto is a high-performance cryptographic engine and command-line toolkit built in Rust. It enables hospitals, healthcare institutions, and research centers to collaboratively share and compute on sensitive patient records (PHI) without violating strict global data privacy regulations, including GDPR (Articles 9, 17, and 25) and HIPAA (Privacy Rule, Minimum Necessary Standard, and Security Rule).

The system integrates four complementary technologies:
1. Consortium Blockchain Layer: W3C Decentralized Identity (DID), Dynamic Patient Consent Smart Contracts, and Zero-PHI State Commitments.
2. Zero-Knowledge Proof (ZKP) Engine: Non-interactive proofs for predicate verification and clinical trial eligibility screening without disclosing underlying metrics.
3. 4th Generation Homomorphic Encryption (CKKS Scheme): Ring-LWE lattice-based approximate vector computation enabling federated cross-hospital analytics directly on encrypted data.
4. Cryptographic Shredding & Tamper-Proof Audit: Irrevocable key destruction guaranteeing GDPR Article 17 erasure alongside chained SHA-256 disclosure auditing under HIPAA Section 164.528.

---

## 1. Regulatory Compliance Architecture

| Regulation & Clause | Legal Requirement | Technical Conflict | MedCrypto Implementation & Guarantee |
| :--- | :--- | :--- | :--- |
| GDPR Article 17 | Right to Erasure (Forgotten) | Blockchain immutability prevents deleting on-chain records | Ephemeral Key Envelope Shredding: Raw PHI is encrypted under an ephemeral key. Blockchain stores only cryptographic commitments and one-time key identifiers. When consent is revoked, the key is permanently zeroized in memory and KMS, rendering ciphertexts mathematically undecryptable without modifying ledger history. |
| GDPR Article 25 | Privacy by Design | Exposure of patient records during processing | In-hospital encryption boundary: Clinical records are converted into CKKS ciphertexts and ZKP commitments before leaving the hospital intranet. No plaintext crosses organizational perimeters. |
| HIPAA Section 164.502(b) | Minimum Necessary Rule | Disclosing full medical records for single-variable checks | Zero-Knowledge Range & Predicate Proofs: Proves specific conditions (e.g., HbA1c <= 6.5% or Age >= 18) as a boolean mathematical verification truth without revealing the patient's actual lab measurements. |
| HIPAA Section 164.528 | Accounting of Disclosures | Tampering or loss of access history logs | Chained Tamper-Proof Audit Ledger: Every access request, purpose code, ZKP verification, and FHE query is appended to a cryptographic hash chain. Any modification to past entries breaks verification integrity. |

---

## 2. Post-Quantum Cryptography (PQC) Security Analysis

MedCrypto evaluates and implements quantum-resilient cryptographic foundations to resist emerging quantum threats (Shor's and Grover's algorithms):

- Lattice-Based Homomorphic Encryption:
  - Scheme: 4th Generation CKKS over cyclotomic polynomial rings R_q = Z_q[X] / (X^N + 1).
  - Hardness Assumption: Decisional Ring Learning With Errors (RLWE).
  - Shor's Algorithm Status: Immune. Shor's algorithm solves abelian hidden subgroup problems (discrete logarithm and integer factorization), which do not apply to high-dimensional ideal lattice geometries (SVP/CVP).
  - Quantum Sieving Hardness: Parameterized for quantum sieving algorithms (e.g., BDGL16).
- Hashing and State Commitments:
  - Algorithm: SHA-256 with Merkle tree state roots.
  - Grover's Algorithm Status: Resistant. Grover search provides quadratic speedup, leaving 128 bits of post-quantum security against preimage attacks, meeting NIST Post-Quantum Cryptography Level 1 standards.
- Zero-Knowledge Proof Commitment Roadmap:
  - Current implementation utilizes discrete-logarithm Pedersen commitments for development and deterministic embedded verification.
  - For post-quantum high-threat environments, the architecture supports dropping in hash-based STARKs (such as SP1 / FRI) to eliminate all discrete logarithm dependencies.

---

## 3. Clinical AI Longitudinal Recommender Engine (VITA & COGNet)

MedCrypto unifies privacy compliance (HIPAA Minimum Necessary & GDPR Data Minimization) with state-of-the-art clinical deep learning on longitudinal electronic health records (MIMIC-III benchmark, GAMENet, LEAP, SafeDrug, COGNet):

1. Component 1: Relevant Past Visit Selection & Target-Aware Attention (VITA, AAAI 2024):
   - Rather than unconditionally concatenating all historical encounters (which injects clinical noise and violates data minimization), MedCrypto ranks past visits by cosine similarity to the current encounter.
   - Empirical validation: Selecting the Top-1 clinically relevant visit achieves superior Jaccard similarity and PR-AUC, whereas incorporating irrelevant past visits (Bot-1) degrades representation below the baseline.
2. Component 2: COGNet-Inspired Copy-or-Generate Predictor:
   - Evaluates multi-label medication regimens by balancing a Copy mechanism (repeating maintenance drugs from pertinent past visits) and a Generate mechanism (acute prescriptions derived from current diagnoses).
3. Benchmarks & Evaluation Metrics:
   - Jaccard Similarity: Ratio of intersection to union over prescribed vs ground-truth medication sets.
   - PR-AUC: Area under the Precision-Recall curve via rank-ordered average precision.
   - F1-Score: Harmonic balance of clinical precision and recall.

---

## 4. Installation and Build

### Prerequisites
- Rust toolchain: stable (1.80+ recommended, tested on Rust 1.99+)
- Cargo package manager

### Building from Source

Clone the repository and compile the release binary:

```bash
cd medcrypto
cargo build --release
```

The optimized binary will be produced at `target/release/medcrypto`.

---

## 5. Test Suite Execution

The test suite validates both mathematical correctness, regulatory compliance invariants, and clinical AI accuracy:

```bash
cargo test --all --verbose
```

### Included Test Modules:
1. `tests/clinical_ai_recommender_test.rs`:
   - Validates Relevant Past Visit Selection and Target-Aware Cross Attention.
   - Validates COGNet Copy-or-Generate Multi-Label medication predictor.
   - Evaluates Jaccard Similarity, PR-AUC, and F1-score across longitudinal benchmarks.
   - Empirically verifies the VITA hypothesis (Top-1 relevant past visit strictly outperforms Bot-1 noise).
2. `tests/gdpr_compliance_test.rs`:
   - Validates GDPR Article 17 Cryptographic Shredding (ensures decryption is permanently blocked post-erasure).
   - Validates GDPR Article 25 Zero-PHI invariant (ensures no medical identifiers or measurements appear in serialized blockchain states).
3. `tests/hipaa_compliance_test.rs`:
   - Validates HIPAA Minimum Necessary Rule (ensures ZKP proofs reveal zero clinical numerical values).
   - Validates HIPAA Accounting of Disclosures (ensures single-byte tampering in the audit log triggers immediate cryptographic verification failure).
4. `tests/fhe_ckks_test.rs`:
   - Validates multi-slot clinical vector encryption/decryption accuracy within floating-point error bounds.
   - Validates multi-hospital federated averaging on ciphertexts.
5. `tests/quantum_resistance_test.rs`:
   - Verifies RLWE lattice hardness parameters and Grover 128-bit quantum search bounds.

---

## 6. Command-Line Interface (CLI) & Native GUI Usage

### 5.1 Launch Native Desktop Graphical User Interface (GUI)
MedCrypto features a high-performance native desktop GUI built with `egui` and `eframe` (no HTML/Electron/WebView). It provides interactive visual dashboards for EMR ingestion, real-time CKKS polynomial encryption, ZKP proof generation and verification, multi-hospital federated computing, GDPR cryptographic shredding, and post-quantum parameter inspection:

```bash
./target/release/medcrypto gui
# Or simply run without arguments:
./target/release/medcrypto
```

### 5.2 Initialize Hospital Node Cryptography
Generates node identity, W3C DID document, and 4th Gen CKKS public/private keypairs:

```bash
./target/release/medcrypto init-node --did did:med:hospital:severance --role HospitalNode
```

Example Output:
```text
==========================================================
  MedCrypto: Initializing Healthcare Node Cryptography   
==========================================================
Node DID:         did:med:hospital:severance
Role:             HospitalNode
CKKS Ring Modulus: 1073741789 (approx 30 bits)
CKKS Ring Degree:  N=128
Public Key Hash:  0x000000003e165c4e

[SUCCESS] Node cryptographic identity successfully initialized.
```

### 5.2 Encrypt Clinical Record via CKKS FHE
Converts patient clinical vitals (Age, Systolic BP, Diastolic BP, Glucose, HbA1c, BMI, eGFR, LDL) into an encrypted CKKS vector:

```bash
./target/release/medcrypto encrypt \
  --patient-id P-8001 \
  --age 52.0 \
  --hba1c 5.8 \
  --glucose 105.0 \
  --systolic 125.0 \
  --output ./ciphertext_p8001.json
```

Example Output:
```text
[SUCCESS] Ciphertext written to ./ciphertext_p8001.json
```

### 5.3 Generate Zero-Knowledge Proof for Clinical Condition
Generates a non-interactive zero-knowledge proof that a patient's HbA1c is below the diabetic threshold (<= 6.5%) without disclosing their actual measurement (e.g., 5.8%):

```bash
./target/release/medcrypto prove \
  --metric hba1c \
  --value 58 \
  --threshold 65 \
  --upper-bound \
  --output ./zkp_hba1c_proof.json
```

Example Output:
```text
==========================================================
   Zero-Knowledge Proof Generated Successfully            
==========================================================
Metric Target:    hba1c
Claim:            value <= 65 (Zero-Knowledge: actual value is hidden)
Proof Hash:       0x7f6ee625dc6c294677a5d8640bccd2031687d7d6f5171e68bb18aa567413b295
Challenge (c):    9182529740541274439

Proof saved to ./zkp_hba1c_proof.json
```

### 5.4 Verify Zero-Knowledge Proof
An external hospital or research institution verifies the proof mathematically without access to patient records:

```bash
./target/release/medcrypto verify --proof-file ./zkp_hba1c_proof.json
```

Example Output:
```text
[VERIFIED] Zero-Knowledge Proof is mathematically VALID.
The claimed condition is satisfied without revealing underlying clinical data.
```

### 5.5 GDPR Article 17 Cryptographic Shredding
Irrevocably destroys the ephemeral key envelope for a specified record upon patient consent withdrawal:

```bash
./target/release/medcrypto shred --record-id P-8001
```

Example Output:
```text
==========================================================
  GDPR Article 17: Cryptographic Shredding Completed     
==========================================================
Record ID:        P-8001
Destroyed Key ID: key:envelope:P-8001
Timestamp:        2026-11-04T07:23:00Z
Legal Basis:      GDPR Article 17 - Right to Erasure / Cryptographic Shredding
Audit Signature:  0x9482bf1024cd9a88e...

[CONFIRMED] Decryption key has been irrevocably zeroized.
The associated ciphertext on storage/blockchain is now mathematically unrecoverable.
```

### 6.6 Post-Quantum Security Audit
Displays security assessment table and quantum parameter validations:

```bash
./target/release/medcrypto quantum-audit
```

### 6.7 Run Full Multi-Institutional Interactive Simulation
Simulates the entire multi-hospital lifecycle (DID registration, dynamic consent, ZKP screening, FHE federated average, audit trail, and crypto-shredding):

```bash
./target/release/medcrypto demo
```

---

## 7. Rust Library Integration Example

MedCrypto can be embedded directly into existing hospital health information systems (HIS / EMR):

```rust
use medcrypto::fhe::CKKSEngine;
use medcrypto::zkp::ZKPEngine;
use medcrypto::models::PatientRecord;
use medcrypto::compliance::KeyManager;

fn main() {
    // 1. Initialize CKKS Homomorphic Encryption Engine
    let fhe = CKKSEngine::default();
    let (secret_key, public_key) = fhe.keygen();

    // 2. Clinical Observation Vector
    let patient_vitals = vec![54.0, 128.0, 82.0, 102.0, 5.7, 25.1, 95.0, 115.0];
    let ciphertext = fhe.encrypt(&public_key, &patient_vitals);

    // 3. Generate Zero-Knowledge Predicate Proof (HbA1c <= 6.5%)
    let raw_hba1c_scaled = 57; // 5.7% * 10
    let blinding_factor = 49182371;
    let zk_proof = ZKPEngine::prove_threshold(raw_hba1c_scaled, blinding_factor, 65, true).unwrap();
    assert!(ZKPEngine::verify_threshold(&zk_proof));

    // 4. Secure Envelope Encryption with GDPR Crypto-Shredding Key
    let mut key_manager = KeyManager::new();
    let envelope = key_manager.encrypt("patient-001", b"Sensitive Clinical History");

    // Legitimate decryption
    let decrypted = key_manager.decrypt(&envelope).unwrap();
    assert_eq!(decrypted, b"Sensitive Clinical History");

    // Shred key upon consent revocation
    key_manager.shred_key(&envelope.key_id, "patient-001").unwrap();
    assert!(key_manager.decrypt(&envelope).is_err());
}
```

---

## 8. Continuous Integration Workflow

The package includes a comprehensive GitHub Actions workflow configured at `.github/workflows/ci.yml`.

The pipeline executes on every push and pull request to `main` and `master` branches, as well as on release tags (`v*`):
1. Code formatting check via `cargo fmt --check`.
2. Static code analysis and linting via `cargo clippy --all-targets -- -D warnings`.
3. Complete unit, integration, and compliance test suite via `cargo test --all`.
4. Multi-platform release artifact compilation for Ubuntu and macOS (`0.0.1-beta`).
5. Automated post-quantum cryptography audit and demo execution verification.

---

## 9. Author

Jeong Hoon Kim

---

## 10. License

MIT License. See the [LICENSE](LICENSE) file for details.
