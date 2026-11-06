# MedCrypto

**English** | [한국어](README.ko.md)

Hospitals want to answer questions together, such as "what is the average HbA1c of diabetic patients across
our three institutions?", and privacy law stops them from pooling patient records to do it. MedCrypto lets them compute
the answer without any of them, or anyone else, seeing another hospital's records.

Each hospital reads its own EMR through HL7 FHIR, encrypts the results, and sends only ciphertexts to the others. They
add the ciphertexts up without decrypting anything. The total can be decrypted only when several hospitals cooperate,
and only if the patients consented and enough of them are in the result.

```
 Hospital A                     Hospital B                      Hospital C
 FHIR server                    FHIR server                     FHIR server
     |                              |                               |
     v                              v                               v
 clean, pseudonymize            clean, pseudonymize             clean, pseudonymize
 filter by consent              filter by consent               filter by consent
 encrypt (RNS-CKKS)             encrypt (RNS-CKKS)              encrypt (RNS-CKKS)
     |                              |                               |
     +-------- ciphertexts over gRPC + mutual TLS, no central server -+
                                    |
                 every node adds them up, without any key
                                    |
                 any 2 of 3 nodes decrypt the totals only
                                    |
                 count 1500, mean HbA1c 7.106 %, std. dev. 1.370
```

Written in Rust, with one WebAssembly Component for Python, TypeScript and Go.

> **Status.** This is research software, with a real implementation tested end to end. It is not a certified medical
> device, and using it does not by itself make anyone compliant with HIPAA or GDPR. Read
> [Security model and limitations](#16-security-model-and-limitations) before relying on it, and do not put real patient
> data through it without your own review.

## Contents

1. [The ideas in five minutes](#1-the-ideas-in-five-minutes)
2. [What it can do](#2-what-it-can-do)
3. [Install and build](#3-install-and-build)
4. [Tutorial: one hospital](#4-tutorial-one-hospital)
5. [Tutorial: three hospitals with the daemon](#5-tutorial-three-hospitals-with-the-daemon)
6. [Tutorial: erasing a patient](#6-tutorial-erasing-a-patient)
7. [Tutorial: proving a lab value is in range](#7-tutorial-proving-a-lab-value-is-in-range)
8. [Homomorphic encryption in depth](#8-homomorphic-encryption-in-depth)
9. [Packing: horizontal and vertical](#9-packing-horizontal-and-vertical)
10. [FHIR ingestion](#10-fhir-ingestion)
11. [Zero-knowledge proofs and post-quantum backends](#11-zero-knowledge-proofs-and-post-quantum-backends)
12. [The consortium daemon](#12-the-consortium-daemon)
13. [Threshold decryption](#13-threshold-decryption)
14. [WebAssembly Component](#14-webassembly-component)
15. [Rust library](#15-rust-library)
16. [Security model and limitations](#16-security-model-and-limitations)
17. [Regulatory mapping](#17-regulatory-mapping)
18. [Performance](#18-performance)
19. [Command reference](#19-command-reference)
20. [File formats](#20-file-formats)
21. [Clinical AI module and the GUI](#21-clinical-ai-module-and-the-gui)
22. [Repository layout](#22-repository-layout)
23. [Testing and CI/CD](#23-testing-and-cicd)
24. [Roadmap status](#24-roadmap-status)
25. [Troubleshooting](#25-troubleshooting)
26. [Glossary](#26-glossary)
27. [License](#27-license)

---

## 1. The ideas in five minutes

No cryptography background is needed for this section.

**Homomorphic encryption** means computing on data while it stays encrypted. If `Enc(5)` and `Enc(7)` are ciphertexts,
anybody can produce `Enc(12)` from them with no key and no idea of the numbers inside. MedCrypto uses a scheme called
CKKS, which works on vectors of real numbers and gives approximate answers, accurate to several decimal places. That
suits lab values well.

**Slots** are the positions inside one ciphertext. A single ciphertext here holds 4096 numbers, and adding two
ciphertexts adds them position by position, which is why one operation can process thousands of patients.

**Levels** are a budget. Each multiplication adds noise and uses up one level to remove it. The smaller parameter set
has two levels, so at most two multiplications in a row. Additions and rotations cost no levels at all. Statistics need
only additions, which is why they are so cheap.

**Threshold decryption** means there is no single secret key anywhere. The hospitals generate a key together, and
each ends up holding a share of it. Any `k` of them can decrypt together, and `k - 1` learn nothing. So no hospital
can read the others' data alone, and one being offline does not stop the work.

**A zero-knowledge proof** convinces someone that a statement is true while revealing nothing else. "This patient's
HbA1c is at most 6.5%" can be verified without learning that it is 5.8%.

**Cryptographic shredding** handles the right to erasure. Each patient's record gets its own key. Destroying that key
makes every copy of the record unreadable, including backups of the ciphertext and copies on an immutable ledger.

**Post-quantum** means safe against a future large quantum computer. CKKS rests on a lattice problem with no known
efficient quantum attack. Elliptic curves, which the fast proofs, signatures and TLS certificates use, do not survive
one. This project is clear about which parts are which: see [Section 16](#16-security-model-and-limitations).

---

## 2. What it can do

| Capability | How | Where |
| :--- | :--- | :--- |
| Encrypted arithmetic on real vectors | RNS-CKKS at `N = 8192` or `16384`, 128 post-quantum bits by the HE Standard's table | [`crates/medcrypto-fhe`](crates/medcrypto-fhe) |
| Multiplication, relinearization, rescaling | Hybrid key switching with one digit per prime | [`ckks.rs`](crates/medcrypto-fhe/src/ckks.rs) |
| Slot rotation | Galois keys, applied by permutation in the NTT domain | [`ckks.rs`](crates/medcrypto-fhe/src/ckks.rs) |
| Clinical scoring on ciphertexts | Linear models, cubic polynomials, a logistic curve | [`ckks.rs`](crates/medcrypto-fhe/src/ckks.rs) |
| No single key holder | k-of-n key generation and threshold decryption | [`threshold.rs`](crates/medcrypto-fhe/src/threshold.rs) |
| EMR input | FHIR R4 parsing, LOINC, UCUM conversion, winsorization, imputation | [`crates/medcrypto-fhir`](crates/medcrypto-fhir) |
| Per-patient and cohort packing | `RecordEnvelope` and `CohortBatch` | [`src/packing`](src/packing) |
| Range proofs | Pedersen commitments over ristretto255, swappable for an external prover | [`src/zkp`](src/zkp) |
| Multi-hospital daemon | gRPC over mutual TLS, signed messages, no central server | [`src/consortium`](src/consortium) |
| Consent | File ledger, or a smart contract through JSON-RPC | [`consent.rs`](src/consortium/consent.rs), [`ConsentRegistry.sol`](contracts/ConsentRegistry.sol) |
| Erasure and audit | Per-record keys, destroyed on request, with a hash-chained audit log | [`src/compliance`](src/compliance/mod.rs) |
| Other languages | One Wasm Component with no imports | [`component`](component) |

---

## 3. Install and build

You need a stable Rust toolchain (tested with 1.99). No `protoc` is needed, because the gRPC definitions compile in pure
Rust. There is no C library to install for the cryptography.

```bash
git clone https://github.com/Aetherx86/medcrypto.git
cd medcrypto
cargo build --release
./target/release/medcrypto --help
```

Prebuilt archives for Linux x86-64 and macOS ARM are attached to each
[release](https://github.com/Aetherx86/medcrypto/releases/latest), with checksums and build provenance.

**License.** This software is proprietary, and only its author may use it: see [LICENSE](LICENSE). The `medcrypto` binary also
looks for an Ed25519-signed license token at startup, in `AETHER_LICENSE_KEY` or `~/.aether/license.key`, and exits if there is
none.

To see the whole flow on synthetic data first:

```bash
./target/release/medcrypto demo
```

---

## 4. Tutorial: one hospital

This goes from a FHIR bundle to encrypted statistics on one machine. Everything below was run as written, and the data
comes from a generator that makes random patients.

**Make some data.** About half of the glucose results are in mg/dL and half in mmol/L, as in real multi-site data.

```bash
cargo build --release --examples
./target/release/examples/make_sample_bundle 400 1 > site-a.json
./target/release/examples/make_sample_bundle 600 2 > site-b.json
```

**Make keys.** This writes `secret-key.json`, readable only by you, and three public files: `public-key.json`,
`galois-keys.json` and `relin-key.json`.

```bash
./target/release/medcrypto keygen --output-dir keys
```

**Ingest and encrypt.** `2339-0` and `15074-8` are both glucose, in different units, so they become one column in mg/dL.

```bash
./target/release/medcrypto ingest-fhir \
  --bundle site-a.json \
  --loinc-filter 8480-6,4548-4,2339-0,15074-8 \
  --mode vertical \
  --public-key keys/public-key.json \
  --output a.ct.json
```

```text
Parsed 400 patients and 1200 observations. Left out: 0 by status, 0 incomplete, 0 other resources.
[NOTE] created the pseudonym key a.ct.json.pseudonym-key. Keep it, or pseudonyms will change.
Encrypting 400 patients and 3 analytes...
[SUCCESS] 1 batch(es) per analyte written to a.ct.json
          a.ct.json.slots maps slots to patients, and stays inside the hospital.
| Analyte     | Unit   | Results | Unknown unit | Implausible | Winsorized | Missing | Imputed |
| systolic_bp | mm[Hg] | 400     | 0            | 0           | 0          | 0       | 0       |
| hba1c       | %      | 400     | 0            | 0           | 0          | 0       | 0       |
| glucose     | mg/dL  | 400     | 0            | 0           | 0          | 0       | 0       |
```

Three files came out, and they go to different places:

| File | What it is | Where it goes |
| :--- | :--- | :--- |
| `a.ct.json` | The ciphertexts. No identifiers in it | Can leave the hospital |
| `a.ct.json.slots` | Which pseudonym is in which slot | Stays inside |
| `a.ct.json.pseudonym-key` | The secret behind the pseudonyms | Stays inside, and keep it |

**Do the same for site B, merge, and compute.** Merging collects batches. Nothing is decrypted at any point until the
last command, and that decrypts only totals.

```bash
./target/release/medcrypto ingest-fhir --bundle site-b.json \
  --loinc-filter 8480-6,4548-4,2339-0,15074-8 --mode vertical \
  --public-key keys/public-key.json --output b.ct.json

./target/release/medcrypto cohort-merge a.ct.json b.ct.json --output ab.ct.json
./target/release/medcrypto cohort-stats --input ab.ct.json --keys keys
```

```text
| Analyte     | Unit   | Count | Mean    | Std. deviation |
| systolic_bp | mm[Hg] | 1000  | 135.490 | 20.629         |
| hba1c       | %      | 1000  | 7.089   | 1.355          |
| glucose     | mg/dL  | 1000  | 133.561 | 37.341         |
```

Results from fewer than 11 patients are withheld by default. Change that with `--min-cell-size`.

This tutorial has one key holder, so that person could decrypt everything. For the real setting, where nobody can, see
the next section.

**From a live FHIR server** instead of a file, use `--endpoint`. A bearer token goes in the `MEDCRYPTO_FHIR_TOKEN`
environment variable, so that it stays out of your shell history.

```bash
export MEDCRYPTO_FHIR_TOKEN=...
./target/release/medcrypto ingest-fhir \
  --endpoint "https://emr.hospital.org/fhir/R4" \
  --loinc-filter "8480-6,4548-4,2339-0" \
  --mode vertical \
  --output ./encrypted_cohort.json
```

**From `PatientRecord` JSON files** in a directory, use `batch-pack`:

```bash
./target/release/medcrypto batch-pack \
  --input-dir ./patient_records/ \
  --batch-size 4096 \
  --output ./cohort_vertical_ct.json
```

Without `--public-key`, these commands create a key set next to the output, in `<output>.keys/`, so a first try just works.

---

## 5. Tutorial: three hospitals with the daemon

Three real daemons on one machine, talking gRPC over mutual TLS, with a 2-of-3 threshold. In a real deployment each
would run at its own hospital, and only the endpoints would change.

**Step 1. Create the consortium.** This makes a certificate authority, a certificate and signing key for each node, a
shared `roster.json`, and a `node.json` for each. See the caveat on this bootstrap in
[Section 12](#bootstrap-and-its-caveat).

```bash
M=./target/release/medcrypto
$M consortium-init --out consortium --threshold 2 --nodes \
  hospital-a=https://127.0.0.1:7443,hospital-b=https://127.0.0.1:7444,hospital-c=https://127.0.0.1:7445
```

**Step 2. Each hospital prepares its table.** `--mode table` runs the cleaning pipeline and stops before encryption. The
daemon encrypts later, once the collective key exists and it knows who consented. This file holds patient data, so it
stays at that hospital.

```bash
./target/release/examples/make_sample_bundle 500 3 > site-c.json
for s in a b c; do
  $M ingest-fhir --bundle site-$s.json \
    --loinc-filter 8480-6,4548-4,2339-0,15074-8 --mode table \
    --output consortium/hospital-$s/data/cohorts/diabetes-2026.json \
    --pseudonym-key consortium/hospital-$s/pseudonym.key
done
```

**Step 3. Define the study** in `consortium/studies.json`, which all hospitals share:

```json
[{
  "id": "diabetes-2026",
  "epoch": 1,
  "scope": "DIABETES_STATISTICS",
  "analytes": ["systolic_bp", "hba1c", "glucose"],
  "participants": ["hospital-a", "hospital-b", "hospital-c"],
  "min_cell_size": 11
}]
```

**Step 4. Record consent.** For this tutorial, every patient consents and the study is not approved yet. In production,
this would be the smart contract in [Section 12](#consent-sources) rather than a file.

```bash
UNTIL=$(($(date +%s)+31536000))
jq -s --argjson until $UNTIL '{
    studies: [{id: "diabetes-2026", epoch: 1, active: false}],
    consents: [.[].rows[].pseudo_id | {patient: ., scope: "DIABETES_STATISTICS", valid_until: $until, active: true}]
  }' consortium/hospital-*/data/cohorts/diabetes-2026.json > consortium/consent.json
```

**Step 5. Start the daemons**, in three terminals. They run distributed key generation among themselves, which takes
a few seconds, and then wait.

```bash
$M daemon run --config consortium/hospital-a/node.json
$M daemon run --config consortium/hospital-b/node.json
$M daemon run --config consortium/hospital-c/node.json
```

```bash
$M daemon status --config consortium/hospital-a/node.json --node hospital-c
```

```text
Node:      hospital-c
Keys:      ready
Running:   []
Finished:  []
Failed:    []
```

**Step 6. Approve the study.** This is the only trigger: nobody sends a command to a server, because there is no server.

```bash
jq '.studies[0].active = true' consortium/consent.json > c.tmp && mv c.tmp consortium/consent.json
```

Within seconds, each daemon filters its table by consent, encrypts, exchanges ciphertexts, adds them up, compares hashes,
and releases the result with two partial decryptions:

```bash
cat consortium/hospital-b/data/results/*.json | jq -c '.analytes[]'
```

```json
{"status":"released","analyte":"systolic_bp","unit":"mm[Hg]","count":1500,"mean":135.2394,"variance":424.722,"standard_deviation":20.6088}
{"status":"released","analyte":"hba1c","unit":"%","count":1500,"mean":7.1062,"variance":1.8775,"standard_deviation":1.3702}
{"status":"released","analyte":"glucose","unit":"mg/dL","count":1500,"mean":134.2220,"variance":1418.5607,"standard_deviation":37.6638}
```

Each node also has `data/audit.json`, a hash chain recording what it contributed and released.

Things to try next: revoke one patient's consent before approving a new epoch and watch the count drop; set
`min_cell_size` above the cohort and watch the result come back as `suppressed`; stop one daemon after key generation and
see that the other two still finish a study that has only them as participants.

---

## 6. Tutorial: erasing a patient

```bash
M=./target/release/medcrypto
$M pack-record --record-id P-8001 --values 52,5.8,105 --features age,hba1c,glucose \
  --public-key keys/public-key.json --output record.json

$M open-record --input record.json --secret-key keys/secret-key.json
```

```text
age: 52.0000
hba1c: 5.8000
glucose: 105.0000
```

```bash
$M shred --record-id P-8001
```

```text
Record ID:        P-8001
Destroyed Key ID: key:envelope:P-8001
Legal Basis:      GDPR Article 17 - Right to Erasure / Cryptographic Shredding
[CONFIRMED] The key is gone from medcrypto-keystore.json.
```

Now `open-record` fails, even with the FHE secret key and the envelope in hand, and this holds in any later process.
Shredding a record with no key is an error, and no certificate is issued for it.

Know what this does and does not reach:

- It reaches every copy of that **envelope**, wherever it was copied, because they all need the destroyed key.
- It does **not** reach backups of the key store itself. The default store is a file, and an SSD or a journaling file
  system may keep old blocks. Use an HSM or KMS in production, where deletion can be trusted.
- It does **not** reach a **vertical batch**, since one key covers many patients there. Rebuild that batch without the
  patient, using its `.slots` file. A statistic that has already been released cannot be taken back.

---

## 7. Tutorial: proving a lab value is in range

```bash
M=./target/release/medcrypto
$M prove --metric hba1c --value 58 --threshold 65 --output proof.json
$M verify --proof-file proof.json
```

```text
[VERIFIED] The proof is valid.
The committed value is at most 65, with nothing else revealed about it.
```

The value is scaled to an integer, so 58 here means 5.8%. Use `--lower-bound` for "at least", such as age 18 or over.

A false claim gets no proof, and editing the threshold in a proof file makes verification fail. The proof is 2,242 bytes
for this range.

For production, ask for the post-quantum backend. The Pedersen backend is refused there:

```bash
$M prove --value 58 --threshold 65 --profile production
# [ERROR] proof backend: the production profile needs a STARK runner: the Pedersen backend is not post-quantum

$M prove --value 58 --threshold 65 --profile production --backend stark \
  --guest-elf ./guest.elf --runner ./my-sp1-runner
```

---

## 8. Homomorphic encryption in depth

### Parameters

| Preset | `N` | Slots | Chain, in bits | Special prime | Total `log QP` | Limit, quantum 128 | Multiplications |
| :--- | ---: | ---: | :--- | ---: | ---: | ---: | ---: |
| `N8192` | 8192 | 4096 | 60, 40, 40 | 60 | 200 | 202 | 2 |
| `N16384` | 16384 | 8192 | 60, 40 x 7 | 60 | 400 | 411 | 7 |

The limits are from the Homomorphic Encryption Standard's table for ternary secrets, as published in Microsoft SEAL's
`hestdparms.h`. `CkksParams::validate` enforces them, so a chain that is too long is an error rather than a quiet loss of
security. The default scale is `2^40`. The secret is uniform ternary, and the error is a centered binomial of standard
deviation 3.24, which is close to the 3.2 the table assumes.

`medcrypto quantum-audit` shows the same check. It reads a published table. It does not run a lattice estimator.

### How the code is organized

| Layer | File | What is in it |
| :--- | :--- | :--- |
| Word arithmetic | [`arith.rs`](crates/medcrypto-fhe/src/arith.rs) | Barrett and Shoup reduction with mask-based conditional subtraction, deterministic Miller-Rabin, NTT prime search |
| Transform | [`ntt.rs`](crates/medcrypto-fhe/src/ntt.rs) | Negacyclic NTT and the Galois permutation |
| Parameters | [`params.rs`](crates/medcrypto-fhe/src/params.rs) | The presets, the standard's table, validation |
| Encoding | [`encoder.rs`](crates/medcrypto-fhe/src/encoder.rs) | The canonical embedding, with the `5^j` slot order |
| Polynomials | [`rns.rs`](crates/medcrypto-fhe/src/rns.rs) | RNS representation, hexadecimal in JSON and raw bytes in binary |
| Scheme | [`ckks.rs`](crates/medcrypto-fhe/src/ckks.rs) | Everything else |
| Threshold | [`threshold.rs`](crates/medcrypto-fhe/src/threshold.rs) | Key generation and decryption among parties |

The crate has `#![forbid(unsafe_code)]`, and no C dependencies.

### Why RNS

The ciphertext modulus `Q` is a product of primes that each fit a machine word. By the Chinese Remainder Theorem, a number
modulo `Q` can be stored as one residue per prime, and addition and multiplication then work on each residue on its own,
with no big-integer arithmetic at all. Combined with the NTT, multiplying two polynomials costs `O(N log N)` word
multiplications per prime. The last prime in the chain also gives rescaling its divisor directly.

### Operations

| Operation | Function | Level cost | Key needed | Notes |
| :--- | :--- | ---: | :--- | :--- |
| Add, subtract | `add`, `sub` | 0 | None | Levels and scales have to match, or it is an error |
| Add a constant | `add_constant` | 0 | None | To every slot |
| Multiply by a whole number | `scalar_mul` | 0 | None | |
| Multiply by a fraction | `scalar_mul` | 1 | None | The scale comes back exactly |
| Multiply by plaintext weights | `multiply_plain_rescale` | 1 | None | Slot by slot |
| Multiply two ciphertexts | `multiply` | 0, then rescale for 1 | None | Gives degree 2 |
| Relinearize | `relinearize` | 0 | `RelinKey` | Degree 2 back to 1 |
| Rescale | `rescale_to_next` | 1 | None | Divides by the last prime |
| Rotate | `rotate` | 0 | `GaloisKey` for that step | Negative steps go right |
| Sum all slots | `sum_slots` | 0 | `GaloisKey` for powers of two | `log2(slots)` rotations |
| Federated average | `federated_average` | 0 | None | Adds, and multiplies the recorded scale by the count |
| Linear score | `evaluate_linear_risk_model` | 1 | `GaloisKey` | `sum(w * x) + bias` in every slot |
| Cubic | `evaluate_cubic` | 2 | `RelinKey` | |
| Logistic | `evaluate_logistic` | 2 | `RelinKey` | `0.5 + 0.15012 x - 0.001593 x^3`, meaningful only on `[-8, 8]` |
| Drop levels | `mod_switch_to_level` | any | None | To line up two ciphertexts |

### Key switching

Relinearization and rotation both have to change which secret a piece of a ciphertext is under. The method here
is hybrid key switching with one digit per ciphertext prime and a single special prime `P`. For each digit `i`, the key
holds `(b_i, a_i)` with `b_i = -a_i s + e_i + P * s'`, the last term on prime `q_i` only. Switching breaks the polynomial
into its residues, multiplies each by its key, adds them up over `Q * P`, and divides by `P`, which removes most of the
noise. `P` is the largest prime, so that the noise left over is small compared to the scale.

### Rotation without a transform

An automorphism `X -> X^g` only permutes a polynomial's evaluation points. So in the NTT domain, a rotation is a table
lookup and needs no transform at all, which [`galois_permutation`](crates/medcrypto-fhe/src/ntt.rs) computes. A test
checks it against the coefficient-domain definition.

Summing all slots uses doubling: add the ciphertext to itself rotated by 1, then that to itself rotated by 2, then by 4, and
so on. After `log2(slots)` steps, **every slot holds the total**. This is what makes threshold decryption of statistics
safe: what gets decrypted has no individual values left in it.

### Keeping scales straight

Rescaling divides by a prime close to `2^40` but not equal to it, so the scale drifts slightly. Adding two ciphertexts at
different scales would give a wrong answer, so `add` refuses when they differ by more than one part in `10^9`. The engine
avoids the problem where it can. `multiply_plain_rescale` and fractional `scalar_mul` encode their constant at exactly
the scale of the prime being dropped, so the scale comes back unchanged. `evaluate_cubic` picks a separate constant for
each term, so that all terms arrive at one exact final scale.

A worked example of the budget, for `0.25 x^3 - 0.5 x^2 + 2 x + 1` at `N = 8192`:

```
Level 2:  x at scale 2^40
          x * x, relinearized and rescaled      -> x^2 at level 1
          x * 0.25, rescaled                    -> 0.25 x at level 1
Level 1:  x^2 * 0.25 x, relinearized and rescaled -> 0.25 x^3 at level 0, scale t
          x^2 * -0.5, rescaled, constant chosen -> -0.5 x^2 at level 0, scale t
          x * 2 (x dropped a level first), the same way -> 2 x at level 0, scale t
Level 0:  add all three, and add the constant 1 at scale t
```

### Precision and capacity

- A fresh ciphertext decrypts with an error under `10^-5` for values in the low hundreds, which the tests assert.
- A value's size is limited by the modulus at its level. Encoding refuses a coefficient that would not fit, rather than
  wrapping around silently. So at level 0 of `N8192`, with only the 60-bit prime left and scale `2^40`, the limit is
  around `2^19`, which is why cohort totals are kept at the top level.
- Multiplication refuses a product whose scale would not fit the remaining modulus.
- Noise grows along with the value in repeated squaring, so relative error is the measure to use there. Seven squarings
  of 1.1 at `N16384` come out with a relative error of about `10^-6`.

### What the API differs on from the roadmap's sketch

The roadmap proposed `rotate`, `relinearize` and `rescale_to_next` returning plain values. Here they return `Result`, so that
a bad input is an error and not a panic in a long-running daemon. `steps` is `i64`.

---

## 9. Packing: horizontal and vertical

The two modes solve opposite problems, and that is why both exist.

| | Horizontal: `RecordEnvelope` | Vertical: `CohortBatch` |
| :--- | :--- | :--- |
| One ciphertext holds | Many analytes of one patient | One analyte of up to 4096 or 8192 patients |
| Good for | Scoring one patient, and erasure | Statistics over a cohort |
| Outer key | One per patient, AES-256-GCM | None |
| Erasure | Destroy the key | Rebuild the batch |
| Size per 1000 patients, 3 analytes | 1000 ciphertexts | 9 ciphertexts |

```
                 age   sbp   hba1c  glucose
 patient 1  [    54    128   5.8    110    ]  <- horizontal: one ciphertext per row
 patient 2  [    61    140   7.1    160    ]
 patient 3  [    47    119   5.4     95    ]
                  ^     ^     ^      ^
                  vertical: one ciphertext per column
```

### Vertical packing

For each analyte, and each batch of patients, there are three ciphertexts:

| Ciphertext | Slot `i` holds | Sum over slots gives |
| :--- | :--- | :--- |
| `values` | Patient `i`'s value, or 0 if missing | `sum` |
| `squares` | That value squared | `sum_of_squares` |
| `presence` | 1 if patient `i` has a value, otherwise 0 | `count` |

Then `mean = sum / count`, and `variance = (sum_of_squares - sum^2 / count) / (count - 1)`. The presence mask is what lets
a missing result be left out rather than counted as a zero. The squares are computed at the hospital before
encryption, so that the aggregation needs no multiplication and no relinearization key under the collective secret.

A cohort larger than `--batch-size` spans several batches. The batch size can be at most the slot count.

Merging two cohorts collects their batches without any arithmetic, since slot 7 at one hospital and slot 7 at another are
different people. Merging refuses cohorts with different analytes or different units.

### Horizontal packing

`RecordEnvelope::seal` encrypts the patient's vector with CKKS, then wraps those bytes in AES-256-GCM under a key used for
that record only. The AES layer is what provides erasure, and CKKS still protects the data while it is being computed on.

With `ingest-fhir --mode horizontal`, each missing value goes in as 0, and a parallel `<analyte>.present` slot records
whether it was real.

---

## 10. FHIR ingestion

[`crates/medcrypto-fhir`](crates/medcrypto-fhir) is a separate crate with no dependency on the cryptography. Its output is a plain
table.

### Pipeline, in order

1. **Fetch or read.** `GET {endpoint}/Observation?code=http://loinc.org|...&_include=Observation:subject&_count=500`, following
   `next` links.
2. **Parse.** `Patient`, `Observation` (with `component` for blood pressure panels) and `Condition`. Other resources are
   counted and skipped.
3. **Filter by status.** Only `final`, `amended` and `corrected` results count. `entered-in-error`, `preliminary` and
   others are left out and counted.
4. **Drop incomplete results.** No numeric value, no LOINC code, a subject that is not a patient, or a comparator such as
   `<40`, where the real value is not the number shown.
5. **Convert units.** To the analyte's canonical unit. An unknown unit is dropped and counted, and never guessed: mistaking
   mmol/L for mg/dL would be off by a factor of 18.
6. **Check plausibility.** A value outside the analyte's plausible limits is dropped as an error, since it usually means a
   wrong unit.
7. **Pick the latest** result per patient and analyte. Codes for the same analyte merge into one column.
8. **Winsorize.** `--winsorize clinical` (default) clamps to catalog limits, `p1p99` clamps to this cohort's 1st and 99th
   percentiles, and `off` leaves values alone.
9. **Impute.** `--impute none` (default) leaves results missing, `median` and `mean` fill them in. Keep the default for
   federated statistics, since imputed values count as present and pull the variance down.
10. **Pseudonymize.** `HMAC-SHA256(site secret, patient id)`. A plain hash would not do, because anybody could hash every
    possible record number. Rows are sorted by pseudonym, so slot order reveals nothing about record number or admission order.

Every step's counts appear in the quality report, per analyte, so a study can report them.

### LOINC catalog

| Analyte (`id`) | Canonical unit | LOINC codes | Accepted units |
| :--- | :--- | :--- | :--- |
| Systolic BP (`systolic_bp`) | `mm[Hg]` | 8480-6 | `mm[Hg]`, `mmHg`, `kPa` |
| Diastolic BP (`diastolic_bp`) | `mm[Hg]` | 8462-4 | `mm[Hg]`, `mmHg`, `kPa` |
| HbA1c, NGSP (`hba1c`) | `%` | 4548-4, 17856-6, 59261-8 | `%`, `mmol/mol` |
| Glucose (`glucose`) | `mg/dL` | 2339-0, 2345-7, 15074-8, 14749-6 | `mg/dL`, `mmol/L`, `g/L` |
| Fasting glucose (`fasting_glucose`) | `mg/dL` | 1558-6, 14771-0 | `mg/dL`, `mmol/L`, `g/L` |
| Total cholesterol (`total_cholesterol`) | `mg/dL` | 2093-3, 14647-2 | `mg/dL`, `mmol/L`, `g/L` |
| LDL (`ldl_cholesterol`) | `mg/dL` | 2089-1, 13457-7, 18262-6, 22748-8 | `mg/dL`, `mmol/L`, `g/L` |
| HDL (`hdl_cholesterol`) | `mg/dL` | 2085-9, 14646-4 | `mg/dL`, `mmol/L`, `g/L` |
| Triglycerides (`triglycerides`) | `mg/dL` | 2571-8, 14927-8 | `mg/dL`, `mmol/L`, `g/L` |
| Creatinine (`creatinine`) | `mg/dL` | 2160-0, 14682-9 | `mg/dL`, `umol/L`, `mmol/L` |
| eGFR (`egfr`) | `mL/min/{1.73_m2}` | 33914-3, 48642-3, 48643-1, 62238-1, 98979-8 | `mL/min/{1.73_m2}`, `mL/min/1.73m2`, `mL/min` |
| BMI (`bmi`) | `kg/m2` | 39156-5 | `kg/m2` |
| Weight (`body_weight`) | `kg` | 29463-7, 3141-9 | `kg`, `g`, `[lb_av]`, `lb` |
| Height (`body_height`) | `cm` | 8302-2, 8306-3 | `cm`, `m`, `[in_i]`, `in` |
| Heart rate (`heart_rate`) | `/min` | 8867-4 | `/min`, `{beats}/min`, `{beat}/min`, `bpm` |
| Temperature (`body_temperature`) | `Cel` | 8310-5 | `Cel`, `C`, `[degF]`, `F` |

Molar conversions depend on the molecule: glucose uses 180.156 g/mol, cholesterol 386.65 g/mol, triglycerides 885.7 g/mol
(as triolein), creatinine 113.12 g/mol. HbA1c from IFCC to NGSP uses the master equation `% = 0.09148 * mmol/mol + 2.152`.

The plausible and clinical limits are in [`terminology.rs`](crates/medcrypto-fhir/src/terminology.rs). They are engineering
defaults for cleaning data and **are not clinical reference ranges**, so review them for your deployment. A code not in the
catalog is refused rather than passed through unnormalized.

### What the client refuses

The server is trusted with nothing beyond its own data.

- `http://`, unless the host is the local machine or `--allow-insecure-http` is given.
- A `next` link to any other origin, checked before anything is sent, so that a hostile response cannot collect the bearer
  token or reach internal addresses.
- Redirects, which could carry the token somewhere unchecked.
- URLs with embedded credentials.
- More than 1000 pages, or a page over 256 MiB.

---

## 11. Zero-knowledge proofs and post-quantum backends

Everything goes through one small interface, so the proof system can be swapped without touching what uses it:

```rust
pub trait ZkPredicateProver {
    fn prove_range(&self, val: u64, min: u64, max: u64) -> Result<ZkProof, CryptoError>;
    fn verify_range(&self, proof: &ZkProof, min: u64, max: u64) -> bool;
}
```

| Backend | Assumption | Post-quantum | Needs | Use |
| :--- | :--- | :--- | :--- | :--- |
| `PedersenBackend` | Discrete logarithm on ristretto255 | No | Nothing | Development and testing inside a hospital |
| `StarkCoprocessorBackend` | Depends on the prover, typically hash-based | If the runner is | An external runner and guest program | Audit and production |

`--profile production` refuses `PedersenBackend`, by way of `backend_for_profile`.

### How the Pedersen range proof works

To prove `min <= v <= max` for the `v` in a commitment `C = v G + r H`, the prover writes both `a = v - min` and
`b = max - v` as `n` bits, with `n` enough for `max - min`.

1. Each bit gets a commitment `C_i = bit * G + r_i * H`, and a one-of-two Schnorr proof that it opens to 0 or 1. The branch that
   is false gets simulated, so the proof does not reveal which bit it is.
2. The blindings are chosen so that the bit commitments add up: `sum(2^i C_a,i) = C - min G` and `sum(2^i C_b,i) = max G - C`.
3. All challenges come from SHA-512 over the commitment, range, bit index and side (Fiat-Shamir).

Since `a` and `b` are both non-negative integers far below the group order, wrapping around is impossible, and the two
together pin `v` to the range. `H` comes from a hash, so nobody knows its discrete logarithm relative to `G`. Proof size is
`2n * 160` bytes plus framing. That is 2.2 KiB for `[0, 65]` and 10 KiB for a 32-bit range.

### The STARK runner protocol

The adapter talks to a separate executable with JSON over pipes. The witness goes over standard input, because command
lines are visible to other processes.

```text
runner info                     -> {"system": "...", "post_quantum": true, "zero_knowledge": true}
runner prove  --elf GUEST.elf   <- {"value": 58, "min": 0, "max": 65}
                                -> {"commitment": "hex", "proof": "hex"}
runner verify --elf GUEST.elf   <- {"commitment": "hex", "proof": "hex", "min": 0, "max": 65}
                                -> {"valid": true}
```

Rules the adapter enforces, all failing closed:

- A runner must declare **both** `post_quantum` and `zero_knowledge`. Being a STARK does not by itself make a proof
  zero-knowledge. Many zkVM proofs are only succinct, so a proof could leak the very value it is about, and wrapping one in a
  Groth16 proof to hide it brings the elliptic curves back. **Check this property for the system you choose.**
- A proof is tied to the SHA-256 of one exact guest program.
- If the runner is missing, broken or times out, verification returns `false`.

**What has and has not been tested.** The adapter's tests use a stand-in shell script that follows the protocol and
proves nothing. They exercise the plumbing and the refusal rules. **No real prover has been run through it**, and
[`zk/guest-range`](zk/guest-range) is an uncompiled template for an SP1 guest, because the SP1 toolchain was not available
where this was built. To deploy, write a small host program around your prover that speaks this protocol.

### Why zk-HyperVM is not the post-quantum backend

An earlier roadmap named zk-HyperVM for this. It does not fit. It folds over commitments on the BN254 elliptic curve, which
Shor's algorithm breaks, and it proves hypervisor state transitions and has no runner for guest programs. The two
projects stay separate tools. An SP1-style or other hash-based system is what this slot needs.

---

## 12. The consortium daemon

### What happens, step by step

```
 1. Key generation     All nodes, once.
                       Publish public shares, send each other node a secret share.
                       Persist the key share and the collective keys.

 2. Trigger            A node's consent source reports the study's epoch as active.

 3. Contribution       Each participant: read its table, keep patients whose consent covers
                       the scope, encrypt, write a marker, send to everyone.

 4. Aggregation        With all participants' cohorts: merge in a fixed order, sum the slots.
                       This is deterministic, so honest nodes get identical bytes.
                       Announce the hash of the result.

 5. Release: counts    When k nodes announce the same hash, the lowest k of them publish partial
                       decryptions of the counts. The study's approval is checked again first.

 6. Release: sums      For analytes with count >= min_cell_size, the same step for the sums.
                       Others are suppressed.

 7. Result             Write results/<job>.json, and append to the audit chain.
```

The job's identifier comes from the study's `id` and `epoch`, so all nodes derive it independently. Rerunning a study means
a new epoch.

Messages may arrive in any order. A partial decryption that arrives before its aggregate is stored until that is ready. Delivery to a peer that is down retries for up to an hour.

### Trust checks on every message

1. **TLS.** The peer's certificate has to chain to the consortium's CA, on both sides of the connection.
2. **Roster.** The certificate's SHA-256 has to be the one the roster lists for the claimed sender, so even the CA cannot add a
   member without changing every node's roster.
3. **Signature.** An Ed25519 signature has to cover the consortium, sender, recipient and payload hash, so a recorded message
   cannot be replayed to another node or another consortium.
4. **Protocol.** A share or partial decryption has to be from the party it claims. Ciphertexts are fully validated, including
   that every residue is below its prime, before anything uses them.

The gRPC service is defined in [`proto/consortium.proto`](proto/consortium.proto), and compiles with no `protoc`.

### Privacy checks

- **Consent, per patient,** at contribution time. A failed lookup counts as no.
- **Study approval,** before any work starts, and again before each partial decryption. So a study withdrawn after
  contributions have been made is never decrypted, which a test confirms.
- **Hash agreement,** so nodes that computed different totals do not count towards the threshold.
- **Only totals are decrypted.** `sum_slots` removes individual values before any partial decryption exists.
- **Minimum cell size,** which suppresses results from too few patients. The conventional 11 is a common starting point for
  health statistics. Decide on yours with your compliance team.

### Consent sources

**A file** (`type: file`), read fresh on every lookup, so a revocation takes effect immediately. Whoever can write that file
controls consent, so it suits tests and deployments with their own access control.

**A smart contract** (`type: evm`), with [`contracts/ConsentRegistry.sol`](contracts/ConsentRegistry.sol). The node only makes
`eth_call`, so it needs no wallet and pays nothing. Identifiers go on chain as Keccak-256 hashes, so no health information does.
Set it in `node.json`:

```json
"consent": {
  "type": "evm",
  "rpc_url": "https://your-node.example",
  "contract": "0x5FbDB2315678afecb367f032d93F642f64180aa3"
}
```

Remote RPC has to use https. A response that is empty, a revert or anything but exactly `true` counts as no.

Hashing a pseudonym does not make it anonymous, since a holder of the list of pseudonyms can recognize them. Whether a
pseudonym's hash on a public chain counts as personal data under GDPR is a real question, so use a permissioned chain, or get
legal advice. Review this contract carefully before deploying it.

The contract has been tested on a real local chain with Foundry's `anvil`. That test runs when Foundry is installed and is
skipped otherwise, which includes the CI runners.

### Bootstrap and its caveat

`consortium-init` is convenient and suits a pilot, or a testbed in one organization. **Whoever runs it has seen every node's
private TLS and signing keys.** Between real institutions, each should generate its own keys and have only a certificate
request signed, and the roster should be agreed out of band. The threshold secret is not affected, since the daemons make that
among themselves.

To give each hospital its part, copy over its own directory, plus `ca.pem`, `roster.json` and `studies.json`. `ca-key.pem`
goes to none of them. Then edit the paths in `node.json`.

### Known operational limits

- A restart after key generation restores keys from disk. A restart **during** key generation means starting key generation
  over, on all nodes.
- A node that restarts during a job gives that job up, rather than encrypting a second time, because peers would hold a
  different ciphertext and the hashes would never match. Run a new epoch.
- All listed participants have to contribute before anything is computed. A participant being down stalls the study, though
  once the data has been exchanged, any `k` nodes can finish it.
- Membership is fixed, with no resharing. Adding a node or rotating keys means a new consortium.
- The default port-binding is whatever `listen` says, with no rate limiting. Peers are authenticated, and a misbehaving peer
  can still burn CPU with large valid messages.

---

## 13. Threshold decryption

Each party `i` draws its own ternary secret `s_i`. The collective secret `s = sum(s_i)` is never assembled anywhere.

**Key generation** has two parts, each one round:

- Public: for a common random `a` derived from a public seed, each party publishes `b_i = -a s_i + e_i`. The sum gives a public
  key for `s`. The same trick gives Galois keys, because a key-switching key for a rotation is linear in the secret.
- Secret: each party Shamir-shares `s_i` to all parties, over the ciphertext modulus and in the NTT domain, which works because
  Shamir sharing is linear. A party's final share is the sum of what it received.

Relinearization keys are **not** generated collectively. They are not linear in the secret and take an extra round. This
protocol does not need them, because statistics take only additions and rotations.

**Decryption.** For a set `T` of exactly `k` parties, each publishes

```
d_j = lambda_j * share_j * c1 + smudge_j
```

where `lambda_j` is the Lagrange coefficient for `T`. Then `c0 + sum(d_j)` is the message plus a little noise.

The Lagrange coefficient has to be applied before the noise is added, since it is huge modulo `Q` and would amplify any noise
added earlier. That is why a partial decryption names its set, and why `T` is chosen deterministically, as the lowest `k` of
those who announced the same hash.

**Smudging noise** matters. Without it, a partial decryption reveals the ciphertext's error term, and for CKKS that can leak the
key (the attack of Li and Micciancio). Each party adds noise uniform in `[-2^b, 2^b)`. The default `b = 24`, in the roster's
`smudging_bits`, leaves about `2^-9` of absolute noise per party in a decoded value, at scale `2^40` and `N = 8192`.

**Be aware of what this is.** The ratio between this noise and the ciphertext's own noise is at most around `2^14`, which is well short
of the statistically negligible distance that a security proof by noise flooding asks for. Raising `smudging_bits` helps at a
direct cost to precision, and the 2^40 scale leaves limited room. Treat the current value as defense in depth, for
parties following the protocol.

**Security model: honest but curious.** A party can look at everything it receives, and fewer than `k` such parties learn nothing
about `s`. A party that actively lies is **not** handled: there is no verifiable secret sharing, no proof of correct partial
decryption and no proof that a cohort's values are in range. It could cause a wrong result, or a denial of service, or inflate
a statistic with made-up patients. Contractual and audit controls have to cover that.

**A test shows the failure mode.** If two parties of a 3-of-5 forge a third party's contribution, the result is garbage with
nothing to do with the message.

---

## 14. WebAssembly Component

[`component/`](component) packages the cryptography as one
[WebAssembly Component](https://component-model.bytecodealliance.org/). There is one `medcrypto.wasm`, attached to each
[release](https://github.com/Aetherx86/medcrypto/releases/latest), with its interface in
[`component/wit/medcrypto.wit`](component/wit/medcrypto.wit). No language-specific C bindings are involved.

### The `api` interface

| Function | What it is | Checked against |
| :--- | :--- | :--- |
| `sha256` | SHA-256 | FIPS 180 |
| `hkdf` | HKDF-SHA-256 key derivation | RFC 5869 |
| `seal`, `open` | AES-256-GCM authenticated encryption | NIST vectors |
| `keypair-from-seed`, `sign`, `verify` | Ed25519 signatures | RFC 8032 |
| `merkle-root` | Merkle tree with separate leaf and node hashes | RFC 6962 reference data |
| `audit-link` | One link of a tamper-evident audit chain | Own tests |
| `constant-time-equal` | Comparison whose time does not depend on the contents | Own tests |

### The `fhe-ops` interface

```wit
interface fhe-ops {
    record fhe-keypair { public-key: list<u8>, secret-key: list<u8> }
    record ciphertext { data: list<u8>, degree: u32, scale: f64 }

    keygen: func(entropy: list<u8>) -> result<fhe-keypair, fhe-error>;
    encrypt-vector: func(pk: list<u8>, values: list<f64>, entropy: list<u8>) -> result<ciphertext, fhe-error>;
    decrypt-vector: func(sk: list<u8>, a: ciphertext) -> result<list<f64>, fhe-error>;
    homomorphic-add: func(a: ciphertext, b: ciphertext) -> result<ciphertext, fhe-error>;
    homomorphic-scalar-mul: func(a: ciphertext, scalar: f64) -> result<ciphertext, fhe-error>;
}
```

This runs at `N = 8192`. It differs from the roadmap's sketch in three ways, on purpose: `encrypt-vector` takes `entropy`, because
this component has no random source; functions return `result`, because input can be bad; and `keygen` and `decrypt-vector` are
added, since nothing could be used otherwise.

**It imports nothing.** The component has no file, clock, network or random access, which CI checks on every build, so whatever a
bug in it could do is limited to computing a wrong answer. Because of that, randomness has to come from the caller. Pass 32 fresh
bytes from a cryptographic source to `keygen` and to each `encrypt-vector`, and never reuse them. All zeros is refused,
since that is what a broken random source tends to produce.

### From each language

```python
# Python, with wasmtime
pair = m.fhe_call("keygen", secrets.token_bytes(32))
public = bytes(getattr(pair, "public-key"))
secret = bytes(getattr(pair, "secret-key"))
a = m.fhe_call("encrypt-vector", public, [120.5, 80.0, 5.75], secrets.token_bytes(32))
b = m.fhe_call("encrypt-vector", public, [10.0, 20.0, 0.25], secrets.token_bytes(32))
print(m.fhe_call("decrypt-vector", secret, m.fhe_call("homomorphic-add", a, b)))
```

```javascript
// TypeScript or JavaScript, through jco
import { fheOps } from "./generated/medcrypto.js";
const random = () => crypto.getRandomValues(new Uint8Array(32));
const { publicKey, secretKey } = fheOps.keygen(random());
const a = fheOps.encryptVector(publicKey, Float64Array.of(120.5, 80.0, 5.75), random());
const doubled = fheOps.homomorphicScalarMul(a, 2.0);
console.log(fheOps.decryptVector(secretKey, doubled));
```

The hosts in `component/hosts/` each run the same file and have to print exactly
[`expected.txt`](component/hosts/expected.txt), and a native test checks that file against the Rust code:

```bash
sh component/build.sh     # Needs the wasm32-unknown-unknown target and wasm-tools.

# Python
pip install -r component/hosts/python/requirements.txt
python component/hosts/python/run.py component/dist/medcrypto.wasm

# TypeScript
cd component/hosts/typescript && npm ci --ignore-scripts && npm run transpile && node run.mjs

# Go
cd component/hosts/go && go run . ../../dist/medcrypto.wasm
```

Python and TypeScript use real component runtimes (`wasmtime` and `jco`). Go has no mature one yet, so the Go host uses `wazero` to
run the core module inside the component file, and handles the Canonical ABI by hand. That is the same compiled code, but it
is more work, and it only works this simply because the component has no imports. Those hosts also show how the record's `f64`
changes the memory layout.

The expected output rounds decrypted values. Ciphertexts are not compared across platforms, because the floating-point library
may differ in the last bit between native code and Wasm, which changes rounding in the encoder, though not the decrypted answer.

---

## 15. Rust library

From [`examples/readme_tour.rs`](examples/readme_tour.rs), which CI compiles:

```rust
use medcrypto::compliance::KeyManager;
use medcrypto::fhe::{CKKSEngine, CkksPreset};
use medcrypto::packing::RecordEnvelope;
use medcrypto::zkp::{PedersenBackend, ZKPEngine, ZkPredicateProver};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // N = 8192: 4096 slots, two multiplications, 128 post-quantum bits by the HE Standard's table.
    let fhe = CKKSEngine::from_preset(CkksPreset::N8192);
    let (secret, public) = fhe.keygen();
    let relin = fhe.relin_keygen(&secret);
    let galois = fhe.galois_keygen(&secret, &fhe.sum_rotation_steps());

    // Slot-wise arithmetic on encrypted vectors.
    let a = fhe.encrypt(&public, &[1.5, 2.5, 3.5, 4.5])?;
    let b = fhe.encrypt(&public, &[2.0, 2.0, 2.0, 2.0])?;
    let product = fhe.multiply_relin_rescale(&a, &b, &relin)?;
    println!("product: {:.3?}", fhe.decrypt(&secret, &product)?); // [3.0, 5.0, 7.0, 9.0]

    // Rotation moves slots left, and a negative step moves them right.
    let rotated = fhe.rotate(&a, 1, &galois)?;
    println!("rotated: {:.3}", fhe.decrypt(&secret, &rotated)?[0]); // 2.5

    // A linear score: sum(weight * feature) + bias, all under encryption.
    let features = fhe.encrypt(&public, &[54.0, 128.0, 5.8])?;
    let score = fhe.evaluate_linear_risk_model(&features, &[0.02, 0.01, 0.3], -1.5, &galois)?;
    println!("score: {:.3}", fhe.decrypt(&secret, &score)?[0]); // 2.6

    // A nonlinear score: a logistic curve, by a cubic approximation.
    let inputs = fhe.encrypt(&public, &[-2.0, 0.0, 2.0])?;
    let probability = fhe.evaluate_logistic(&inputs, &relin)?;
    println!("logistic: {:.3?}", fhe.decrypt(&secret, &probability)?); // About 0.21, 0.5, 0.79

    // A range proof: the verifier learns that the value is in the range, and nothing else about it.
    let proof = PedersenBackend.prove_range(58, 0, 65)?;
    assert!(PedersenBackend.verify_range(&proof, 0, 65));
    let threshold = ZKPEngine::prove_threshold(58, 65, true)?;
    assert!(ZKPEngine::verify_threshold(&threshold));

    // An envelope that can be erased by destroying its key.
    let mut keys = KeyManager::new();
    let names = vec!["hba1c".to_string(), "glucose".to_string()];
    let envelope = RecordEnvelope::seal(&fhe, &public, &mut keys, "patient-1", names, &[5.9, 108.0])?;
    assert!(envelope.open(&fhe, &keys).is_ok());
    keys.shred_key(&envelope.envelope.key_id, "patient-1")?;
    assert!(envelope.open(&fhe, &keys).is_err());
    Ok(())
}
```

`medcrypto::fhe` is the `medcrypto-fhe` crate, and `medcrypto::fhir` is `medcrypto-fhir`. Every function that needs randomness has a
`_with` form taking your own generator, and that is the only form when the crate is built without its `os-rng` feature.

Input from anywhere else goes through `validate_ciphertext`, `validate_public_key`, `validate_secret_key` and the like before use.
Secret keys and shares wipe their memory when dropped, and print no key material in debug output.

---

## 16. Security model and limitations

### What it protects, assuming the protocol is followed

| Against | Protection |
| :--- | :--- |
| A network observer | Mutual TLS |
| A participant reading another's patients | Only ciphertexts are exchanged, and only totals are decrypted |
| Fewer than `k` colluding hospitals | They cannot decrypt anything |
| An outsider joining | CA, roster hash and signature checks |
| A tampered audit log | The hash chain breaks at the changed entry |
| A leaked envelope after erasure | Its key no longer exists |
| A verifier wanting more than a yes or no | Zero-knowledge range proofs |

### What it does not protect against

- **An actively malicious hospital.** See [Section 13](#13-threshold-decryption). It can contribute false data and skew a result, and can
  stall a study. Nothing proves that a contribution is honest.
- **`k` or more colluding hospitals.** They can decrypt any ciphertext they hold, including another hospital's individual
  contributions. Choose `k` with that in mind.
- **Differencing attacks.** With two hospitals, each can subtract its own data from the total and learn the other's total. Across repeated
  studies with slightly different consent sets, a released mean can reveal one patient's value. Minimum cell size does not stop this.
  There is no differential privacy here.
- **A compromised hospital before encryption.** The plaintext table sits on its disk, so protect that.
- **Side channels.** Modular reduction uses masks and not branches, and secrets print nowhere, but this has had no side-channel
  evaluation. Floating point is used in encoding, on values that are themselves secret.
- **Fault attacks and memory forensics.** Wiping memory is best effort, and copies made by the allocator are out of reach.

### Post-quantum status of each part

| Part | Rests on | Against a quantum computer |
| :--- | :--- | :--- |
| CKKS at the presets | RLWE, 128 bits by the standard's table | No efficient attack known |
| SHA-256 chains, AES-256-GCM | Symmetric | About 128 bits under Grover |
| Pedersen proofs | Discrete logarithm on an elliptic curve | **Broken** |
| Ed25519 message signatures | Elliptic curve | **Broken** |
| TLS certificates and key exchange | Whatever `rustls` negotiates, with elliptic-curve certificates | **Certificates broken.** Traffic recorded now may be decrypted later |
| Consent contract | Ethereum's own signatures | **Broken**, for that chain |

So the claim is narrow: the data's homomorphic encryption is post-quantum. **The system as a whole is not.** Ciphertexts recorded from the
network remain protected by their CKKS layer, though secret shares sent during key generation rely on TLS alone, which matters if an
attacker records that traffic today and has a quantum computer later.

---

## 17. Regulatory mapping

This shows which technical measure relates to which requirement. It is engineering guidance and not legal advice, and it is not a claim of
compliance, which depends on the whole deployment, its contracts and its processes. Encrypted or pseudonymized health data can still
be personal data under GDPR.

| Clause | Requirement | Measure | What it does not cover |
| :--- | :--- | :--- | :--- |
| GDPR Art. 5(1)(c) | Data minimization | Only study analytes are contributed, and only totals are decrypted | Whether the study needs those analytes |
| GDPR Art. 7 | Conditions for consent | Per-patient checks, revocation effective immediately | The consent process itself |
| GDPR Art. 9 | Special category data | Encryption before leaving the hospital | The legal basis for processing |
| GDPR Art. 17 | Right to erasure | Per-record keys, destroyed on request | Key store backups, vertical batches, released statistics |
| GDPR Art. 25 | Data protection by design | Pseudonyms, encryption, threshold keys, cell suppression | Everything organizational |
| GDPR Art. 32 | Security of processing | TLS, signatures, access checks | Operational security |
| HIPAA 164.502(b) | Minimum necessary | Range proofs give a yes or no, not the value | Which questions are asked |
| HIPAA 164.514 | De-identification | HMAC pseudonyms | Pseudonymized data is **not** de-identified by that alone |
| HIPAA 164.528 | Accounting of disclosures | Hash-chained audit log per node | It detects changes, and a node that truncates the whole chain needs external anchoring |
| HIPAA 164.312 | Technical safeguards | Mutual TLS, per-node identity | Workforce and physical safeguards |

Legal notes are in [LEGAL.md](LEGAL.md).

---

## 18. Performance

Measured on an Apple M4 in release mode, on one thread, with `cargo run --release --example fhe_benchmark`. Your numbers
will differ, so run it.

| Operation | `N = 8192` (ms) | `N = 16384` (ms) |
| :--- | ---: | ---: |
| Key generation | 1.16 | 7.20 |
| Relinearization key | 7.69 | 42.67 |
| One rotation key | 11.99 | 40.22 |
| Encrypt, all slots | 2.19 | 8.36 |
| Decrypt | 11.26 | 56.17 |
| Add | 0.02 | 0.09 |
| Multiply | 0.14 | 0.69 |
| Relinearize | 2.27 | 22.40 |
| Rescale | 0.54 | 3.33 |
| Rotate | 2.29 | 26.67 |
| Sum all slots | 28.84 | 370.85 |

| Size | `N = 8192` | `N = 16384` |
| :--- | ---: | ---: |
| Ciphertext, binary | 384 KiB | 2048 KiB |
| Ciphertext, in a JSON file | about 770 KiB | about 4 MiB |
| Public key | 384 KiB | 2048 KiB |
| Relinearization key | 1.5 MiB | 18 MiB |
| Rotation keys for `sum_slots` | 18 MiB | 234 MiB |

| Range proof (Pedersen) | Prove (ms) | Verify (ms) | Size |
| :--- | ---: | ---: | ---: |
| `[0, 65]` | 2.04 | 1.91 | 2.2 KiB |
| 32-bit range | 8.82 | 9.21 | 10 KiB |

The three-node tutorial, with 1500 patients and 3 analytes, finished key generation and the study within tens of seconds on one laptop. In a real deployment, the bandwidth dominates: each participant sends `3 x analytes x batches` ciphertexts to each
other node, and each node sends its share of the rotation keys during key generation.

---

## 19. Command reference

Run any of these with `--help` for all of its options.

| Command | What it does |
| :--- | :--- |
| `gui` | The desktop GUI. Also what runs with no command at all |
| `demo` | The whole multi-hospital flow on synthetic data |
| `init-node` | Shows a node's DID and parameters, with a throwaway key |
| `keygen` | Writes a secret key, public key, rotation keys and relinearization key |
| `encrypt` | Encrypts one patient's vitals |
| `decrypt` | Decrypts a ciphertext file |
| `ingest-fhir` | FHIR server or bundle, to vertical ciphertexts, horizontal envelopes, or a plain table |
| `batch-pack` | A directory of `PatientRecord` files or bundles, to vertical ciphertexts |
| `cohort-merge` | Combines several sites' cohorts |
| `cohort-stats` | Count, mean and deviation, with one secret key |
| `pack-record` | One record into an erasable envelope |
| `open-record` | Opens and decrypts an envelope, if its key exists |
| `shred` | Destroys a record's key |
| `prove`, `verify` | Range proofs with either backend |
| `quantum-audit` | Checks parameters against the HE Standard |
| `consortium-init` | Creates a CA, certificates, keys, a roster and node configurations |
| `daemon run` | Runs a node until interrupted |
| `daemon status` | Asks a node how it is doing |

Options for `ingest-fhir`:

| Option | Default | Meaning |
| :--- | :--- | :--- |
| `--endpoint`, `--bundle` | | A FHIR server base URL, or a bundle file. Exactly one |
| `--loinc-filter` | Required | Comma-separated LOINC codes |
| `--mode` | `vertical` | `vertical`, `horizontal` or `table` |
| `--output` | Required | Output file |
| `--batch-size` | 4096 | Patients per ciphertext, up to the slot count |
| `--winsorize` | `clinical` | `clinical`, `p1p99` or `off` |
| `--impute` | `none` | `none`, `median` or `mean` |
| `--public-key` | New keys next to the output | Public key file |
| `--pseudonym-key` | Next to the output | The site's secret, created if missing |
| `--key-store` | `medcrypto-keystore.json` | Envelope keys, for horizontal mode |
| `--allow-insecure-http` | Off | Allow `http://` to a remote host |

Exit status is 0 on success and 1 on any error, including a proof that fails to verify, and 126 for a license problem.

---

## 20. File formats

Binary formats use postcard, and JSON files hold polynomials as hexadecimal strings. Nothing here is a stable format
between minor versions before 1.0.

**A keys directory**

| File | Secret | Contents |
| :--- | :--- | :--- |
| `secret-key.json` | **Yes**, written mode 0600 | The ternary secret |
| `public-key.json` | No | For encrypting |
| `galois-keys.json` | No | For `sum_slots` |
| `relin-key.json` | No | For multiplication |

**A cohort file** (`--mode vertical`)

```json
{
  "format": "medcrypto-cohort-v1",
  "param_id": 1234567890,
  "batch_size": 4096,
  "columns": [{
    "column": {"analyte": "hba1c", "display": "Hemoglobin A1c (NGSP)", "unit": "%"},
    "batches": [{"values": {}, "squares": {}, "presence": {}}]
  }],
  "quality": [{"analyte": "hba1c", "observations": 400, "unknown_unit": 0, "implausible": 0,
               "winsorized": 0, "missing": 0, "imputed": 0}]
}
```

**A table** (`--mode table`, kept at the hospital)

```json
{
  "columns": [{"analyte": "hba1c", "display": "...", "unit": "%"}],
  "rows": [{"pseudo_id": "did:med:patient:...", "values": [5.8]}],
  "quality": []
}
```

**A node's data directory**

| Path | Contents | Sensitive |
| :--- | :--- | :--- |
| `cohorts/<study>.json` | The plain table, which you put there | **Yes** |
| `threshold-share.bin` | This node's share of the secret | **Yes** |
| `collective-keys.bin` | Public keys | No |
| `jobs/<job>.started` | Marker that this node contributed | No |
| `results/<job>.json` | Released statistics | Aggregates only |
| `audit.json` | The hash chain | Metadata |

**A consent ledger**

```json
{
  "studies": [{"id": "diabetes-2026", "epoch": 1, "active": true}],
  "consents": [{"patient": "did:med:patient:...", "scope": "DIABETES_STATISTICS",
                "valid_until": 1830000000, "active": true}]
}
```

---

## 21. Clinical AI module and the GUI

[`src/clinical_ai`](src/clinical_ai/mod.rs) has a small medication recommender drawing on ideas from VITA (AAAI 2024) and COGNet (SIGIR
2022): choosing relevant past visits, attention over them, a copy-or-generate predictor, and suppression of known drug interactions.

```bash
cargo run --example clinical_ai_benchmark
```

**What this is, plainly.** It runs on one hand-written trajectory. It has no training data and no dataset, and its numbers say
nothing about how the method compares with published models. Earlier versions of this README showed it beating published models on
MIMIC-III. That was wrong, and it was removed: see the [changelog](CHANGELOG.md). It is not a medical device, and it must not be
used for treatment decisions.

It also does not run on encrypted data. The two parts of the project are separate.

**The GUI** is a native desktop app with `egui`, with no web view:

```bash
./target/release/medcrypto gui
```

It has tabs for consent, encryption, proofs, federated averaging, compliance, the security audit and the clinical AI sample, and is
meant for demonstrations. The daemon, the FHIR pipeline and threshold decryption are on the command line only.

---

## 22. Repository layout

```
medcrypto/
├── crates/
│   ├── medcrypto-fhe/        RNS-CKKS and threshold decryption. No OS dependency without os-rng
│   └── medcrypto-fhir/       FHIR parsing, terminology, cleaning, HTTP client
├── src/
│   ├── main.rs               The command line
│   ├── packing/              Horizontal envelopes and vertical cohorts
│   ├── zkp/                  ZkPredicateProver, Pedersen range proofs, the STARK adapter
│   ├── consortium/           Roster, consent sources, protocol state machine, gRPC and TLS
│   ├── compliance/           Key store, shredding, audit chain
│   ├── quantum/              The check against the HE Standard
│   ├── blockchain/           DID and consent simulator, EVM calldata
│   ├── clinical_ai/          The medication recommender sample
│   ├── models/               PatientRecord
│   ├── gui/                  The desktop app
│   └── license.rs            The license check of the binary
├── component/                The Wasm Component, its WIT and its Python, TypeScript and Go hosts
├── proto/consortium.proto    The gRPC service
├── contracts/                ConsentRegistry.sol
├── zk/guest-range/           Template guest program for SP1 (not in the workspace)
├── examples/                 Sample data generator, benchmark, library tour, GUI launcher
├── tests/                    Integration tests
└── .github/                  Workflows, and the repository guard
```

See [DEVELOPER.md](DEVELOPER.md) for working on the code.

---

## 23. Testing and CI/CD

```bash
cargo test --workspace --all-targets --all-features
```

The cryptographic crates are built with optimization even in debug mode, so the whole suite takes under a minute or two.

| What | Where | What it establishes |
| :--- | :--- | :--- |
| Modular arithmetic | `arith.rs` | Barrett and Shoup agree with plain division. Primes have the required form |
| NTT | `ntt.rs` | Negacyclic convolution matches schoolbook. The permutation matches the coefficient automorphism |
| Encoder | `encoder.rs` | Round trips, and ring multiplication is slot multiplication |
| Parameters | `params.rs` | Presets fit the table. The old toy parameters and overlong chains are refused |
| CKKS | `crates/medcrypto-fhe/tests/ckks.rs` | Each operation against plaintext, at both presets. Bad input gives an error and not a panic |
| Threshold | same file | Any `k` of `n` decrypts. Fewer or mixed sets do not. A forged share gives garbage |
| FHIR | `crates/medcrypto-fhir/tests` | Parsing, conversion, cleaning, and the client against a real socket, including a hostile `next` link |
| Packing | `tests/packing_test.rs` | Statistics match plaintext, missing values are excluded, erasure holds across processes |
| Range proofs | `tests/zkp_range_test.rs` | Honest proofs verify. Tampering and moved commitments fail. Production refuses Pedersen. The runner rules hold |
| Daemon | `tests/consortium_test.rs` | Three real nodes over mutual TLS get the right statistics, with consent and cell suppression applied, one node down, and restart from disk. An outside certificate is refused. A study withdrawn midway is not decrypted |
| Consent | `tests/evm_consent_test.rs` | ABI encoding, failing closed, and the contract on a real local chain when Foundry is present |
| Command line | `tests/cli_test.rs` | The documented commands, through the real binary |
| Wasm | `component/tests/vectors.rs` | Published vectors, and that the expected host output is right |

**GitHub Actions**

| Workflow | Trigger | What it does |
| :--- | :--- | :--- |
| [`ci.yml`](.github/workflows/ci.yml) | Push, PR | Secret scan, repository guard, conflict markers, no emoji in docs. Then on Ubuntu and macOS: format, clippy with warnings denied, tests, `cargo audit`, strict docs, a demo run |
| [`component.yml`](.github/workflows/component.yml) | Push, PR, tag | Builds the Wasm, checks it imports nothing, runs it from Python, TypeScript and Go on Ubuntu and macOS. On a tag: command line archives, build provenance, and a release |
| [`audit.yml`](.github/workflows/audit.yml) | Push, PR, weekly | Dependency advisories |

All actions are pinned to commits. The repository guard looks for what supply chain attacks hide in: invisible Unicode, things that run
without being asked, install hooks and committed credentials. GitLab CI runs format, clippy, tests and audit on the mirror.

Versioning: a fix increments `0.0.X`, and new functionality or platform support increments `0.X.0`. A tag has to match the version in
`Cargo.toml`, or the release fails. Release notes come from [CHANGELOG.md](CHANGELOG.md).

---

## 24. Roadmap status

| Item | Status | Notes |
| :--- | :--- | :--- |
| RNS-CKKS at `N = 8192` and `16384` | Done | Checked against the standard's table |
| Relinearization, rescaling, rotation | Done | |
| Nonlinear clinical scoring | Done | Up to cubic at `N = 8192` |
| Horizontal and vertical packing, `batch-pack` | Done | |
| FHIR crate, `ingest-fhir` | Done | Tested with a local mock server, not a production EMR |
| `ZkPredicateProver`, real Pedersen range proofs | Done | |
| `StarkCoprocessorBackend` | Adapter done | **Not yet run with a real prover** |
| Daemon over gRPC and mutual TLS | Done | Honest-but-curious model |
| Consent from a smart contract | Done | Tested on a local chain only |
| k-of-n key generation and threshold decryption | Done | No verifiable secret sharing |
| Wasm `fhe-ops` | Done | Python, TypeScript and Go |

Worth doing next, roughly in order of value: verifiable secret sharing and proofs of correct partial decryption; input range proofs for
contributions; differential privacy on released statistics; post-quantum TLS and signatures; a real SP1 runner; key store integration
with an HSM or KMS; and resharing for changing membership.

---

## 25. Troubleshooting

| Message | Cause | What to do |
| :--- | :--- | :--- |
| `[AETHER LICENSE REQUIRED]`, exit 126 | The binary found no license | See [Section 3](#3-install-and-build) |
| `refusing http:// ... patient data needs https` | A plain remote endpoint | Use https. `--allow-insecure-http` is for testing only |
| `LOINC code ... is not in the catalog` | A code not in [the catalog](#loinc-catalog) | Add it in `terminology.rs`, with its units |
| High `Unknown unit` count | A server's unit spelling is new | Check the raw data, then add the spelling |
| `a coefficient of about 2^N does not fit` | Value too large at this level | Rescale your values, or stay at a higher level |
| `the scale would overflow` | Multiplying with too little modulus left | Use `N = 16384`, or fewer multiplications |
| `no levels left` | The budget has run out | Plan the circuit against [the budget](#keeping-scales-straight) |
| `scales differ` | Adding after different paths | Follow one path, or use `mod_switch_to_level` and `add_constant` |
| `no Galois key for rotation by N` | That rotation's key was not made | Pass it to `galois_keygen` |
| `made under different parameters` | Keys and ciphertexts from different presets | Use one preset throughout |
| Daemon `this certificate is not in the roster` | Rosters differ between nodes | Give all nodes the same `roster.json` |
| Daemon `this node restarted during the job` | A restart mid-study | Run a new epoch |
| Job shows as failed, `no longer approved` | The study was withdrawn | Working as intended |
| Study never starts | Not approved, or the table is missing | Check `consent.json` or the contract, and `data/cohorts/<id>.json`. The daemon logs to standard error |

---

## 26. Glossary

| Term | Meaning |
| :--- | :--- |
| CKKS | A homomorphic encryption scheme for approximate arithmetic on real numbers |
| RNS | Residue Number System: storing a big number as its residues modulo several small primes |
| RLWE | Ring Learning With Errors, the lattice problem CKKS's security rests on |
| `N` | The polynomial ring's degree. Larger is more secure and slower |
| Slot | A position in a ciphertext's vector. There are `N/2` of them |
| Level | How many more rescales a ciphertext can take |
| Scale | The factor that turns real values into integers, here `2^40` |
| Rescale | Dividing by a prime, after a multiplication, to bring the scale and noise back down |
| Relinearize | Bringing a product of three polynomials back to two |
| Galois key | What lets someone rotate slots with no secret key |
| NTT | Number Theoretic Transform: an FFT over integers, which makes polynomial multiplication fast |
| Smudging | Noise added to a partial decryption, so that it reveals nothing about the key |
| DKG | Distributed Key Generation: making a key that nobody ever holds whole |
| Shamir sharing | Splitting a secret so that any `k` shares rebuild it, and fewer reveal nothing |
| Pedersen commitment | A commitment to a value that hides it perfectly, and binds under discrete logarithm |
| STARK | A proof system based on hashes, generally taken as post-quantum |
| zkVM | A virtual machine whose execution can be proved |
| FHIR | HL7's standard for exchanging health data. R4 is its widely deployed version |
| LOINC | Standard codes for lab tests and observations |
| UCUM | A standard for writing units unambiguously |
| Winsorization | Clamping extreme values to a limit instead of dropping them |
| Imputation | Filling in missing values |
| PHI | Protected Health Information, under HIPAA |
| mTLS | TLS where both sides prove their identity with certificates |

---

## 27. License

Proprietary. Copyright (c) 2026 Jeong Hoon Kim, all rights reserved. Only the author may use this software. See
[LICENSE](LICENSE) and [LEGAL.md](LEGAL.md).
