# Changelog

Versions follow this rule: a bug or security fix increments `0.0.X`, and new functionality or new platform
support increments `0.X.0`.

## 0.4.0

BFV everywhere, post-quantum where it was missing, and keys from older versions carried over. English first, then Korean.

| Area | Before (0.3.0) | After (0.4.0) |
| :--- | :--- | :--- |
| BFV reach | Library and demo | Also threshold decryption, the daemon (`scheme` in a study), the command line, the GUI and Wasm |
| TLS key exchange | Classical (ring) | Hybrid X25519 and ML-KEM-768 (aws-lc-rs), between nodes and to FHIR and RPC servers |
| Production range proofs | Refused unless an external prover was installed | Built in: `--backend hash`, MPC in the head on SHA-256, about 128 post-quantum bits |
| Wasm interfaces | `api`, `fhe-ops` | Also `bfv-ops` and `pq-signatures` |
| Wasm package version | `@0.2.0` | `@0.4.0`, so hosts naming exports have to update that string |
| Rosters from 0.2.x | Had to be created again | Work as they are, and upgrade with `consortium-export-key` and `consortium-import-keys`, keeping key shares and identities |
| `plain_bits` for BFV | 20 to 40 | 20 to 50 |
| Hybrid signature code | In the main crate | In `crates/medcrypto-pq`, so that Wasm can use it |
| New build requirement | None | A C compiler, for the TLS library |

X.509 certificates, the development-only Pedersen backend and a chain's own signatures remain elliptic-curve.

| 영역 | 이전 (0.3.0) | 이후 (0.4.0) |
| :--- | :--- | :--- |
| BFV 적용 범위 | 라이브러리와 데모 | 임계 복호화, 데몬(연구의 `scheme`), 명령줄, GUI, Wasm까지 |
| TLS 키 교환 | 고전 방식(ring) | X25519와 ML-KEM-768 하이브리드(aws-lc-rs). 노드 간, FHIR와 RPC 서버 연결 모두 |
| 프로덕션 범위 증명 | 외부 prover가 없으면 거부 | 내장 `--backend hash`. SHA-256 위의 MPC-in-the-head, 양자 내성 약 128비트 |
| Wasm 인터페이스 | `api`, `fhe-ops` | `bfv-ops`, `pq-signatures` 추가 |
| Wasm 패키지 버전 | `@0.2.0` | `@0.4.0`. export 이름을 직접 쓰는 호스트는 문자열 수정 필요 |
| 0.2.x 로스터 | 다시 만들어야 함 | 그대로 동작하며, `consortium-export-key`, `consortium-import-keys`로 키 조각과 신원을 유지한 채 업그레이드 |
| BFV `plain_bits` | 20~40 | 20~50 |
| 하이브리드 서명 코드 | 메인 크레이트 | Wasm에서 쓰도록 `crates/medcrypto-pq`로 이동 |
| 새 빌드 요구 사항 | 없음 | TLS 라이브러리용 C 컴파일러 |

X.509 인증서, 개발 전용 Pedersen 백엔드, 체인 자체의 서명은 타원곡선으로 남아 있습니다.

## 0.3.0

Adds a second homomorphic scheme and post-quantum signatures. English first, then Korean.

| Area | Before (0.2.2) | After (0.3.0) |
| :--- | :--- | :--- |
| Homomorphic schemes | CKKS, approximate real numbers | CKKS and RNS-BFV, which gives exact integers modulo `t` in `N` slots |
| BFV multiplication | Not available | Exact scaling in word arithmetic only, through an auxiliary basis |
| Signatures on daemon messages | Ed25519 | Ed25519 and ML-DSA-65 (FIPS 204), with both required |
| Roster | One Ed25519 key per node | Both public keys per node. Consortiums made with an older version have to be created again |
| `signing.key` | Ed25519 seed | A seed that both keys derive from |
| Signing files | Not available | `sign-keygen`, `sign`, `verify-signature` |
| Packages | Release files only | Also a container image, `ghcr.io/aetherx86/medcrypto` |
| License | CC BY-ND 4.0 | CC BY-NC-ND 4.0 |

`noise_budget_bits` reports how much room a BFV ciphertext has left, and answers go wrong below
1 bit.

| 영역 | 이전 (0.2.2) | 이후 (0.3.0) |
| :--- | :--- | :--- |
| 동형암호 방식 | CKKS, 근사 실수 | CKKS와 RNS-BFV. BFV는 `N`개 슬롯에서 `t`를 법으로 정확한 정수를 제공 |
| BFV 곱셈 | 없음 | 보조 기저를 통해 워드 연산만으로 정확히 스케일링 |
| 데몬 메시지 서명 | Ed25519 | Ed25519와 ML-DSA-65(FIPS 204), 둘 다 필요 |
| 로스터 | 노드당 Ed25519 키 1개 | 노드당 공개키 2개. 이전 버전으로 만든 컨소시엄은 다시 만들어야 함 |
| `signing.key` | Ed25519 시드 | 두 키를 유도하는 시드 |
| 파일 서명 | 없음 | `sign-keygen`, `sign`, `verify-signature` |
| 패키지 | 릴리스 파일만 | 컨테이너 이미지 `ghcr.io/aetherx86/medcrypto` 추가 |
| 라이선스 | CC BY-ND 4.0 | CC BY-NC-ND 4.0 |

`noise_budget_bits`로 BFV 암호문의 남은 여유를 볼 수 있으며, 1비트 미만이면 답이 틀립니다.

## 0.2.2

- License: from proprietary to Creative Commons Attribution-NoDerivatives 4.0 International (CC BY-ND 4.0), from this version on.
- 라이선스: 이 버전부터 독점 라이선스에서 크리에이티브 커먼즈 저작자표시-변경금지 4.0 국제 라이선스(CC BY-ND 4.0)로 변경했습니다.

## 0.2.1

- License: from MIT to proprietary. Only Jeong Hoon Kim may use this software, from this version on. Copies of 0.2.0 and
  earlier that were obtained under the MIT license stay under it.
- 라이선스: MIT에서 독점 라이선스로 변경했습니다. 이 버전부터 Jeong Hoon Kim만 사용할 수 있습니다. MIT로 받은 0.2.0 이하 복사본은 계속 MIT
  라이선스를 따릅니다.

## 0.2.0

The upgrade from a toy-parameter, single-record tool to a multi-hospital system. English first, then
[Korean](#020-한국어) follows.

### Breaking

Nothing encrypted or proved by 0.1.0 can be read by this version, and it should not be kept: see the security
fixes below. The file formats, the `CKKSEngine` API and the `prove` and `shred` commands all changed.

### What changed into what

| Area | Before (0.1.0) | After (0.2.0) |
| :--- | :--- | :--- |
| Ring degree | `N = 128`, far below anything the HE Standard covers | `N = 8192` or `16384`. Parameters over the standard's limit are refused |
| Modulus | One 30-bit prime | RNS chains: 60+40+40 and a 60-bit special prime (200 bits), or 60+40x7+60 (400 bits) |
| Scale | `2^16` | `2^40` |
| Encoding | Values written straight into coefficients, so multiplying two ciphertexts could not work slot by slot | The canonical embedding, with 4096 or 8192 real slots |
| Polynomial multiplication | Schoolbook, `O(N^2)`, with 128-bit division | Negacyclic NTT, `O(N log N)`, with Barrett and Shoup reduction |
| Ciphertext multiplication | Not available | `multiply`, `relinearize`, `rescale_to_next` |
| Rotation | Not available | `rotate` with Galois keys, and `sum_slots` |
| Clinical scoring | `evaluate_linear_risk_model`, which convolved polynomials and did not compute the score it described | A real inner product, plus `evaluate_cubic` and `evaluate_logistic` |
| Error sampling | Rounded floating-point Gaussian | Centered binomial, standard deviation 3.24 |
| Errors | Panics and asserts | `FheError` on every operation, and full validation of input from elsewhere |
| Crate layout | One crate | `crates/medcrypto-fhe` and `crates/medcrypto-fhir` added, so the Wasm component can share the FHE code |
| Key custody | One secret key | k-of-n distributed key generation and threshold decryption |
| Range proof | A Schnorr proof of an opening, which did not prove the range | Bit decomposition with one-of-two proofs on both sides of the range |
| ZKP group | A 64-bit prime field | ristretto255 |
| ZKP interface | `ZKPEngine` functions | `ZkPredicateProver` with `PedersenBackend` and `StarkCoprocessorBackend` |
| Data input | Numbers on the command line | HL7 FHIR R4 bundles or servers, with LOINC and UCUM normalization, winsorization and imputation |
| Packing | One record per ciphertext | `RecordEnvelope` (horizontal) and `CohortBatch` (vertical) |
| `shred` command | Created a key, destroyed that same key and printed a certificate, with no effect on any real data | Destroys a persisted key, and fails if there is none |
| Multi-hospital | A function called in one process | A daemon: gRPC over mutual TLS, with signed messages and no central server |
| Consent | An in-process simulator | A trait with a file ledger and an EVM contract, `contracts/ConsentRegistry.sol` |
| Wasm interface | Hashes, AES-GCM, Ed25519 and Merkle roots | Those, plus `fhe-ops`: keygen, encrypt, decrypt, add and scalar multiply |
| `quantum-audit` | A formula with no basis, reporting `N = 128` as acceptable | A lookup in the HE Standard's published table |
| CI | Actions pinned to tags | Pinned to commits, with the repository guard, a demo run, and a documentation emoji check |
| Release | A Wasm file | A Wasm file and command line archives for Linux and macOS, with checksums and build provenance |
| Documentation | English only | English `README.md` and Korean `README.ko.md` |

### Added commands

`keygen`, `decrypt`, `batch-pack`, `ingest-fhir`, `cohort-merge`, `cohort-stats`, `pack-record`, `open-record`,
`consortium-init`, `daemon run` and `daemon status`.

### Security fixes

- `prove_threshold` did not prove what it claimed. It showed knowledge of an opening of `C / g^t`, and nothing about
  the difference being non-negative, so a dishonest prover could make a valid-looking proof for a false claim. The
  check that refused false statements ran only on an honest prover's own machine.
- The ZKP group was a 64-bit prime field, where a discrete logarithm can be computed on a laptop. That breaks both the
  binding of commitments and the soundness of proofs. Treat every proof from earlier versions as worthless.
- `GEN_G = 2` and `GEN_H = 5` had a discrete logarithm relation that was easy to find, which breaks binding by itself.
- `N = 128` with a 30-bit modulus offers no meaningful security. Treat anything encrypted by earlier versions as readable.
- `KeyManager::encrypt` replaced the key when a record was encrypted a second time, which made earlier envelopes for
  that record impossible to open. The key is now kept.
- `generate_evm_audit_calldata` used a hard-coded function selector. It is now computed with Keccak-256.
- The audit report tested the 128-bit condition before the 192-bit one, so the 192-bit branch could never be reached.

### Corrected claims

The previous README and example output showed a table with MedCrypto scoring Jaccard 0.5000+, PR-AUC 0.9167 and DDI
0.0000 "on MIMIC-III", and "+13.9% over SOTA". Those numbers came from one hand-written trajectory in the example,
with no dataset involved. On that same trajectory, `All` scored higher than `Top-1`, which the text said could not
happen. The comparison table is gone, because the baseline figures in it could not be traced to a source either. The
marketing line "ALL ... CHECKS PASSED (100%)" at the end of the demo is gone as well. The README now says what the
system does not do, in a section of its own.

### Known limits

See "Security model and limitations" in the README. The main ones: parties assumed honest but
curious; `StarkCoprocessorBackend` has been tested against a stand-in runner only, not against a real prover; and
TLS and Ed25519 are not post-quantum.

### Other

- Removed a compiled `.pyc` from the repository.
- Fixed the GitLab hygiene check, whose pattern matched any line of `=======` in source code.

---

## 0.2.0 (한국어)

토이 파라미터 기반의 단일 레코드 도구를 다기관 시스템으로 격상한 릴리스입니다.

### 호환성 깨짐

0.1.0으로 암호화했거나 증명한 데이터는 이 버전에서 읽을 수 없습니다. 아래 보안 수정 항목에서 보듯 보관할 가치도 없습니다.
파일 형식, `CKKSEngine` API, `prove`와 `shred` 명령이 모두 바뀌었습니다.

### 무엇이 무엇으로 바뀌었나

| 영역 | 이전 (0.1.0) | 이후 (0.2.0) |
| :--- | :--- | :--- |
| 링 차수 | `N = 128`, HE Standard가 다루는 범위보다 훨씬 작음 | `N = 8192` 또는 `16384`. 표준 한도를 넘는 파라미터는 거부 |
| 모듈러스 | 30비트 소수 1개 | RNS 체인: 60+40+40과 60비트 특수 소수(200비트), 또는 60+40x7+60(400비트) |
| 스케일 | `2^16` | `2^40` |
| 인코딩 | 값을 계수에 그대로 기록. 암호문끼리 곱해도 슬롯별 곱이 되지 않음 | 정준 임베딩(canonical embedding), 실수 슬롯 4096개 또는 8192개 |
| 다항식 곱셈 | 교과서 방식 `O(N^2)`, 128비트 나눗셈 | 네가사이클릭 NTT `O(N log N)`, Barrett/Shoup 축약 |
| 암호문 곱셈 | 없음 | `multiply`, `relinearize`, `rescale_to_next` |
| 회전 | 없음 | Galois 키 기반 `rotate`, `sum_slots` |
| 임상 스코어링 | 설명과 달리 다항식 합성곱을 수행해 해당 점수를 계산하지 못하던 `evaluate_linear_risk_model` | 실제 내적, `evaluate_cubic`, `evaluate_logistic` |
| 오차 샘플링 | 반올림한 부동소수 가우시안 | 중심 이항 분포, 표준편차 3.24 |
| 오류 처리 | panic과 assert | 모든 연산에서 `FheError` 반환, 외부 입력 전수 검증 |
| 크레이트 구성 | 1개 | `crates/medcrypto-fhe`, `crates/medcrypto-fhir` 추가. Wasm 컴포넌트가 FHE 코드를 공유 |
| 키 관리 | 비밀키 1개 | k-of-n 분산 키 생성과 임계 복호화 |
| 범위 증명 | 범위를 증명하지 못하는 Schnorr 개구 증명 | 비트 분해와 일대이(one-of-two) 증명을 범위 양쪽에 적용 |
| ZKP 그룹 | 64비트 소수체 | ristretto255 |
| ZKP 인터페이스 | `ZKPEngine` 함수 | `ZkPredicateProver`, `PedersenBackend`, `StarkCoprocessorBackend` |
| 데이터 입력 | 명령줄 숫자 | HL7 FHIR R4 번들 또는 서버, LOINC/UCUM 정규화, 윈저화, 결측치 대체 |
| 패킹 | 암호문당 레코드 1건 | `RecordEnvelope`(수평), `CohortBatch`(수직) |
| `shred` 명령 | 키를 만든 뒤 그 키를 지우고 인증서를 출력할 뿐, 실제 데이터에는 아무 영향이 없었음 | 저장된 키를 파기하고, 키가 없으면 실패 |
| 다기관 처리 | 한 프로세스 안의 함수 호출 | 데몬: gRPC + mTLS, 서명된 메시지, 중앙 서버 없음 |
| 동의 관리 | 프로세스 내부 시뮬레이터 | 파일 원장과 EVM 컨트랙트(`contracts/ConsentRegistry.sol`)를 지원하는 트레이트 |
| Wasm 인터페이스 | 해시, AES-GCM, Ed25519, 머클 루트 | 기존 기능에 `fhe-ops` 추가: 키 생성, 암호화, 복호화, 덧셈, 스칼라 곱 |
| `quantum-audit` | 근거 없는 공식, `N = 128`도 괜찮다고 보고 | HE Standard 공개 표 조회 |
| CI | 태그에 고정한 액션 | 커밋에 고정, 저장소 가드, 데모 실행, 문서 이모지 검사 추가 |
| 릴리스 | Wasm 파일 | Wasm 파일과 Linux, macOS용 CLI 압축 파일, 체크섬, 빌드 출처 증명 |
| 문서 | 영어만 | 영어 `README.md`, 한국어 `README.ko.md` |

### 추가된 명령

`keygen`, `decrypt`, `batch-pack`, `ingest-fhir`, `cohort-merge`, `cohort-stats`, `pack-record`, `open-record`,
`consortium-init`, `daemon run`, `daemon status`.

### 보안 수정

- `prove_threshold`는 주장한 내용을 증명하지 못했습니다. `C / g^t`의 개구를 안다는 사실만 보일 뿐 차이가 음수가 아니라는
  점은 보이지 못해서, 부정직한 증명자가 거짓 주장에 대해 유효해 보이는 증명을 만들 수 있었습니다. 거짓 진술을 거부하는
  검사는 정직한 증명자 자신의 컴퓨터에서만 실행되었습니다.
- ZKP 그룹이 64비트 소수체라 이산로그를 노트북으로 계산할 수 있었습니다. 커밋먼트의 결속성과 증명의 건전성이 모두
  깨집니다. 이전 버전의 증명은 모두 무효로 취급하세요.
- `GEN_G = 2`, `GEN_H = 5`는 이산로그 관계를 쉽게 찾을 수 있어 그 자체로 결속성을 깨뜨립니다.
- 30비트 모듈러스의 `N = 128`에는 의미 있는 보안이 없습니다. 이전 버전으로 암호화한 데이터는 읽힐 수 있다고 보세요.
- `KeyManager::encrypt`는 같은 레코드를 다시 암호화할 때 키를 교체해, 해당 레코드의 이전 엔벨로프를 열 수 없게
  만들었습니다. 이제 키를 유지합니다.
- `generate_evm_audit_calldata`는 하드코딩된 함수 셀렉터를 썼습니다. 이제 Keccak-256으로 계산합니다.
- 감사 보고서가 128비트 조건을 192비트 조건보다 먼저 검사해 192비트 분기에 도달할 수 없었습니다.

### 바로잡은 주장

이전 README와 예제 출력에는 MedCrypto가 "MIMIC-III에서" Jaccard 0.5000+, PR-AUC 0.9167, DDI 0.0000을 기록했고
"SOTA 대비 +13.9%"라는 표가 있었습니다. 이 수치는 데이터셋 없이 예제에 직접 작성한 궤적 1건에서 나온 값입니다. 같은
궤적에서 `All`이 `Top-1`보다 높게 나와, 본문 설명과도 맞지 않았습니다. 비교 표는 기준 모델 수치의 출처도 확인할 수 없어
삭제했습니다. 데모 끝의 "ALL ... CHECKS PASSED (100%)" 문구도 삭제했습니다. 이제 README에 시스템이 하지 못하는 일을 별도
절로 적어 두었습니다.

### 알려진 한계

README의 "보안 모델과 한계"를 참고하세요. 핵심은 다음과 같습니다. 참여자를 정직하지만 호기심
있는(honest but curious) 존재로 가정하며, `StarkCoprocessorBackend`는 실제 prover가 아닌 대역 러너로만 테스트했고, TLS와
Ed25519는 양자 내성이 아닙니다.

### 기타

- 저장소에 들어 있던 컴파일된 `.pyc`를 제거했습니다.
- `=======` 줄이 있는 소스 코드에 모두 걸리던 GitLab 위생 검사 패턴을 고쳤습니다.

---

## 0.1.0

- Added `medcrypto.wasm`, a WebAssembly Component with SHA-256, HKDF, AES-256-GCM, Ed25519, Merkle roots and audit
  chain links. The one binary runs from Python, TypeScript and Go, and it imports nothing at all. It has a checksum
  and a build provenance attestation.
- Security: the command line and the GUI used fixed constants as ZKP blinding factors, so anybody could recover a
  small committed value, such as a lab result, by trying each possibility. Each proof now gets a fresh blinding
  factor from the operating system's random source. Proofs made by earlier versions should be treated as exposing
  their values.
- Added a repository guard against supply chain tampering to CI, least-privilege workflow permissions, and
  commit-pinned actions in the new workflow.

## 0.0.1-beta

First release.
