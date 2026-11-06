# MedCrypto

[English](README.md) | **한국어**

병원들은 "우리 세 기관 당뇨 환자의 평균 HbA1c는 얼마인가?" 같은 질문에 함께 답하고 싶어 합니다. 하지만 개인정보 보호법 때문에 환자
기록을 한곳에 모을 수 없습니다. MedCrypto를 쓰면 어느 병원도, 다른 누구도 다른 병원의 기록을 보지 않은 채 답을 계산할 수 있습니다.

각 병원은 HL7 FHIR로 자기 EMR을 읽고, 결과를 암호화한 뒤, 암호문만 다른 병원에 보냅니다. 병원들은 아무것도 복호화하지 않은 채
암호문을 더합니다. 합계는 여러 병원이 협력해야만 복호화할 수 있고, 환자가 동의했으며 결과에 포함된 환자 수가 충분할 때만 공개됩니다.

```
 병원 A                         병원 B                          병원 C
 FHIR 서버                      FHIR 서버                       FHIR 서버
     |                              |                               |
     v                              v                               v
 정제, 가명화                   정제, 가명화                    정제, 가명화
 동의 여부로 필터링             동의 여부로 필터링              동의 여부로 필터링
 암호화 (RNS-CKKS)              암호화 (RNS-CKKS)               암호화 (RNS-CKKS)
     |                              |                               |
     +--------- gRPC + 상호 TLS로 암호문 교환, 중앙 서버 없음 --------+
                                    |
                 각 노드가 키 없이 암호문을 더함
                                    |
                 3개 중 임의의 2개 노드가 합계만 복호화
                                    |
                 환자 수 1500, 평균 HbA1c 7.106 %, 표준편차 1.370
```

Rust로 작성했으며, Python, TypeScript, Go에서 쓸 수 있는 WebAssembly Component를 하나 제공합니다.

> **현재 상태.** 실제 구현과 전 구간 테스트를 갖춘 연구용 소프트웨어이며, **독립적인 암호 감사를 받지 않았습니다.** 인증받은 의료기기가
> 아니고, 사용한다고 해서 HIPAA나 GDPR을 자동으로 준수하게 되지도 않습니다. 실제로 사용하기 전에
> [보안 모델과 한계](#16-보안-모델과-한계)를 읽으시고, 자체 검토 없이 실제 환자 데이터를 넣지 마세요.

## 목차

1. [5분 만에 보는 핵심 개념](#1-5분-만에-보는-핵심-개념)
2. [할 수 있는 일](#2-할-수-있는-일)
3. [설치와 빌드](#3-설치와-빌드)
4. [튜토리얼: 병원 한 곳](#4-튜토리얼-병원-한-곳)
5. [튜토리얼: 데몬으로 병원 세 곳 연결](#5-튜토리얼-데몬으로-병원-세-곳-연결)
6. [튜토리얼: 환자 기록 파기](#6-튜토리얼-환자-기록-파기)
7. [튜토리얼: 검사 수치가 범위 안에 있음을 증명](#7-튜토리얼-검사-수치가-범위-안에-있음을-증명)
8. [동형암호 상세](#8-동형암호-상세)
9. [패킹: 수평과 수직](#9-패킹-수평과-수직)
10. [FHIR 인제스천](#10-fhir-인제스천)
11. [영지식 증명과 양자 내성 백엔드](#11-영지식-증명과-양자-내성-백엔드)
12. [컨소시엄 데몬](#12-컨소시엄-데몬)
13. [임계 복호화](#13-임계-복호화)
14. [WebAssembly Component](#14-webassembly-component)
15. [Rust 라이브러리](#15-rust-라이브러리)
16. [보안 모델과 한계](#16-보안-모델과-한계)
17. [규제 항목 대응표](#17-규제-항목-대응표)
18. [성능](#18-성능)
19. [명령어 참조](#19-명령어-참조)
20. [파일 형식](#20-파일-형식)
21. [임상 AI 모듈과 GUI](#21-임상-ai-모듈과-gui)
22. [저장소 구조](#22-저장소-구조)
23. [테스트와 CI/CD](#23-테스트와-cicd)
24. [로드맵 현황](#24-로드맵-현황)
25. [문제 해결](#25-문제-해결)
26. [용어집](#26-용어집)
27. [라이선스](#27-라이선스)

---

## 1. 5분 만에 보는 핵심 개념

이 절을 읽는 데 암호학 배경지식은 필요 없습니다.

**동형암호**는 데이터를 암호화한 채로 계산하는 기술입니다. `Enc(5)`와 `Enc(7)`이라는 암호문이 있으면, 누구든 키 없이, 안에 든 숫자를
모른 채 `Enc(12)`를 만들 수 있습니다. MedCrypto는 CKKS라는 방식을 씁니다. 실수 벡터를 다루고 소수점 몇 자리까지 정확한 근사값을 내므로
검사 수치에 잘 맞습니다.

**슬롯**은 암호문 하나 안의 칸입니다. 여기서는 암호문 하나에 숫자 4096개가 들어가고, 암호문 둘을 더하면 칸별로 더해집니다. 그래서 연산
한 번으로 환자 수천 명을 처리할 수 있습니다.

**레벨**은 일종의 예산입니다. 곱셈을 한 번 할 때마다 잡음이 늘고, 그 잡음을 없애는 데 레벨을 하나 씁니다. 작은 파라미터에는 레벨이 2개
있어서 곱셈을 연달아 최대 두 번 할 수 있습니다. 덧셈과 회전은 레벨을 쓰지 않습니다. 통계는 덧셈만으로 계산하므로 아주 저렴합니다.

**임계 복호화**는 비밀키가 어디에도 통째로 존재하지 않는 방식입니다. 병원들이 함께 키를 만들고 각자 조각을 하나씩 갖습니다. 임의의 `k`곳이
모이면 복호화할 수 있고, `k - 1`곳은 아무것도 알아낼 수 없습니다. 그래서 어느 병원도 혼자서 다른 병원 데이터를 읽을 수 없고, 한 곳이
꺼져 있어도 작업은 멈추지 않습니다.

**영지식 증명**은 어떤 명제가 참이라는 사실만 납득시키고 다른 정보는 전혀 드러내지 않습니다. "이 환자의 HbA1c는 6.5% 이하다"를, 실제 값이
5.8%라는 사실을 드러내지 않고 검증할 수 있습니다.

**암호학적 파기(cryptographic shredding)**는 삭제권을 위한 기법입니다. 환자별 기록마다 별도의 키를 둡니다. 그 키를 파기하면 암호문 백업과 불변
원장에 남은 복사본을 포함해 기록의 모든 복사본이 읽을 수 없게 됩니다.

**양자 내성**은 미래의 대형 양자 컴퓨터에도 안전하다는 뜻입니다. CKKS는 효율적인 양자 공격이 알려지지 않은 격자 문제에 기반합니다. 빠른
증명, 서명, TLS 인증서에 쓰이는 타원곡선은 양자 컴퓨터를 견디지 못합니다. 어느 부분이 어느 쪽인지는 [16절](#16-보안-모델과-한계)에
분명히 적어 두었습니다.

---

## 2. 할 수 있는 일

| 기능 | 방법 | 위치 |
| :--- | :--- | :--- |
| 실수 벡터 암호 연산 | `N = 8192` 또는 `16384`의 RNS-CKKS. HE Standard 표 기준 양자 내성 128비트 | [`crates/medcrypto-fhe`](crates/medcrypto-fhe) |
| 곱셈, 재선형화, 재스케일 | 소수당 숫자 하나를 쓰는 하이브리드 키 스위칭 | [`ckks.rs`](crates/medcrypto-fhe/src/ckks.rs) |
| 슬롯 회전 | Galois 키, NTT 영역 순열로 적용 | [`ckks.rs`](crates/medcrypto-fhe/src/ckks.rs) |
| 암호문 상태 임상 스코어링 | 선형 모델, 3차 다항식, 로지스틱 곡선 | [`ckks.rs`](crates/medcrypto-fhe/src/ckks.rs) |
| 단독 키 보유자 없음 | k-of-n 키 생성과 임계 복호화 | [`threshold.rs`](crates/medcrypto-fhe/src/threshold.rs) |
| EMR 입력 | FHIR R4 파싱, LOINC, UCUM 변환, 윈저화, 결측치 대체 | [`crates/medcrypto-fhir`](crates/medcrypto-fhir) |
| 환자별 패킹과 코호트 패킹 | `RecordEnvelope`, `CohortBatch` | [`src/packing`](src/packing) |
| 범위 증명 | ristretto255 위의 Pedersen 커밋먼트, 외부 prover로 교체 가능 | [`src/zkp`](src/zkp) |
| 다기관 데몬 | gRPC + 상호 TLS, 서명된 메시지, 중앙 서버 없음 | [`src/consortium`](src/consortium) |
| 동의 관리 | 파일 원장, 또는 JSON-RPC를 통한 스마트 컨트랙트 | [`consent.rs`](src/consortium/consent.rs), [`ConsentRegistry.sol`](contracts/ConsentRegistry.sol) |
| 파기와 감사 | 레코드별 키를 요청 시 파기, 해시 체인 감사 로그 | [`src/compliance`](src/compliance/mod.rs) |
| 다른 언어 지원 | import가 전혀 없는 Wasm Component | [`component`](component) |

---

## 3. 설치와 빌드

안정 버전 Rust 툴체인이 필요합니다(1.99에서 테스트). gRPC 정의를 순수 Rust로 컴파일하므로 `protoc`은 필요 없습니다. 암호 연산을 위해 설치할
C 라이브러리도 없습니다.

```bash
git clone https://github.com/Aetherx86/medcrypto.git
cd medcrypto
cargo build --release
./target/release/medcrypto --help
```

Linux x86-64와 macOS ARM용 빌드는 각 [릴리스](https://github.com/Aetherx86/medcrypto/releases/latest)에 체크섬, 빌드 출처 증명과 함께
첨부됩니다.

**라이선스 검사 안내.** 소스 코드는 MIT 라이선스입니다. 이와 별개로 `medcrypto` 명령줄 바이너리는 시작할 때 `AETHER_LICENSE_KEY` 또는
`~/.aether/license.key`에서 Ed25519로 서명된 라이선스 토큰을 찾고, 없으면 종료합니다. 라이브러리 크레이트와 Wasm Component에는 이 검사가
없습니다. 토큰은 [포털](https://aetherx86.github.io/#products)에서 받을 수 있습니다.

먼저 합성 데이터로 전체 흐름을 보려면 다음을 실행합니다.

```bash
./target/release/medcrypto demo
```

---

## 4. 튜토리얼: 병원 한 곳

컴퓨터 한 대에서 FHIR 번들을 암호화 통계로 바꾸는 과정입니다. 아래 명령은 모두 적힌 그대로 실행해 확인했고, 데이터는 무작위 환자를 만드는
생성기에서 나옵니다.

**데이터 만들기.** 실제 다기관 데이터처럼 혈당 결과의 절반은 mg/dL, 절반은 mmol/L입니다.

```bash
cargo build --release --examples
./target/release/examples/make_sample_bundle 400 1 > site-a.json
./target/release/examples/make_sample_bundle 600 2 > site-b.json
```

**키 만들기.** 본인만 읽을 수 있는 `secret-key.json`과 공개 파일 3개(`public-key.json`, `galois-keys.json`, `relin-key.json`)를 만듭니다.

```bash
./target/release/medcrypto keygen --output-dir keys
```

**인제스천과 암호화.** `2339-0`과 `15074-8`은 단위만 다른 혈당 코드이므로 mg/dL 열 하나로 합쳐집니다.

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

파일 3개가 나오며, 각각 다루는 방법이 다릅니다.

| 파일 | 내용 | 보관 위치 |
| :--- | :--- | :--- |
| `a.ct.json` | 암호문. 식별자 없음 | 병원 밖으로 나가도 됨 |
| `a.ct.json.slots` | 어떤 슬롯에 어떤 가명이 있는지 | 병원 안에만 보관 |
| `a.ct.json.pseudonym-key` | 가명의 바탕이 되는 비밀값 | 병원 안에 보관, 분실 금지 |

**병원 B도 같은 작업을 하고, 병합한 뒤 계산합니다.** 병합은 배치를 모으기만 합니다. 마지막 명령 전까지는 아무것도 복호화되지 않고, 마지막
명령도 합계만 복호화합니다.

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

환자 수가 11명 미만인 결과는 기본적으로 공개하지 않습니다. `--min-cell-size`로 바꿀 수 있습니다.

이 튜토리얼에서는 키 보유자가 한 명이라 그 사람은 모든 것을 복호화할 수 있습니다. 아무도 혼자 복호화할 수 없는 실제 환경은 다음 절에서 다룹니다.

**파일 대신 실제 FHIR 서버에서** 가져오려면 `--endpoint`를 씁니다. Bearer 토큰은 셸 기록에 남지 않도록 환경 변수 `MEDCRYPTO_FHIR_TOKEN`에 넣습니다.

```bash
export MEDCRYPTO_FHIR_TOKEN=...
./target/release/medcrypto ingest-fhir \
  --endpoint "https://emr.hospital.org/fhir/R4" \
  --loinc-filter "8480-6,4548-4,2339-0" \
  --mode vertical \
  --output ./encrypted_cohort.json
```

**디렉터리의 `PatientRecord` JSON 파일에서** 가져오려면 `batch-pack`을 씁니다.

```bash
./target/release/medcrypto batch-pack \
  --input-dir ./patient_records/ \
  --batch-size 4096 \
  --output ./cohort_vertical_ct.json
```

`--public-key`를 주지 않으면 출력 파일 옆 `<output>.keys/`에 키를 새로 만들므로, 처음 시도할 때 추가 준비 없이 바로 동작합니다.

---

## 5. 튜토리얼: 데몬으로 병원 세 곳 연결

실제 데몬 3개를 한 컴퓨터에서 띄워 gRPC와 상호 TLS로 통신시키며, 임계값은 2-of-3입니다. 실제 배포에서는 각 데몬이 각 병원에서 돌고 엔드포인트만
달라집니다. 앞 절에서 만든 `site-a.json`, `site-b.json`을 사용합니다.

**1단계. 컨소시엄 생성.** 인증 기관, 노드별 인증서와 서명 키, 공용 `roster.json`, 노드별 `node.json`을 만듭니다. 이 부트스트랩의 주의점은
[12절](#부트스트랩과-주의점)을 보세요.

```bash
M=./target/release/medcrypto
$M consortium-init --out consortium --threshold 2 --nodes \
  hospital-a=https://127.0.0.1:7443,hospital-b=https://127.0.0.1:7444,hospital-c=https://127.0.0.1:7445
```

**2단계. 병원별 표 준비.** `--mode table`은 정제 파이프라인까지만 실행하고 암호화 전에 멈춥니다. 공동 키가 생기고 누가 동의했는지 알게 된 뒤에
데몬이 암호화합니다. 이 파일에는 환자 데이터가 있으므로 해당 병원 안에만 둡니다.

```bash
./target/release/examples/make_sample_bundle 500 3 > site-c.json
for s in a b c; do
  $M ingest-fhir --bundle site-$s.json \
    --loinc-filter 8480-6,4548-4,2339-0,15074-8 --mode table \
    --output consortium/hospital-$s/data/cohorts/diabetes-2026.json \
    --pseudonym-key consortium/hospital-$s/pseudonym.key
done
```

**3단계. 연구 정의.** 모든 병원이 공유하는 `consortium/studies.json`에 작성합니다.

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

**4단계. 동의 기록.** 이 튜토리얼에서는 모든 환자가 동의했고 연구는 아직 승인되지 않은 상태입니다. 실제 운영에서는 파일 대신
[12절](#동의-소스)의 스마트 컨트랙트를 씁니다.

```bash
UNTIL=$(($(date +%s)+31536000))
jq -s --argjson until $UNTIL '{
    studies: [{id: "diabetes-2026", epoch: 1, active: false}],
    consents: [.[].rows[].pseudo_id | {patient: ., scope: "DIABETES_STATISTICS", valid_until: $until, active: true}]
  }' consortium/hospital-*/data/cohorts/diabetes-2026.json > consortium/consent.json
```

**5단계. 데몬 시작.** 터미널 3개에서 실행합니다. 데몬끼리 분산 키 생성을 수행하고(수 초 소요) 대기합니다.

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

**6단계. 연구 승인.** 이것이 유일한 트리거입니다. 서버가 없으므로 서버에 명령을 보내는 사람도 없습니다.

```bash
jq '.studies[0].active = true' consortium/consent.json > c.tmp && mv c.tmp consortium/consent.json
```

몇 초 안에 각 데몬이 동의 여부로 표를 필터링하고, 암호화하고, 암호문을 교환하고, 더하고, 해시를 비교한 뒤, 부분 복호화 2개로 결과를 공개합니다.

```bash
cat consortium/hospital-b/data/results/*.json | jq -c '.analytes[]'
```

```json
{"status":"released","analyte":"systolic_bp","unit":"mm[Hg]","count":1500,"mean":135.2394,"variance":424.722,"standard_deviation":20.6088}
{"status":"released","analyte":"hba1c","unit":"%","count":1500,"mean":7.1062,"variance":1.8775,"standard_deviation":1.3702}
{"status":"released","analyte":"glucose","unit":"mg/dL","count":1500,"mean":134.2220,"variance":1418.5607,"standard_deviation":37.6638}
```

각 노드에는 자신이 기여하고 공개한 내용을 기록한 해시 체인 `data/audit.json`도 생깁니다.

이어서 해 볼 만한 실험: 새 epoch를 승인하기 전에 환자 한 명의 동의를 철회해 환자 수가 줄어드는지 확인하기, `min_cell_size`를 코호트보다 크게 잡아
결과가 `suppressed`로 나오는지 확인하기, 키 생성 후 데몬 하나를 끄고 나머지 둘만 참여하는 연구가 끝까지 진행되는지 확인하기.

---

## 6. 튜토리얼: 환자 기록 파기

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

이제 FHE 비밀키와 엔벨로프를 모두 갖고 있어도 `open-record`는 실패하고, 이후 어떤 프로세스에서도 마찬가지입니다. 키가 없는 레코드를 파기하려 하면
오류가 나고 인증서도 발급되지 않습니다.

이 기능이 미치는 범위를 알아 두세요.

- 해당 **엔벨로프**의 모든 복사본에는 효력이 있습니다. 어디로 복사되었든 모두 파기된 키가 필요하기 때문입니다.
- 키 저장소 자체의 백업에는 효력이 **없습니다.** 기본 저장소는 파일이고, SSD나 저널링 파일 시스템은 이전 블록을 남길 수 있습니다. 실제 운영에서는
  삭제를 신뢰할 수 있는 HSM이나 KMS를 쓰세요.
- **수직 배치**에는 효력이 **없습니다.** 키 하나가 많은 환자를 담기 때문입니다. `.slots` 파일을 이용해 해당 환자를 뺀 배치를 다시 만드세요. 이미 공개된
  통계는 되돌릴 수 없습니다.

---

## 7. 튜토리얼: 검사 수치가 범위 안에 있음을 증명

```bash
M=./target/release/medcrypto
$M prove --metric hba1c --value 58 --threshold 65 --output proof.json
$M verify --proof-file proof.json
```

```text
[VERIFIED] The proof is valid.
The committed value is at most 65, with nothing else revealed about it.
```

값은 정수로 스케일링합니다. 여기서 58은 5.8%를 뜻합니다. 18세 이상처럼 "이상"을 증명하려면 `--lower-bound`를 씁니다.

거짓 주장에는 증명이 만들어지지 않고, 증명 파일의 임계값을 고치면 검증에 실패합니다. 이 범위에서 증명 크기는 2,242바이트입니다.

프로덕션에서는 양자 내성 백엔드를 요청합니다. 프로덕션 프로파일에서 Pedersen 백엔드는 거부됩니다.

```bash
$M prove --value 58 --threshold 65 --profile production
# [ERROR] proof backend: the production profile needs a STARK runner: the Pedersen backend is not post-quantum

$M prove --value 58 --threshold 65 --profile production --backend stark \
  --guest-elf ./guest.elf --runner ./my-sp1-runner
```

---

## 8. 동형암호 상세

### 파라미터

| 프리셋 | `N` | 슬롯 | 체인(비트) | 특수 소수 | 전체 `log QP` | 양자 128비트 한도 | 곱셈 횟수 |
| :--- | ---: | ---: | :--- | ---: | ---: | ---: | ---: |
| `N8192` | 8192 | 4096 | 60, 40, 40 | 60 | 200 | 202 | 2 |
| `N16384` | 16384 | 8192 | 60, 40 x 7 | 60 | 400 | 411 | 7 |

한도는 Homomorphic Encryption Standard의 3진 비밀키 표이며, Microsoft SEAL의 `hestdparms.h`에 공개된 값과 대조했습니다. `CkksParams::validate`가 이를
강제하므로, 체인이 너무 길면 보안이 조용히 낮아지는 대신 오류가 납니다. 기본 스케일은 `2^40`입니다. 비밀키는 균등 3진, 오차는 표준편차 3.24의 중심 이항
분포로, 표가 가정하는 3.2에 가깝습니다.

`medcrypto quantum-audit`이 같은 검사를 보여 줍니다. 이 명령은 공개된 표를 읽을 뿐, 격자 추정기를 실행하지는 않습니다.

### 코드 구성

| 계층 | 파일 | 내용 |
| :--- | :--- | :--- |
| 워드 연산 | [`arith.rs`](crates/medcrypto-fhe/src/arith.rs) | 마스크 기반 조건부 뺄셈을 쓰는 Barrett, Shoup 축약, 결정적 Miller-Rabin, NTT 소수 탐색 |
| 변환 | [`ntt.rs`](crates/medcrypto-fhe/src/ntt.rs) | 네가사이클릭 NTT, Galois 순열 |
| 파라미터 | [`params.rs`](crates/medcrypto-fhe/src/params.rs) | 프리셋, 표준 표, 검증 |
| 인코딩 | [`encoder.rs`](crates/medcrypto-fhe/src/encoder.rs) | `5^j` 슬롯 순서를 쓰는 정준 임베딩 |
| 다항식 | [`rns.rs`](crates/medcrypto-fhe/src/rns.rs) | RNS 표현. JSON에서는 16진수, 바이너리에서는 원시 바이트 |
| 스킴 | [`ckks.rs`](crates/medcrypto-fhe/src/ckks.rs) | 나머지 전부 |
| 임계 | [`threshold.rs`](crates/medcrypto-fhe/src/threshold.rs) | 참여자 간 키 생성과 복호화 |

크레이트에는 `#![forbid(unsafe_code)]`가 걸려 있고 C 의존성이 없습니다.

### RNS를 쓰는 이유

암호문 모듈러스 `Q`는 각각 머신 워드에 들어가는 소수들의 곱입니다. 중국인의 나머지 정리에 따라 `Q`를 법으로 하는 수는 소수별 나머지 하나씩으로 저장할 수
있고, 덧셈과 곱셈은 나머지마다 따로 수행하면 되므로 큰 정수 연산이 전혀 필요 없습니다. NTT와 결합하면 다항식 곱셈 비용은 소수당 `O(N log N)`번의 워드 곱셈입니다.
체인의 마지막 소수는 재스케일의 나눗수로 그대로 쓰입니다.

### 연산

| 연산 | 함수 | 레벨 비용 | 필요한 키 | 비고 |
| :--- | :--- | ---: | :--- | :--- |
| 덧셈, 뺄셈 | `add`, `sub` | 0 | 없음 | 레벨과 스케일이 같아야 함. 다르면 오류 |
| 상수 더하기 | `add_constant` | 0 | 없음 | 모든 슬롯에 |
| 정수 곱하기 | `scalar_mul` | 0 | 없음 | |
| 소수 곱하기 | `scalar_mul` | 1 | 없음 | 스케일이 정확히 복원됨 |
| 평문 가중치 곱하기 | `multiply_plain_rescale` | 1 | 없음 | 슬롯별 |
| 암호문끼리 곱하기 | `multiply` | 0, 재스케일 시 1 | 없음 | 차수 2가 됨 |
| 재선형화 | `relinearize` | 0 | `RelinKey` | 차수 2를 1로 |
| 재스케일 | `rescale_to_next` | 1 | 없음 | 마지막 소수로 나눔 |
| 회전 | `rotate` | 0 | 해당 스텝의 `GaloisKey` | 음수는 오른쪽으로 |
| 전체 슬롯 합 | `sum_slots` | 0 | 2의 거듭제곱 `GaloisKey` | 회전 `log2(slots)`번 |
| 연합 평균 | `federated_average` | 0 | 없음 | 더한 뒤 기록된 스케일에 개수를 곱함 |
| 선형 점수 | `evaluate_linear_risk_model` | 1 | `GaloisKey` | 모든 슬롯에 `sum(w * x) + bias` |
| 3차식 | `evaluate_cubic` | 2 | `RelinKey` | |
| 로지스틱 | `evaluate_logistic` | 2 | `RelinKey` | `0.5 + 0.15012 x - 0.001593 x^3`, `[-8, 8]`에서만 유효 |
| 레벨 낮추기 | `mod_switch_to_level` | 임의 | 없음 | 두 암호문의 레벨을 맞출 때 |

### 키 스위칭

재선형화와 회전은 모두 암호문 일부를 다른 비밀키 아래로 옮겨야 합니다. 여기서는 암호문 소수당 숫자(digit) 하나와 특수 소수 `P` 하나를 쓰는 하이브리드 키
스위칭을 사용합니다. 각 숫자 `i`에 대해 키는 `(b_i, a_i)`를 갖고 `b_i = -a_i s + e_i + P * s'`이며, 마지막 항은 소수 `q_i`에만 있습니다. 스위칭은 다항식을
나머지별로 나눠 각각에 키를 곱하고 `Q * P` 위에서 모두 더한 뒤 `P`로 나누는데, 이때 잡음이 대부분 사라집니다. `P`를 가장 큰 소수로 두어 남은 잡음이 스케일보다
충분히 작도록 합니다.

### 변환 없는 회전

자기동형사상 `X -> X^g`는 다항식의 평가점을 치환할 뿐입니다. 따라서 NTT 영역에서 회전은 변환 없이 표 조회만으로 끝나며,
[`galois_permutation`](crates/medcrypto-fhe/src/ntt.rs)이 그 표를 계산합니다. 테스트에서 계수 영역 정의와 대조합니다.

전체 슬롯 합은 배가(doubling)를 씁니다. 암호문에 1칸 회전한 자신을 더하고, 그 결과에 2칸 회전한 자신을 더하고, 4칸, 이런 식으로 진행합니다.
`log2(slots)`번 후에는 **모든 슬롯에 합계가 들어갑니다.** 통계의 임계 복호화가 안전한 이유가 여기에 있습니다. 복호화되는 값에 개별 값이 남아 있지 않습니다.

### 스케일 맞추기

재스케일은 `2^40`에 가깝지만 같지는 않은 소수로 나누므로 스케일이 조금씩 어긋납니다. 스케일이 다른 두 암호문을 더하면 틀린 답이 나오므로, `add`는 차이가
`10^9`분의 1을 넘으면 거부합니다. 엔진은 가능한 곳에서 이 문제를 피합니다. `multiply_plain_rescale`과 소수 `scalar_mul`은 상수를 버려질 소수와 정확히 같은
스케일로 인코딩하므로 스케일이 그대로 돌아옵니다. `evaluate_cubic`은 항마다 다른 상수를 골라 모든 항이 정확히 같은 최종 스케일에 도달하게 합니다.

`N = 8192`에서 `0.25 x^3 - 0.5 x^2 + 2 x + 1`의 레벨 예산 예시입니다.

```
레벨 2:  스케일 2^40의 x
         x * x, 재선형화와 재스케일         -> 레벨 1의 x^2
         x * 0.25, 재스케일                 -> 레벨 1의 0.25 x
레벨 1:  x^2 * 0.25 x, 재선형화와 재스케일  -> 레벨 0, 스케일 t의 0.25 x^3
         x^2 * -0.5, 재스케일, 상수 선택    -> 레벨 0, 스케일 t의 -0.5 x^2
         x * 2 (x를 먼저 한 레벨 낮춤), 동일 -> 레벨 0, 스케일 t의 2 x
레벨 0:  세 항을 더하고, 스케일 t로 상수 1을 더함
```

### 정밀도와 용량

- 수백 단위 값의 새 암호문은 복호화 오차가 `10^-5` 미만이며, 테스트에서 이를 검증합니다.
- 값의 크기는 해당 레벨의 모듈러스가 제한합니다. 인코딩은 들어가지 않는 계수를 조용히 넘기지 않고 거부합니다. `N8192`의 레벨 0에서는 60비트 소수만 남고 스케일이
  `2^40`이므로 한도가 약 `2^19`입니다. 코호트 합계를 최상위 레벨에 유지하는 이유입니다.
- 곱셈은 곱의 스케일이 남은 모듈러스에 들어가지 않으면 거부합니다.
- 반복 제곱에서는 잡음이 값과 함께 자라므로 상대오차로 판단해야 합니다. `N16384`에서 1.1을 7번 제곱하면 상대오차가 약 `10^-6`입니다.

### 로드맵 초안과 달라진 API

로드맵은 `rotate`, `relinearize`, `rescale_to_next`가 값을 그대로 반환하도록 제안했습니다. 여기서는 오래 실행되는 데몬에서 잘못된 입력이 panic이 아니라 오류가
되도록 `Result`를 반환합니다. `steps`는 `i64`입니다.

---

## 9. 패킹: 수평과 수직

두 방식은 서로 반대되는 문제를 풀기 때문에 둘 다 필요합니다.

| | 수평: `RecordEnvelope` | 수직: `CohortBatch` |
| :--- | :--- | :--- |
| 암호문 하나에 담기는 것 | 환자 한 명의 여러 항목 | 항목 하나의 환자 최대 4096 또는 8192명 |
| 적합한 용도 | 환자 한 명 스코어링, 파기 | 코호트 통계 |
| 외부 키 | 환자별 AES-256-GCM | 없음 |
| 파기 | 키 파기 | 배치 재구성 |
| 환자 1000명, 항목 3개일 때 | 암호문 1000개 | 암호문 9개 |

```
                 나이  수축기 hba1c  혈당
 환자 1     [    54    128   5.8    110    ]  <- 수평: 행마다 암호문 하나
 환자 2     [    61    140   7.1    160    ]
 환자 3     [    47    119   5.4     95    ]
                  ^     ^     ^      ^
                  수직: 열마다 암호문 하나
```

### 수직 패킹

항목과 환자 배치마다 암호문이 3개 있습니다.

| 암호문 | 슬롯 `i`의 내용 | 슬롯 합으로 얻는 값 |
| :--- | :--- | :--- |
| `values` | 환자 `i`의 값, 없으면 0 | `sum` |
| `squares` | 그 값의 제곱 | `sum_of_squares` |
| `presence` | 환자 `i`에게 값이 있으면 1, 없으면 0 | `count` |

그러면 `mean = sum / count`, `variance = (sum_of_squares - sum^2 / count) / (count - 1)`입니다. 존재 마스크 덕분에 결측치를 0으로 세지 않고 제외할 수 있습니다.
제곱은 병원에서 암호화 전에 계산하므로, 집계에 곱셈도 공동 비밀키의 재선형화 키도 필요 없습니다.

코호트가 `--batch-size`보다 크면 여러 배치로 나뉩니다. 배치 크기는 슬롯 수를 넘을 수 없습니다.

두 코호트 병합은 연산 없이 배치만 모읍니다. 한 병원의 7번 슬롯과 다른 병원의 7번 슬롯은 서로 다른 사람이기 때문입니다. 항목이나 단위가 다른 코호트는 병합을
거부합니다.

### 수평 패킹

`RecordEnvelope::seal`은 환자 벡터를 CKKS로 암호화한 뒤 그 바이트를 해당 레코드 전용 키의 AES-256-GCM으로 감쌉니다. 파기 기능은 AES 계층이 제공하고, 계산
중인 데이터는 CKKS가 계속 보호합니다.

`ingest-fhir --mode horizontal`에서 결측치는 0으로 들어가고, `<analyte>.present` 슬롯이 실제 값 여부를 기록합니다.

---

## 10. FHIR 인제스천

[`crates/medcrypto-fhir`](crates/medcrypto-fhir)는 암호 코드에 의존하지 않는 별도 크레이트입니다. 출력은 평범한 표입니다.

### 파이프라인 순서

1. **가져오기 또는 읽기.** `GET {endpoint}/Observation?code=http://loinc.org|...&_include=Observation:subject&_count=500`, `next` 링크를 따라갑니다.
2. **파싱.** `Patient`, `Observation`(혈압 패널의 `component` 포함), `Condition`. 다른 리소스는 세고 건너뜁니다.
3. **상태 필터.** `final`, `amended`, `corrected`만 사용합니다. `entered-in-error`, `preliminary` 등은 제외하고 셉니다.
4. **불완전한 결과 제외.** 숫자 값이 없거나, LOINC 코드가 없거나, 대상이 환자가 아니거나, `<40`처럼 실제 값이 표시된 숫자가 아닌 경우입니다.
5. **단위 변환.** 항목의 표준 단위로 변환합니다. 모르는 단위는 제외하고 세며 절대 추측하지 않습니다. mmol/L를 mg/dL로 착각하면 18배 차이가 납니다.
6. **타당성 검사.** 타당 범위를 벗어난 값은 대개 단위 오류이므로 오류로 보고 제외합니다.
7. **최신 값 선택.** 환자와 항목별로 최신 결과를 고릅니다. 같은 항목의 코드는 열 하나로 합칩니다.
8. **윈저화.** `--winsorize clinical`(기본값)은 카탈로그 한도로, `p1p99`는 코호트의 1, 99 백분위로 값을 잘라 내고, `off`는 그대로 둡니다.
9. **결측치 대체.** `--impute none`(기본값)은 결측으로 남기고, `median`과 `mean`은 채웁니다. 대체값도 존재로 집계되어 분산을 낮추므로 연합 통계에는 기본값을 쓰세요.
10. **가명화.** `HMAC-SHA256(병원 비밀값, 환자 ID)`입니다. 단순 해시로는 모든 등록번호를 해시해 볼 수 있으므로 부족합니다. 행을 가명순으로 정렬해 슬롯 순서로
    등록번호나 입원 순서를 알 수 없게 합니다.

각 단계의 건수는 항목별 품질 보고서에 나타나므로 연구 보고에 그대로 쓸 수 있습니다.

### LOINC 카탈로그

| 항목(`id`) | 표준 단위 | LOINC 코드 | 허용 단위 |
| :--- | :--- | :--- | :--- |
| 수축기 혈압(`systolic_bp`) | `mm[Hg]` | 8480-6 | `mm[Hg]`, `mmHg`, `kPa` |
| 이완기 혈압(`diastolic_bp`) | `mm[Hg]` | 8462-4 | `mm[Hg]`, `mmHg`, `kPa` |
| 당화혈색소, NGSP(`hba1c`) | `%` | 4548-4, 17856-6, 59261-8 | `%`, `mmol/mol` |
| 혈당(`glucose`) | `mg/dL` | 2339-0, 2345-7, 15074-8, 14749-6 | `mg/dL`, `mmol/L`, `g/L` |
| 공복 혈당(`fasting_glucose`) | `mg/dL` | 1558-6, 14771-0 | `mg/dL`, `mmol/L`, `g/L` |
| 총콜레스테롤(`total_cholesterol`) | `mg/dL` | 2093-3, 14647-2 | `mg/dL`, `mmol/L`, `g/L` |
| LDL(`ldl_cholesterol`) | `mg/dL` | 2089-1, 13457-7, 18262-6, 22748-8 | `mg/dL`, `mmol/L`, `g/L` |
| HDL(`hdl_cholesterol`) | `mg/dL` | 2085-9, 14646-4 | `mg/dL`, `mmol/L`, `g/L` |
| 중성지방(`triglycerides`) | `mg/dL` | 2571-8, 14927-8 | `mg/dL`, `mmol/L`, `g/L` |
| 크레아티닌(`creatinine`) | `mg/dL` | 2160-0, 14682-9 | `mg/dL`, `umol/L`, `mmol/L` |
| 사구체여과율(`egfr`) | `mL/min/{1.73_m2}` | 33914-3, 48642-3, 48643-1, 62238-1, 98979-8 | `mL/min/{1.73_m2}`, `mL/min/1.73m2`, `mL/min` |
| 체질량지수(`bmi`) | `kg/m2` | 39156-5 | `kg/m2` |
| 체중(`body_weight`) | `kg` | 29463-7, 3141-9 | `kg`, `g`, `[lb_av]`, `lb` |
| 신장(`body_height`) | `cm` | 8302-2, 8306-3 | `cm`, `m`, `[in_i]`, `in` |
| 심박수(`heart_rate`) | `/min` | 8867-4 | `/min`, `{beats}/min`, `{beat}/min`, `bpm` |
| 체온(`body_temperature`) | `Cel` | 8310-5 | `Cel`, `C`, `[degF]`, `F` |

몰 농도 변환은 분자마다 다릅니다. 포도당 180.156 g/mol, 콜레스테롤 386.65 g/mol, 중성지방 885.7 g/mol(트리올레인 기준), 크레아티닌 113.12 g/mol을 씁니다. HbA1c의
IFCC에서 NGSP로의 변환은 마스터 방정식 `% = 0.09148 * mmol/mol + 2.152`를 씁니다.

타당 범위와 임상 한도는 [`terminology.rs`](crates/medcrypto-fhir/src/terminology.rs)에 있습니다. 데이터 정제를 위한 공학적 기본값이며 **임상 참고치가 아니므로**,
배포 환경에 맞게 검토하세요. 카탈로그에 없는 코드는 정규화 없이 통과시키지 않고 거부합니다.

### 클라이언트가 거부하는 것

서버의 데이터 외에는 서버를 신뢰하지 않습니다.

- `http://`. 단, 호스트가 로컬이거나 `--allow-insecure-http`를 준 경우는 제외합니다.
- 다른 출처(origin)로 가는 `next` 링크. 무엇이든 보내기 전에 검사하므로, 악의적인 응답이 Bearer 토큰을 수집하거나 내부 주소에 접근할 수 없습니다.
- 리다이렉트. 검사하지 않은 곳으로 토큰이 전달될 수 있기 때문입니다.
- 자격 증명이 포함된 URL.
- 1000페이지 초과, 또는 256 MiB를 넘는 페이지.

---

## 11. 영지식 증명과 양자 내성 백엔드

모든 증명은 작은 인터페이스 하나를 거치므로, 사용하는 쪽을 건드리지 않고 증명 시스템을 교체할 수 있습니다.

```rust
pub trait ZkPredicateProver {
    fn prove_range(&self, val: u64, min: u64, max: u64) -> Result<ZkProof, CryptoError>;
    fn verify_range(&self, proof: &ZkProof, min: u64, max: u64) -> bool;
}
```

| 백엔드 | 가정 | 양자 내성 | 필요한 것 | 용도 |
| :--- | :--- | :--- | :--- | :--- |
| `PedersenBackend` | ristretto255의 이산로그 | 아니요 | 없음 | 병원 내부 개발과 테스트 |
| `StarkCoprocessorBackend` | prover에 따라 다름. 보통 해시 기반 | 러너가 그러하면 | 외부 러너와 guest 프로그램 | 감사와 프로덕션 |

`--profile production`은 `backend_for_profile`을 통해 `PedersenBackend`를 거부합니다.

### Pedersen 범위 증명의 원리

커밋먼트 `C = v G + r H`의 `v`에 대해 `min <= v <= max`를 증명하려면, 증명자는 `a = v - min`과 `b = max - v`를 모두 `n`비트로 씁니다. `n`은 `max - min`을 표현할
만큼 잡습니다.

1. 각 비트에 커밋먼트 `C_i = bit * G + r_i * H`와, 그것이 0 또는 1로 열린다는 일대이 Schnorr 증명을 붙입니다. 거짓인 쪽은 시뮬레이션하므로 어느 비트인지 드러나지
   않습니다.
2. 비트 커밋먼트의 합이 맞도록 블라인딩을 고릅니다. `sum(2^i C_a,i) = C - min G`, `sum(2^i C_b,i) = max G - C`.
3. 모든 챌린지는 커밋먼트, 범위, 비트 번호, 방향에 대한 SHA-512로 만듭니다(Fiat-Shamir).

`a`와 `b`는 모두 그룹 위수보다 훨씬 작은 음이 아닌 정수이므로 순환(wrap-around)이 불가능하고, 둘이 함께 `v`를 범위 안에 고정합니다. `H`는 해시에서 만들어 `G`에 대한
이산로그를 아무도 모릅니다. 증명 크기는 `2n * 160`바이트에 프레이밍을 더한 값이며, `[0, 65]`는 2.2 KiB, 32비트 범위는 10 KiB입니다.

### STARK 러너 프로토콜

어댑터는 별도 실행 파일과 파이프를 통한 JSON으로 통신합니다. 명령줄은 다른 프로세스에 보이므로 비밀값은 표준 입력으로 보냅니다.

```text
runner info                     -> {"system": "...", "post_quantum": true, "zero_knowledge": true}
runner prove  --elf GUEST.elf   <- {"value": 58, "min": 0, "max": 65}
                                -> {"commitment": "hex", "proof": "hex"}
runner verify --elf GUEST.elf   <- {"commitment": "hex", "proof": "hex", "min": 0, "max": 65}
                                -> {"valid": true}
```

어댑터가 강제하는 규칙이며, 모두 실패 시 거부(fail-closed)로 동작합니다.

- 러너는 `post_quantum`과 `zero_knowledge`를 **둘 다** 선언해야 합니다. STARK라고 해서 저절로 영지식이 되지는 않습니다. 많은 zkVM 증명은 간결하기만 해서 증명이 바로 그
  값을 누출할 수 있고, 이를 숨기려 Groth16으로 감싸면 타원곡선이 다시 들어옵니다. **선택한 시스템에서 이 속성을 직접 확인하세요.**
- 증명은 정확히 하나의 guest 프로그램 SHA-256에 묶입니다.
- 러너가 없거나, 고장 났거나, 시간을 초과하면 검증은 `false`를 반환합니다.

**테스트한 것과 하지 않은 것.** 어댑터 테스트는 프로토콜만 따르고 아무것도 증명하지 않는 대역 셸 스크립트를 씁니다. 배관(plumbing)과 거부 규칙만 검증합니다. **실제
prover를 연결해 실행해 본 적은 없고**, [`zk/guest-range`](zk/guest-range)는 SP1 툴체인 없이 작성해 컴파일하지 않은 템플릿입니다. 배포하려면 사용할 prover를 감싸 이
프로토콜을 말하는 작은 호스트 프로그램을 작성하세요.

### zk-HyperVM이 양자 내성 백엔드가 아닌 이유

이전 로드맵은 이 자리에 zk-HyperVM을 지목했지만 맞지 않습니다. zk-HyperVM은 Shor 알고리즘에 깨지는 BN254 타원곡선 커밋먼트 위에서 폴딩하고, 하이퍼바이저 상태 전이를
증명하며, guest 프로그램용 러너가 없습니다. 두 프로젝트는 별개의 도구로 남습니다. 이 자리에 필요한 것은 SP1 계열이나 다른 해시 기반 시스템입니다.

---

## 12. 컨소시엄 데몬

### 단계별 동작

```
 1. 키 생성         모든 노드, 한 번.
                    공개 조각을 공표하고, 다른 노드마다 비밀 조각을 보냄.
                    키 조각과 공동 키를 저장.

 2. 트리거          노드의 동의 소스가 연구의 해당 epoch를 활성으로 보고.

 3. 기여            각 참여자: 표를 읽고, 동의 범위에 든 환자만 남기고, 암호화하고,
                    표시 파일을 쓰고, 모두에게 전송.

 4. 집계            모든 참여자의 코호트가 모이면: 고정된 순서로 병합하고 슬롯을 합산.
                    결정적 연산이므로 정직한 노드는 같은 바이트를 얻음.
                    결과의 해시를 알림.

 5. 공개: 환자 수   k개 노드가 같은 해시를 알리면, 그중 가장 낮은 k개 노드가 환자 수의
                    부분 복호화를 공표. 그 전에 연구 승인을 다시 확인.

 6. 공개: 합계      환자 수 >= min_cell_size인 항목에 대해 합계도 같은 단계를 수행.
                    나머지는 비공개 처리.

 7. 결과            results/<job>.json을 쓰고 감사 체인에 추가.
```

작업 식별자는 연구의 `id`와 `epoch`에서 만들어지므로 모든 노드가 각자 같은 값을 도출합니다. 연구를 다시 실행하려면 새 epoch를 씁니다.

메시지 순서가 바뀌어도 문제없습니다. 집계보다 먼저 도착한 부분 복호화는 집계가 준비될 때까지 보관합니다. 꺼져 있는 노드로의 전달은 최대 1시간 재시도합니다.

### 모든 메시지에 대한 신뢰 검사

1. **TLS.** 연결의 양쪽 모두 인증서가 컨소시엄 CA로 이어져야 합니다.
2. **로스터.** 인증서의 SHA-256이 로스터에 적힌 발신자의 값과 같아야 합니다. CA조차 모든 노드의 로스터를 바꾸지 않고는 구성원을 추가할 수 없습니다.
3. **서명.** Ed25519 서명이 컨소시엄, 발신자, 수신자, 페이로드 해시를 포함해야 합니다. 따라서 녹화된 메시지를 다른 노드나 다른 컨소시엄에 재전송할 수 없습니다.
4. **프로토콜.** 조각이나 부분 복호화는 주장한 참여자의 것이어야 합니다. 암호문은 사용 전에 모든 나머지가 소수보다 작은지까지 전수 검증합니다.

gRPC 서비스는 [`proto/consortium.proto`](proto/consortium.proto)에 정의되어 있으며 `protoc` 없이 컴파일됩니다.

### 프라이버시 검사

- **환자별 동의.** 기여 시점에 확인합니다. 조회 실패는 거부로 처리합니다.
- **연구 승인.** 작업 시작 전과 각 부분 복호화 전에 확인합니다. 기여가 끝난 뒤 철회된 연구는 복호화되지 않으며, 테스트로 확인합니다.
- **해시 일치.** 다른 합계를 계산한 노드는 임계값에 포함되지 않습니다.
- **합계만 복호화.** `sum_slots`가 부분 복호화 전에 개별 값을 없앱니다.
- **최소 셀 크기.** 환자 수가 너무 적은 결과를 비공개 처리합니다. 보건 통계에서 흔히 쓰는 11을 시작점으로 하되, 실제 값은 컴플라이언스 팀과 정하세요.

### 동의 소스

**파일**(`type: file`)은 조회할 때마다 새로 읽으므로 철회가 즉시 반영됩니다. 이 파일에 쓸 수 있는 사람이 동의를 통제하므로, 테스트나 자체 접근 통제를 갖춘 배포에 맞습니다.

**스마트 컨트랙트**(`type: evm`)는 [`contracts/ConsentRegistry.sol`](contracts/ConsentRegistry.sol)을 씁니다. 노드는 `eth_call`만 하므로 지갑도 비용도 필요 없습니다.
식별자는 Keccak-256 해시로 올라가므로 건강 정보는 체인에 올라가지 않습니다. `node.json`에 다음처럼 설정합니다.

```json
"consent": {
  "type": "evm",
  "rpc_url": "https://your-node.example",
  "contract": "0x5FbDB2315678afecb367f032d93F642f64180aa3"
}
```

원격 RPC는 https여야 합니다. 빈 응답, revert, 정확히 `true`가 아닌 값은 모두 거부로 처리합니다.

가명을 해시해도 익명이 되지는 않습니다. 가명 목록을 가진 쪽은 알아볼 수 있기 때문입니다. 공개 체인의 가명 해시가 GDPR상 개인정보인지는 실제로 따져 봐야 할 문제이므로,
허가형 체인을 쓰거나 법률 자문을 받으세요. 컨트랙트 감사 없이 이 컨트랙트를 배포하지 마세요.

컨트랙트는 Foundry의 `anvil`로 실제 로컬 체인에서 테스트했습니다. 이 테스트는 Foundry가 있을 때만 실행되고 없으면 건너뛰며, CI 러너도 건너뜁니다.

### 부트스트랩과 주의점

`consortium-init`은 편리하며 파일럿이나 한 조직 내 시험 환경에 적합합니다. **이 명령을 실행한 사람은 모든 노드의 TLS와 서명 비밀키를 본 셈입니다.** 실제 기관 간에는 각
기관이 자체 키를 만들고 인증서 요청만 서명받아야 하며, 로스터는 별도 경로로 합의해야 합니다. 임계 비밀키는 데몬들이 직접 만들므로 영향받지 않습니다.

병원별로 나눠 줄 때는 해당 병원의 디렉터리와 `ca.pem`, `roster.json`, `studies.json`을 복사합니다. `ca-key.pem`은 어느 병원에도 주지 않습니다. 그런 다음 `node.json`의
경로를 고칩니다.

### 알려진 운영 한계

- 키 생성 후 재시작은 디스크에서 키를 복원합니다. 키 생성 **도중** 재시작하면 모든 노드에서 키 생성을 다시 해야 합니다.
- 작업 도중 재시작한 노드는 그 작업을 포기합니다. 다시 암호화하면 다른 노드가 가진 암호문과 달라져 해시가 맞지 않기 때문입니다. 새 epoch를 실행하세요.
- 등록된 참여자가 모두 기여해야 계산이 시작됩니다. 참여자 하나가 꺼져 있으면 연구가 멈추지만, 데이터 교환이 끝난 뒤에는 임의의 `k`개 노드가 마칠 수 있습니다.
- 구성원은 고정되어 있고 재공유(resharing)는 없습니다. 노드 추가나 키 교체는 새 컨소시엄을 뜻합니다.
- 바인딩 주소는 `listen` 설정 그대로이며 속도 제한은 없습니다. 상대는 인증되어 있지만, 오작동하는 상대가 유효하고 큰 메시지로 CPU를 소모시킬 수는 있습니다.

---

## 13. 임계 복호화

각 참여자 `i`는 자신의 3진 비밀값 `s_i`를 뽑습니다. 공동 비밀키 `s = sum(s_i)`는 어디에서도 조립되지 않습니다.

**키 생성**은 두 부분이고 각각 한 라운드입니다.

- 공개: 공개 시드에서 유도한 공통 난수 `a`에 대해 각 참여자가 `b_i = -a s_i + e_i`를 공표합니다. 그 합이 `s`의 공개키입니다. 회전용 키 스위칭 키는 비밀값에 선형이므로
  Galois 키도 같은 방법으로 만듭니다.
- 비밀: 각 참여자가 `s_i`를 모든 참여자에게 Shamir 분배합니다. 암호문 모듈러스 위 NTT 영역에서 수행하며, Shamir 분배가 선형이라 가능합니다. 참여자의 최종 조각은 받은
  값의 합입니다.

재선형화 키는 공동으로 만들지 **않습니다.** 비밀값에 선형이 아니라 라운드가 더 필요합니다. 통계에는 덧셈과 회전만 필요하므로 이 프로토콜에는 쓰이지 않습니다.

**복호화.** 정확히 `k`명으로 이뤄진 집합 `T`에 대해 각자 다음을 공표합니다.

```
d_j = lambda_j * share_j * c1 + smudge_j
```

`lambda_j`는 `T`의 라그랑주 계수입니다. 그러면 `c0 + sum(d_j)`는 메시지에 약간의 잡음이 더해진 값입니다.

라그랑주 계수는 `Q`를 법으로 매우 큰 값이어서 먼저 더한 잡음을 증폭시키므로, 잡음을 더하기 전에 적용해야 합니다. 부분 복호화가 자기 집합을 명시하고, 같은 해시를 알린
노드 중 가장 낮은 `k`개로 `T`를 결정적으로 고르는 이유입니다.

**스머징 잡음**은 중요합니다. 이 잡음이 없으면 부분 복호화가 암호문의 오차항을 드러내고, CKKS에서는 그것으로 키가 누출될 수 있습니다(Li와 Micciancio의 공격). 각 참여자는
`[-2^b, 2^b)` 균등 잡음을 더합니다. 로스터의 `smudging_bits` 기본값 `b = 24`는 스케일 `2^40`, `N = 8192`에서 복호화 값에 참여자당 약 `2^-9`의 절대 잡음을 남깁니다.

**이것의 의미를 알아 두세요.** 이 잡음과 암호문 자체 잡음의 비는 많아야 `2^14` 정도로, 잡음 플러딩 방식의 보안 증명이 요구하는 통계적으로 무시할 수 있는 거리에는 크게
못 미칩니다. `smudging_bits`를 올리면 나아지지만 그만큼 정밀도가 떨어지고, `2^40` 스케일에서는 여유가 많지 않습니다. 현재 값은 프로토콜을 따르는 참여자를 위한 다층 방어의
한 겹으로 여기세요.

**보안 모델: 정직하지만 호기심 있는 참여자.** 참여자는 받은 모든 것을 살펴볼 수 있고, `k`명 미만의 그런 참여자는 `s`에 대해 아무것도 알아낼 수 없습니다. 적극적으로 거짓을
말하는 참여자는 다루지 **않습니다.** 검증 가능한 비밀 분배도, 부분 복호화의 정확성 증명도, 코호트 값의 범위 증명도 없습니다. 그런 참여자는 틀린 결과나 서비스 거부를
일으키거나, 가짜 환자로 통계를 부풀릴 수 있습니다. 이 부분은 계약과 감사 통제로 다뤄야 합니다.

**실패 양상을 보여 주는 테스트.** 3-of-5에서 두 참여자가 세 번째 참여자의 기여를 위조하면 메시지와 무관한 쓰레기 값이 나옵니다.

---

## 14. WebAssembly Component

[`component/`](component)는 암호 기능을 하나의 [WebAssembly Component](https://component-model.bytecodealliance.org/)로 묶습니다. `medcrypto.wasm` 하나가 각
[릴리스](https://github.com/Aetherx86/medcrypto/releases/latest)에 첨부되고, 인터페이스는 [`component/wit/medcrypto.wit`](component/wit/medcrypto.wit)에 있습니다. 언어별
C 바인딩은 없습니다.

### `api` 인터페이스

| 함수 | 내용 | 대조 기준 |
| :--- | :--- | :--- |
| `sha256` | SHA-256 | FIPS 180 |
| `hkdf` | HKDF-SHA-256 키 유도 | RFC 5869 |
| `seal`, `open` | AES-256-GCM 인증 암호화 | NIST 벡터 |
| `keypair-from-seed`, `sign`, `verify` | Ed25519 서명 | RFC 8032 |
| `merkle-root` | 리프와 노드 해시를 구분한 머클 트리 | RFC 6962 참조 데이터 |
| `audit-link` | 변조 감지 감사 체인의 고리 하나 | 자체 테스트 |
| `constant-time-equal` | 내용과 무관한 시간의 비교 | 자체 테스트 |

### `fhe-ops` 인터페이스

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

`N = 8192`에서 동작합니다. 로드맵 초안과 의도적으로 세 가지가 다릅니다. 이 컴포넌트에는 난수 소스가 없으므로 `encrypt-vector`가 `entropy`를 받고, 입력이 잘못될 수 있으므로
함수가 `result`를 반환하며, 없으면 쓸 수 없으므로 `keygen`과 `decrypt-vector`를 추가했습니다.

**import가 전혀 없습니다.** 파일, 시계, 네트워크, 난수에 접근하지 않으며 CI가 빌드마다 확인합니다. 그래서 버그가 있어도 할 수 있는 일은 틀린 답을 계산하는 것뿐입니다. 난수는
호출자가 줘야 합니다. `keygen`과 각 `encrypt-vector`에 암호학적 소스에서 얻은 새 32바이트를 주고 절대 재사용하지 마세요. 전부 0인 값은 고장 난 난수 소스의 전형이므로 거부합니다.

### 언어별 사용법

```python
# Python, wasmtime 사용
pair = m.fhe_call("keygen", secrets.token_bytes(32))
public = bytes(getattr(pair, "public-key"))
secret = bytes(getattr(pair, "secret-key"))
a = m.fhe_call("encrypt-vector", public, [120.5, 80.0, 5.75], secrets.token_bytes(32))
b = m.fhe_call("encrypt-vector", public, [10.0, 20.0, 0.25], secrets.token_bytes(32))
print(m.fhe_call("decrypt-vector", secret, m.fhe_call("homomorphic-add", a, b)))
```

```javascript
// TypeScript 또는 JavaScript, jco 사용
import { fheOps } from "./generated/medcrypto.js";
const random = () => crypto.getRandomValues(new Uint8Array(32));
const { publicKey, secretKey } = fheOps.keygen(random());
const a = fheOps.encryptVector(publicKey, Float64Array.of(120.5, 80.0, 5.75), random());
const doubled = fheOps.homomorphicScalarMul(a, 2.0);
console.log(fheOps.decryptVector(secretKey, doubled));
```

`component/hosts/`의 호스트들은 같은 파일을 실행해 [`expected.txt`](component/hosts/expected.txt)와 똑같이 출력해야 하고, 네이티브 테스트가 그 파일을 Rust 코드와 대조합니다.

```bash
sh component/build.sh     # wasm32-unknown-unknown 타깃과 wasm-tools가 필요합니다.

# Python
pip install -r component/hosts/python/requirements.txt
python component/hosts/python/run.py component/dist/medcrypto.wasm

# TypeScript
cd component/hosts/typescript && npm ci --ignore-scripts && npm run transpile && node run.mjs

# Go
cd component/hosts/go && go run . ../../dist/medcrypto.wasm
```

Python과 TypeScript는 실제 컴포넌트 런타임(`wasmtime`, `jco`)을 씁니다. Go에는 아직 성숙한 런타임이 없어, Go 호스트는 `wazero`로 컴포넌트 파일 안의 코어 모듈을 실행하고
Canonical ABI를 직접 처리합니다. 같은 컴파일 코드지만 손이 더 가며, 컴포넌트에 import가 없기 때문에 이렇게 간단히 가능합니다. 레코드의 `f64`가 메모리 배치를 어떻게 바꾸는지도
이 호스트에서 볼 수 있습니다.

기대 출력은 복호화 값을 반올림합니다. 네이티브와 Wasm의 부동소수 라이브러리는 마지막 비트가 다를 수 있어 인코더의 반올림이 달라지므로, 플랫폼 간 암호문은 비교하지 않습니다. 복호화
결과에는 영향이 없습니다.

---

## 15. Rust 라이브러리

CI가 컴파일하는 [`examples/readme_tour.rs`](examples/readme_tour.rs)의 내용입니다.

```rust
use medcrypto::compliance::KeyManager;
use medcrypto::fhe::{CKKSEngine, CkksPreset};
use medcrypto::packing::RecordEnvelope;
use medcrypto::zkp::{PedersenBackend, ZKPEngine, ZkPredicateProver};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // N = 8192: 슬롯 4096개, 곱셈 2번, HE Standard 표 기준 양자 내성 128비트.
    let fhe = CKKSEngine::from_preset(CkksPreset::N8192);
    let (secret, public) = fhe.keygen();
    let relin = fhe.relin_keygen(&secret);
    let galois = fhe.galois_keygen(&secret, &fhe.sum_rotation_steps());

    // 암호화된 벡터의 슬롯별 연산.
    let a = fhe.encrypt(&public, &[1.5, 2.5, 3.5, 4.5])?;
    let b = fhe.encrypt(&public, &[2.0, 2.0, 2.0, 2.0])?;
    let product = fhe.multiply_relin_rescale(&a, &b, &relin)?;
    println!("product: {:.3?}", fhe.decrypt(&secret, &product)?); // [3.0, 5.0, 7.0, 9.0]

    // 회전은 슬롯을 왼쪽으로 옮기고, 음수는 오른쪽으로 옮깁니다.
    let rotated = fhe.rotate(&a, 1, &galois)?;
    println!("rotated: {:.3}", fhe.decrypt(&secret, &rotated)?[0]); // 2.5

    // 선형 점수: 암호화 상태에서 sum(weight * feature) + bias.
    let features = fhe.encrypt(&public, &[54.0, 128.0, 5.8])?;
    let score = fhe.evaluate_linear_risk_model(&features, &[0.02, 0.01, 0.3], -1.5, &galois)?;
    println!("score: {:.3}", fhe.decrypt(&secret, &score)?[0]); // 2.6

    // 비선형 점수: 3차 근사로 구한 로지스틱 곡선.
    let inputs = fhe.encrypt(&public, &[-2.0, 0.0, 2.0])?;
    let probability = fhe.evaluate_logistic(&inputs, &relin)?;
    println!("logistic: {:.3?}", fhe.decrypt(&secret, &probability)?); // 약 0.21, 0.5, 0.79

    // 범위 증명: 검증자는 값이 범위 안에 있다는 사실 외에는 아무것도 알 수 없습니다.
    let proof = PedersenBackend.prove_range(58, 0, 65)?;
    assert!(PedersenBackend.verify_range(&proof, 0, 65));
    let threshold = ZKPEngine::prove_threshold(58, 65, true)?;
    assert!(ZKPEngine::verify_threshold(&threshold));

    // 키를 파기해 지울 수 있는 엔벨로프.
    let mut keys = KeyManager::new();
    let names = vec!["hba1c".to_string(), "glucose".to_string()];
    let envelope = RecordEnvelope::seal(&fhe, &public, &mut keys, "patient-1", names, &[5.9, 108.0])?;
    assert!(envelope.open(&fhe, &keys).is_ok());
    keys.shred_key(&envelope.envelope.key_id, "patient-1")?;
    assert!(envelope.open(&fhe, &keys).is_err());
    Ok(())
}
```

`medcrypto::fhe`는 `medcrypto-fhe` 크레이트이고, `medcrypto::fhir`는 `medcrypto-fhir`입니다. 난수가 필요한 함수에는 모두 생성기를 직접 받는 `_with` 형태가 있으며, `os-rng`
기능 없이 빌드하면 이 형태만 쓸 수 있습니다.

외부에서 온 입력은 사용 전에 `validate_ciphertext`, `validate_public_key`, `validate_secret_key` 등을 거칩니다. 비밀키와 조각은 drop될 때 메모리를 지우고, 디버그 출력에 키
값을 찍지 않습니다.

---

## 16. 보안 모델과 한계

### 프로토콜을 따른다는 전제에서 막아 주는 것

| 위협 | 보호 수단 |
| :--- | :--- |
| 네트워크 관찰자 | 상호 TLS |
| 다른 병원 환자 정보를 읽으려는 참여자 | 암호문만 교환하고 합계만 복호화 |
| `k`곳 미만의 공모 | 아무것도 복호화할 수 없음 |
| 외부자의 참여 | CA, 로스터 해시, 서명 검사 |
| 감사 로그 변조 | 바뀐 항목에서 해시 체인이 끊어짐 |
| 파기 후 유출된 엔벨로프 | 키가 더 이상 존재하지 않음 |
| 예/아니요 이상을 알려는 검증자 | 영지식 범위 증명 |

### 막지 못하는 것

- **적극적으로 악의적인 병원.** [13절](#13-임계-복호화)을 보세요. 거짓 데이터를 기여해 결과를 왜곡하거나 연구를 멈출 수 있습니다. 기여의 정직성을 증명하는 수단은 없습니다.
- **`k`곳 이상의 공모.** 다른 병원의 개별 기여를 포함해 가진 암호문을 모두 복호화할 수 있습니다. 이 점을 고려해 `k`를 정하세요.
- **차분 공격.** 병원이 둘이면 각자 자기 데이터를 합계에서 빼서 상대의 합계를 알 수 있습니다. 동의 집합이 조금씩 다른 연구를 반복하면 공개된 평균에서 환자 한 명의 값이 드러날
  수 있습니다. 최소 셀 크기로는 막지 못합니다. 차등 프라이버시는 없습니다.
- **암호화 전에 침해된 병원.** 평문 표는 그 병원 디스크에 있으므로 별도로 보호하세요.
- **부채널.** 모듈러 축약은 분기 대신 마스크를 쓰고 비밀값은 출력되지 않지만, 부채널 평가를 받지 않았습니다. 인코딩에는 그 자체가 비밀인 값에 부동소수를 씁니다.
- **결함 공격과 메모리 포렌식.** 메모리 지우기는 최선 노력일 뿐이며, 할당자가 만든 복사본에는 닿지 않습니다.

### 구성 요소별 양자 내성

| 구성 요소 | 기반 | 양자 컴퓨터 상대 |
| :--- | :--- | :--- |
| 프리셋의 CKKS | RLWE, 표준 표 기준 128비트 | 효율적인 공격 알려지지 않음 |
| SHA-256 체인, AES-256-GCM | 대칭키 | Grover 기준 약 128비트 |
| Pedersen 증명 | 타원곡선 이산로그 | **깨짐** |
| Ed25519 메시지 서명 | 타원곡선 | **깨짐** |
| TLS 인증서와 키 교환 | `rustls`가 협상한 방식, 타원곡선 인증서 | **인증서 깨짐.** 지금 녹화한 트래픽이 나중에 복호화될 수 있음 |
| 동의 컨트랙트 | 이더리움 자체 서명 | 해당 체인에서 **깨짐** |

따라서 주장의 범위는 좁습니다. 데이터의 동형암호는 양자 내성이지만, **시스템 전체가 그런 것은 아닙니다.** 네트워크에서 녹화된 암호문은 CKKS 계층이 계속 보호하지만, 키 생성 중
전송되는 비밀 조각은 TLS에만 의존합니다. 공격자가 지금 트래픽을 녹화해 두고 나중에 양자 컴퓨터를 갖는다면 문제가 됩니다.

### 감사받지 않음

구현은 직접 작성했고, 테스트는 정의와 공개 벡터가 있는 곳에서는 그것과 대조합니다. 독립적인 검토는 받지 않았습니다. OpenFHE, Microsoft SEAL, Lattigo 같은 성숙한 라이브러리는 훨씬
많은 검증을 거쳤습니다. 여기서 직접 구현을 택한 이유는 순수 Rust, Wasm 지원, import 없는 빌드 때문이니 이를 감안해 판단하세요.

---

## 17. 규제 항목 대응표

어떤 기술 수단이 어떤 요건과 관련되는지 보여 주는 표입니다. 공학적 안내일 뿐 법률 자문이 아니며, 규정 준수를 주장하는 것도 아닙니다. 준수 여부는 배포 전체와 계약, 절차에
달려 있습니다. 암호화되거나 가명화된 건강 데이터도 GDPR상 개인정보일 수 있습니다.

| 조항 | 요건 | 수단 | 다루지 못하는 부분 |
| :--- | :--- | :--- | :--- |
| GDPR 5(1)(c) | 데이터 최소화 | 연구 항목만 기여, 합계만 복호화 | 연구에 그 항목이 필요한지 여부 |
| GDPR 7 | 동의 조건 | 환자별 확인, 철회 즉시 반영 | 동의 절차 자체 |
| GDPR 9 | 민감 정보 | 병원을 떠나기 전 암호화 | 처리의 법적 근거 |
| GDPR 17 | 삭제권 | 레코드별 키, 요청 시 파기 | 키 저장소 백업, 수직 배치, 공개된 통계 |
| GDPR 25 | 설계에 의한 보호 | 가명, 암호화, 임계 키, 셀 비공개 | 조직적 조치 전반 |
| GDPR 32 | 처리의 보안 | TLS, 서명, 접근 검사 | 운영 보안 |
| HIPAA 164.502(b) | 최소 필요 | 범위 증명은 값이 아니라 예/아니요만 제공 | 어떤 질문을 하는지 |
| HIPAA 164.514 | 비식별화 | HMAC 가명 | 가명화만으로는 비식별화가 **아님** |
| HIPAA 164.528 | 공개 내역 기록 | 노드별 해시 체인 감사 로그 | 변경은 감지하지만, 체인 전체를 잘라 내는 노드에는 외부 앵커링이 필요 |
| HIPAA 164.312 | 기술적 보호 | 상호 TLS, 노드별 신원 | 인력과 물리적 보호 |

법적 고지는 [LEGAL.md](LEGAL.md)에 있습니다.

---

## 18. 성능

Apple M4에서 릴리스 모드, 단일 스레드로 `cargo run --release --example fhe_benchmark`를 실행해 측정했습니다. 환경마다 다르므로 직접 실행해 보세요.

| 연산 | `N = 8192` (ms) | `N = 16384` (ms) |
| :--- | ---: | ---: |
| 키 생성 | 1.16 | 7.20 |
| 재선형화 키 | 7.69 | 42.67 |
| 회전 키 1개 | 11.99 | 40.22 |
| 암호화, 전체 슬롯 | 2.19 | 8.36 |
| 복호화 | 11.26 | 56.17 |
| 덧셈 | 0.02 | 0.09 |
| 곱셈 | 0.14 | 0.69 |
| 재선형화 | 2.27 | 22.40 |
| 재스케일 | 0.54 | 3.33 |
| 회전 | 2.29 | 26.67 |
| 전체 슬롯 합 | 28.84 | 370.85 |

| 크기 | `N = 8192` | `N = 16384` |
| :--- | ---: | ---: |
| 암호문, 바이너리 | 384 KiB | 2048 KiB |
| 암호문, JSON 파일 내 | 약 770 KiB | 약 4 MiB |
| 공개키 | 384 KiB | 2048 KiB |
| 재선형화 키 | 1.5 MiB | 18 MiB |
| `sum_slots`용 회전 키 | 18 MiB | 234 MiB |

| 범위 증명(Pedersen) | 증명 (ms) | 검증 (ms) | 크기 |
| :--- | ---: | ---: | ---: |
| `[0, 65]` | 2.04 | 1.91 | 2.2 KiB |
| 32비트 범위 | 8.82 | 9.21 | 10 KiB |

환자 1500명, 항목 3개의 3노드 튜토리얼은 노트북 한 대에서 키 생성과 연구까지 모두 수십 초 안에 끝났습니다. 실제 배포에서는 대역폭이 가장 큰 비용입니다. 각 참여자는 다른 노드마다
`3 x 항목 수 x 배치 수`개의 암호문을 보내고, 각 노드는 키 생성 중에 회전 키 조각을 보냅니다.

---

## 19. 명령어 참조

어느 명령이든 `--help`로 전체 옵션을 볼 수 있습니다.

| 명령 | 하는 일 |
| :--- | :--- |
| `gui` | 데스크톱 GUI. 명령 없이 실행해도 이것이 실행됨 |
| `demo` | 합성 데이터로 전체 다기관 흐름 실행 |
| `init-node` | 일회용 키로 노드의 DID와 파라미터 표시 |
| `keygen` | 비밀키, 공개키, 회전 키, 재선형화 키 작성 |
| `encrypt` | 환자 한 명의 바이탈 암호화 |
| `decrypt` | 암호문 파일 복호화 |
| `ingest-fhir` | FHIR 서버 또는 번들을 수직 암호문, 수평 엔벨로프, 평문 표로 변환 |
| `batch-pack` | `PatientRecord` 파일이나 번들 디렉터리를 수직 암호문으로 변환 |
| `cohort-merge` | 여러 병원 코호트 결합 |
| `cohort-stats` | 비밀키 하나로 환자 수, 평균, 표준편차 계산 |
| `pack-record` | 레코드 하나를 파기 가능한 엔벨로프로 |
| `open-record` | 키가 있으면 엔벨로프를 열고 복호화 |
| `shred` | 레코드 키 파기 |
| `prove`, `verify` | 두 백엔드 중 하나로 범위 증명 |
| `quantum-audit` | 파라미터를 HE Standard와 대조 |
| `consortium-init` | CA, 인증서, 키, 로스터, 노드 설정 생성 |
| `daemon run` | 중단할 때까지 노드 실행 |
| `daemon status` | 노드 상태 조회 |

`ingest-fhir` 옵션은 다음과 같습니다.

| 옵션 | 기본값 | 의미 |
| :--- | :--- | :--- |
| `--endpoint`, `--bundle` | | FHIR 서버 기본 URL 또는 번들 파일. 둘 중 하나 |
| `--loinc-filter` | 필수 | 쉼표로 구분한 LOINC 코드 |
| `--mode` | `vertical` | `vertical`, `horizontal`, `table` |
| `--output` | 필수 | 출력 파일 |
| `--batch-size` | 4096 | 암호문당 환자 수, 슬롯 수까지 |
| `--winsorize` | `clinical` | `clinical`, `p1p99`, `off` |
| `--impute` | `none` | `none`, `median`, `mean` |
| `--public-key` | 출력 옆에 새 키 생성 | 공개키 파일 |
| `--pseudonym-key` | 출력 옆 | 병원 비밀값, 없으면 생성 |
| `--key-store` | `medcrypto-keystore.json` | 수평 모드의 엔벨로프 키 |
| `--allow-insecure-http` | 꺼짐 | 원격 호스트에 `http://` 허용 |

종료 코드는 성공 시 0, 검증에 실패한 증명을 포함한 모든 오류에서 1, 라이선스 문제에서 126입니다.

---

## 20. 파일 형식

바이너리 형식은 postcard를 쓰고, JSON 파일은 다항식을 16진수 문자열로 담습니다. 1.0 이전에는 마이너 버전 간에 형식이 유지된다고 보장하지 않습니다.

**키 디렉터리**

| 파일 | 비밀 여부 | 내용 |
| :--- | :--- | :--- |
| `secret-key.json` | **비밀**, 모드 0600으로 작성 | 3진 비밀값 |
| `public-key.json` | 공개 | 암호화용 |
| `galois-keys.json` | 공개 | `sum_slots`용 |
| `relin-key.json` | 공개 | 곱셈용 |

**코호트 파일**(`--mode vertical`)

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

**표**(`--mode table`, 병원 내 보관)

```json
{
  "columns": [{"analyte": "hba1c", "display": "...", "unit": "%"}],
  "rows": [{"pseudo_id": "did:med:patient:...", "values": [5.8]}],
  "quality": []
}
```

**노드 데이터 디렉터리**

| 경로 | 내용 | 민감 여부 |
| :--- | :--- | :--- |
| `cohorts/<study>.json` | 직접 넣어 두는 평문 표 | **민감** |
| `threshold-share.bin` | 이 노드의 비밀 조각 | **민감** |
| `collective-keys.bin` | 공개키 | 공개 |
| `jobs/<job>.started` | 이 노드가 기여했다는 표시 | 공개 |
| `results/<job>.json` | 공개된 통계 | 집계값만 |
| `audit.json` | 해시 체인 | 메타데이터 |

**동의 원장**

```json
{
  "studies": [{"id": "diabetes-2026", "epoch": 1, "active": true}],
  "consents": [{"patient": "did:med:patient:...", "scope": "DIABETES_STATISTICS",
                "valid_until": 1830000000, "active": true}]
}
```

---

## 21. 임상 AI 모듈과 GUI

[`src/clinical_ai`](src/clinical_ai/mod.rs)에는 VITA(AAAI 2024)와 COGNet(SIGIR 2022)의 아이디어를 참고한 작은 약물 추천기가 있습니다. 관련 과거 방문 선택, 어텐션, copy-or-generate
예측기, 알려진 약물 상호작용 억제로 구성됩니다.

```bash
cargo run --example clinical_ai_benchmark
```

**이 모듈의 실체를 분명히 밝힙니다.** 직접 작성한 궤적 1건으로 실행되며, 학습 데이터도 데이터셋도 없습니다. 이 수치는 이 방법이 공개된 모델과 비교해 어떤지 아무것도 말해 주지 않습니다.
이 README의 이전 버전은 이 모듈이 MIMIC-III에서 공개 모델을 능가한다고 표시했지만, 잘못된 내용이라 삭제했습니다. [변경 이력](CHANGELOG.md)을 참고하세요. 의료기기가 아니며 치료 결정에
쓰면 안 됩니다.

암호화된 데이터에서 동작하지도 않습니다. 이 프로젝트의 두 부분은 별개입니다.

**GUI**는 웹뷰 없이 `egui`로 만든 네이티브 데스크톱 앱입니다.

```bash
./target/release/medcrypto gui
```

동의, 암호화, 증명, 연합 평균, 컴플라이언스, 보안 감사, 임상 AI 샘플 탭이 있고 시연용입니다. 데몬, FHIR 파이프라인, 임계 복호화는 명령줄에서만 쓸 수 있습니다.

---

## 22. 저장소 구조

```
medcrypto/
├── crates/
│   ├── medcrypto-fhe/        RNS-CKKS와 임계 복호화. os-rng 없이는 OS 의존성 없음
│   └── medcrypto-fhir/       FHIR 파싱, 용어, 정제, HTTP 클라이언트
├── src/
│   ├── main.rs               명령줄
│   ├── packing/              수평 엔벨로프와 수직 코호트
│   ├── zkp/                  ZkPredicateProver, Pedersen 범위 증명, STARK 어댑터
│   ├── consortium/           로스터, 동의 소스, 프로토콜 상태 기계, gRPC와 TLS
│   ├── compliance/           키 저장소, 파기, 감사 체인
│   ├── quantum/              HE Standard 대조
│   ├── blockchain/           DID와 동의 시뮬레이터, EVM calldata
│   ├── clinical_ai/          약물 추천 샘플
│   ├── models/               PatientRecord
│   ├── gui/                  데스크톱 앱
│   └── license.rs            바이너리의 라이선스 검사
├── component/                Wasm Component, WIT, Python, TypeScript, Go 호스트
├── proto/consortium.proto    gRPC 서비스
├── contracts/                ConsentRegistry.sol
├── zk/guest-range/           SP1용 guest 템플릿 (워크스페이스 밖)
├── examples/                 샘플 데이터 생성기, 벤치마크, 라이브러리 투어, GUI 실행기
├── tests/                    통합 테스트
└── .github/                  워크플로와 저장소 가드
```

코드 작업은 [DEVELOPER.md](DEVELOPER.md)를 참고하세요.

---

## 23. 테스트와 CI/CD

```bash
cargo test --workspace --all-targets --all-features
```

암호 크레이트는 디버그 모드에서도 최적화해 빌드하므로 전체 테스트가 1~2분 안에 끝납니다.

| 대상 | 위치 | 확인하는 내용 |
| :--- | :--- | :--- |
| 모듈러 연산 | `arith.rs` | Barrett, Shoup이 일반 나눗셈과 일치. 소수가 요구된 형태 |
| NTT | `ntt.rs` | 네가사이클릭 합성곱이 교과서 방식과 일치. 순열이 계수 자기동형사상과 일치 |
| 인코더 | `encoder.rs` | 왕복 변환, 링 곱셈이 슬롯 곱셈임 |
| 파라미터 | `params.rs` | 프리셋이 표에 맞음. 이전 토이 파라미터와 너무 긴 체인 거부 |
| CKKS | `crates/medcrypto-fhe/tests/ckks.rs` | 두 프리셋에서 각 연산을 평문과 대조. 잘못된 입력은 panic이 아닌 오류 |
| 임계 | 같은 파일 | 임의의 `k`곳이 복호화. 더 적거나 섞인 집합은 불가. 위조 조각은 쓰레기 값 |
| FHIR | `crates/medcrypto-fhir/tests` | 파싱, 변환, 정제, 악의적 `next` 링크를 포함한 실제 소켓 클라이언트 |
| 패킹 | `tests/packing_test.rs` | 통계가 평문과 일치, 결측치 제외, 파기가 프로세스를 넘어 유지 |
| 범위 증명 | `tests/zkp_range_test.rs` | 정직한 증명 통과. 변조와 커밋먼트 이동 실패. 프로덕션이 Pedersen 거부. 러너 규칙 동작 |
| 데몬 | `tests/consortium_test.rs` | 상호 TLS의 실제 노드 3개가 동의와 셀 비공개를 적용해 맞는 통계를 얻음, 노드 하나 정지, 디스크에서 재시작. 외부 인증서 거부. 중간에 철회된 연구는 복호화되지 않음 |
| 동의 | `tests/evm_consent_test.rs` | ABI 인코딩, 실패 시 거부, Foundry가 있으면 실제 로컬 체인의 컨트랙트 |
| 명령줄 | `tests/cli_test.rs` | 문서의 명령을 실제 바이너리로 실행 |
| Wasm | `component/tests/vectors.rs` | 공개 벡터, 호스트 기대 출력의 정확성 |

**GitHub Actions**

| 워크플로 | 트리거 | 하는 일 |
| :--- | :--- | :--- |
| [`ci.yml`](.github/workflows/ci.yml) | Push, PR | 비밀 스캔, 저장소 가드, 충돌 표시, 문서 이모지 금지. 이어서 Ubuntu와 macOS에서 포맷, 경고 금지 clippy, 테스트, `cargo audit`, 엄격한 문서 빌드, 데모 실행 |
| [`component.yml`](.github/workflows/component.yml) | Push, PR, 태그 | Wasm 빌드, import 없음 확인, Ubuntu와 macOS에서 Python, TypeScript, Go로 실행. 태그에서는 CLI 압축 파일, 빌드 출처 증명, 릴리스 |
| [`audit.yml`](.github/workflows/audit.yml) | Push, PR, 매주 | 의존성 취약점 |

모든 액션은 커밋에 고정되어 있습니다. 저장소 가드는 공급망 공격이 숨는 곳(보이지 않는 유니코드, 요청 없이 실행되는 항목, 설치 훅, 커밋된 자격 증명)을 찾습니다. GitLab CI는 미러에서
포맷, clippy, 테스트, 감사를 실행합니다.

버전 규칙: 수정은 `0.0.X`, 새 기능이나 플랫폼 지원은 `0.X.0`을 올립니다. 태그가 `Cargo.toml`의 버전과 다르면 릴리스가 실패합니다. 릴리스 노트는 [CHANGELOG.md](CHANGELOG.md)에서 가져옵니다.

---

## 24. 로드맵 현황

| 항목 | 상태 | 비고 |
| :--- | :--- | :--- |
| `N = 8192`, `16384`의 RNS-CKKS | 완료 | 표준 표와 대조 |
| 재선형화, 재스케일, 회전 | 완료 | |
| 비선형 임상 스코어링 | 완료 | `N = 8192`에서 3차까지 |
| 수평, 수직 패킹, `batch-pack` | 완료 | |
| FHIR 크레이트, `ingest-fhir` | 완료 | 로컬 모의 서버로 테스트. 실제 운영 EMR로는 테스트하지 않음 |
| `ZkPredicateProver`, 실제 Pedersen 범위 증명 | 완료 | |
| `StarkCoprocessorBackend` | 어댑터 완료 | **실제 prover로는 아직 실행하지 않음** |
| gRPC, 상호 TLS 데몬 | 완료 | 정직하지만 호기심 있는 참여자 모델 |
| 스마트 컨트랙트 동의 | 완료 | 로컬 체인에서만 테스트 |
| k-of-n 키 생성과 임계 복호화 | 완료 | 검증 가능한 비밀 분배 없음 |
| Wasm `fhe-ops` | 완료 | Python, TypeScript, Go |

다음에 할 만한 일을 가치순으로 적으면 다음과 같습니다. 검증 가능한 비밀 분배와 부분 복호화 정확성 증명, 기여 값의 입력 범위 증명, 공개 통계의 차등 프라이버시, 양자 내성 TLS와 서명, 실제 SP1
러너, 키 저장소의 HSM/KMS 연동, 구성원 변경을 위한 재공유, 독립 감사.

---

## 25. 문제 해결

| 메시지 | 원인 | 해결 |
| :--- | :--- | :--- |
| `[AETHER LICENSE REQUIRED]`, 종료 코드 126 | 바이너리가 라이선스를 찾지 못함 | [3절](#3-설치와-빌드) 참고 |
| `refusing http:// ... patient data needs https` | 원격 평문 엔드포인트 | https 사용. `--allow-insecure-http`는 테스트 전용 |
| `LOINC code ... is not in the catalog` | [카탈로그](#loinc-카탈로그)에 없는 코드 | `terminology.rs`에 코드와 단위 추가 |
| `Unknown unit` 수가 많음 | 서버의 단위 표기가 새로움 | 원본 데이터 확인 후 표기 추가 |
| `a coefficient of about 2^N does not fit` | 이 레벨에 비해 값이 너무 큼 | 값 스케일 조정, 또는 높은 레벨 유지 |
| `the scale would overflow` | 남은 모듈러스가 곱셈에 부족 | `N = 16384` 사용, 또는 곱셈 줄이기 |
| `no levels left` | 예산 소진 | [예산](#스케일-맞추기)에 맞춰 회로 설계 |
| `scales differ` | 다른 경로를 거친 암호문을 더함 | 한 경로로 통일하거나 `mod_switch_to_level`, `add_constant` 사용 |
| `no Galois key for rotation by N` | 해당 회전 키가 없음 | `galois_keygen`에 추가 |
| `made under different parameters` | 키와 암호문의 프리셋이 다름 | 프리셋 통일 |
| 데몬 `this certificate is not in the roster` | 노드 간 로스터가 다름 | 모든 노드에 같은 `roster.json` 배포 |
| 데몬 `this node restarted during the job` | 연구 도중 재시작 | 새 epoch 실행 |
| 작업 실패, `no longer approved` | 연구가 철회됨 | 의도된 동작 |
| 연구가 시작되지 않음 | 미승인이거나 표가 없음 | `consent.json` 또는 컨트랙트와 `data/cohorts/<id>.json` 확인. 데몬은 표준 오류로 로그를 남김 |

---

## 26. 용어집

| 용어 | 뜻 |
| :--- | :--- |
| CKKS | 실수의 근사 연산을 위한 동형암호 방식 |
| RNS | 잉여 수 체계. 큰 수를 여러 작은 소수에 대한 나머지로 저장 |
| RLWE | Ring Learning With Errors. CKKS 보안의 기반인 격자 문제 |
| `N` | 다항식 링의 차수. 클수록 안전하고 느림 |
| 슬롯 | 암호문 벡터의 칸. `N/2`개 |
| 레벨 | 암호문이 앞으로 재스케일할 수 있는 횟수 |
| 스케일 | 실수를 정수로 바꾸는 배율. 여기서는 `2^40` |
| 재스케일 | 곱셈 후 소수로 나눠 스케일과 잡음을 낮추는 연산 |
| 재선형화 | 다항식 3개가 된 곱을 2개로 되돌리는 연산 |
| Galois 키 | 비밀키 없이 슬롯을 회전할 수 있게 하는 키 |
| NTT | 수론 변환. 정수 위의 FFT로, 다항식 곱셈을 빠르게 함 |
| 스머징 | 부분 복호화가 키를 드러내지 않도록 더하는 잡음 |
| DKG | 분산 키 생성. 아무도 통째로 갖지 않는 키를 만듦 |
| Shamir 분배 | 임의의 `k`개 조각으로 복원되고 그보다 적으면 아무것도 드러나지 않는 비밀 분할 |
| Pedersen 커밋먼트 | 값을 완벽히 숨기고 이산로그 가정 아래 결속되는 커밋먼트 |
| STARK | 해시 기반 증명 시스템. 일반적으로 양자 내성으로 간주 |
| zkVM | 실행을 증명할 수 있는 가상 머신 |
| FHIR | 건강 데이터 교환을 위한 HL7 표준. R4가 널리 쓰이는 버전 |
| LOINC | 검사와 관찰 항목의 표준 코드 |
| UCUM | 단위를 모호하지 않게 쓰는 표준 |
| 윈저화 | 극단값을 버리지 않고 한도로 잘라 내는 처리 |
| 대체(Imputation) | 결측값을 채우는 처리 |
| PHI | HIPAA상 보호 대상 건강 정보 |
| mTLS | 양쪽 모두 인증서로 신원을 증명하는 TLS |

---

## 27. 라이선스

MIT, Jeong Hoon Kim. [LICENSE](LICENSE)와 [LEGAL.md](LEGAL.md)를 참고하세요.
