# S3 Public Bucket Sentinel — “오픈버킷 즉시 봉합”

> **목적**
> S3 버킷이 **공개(ACL/정책)** 되거나 **서버사이드 암호화(SSE) 미적용** 상태로 전환되는 즉시 탐지하여, **Public Access Block 활성화·Public ACL/정책 제거·SSE 강제**를 자동으로 수행하고 **알림(SNS/Slack)** 을 발송합니다.
> **핵심 효과**: MTTR 대폭 단축, 컴플라이언스 위반 예방(개인정보/규제 데이터), 운영 실수로 인한 대규모 노출 방지.

---

## 목차

* [주요 기능](#주요-기능)
* [빠른 시작 (Quick Start)](#빠른-시작-quick-start)

  * [전제 및 준비물](#전제-및-준비물)
  * [설치 & 배포](#설치--배포)
  * [환경 변수 설정](#환경-변수-설정)
  * [데모/테스트](#데모테스트)
  * [삭제](#삭제)
* [설정 / 구성](#설정--구성)

  * [환경 변수 테이블](#환경-변수-테이블)
  * [SAM 파라미터 테이블](#sam-파라미터-테이블)
  * [필요 IAM 권한(람다 실행역할)](#필요-iam-권한람다-실행역할)
* [아키텍처 개요](#아키텍처-개요)

  * [컴포넌트 & 데이터플로우](#컴포넌트--데이터플로우)
  * [이벤트 처리 순서](#이벤트-처리-순서)
* [운영 방법 (Runbook)](#운영-방법-runbook)

  * [로그·지표·알람](#로그지표알람)
  * [자주 나는 장애와 복구](#자주-나는-장애와-복구)
  * [롤백 전략](#롤백-전략)
* [보안 · 컴플라이언스](#보안--컴플라이언스)
* [예외(Allowlist) 정책](#예외allowlist-정책)

  * [태그 기반 (권장)](#태그-기반-권장)
  * [DynamoDB 기반](#dynamodb-기반)
  * [파일 기반](#파일-기반)
* [CI/CD 통합 (선택)](#cicd-통합-선택)
* [개발/테스트](#개발테스트)
* [Make 명령 모음](#make-명령-모음)
* [FAQ](#faq)
* [변경 이력 & 라이선스](#변경-이력--라이선스)
* [부록 A — 샘플 알림 페이로드](#부록-a--샘플-알림-페이로드)
* [부록 B — samconfig 예시](#부록-b--samconfig-예시)
* [부록 C — CloudWatch 알람 샘플](#부록-c--cloudwatch-알람-샘플)
* [부록 D — 최소권한 IAM 정책 스니펫](#부록-d--최소권한-iam-정책-스니펫)

---

## 주요 기능

* **즉시 감지**: `PutBucketAcl`, `PutBucketPolicy`, `DeletePublicAccessBlock`, `PutBucketEncryption` 등 **버킷 설정 변경**을 CloudTrail 관리 이벤트 → EventBridge 규칙으로 구독
* **자동 봉합(Remediation)**

  * **Public Access Block** 4종 모두 **ON**
  * **Public ACL** 제거(“AllUsers” / “AuthenticatedUsers” 그랜트 삭제)
  * **Public Policy** 정리 또는 삭제(Principal `*` 등 공개 조건 제거, 스냅샷 저장)
  * **서버사이드 암호화(SSE)** **AES-256 또는 KMS** 강제
* **알림**: SNS(필수) + Slack(옵션)으로 **조치 내역**과 **변경 전/후 요약**
* **예외 허용(Allowlist)**: **태그 / DynamoDB / 파일** 3가지 모드 지원 + **만료일** 필수
* **운영 가시성**: CloudWatch Logs + **EMF 지표** (예: `RemediationApplied`, `DetectedPublicPolicy`)

> ⚠️ **실무 팁**
> 공개 허용이 필요한 정적 사이트/자산 버킷은 예외 태그(`sentinel:allow=true` + `sentinel:until=YYYY-MM-DD`)로 **기간 제한**을 두세요. 모든 예외는 **감사 로그**에 남습니다.

---

## 빠른 시작 (Quick Start)

### 전제 및 준비물

* AWS 권한: CloudFormation/SAM 배포, Lambda/S3/EventBridge/SNS 생성
* 로컬 도구: `awscli`, `aws-sam-cli`(SAM), `python 3.11+`, `make`(선택)
* 레포 클론:

```bash
git clone https://github.com/jijae92/S3PublicBucketSentinel.git
cd S3PublicBucketSentinel
```

### 설치 & 배포

```bash
# 의존성 설치
make deps    # 또는: pip install -r requirements.txt

# SAM 빌드
sam build

# 최초 배포(--guided)
sam deploy --guided \
  --stack-name s3pb-sentinel \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    ProjectName=S3PBSentinel \
    Remediate=true \
    ForceSSE=AES256 \
    KmsKeyArn="" \
    NotifyLevel=INFO \
    SlackWebhookUrl="" \
    AllowlistMode=TAG \
    AllowlistTableName="" \
    LogRetentionDays=30
```

> **TIP**: 매번 `--guided`를 쓰기 번거롭다면, [부록 B](#부록-b--samconfig-예시)의 `samconfig.toml` 예시를 루트에 추가하세요. 이후 `sam deploy`만으로 동일 설정이 적용됩니다.

### 환경 변수 설정

레포에 **`.env.example`** 가 있다면 복사해 실제 값으로 채웁니다.

```bash
cp .env.example .env
```

`.env` 주요 항목:

```dotenv
REMEDIATE=true                 # false=감지만
FORCE_SSE=AES256               # AES256 | aws:kms
KMS_KEY_ARN=                   # KMS 사용시 필수
NOTIFY_LEVEL=INFO              # INFO|WARN|ERROR
SLACK_WEBHOOK_URL=             # 선택

ALLOWLIST_MODE=TAG             # TAG|DDB|FILE
ALLOW_TAG_KEY=sentinel:allow
ALLOW_TAG_UNTIL=sentinel:until # ISO-8601 날짜
ALLOWLIST_TABLE=               # DDB 모드일 때
ALLOWLIST_FILE=config/allowlist.json

SNAPSHOT_BUCKET=               # 없으면 로그 버킷 재사용
LOG_RETENTION_DAYS=30
```

### 데모/테스트

**옵션 A — 스크립트 기반 데모**
레포에 `scripts/demo_public_bucket.py` 가 있다면:

```bash
make demo
```

**옵션 B — AWS CLI로 수동 재현**

```bash
export DEMO_BUCKET=<테스트용 고유 버킷명>
export AWS_REGION=<리전>

# 1) 버킷 생성
aws s3api create-bucket --bucket "$DEMO_BUCKET" --region "$AWS_REGION" \
  --create-bucket-configuration LocationConstraint=$AWS_REGION

# 2) 의도적으로 공개 ACL 부여 (Sentinel가 자동 봉합해야 함)
aws s3api put-bucket-acl --bucket "$DEMO_BUCKET" --acl public-read

# 3) 몇 초 후 로그/알림 확인
aws logs tail /aws/lambda/s3pb-sentinel-remediator --follow
```

### 삭제

```bash
sam delete --stack-name s3pb-sentinel
```

---

## 설정 / 구성

### 환경 변수 테이블

| 변수                   | 설명                              | 예시/기본값                  |
| -------------------- | ------------------------------- | ----------------------- |
| `REMEDIATE`          | `true`면 자동봉합, `false`면 감지만      | `true`                  |
| `FORCE_SSE`          | SSE 유형: `AES256` 또는 `aws:kms`   | `AES256`                |
| `KMS_KEY_ARN`        | KMS 사용 시 키 ARN                  | `""`                    |
| `NOTIFY_LEVEL`       | 알림 하한 레벨(`INFO`/`WARN`/`ERROR`) | `INFO`                  |
| `SLACK_WEBHOOK_URL`  | Slack Webhook URL(옵션)           | `""`                    |
| `ALLOWLIST_MODE`     | 예외모드: `TAG` / `DDB` / `FILE`    | `TAG`                   |
| `ALLOW_TAG_KEY`      | 예외 태그 키                         | `sentinel:allow`        |
| `ALLOW_TAG_UNTIL`    | 예외 만료 태그 키(ISO-8601 날짜)         | `sentinel:until`        |
| `ALLOWLIST_TABLE`    | DDB 테이블명(DDB 모드 시)              | `""`                    |
| `ALLOWLIST_FILE`     | 파일 기반 예외 JSON 경로(FILE 모드 시)     | `config/allowlist.json` |
| `SNAPSHOT_BUCKET`    | 정책/ACL 스냅샷 저장용 버킷(미설정시 로그버킷 사용) | `""`                    |
| `LOG_RETENTION_DAYS` | 로그 보존 일수                        | `30`                    |

### SAM 파라미터 테이블

> ⚠️ **매치 체크**: 아래 파라미터명이 실제 `template.yaml`(또는 `sam-template.yaml`) `Parameters` 섹션과 **완전히 동일**한지 확인하세요.

| 파라미터                 | 타입/예시           | 설명                    |
| -------------------- | --------------- | --------------------- |
| `ProjectName`        | String          | 리소스 네이밍 prefix        |
| `Remediate`          | true/false      | 자동봉합 여부               |
| `ForceSSE`           | AES256/KMS      | SSE 강제 모드             |
| `KmsKeyArn`          | String          | KMS 키 ARN             |
| `NotifyLevel`        | INFO/WARN/ERROR | 알림 하한 레벨              |
| `SlackWebhookUrl`    | String          | Slack Webhook URL(옵션) |
| `AllowlistMode`      | TAG/DDB/FILE    | 예외 관리 방식              |
| `AllowlistTableName` | String          | DDB 테이블명(옵션)          |
| `LogRetentionDays`   | Number          | 로그 보존 일수              |

### 필요 IAM 권한(람다 실행역할)

* `s3:PutPublicAccessBlock`, `s3:GetPublicAccessBlock`
* `s3:PutBucketPolicy`, `s3:DeleteBucketPolicy`, `s3:GetBucketPolicy`
* `s3:PutBucketAcl`, `s3:GetBucketAcl`
* `s3:GetBucketTagging`, `s3:PutBucketTagging` (태그 예외 모드)
* `s3:PutBucketEncryption`, `s3:GetBucketEncryption`
* `logs:*`(해당 로그그룹), `cloudwatch:PutMetricData`
* `sns:Publish`(특정 토픽으로 **제한** 권장)

---

## 아키텍처 개요

flowchart LR
  A[CloudTrail management events]
  B[EventBridge rule]
  C[Lambda remediator]
  D[S3 bucket]
  E[SNS topic]
  F[CloudWatch Logs & EMF]
  G[Snapshot bucket (optional)]
  H[Allowlist store: DynamoDB · Tag · File]

  A --> B
  B --> C
  C -->|Enforce PAB, clean ACL & policy, force SSE| D
  C --> E
  C --> F
  C --> G
  C --> H



### 컴포넌트 & 데이터플로우

* **CloudTrail → EventBridge**: 버킷 설정 변경 이벤트 수신
* **Lambda Remediator**: 상태 진단 → 예외검사 → 봉합 → 알림 → 스냅샷/로그/지표
* **SNS/Slack**: 운영자 알림
* **Allowlist**: 태그·DDB·파일 기반 예외 + 만료일

### 이벤트 처리 순서

1. 위험 이벤트 수신 (ACL/Policy/BPA/SSE 변경)
2. 현재 상태 진단 + 변경내역 스냅샷(옵션)
3. **예외 확인**(만료일 고려) → 예외면 “Skip & Log”
4. **봉합 순서**

   * Public Access Block 4종 ON
   * Public ACL 제거
   * Public Policy 정리/삭제 (스냅샷 저장)
   * SSE 강제(AES256 or KMS)
5. SNS/Slack 알림, 로그/EMF 지표 전송

---

## 운영 방법 (Runbook)

### 로그·지표·알람

* **로그 그룹**: `/aws/lambda/s3pb-sentinel-remediator`

  > ⚠️ 함수명이 다른 경우 **실제 함수명**으로 수정!
* **주요 로그 키워드**

  * `DetectedPublicAcl`, `DetectedPublicPolicy`, `AppliedPublicAccessBlock`
  * `RemovedPublicGrant`, `RemovedPublicStatement`, `EnforcedSSE`
* **EMF 지표(예시)**

  * `RemediationApplied`, `RemediationFailed`, `SkippedByAllowlist`, `NotificationsSent`

### 자주 나는 장애와 복구

| 증상                   | 원인              | 조치                                                     |
| -------------------- | --------------- | ------------------------------------------------------ |
| `AccessDenied` (KMS) | KMS 키 권한 미부여    | 람다 Role과 대상 버킷에 `kms:Encrypt`/`kms:GenerateDataKey` 허용 |
| 봉합 실패                | 람다 Role 권한 부족   | 상단 **필요 IAM 권한** 확인/보강                                 |
| 예외가 영구 허용됨           | 만료일 누락/경과 미정리   | 태그/레코드에 **만료일 필수** + 만료 시 정리                           |
| 알림 누락                | SNS/Slack 설정 미스 | SNS 토픽/구독 상태, Slack Webhook 확인                         |

### 롤백 전략

* 일시 중지: 파라미터 `Remediate=false` 후 재배포(감지만)
* 정책/ACL 복원: 스냅샷 버킷의 직전 정책/ACL JSON으로 수동 복원

---

## 보안 · 컴플라이언스

* **비밀 관리**: `.env`에 민감값 저장 금지. SSM Parameter Store / Secrets Manager 권장
* **최소 권한**: 실행역할의 S3/SNS 권한을 **대상 리소스 ARN으로만** 제한
* **데이터 보존**: 로그 보존 기간(`LogRetentionDays`) 및 스냅샷 수명주기 정책으로 비용/규정 준수
* **감사 추적**: 모든 조치 전/후 상태를 로그/스냅샷으로 기록. 예외는 사유·만료일 필수 기록
* **취약점 신고**: `SECURITY.md`에 신고 경로 명시(이메일/템플릿)

---

## 예외(Allowlist) 정책

### 태그 기반 (권장)

* 버킷 태그:

  * `sentinel:allow=true`
  * `sentinel:until=YYYY-MM-DD` (만료일 **필수**)
* 만료일 경과 시 자동으로 예외 무효화(로그 남김)

### DynamoDB 기반

```json
// 파티션키: BucketName, 정렬키: Scope("ACL"|"Policy"|"All"), Until: "2025-12-31"
{ "BucketName": "public-assets-prod", "Scope": "Policy", "Until": "2025-12-31", "Reason": "CDN 공개" }
```

### 파일 기반

`config/allowlist.json`:

```json
[
  { "bucket": "public-assets-dev", "scope": "All", "until": "2025-06-30", "reason": "개발 테스트" }
]
```

> 💡 **프로세스 권장**: 예외 승인 시 **사유·만료일 필수**. 만료일 경과 시 CI에서 실패시키거나 PR 체커로 차단.

---

## CI/CD 통합 (선택)

* **PR 시뮬레이션**: 공개 ACL/정책 변경을 포함한 IaC PR에 대해 스캐너/유닛테스트 실행
* **자동 요약 코멘트**: 상위 10개 조치 로그/권장 스니펫을 PR 코멘트봇으로 첨부
* **GitHub Actions 예시**(요지)

```yaml
name: sentinel-ci
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install -r requirements.txt
      - run: pytest -q --maxfail=1
      - run: sam validate
```

---

## 개발/테스트

* **코드 스타일**: `ruff`, `black`
* **테스트**: `pytest` (기본 커버리지 80%+ 권장)
* **로컬 실행**: `make demo` 또는 수동 AWS CLI 시나리오

---

## Make 명령 모음

```Makefile
.PHONY: deps build deploy delete demo test logs fmt lint

deps:          ## 의존성 설치
\tpip install -r requirements.txt

build:
\tsam build

deploy:        ## --guided를 사용하지 않으려면 samconfig.toml 참고
\tsam deploy --stack-name s3pb-sentinel --capabilities CAPABILITY_IAM

delete:
\tsam delete --stack-name s3pb-sentinel

demo:          ## 오픈버킷 재현 → 자동 봉합
\tpython scripts/demo_public_bucket.py || echo "scripts/demo_public_bucket.py 미존재 시 README의 수동 데모 절차를 사용하세요"

test:
\tpytest -q --maxfail=1 --disable-warnings

logs:
\taws logs tail /aws/lambda/s3pb-sentinel-remediator --follow

fmt:
\truff check --fix . && black .

lint:
\truff check . && black --check .
```

> ⚠️ **매치 체크**: `scripts/demo_public_bucket.py` 가 레포에 없다면 `demo` 타겟을 직접 수정하거나 README의 수동 데모 절차를 사용하세요.

---

## FAQ

**Q. 정적 웹 호스팅 등 합법적 공개가 필요한 버킷은?**
A. 태그 예외(`sentinel:allow=true` + `sentinel:until=YYYY-MM-DD`)를 사용하세요. 예외는 로그에 남고, 만료일 필수입니다.

**Q. KMS 사용 시 AccessDenied가 납니다.**
A. 람다 Role/버킷에 해당 KMS 키 사용 권한(`kms:Encrypt`, `kms:GenerateDataKey`)을 부여하세요.

**Q. 멀티리전 환경은 어떻게 보호하나요?**
A. EventBridge 룰/람다를 **각 리전**에 배포하거나 Organizations/CloudTrail 중앙화 전략을 고려하세요.

**Q. Slack Webhook은 어디에 두나요?**
A. `.env`에 직접 쓰지 말고, SSM/Secrets Manager에 저장 후 환경 변수로 주입하세요.

---

## 변경 이력 & 라이선스

* **변경 이력**: `CHANGELOG.md` 또는 GitHub Releases
* **라이선스**: 루트에 `LICENSE`(MIT/Apache-2.0 등) 포함

---

## 부록 A — 샘플 알림 페이로드

**SNS/Slack 공통 요지(JSON 요약)**

```json
{
  "bucket": "example-public-bucket",
  "detected": ["PublicAcl", "PublicPolicy"],
  "actions": ["AppliedPublicAccessBlock", "RemovedPublicGrant", "RemovedPublicStatement", "EnforcedSSE:AES256"],
  "allowlist": { "matched": false },
  "before": { "acl": "public-read", "policy_has_star_principal": true, "sse": "none" },
  "after":  { "acl": "private", "policy_removed": true, "sse": "AES256" },
  "remediation": "success",
  "timestamp": "2025-01-01T12:34:56Z"
}
```

---

## 부록 B — `samconfig` 예시

루트에 `samconfig.toml` 추가 시 `sam deploy`만으로 동일 파라미터 적용:

```toml
version = 0.1
[default.deploy.parameters]
stack_name = "s3pb-sentinel"
capabilities = "CAPABILITY_IAM"
parameter_overrides = "ProjectName=S3PBSentinel Remediate=true ForceSSE=AES256 KmsKeyArn=\"\" NotifyLevel=INFO SlackWebhookUrl=\"\" AllowlistMode=TAG AllowlistTableName=\"\" LogRetentionDays=30"
confirm_changeset = true
resolve_s3 = true
region = "ap-northeast-2"  # 실제 리전으로 수정
```

---

## 부록 C — CloudWatch 알람 샘플

**봉합 실패 감지**

* 지표: `RemediationFailed` (Sum, 5분)
* 임계치: `>= 1` → SNS 알림

**감지 급증**

* 지표: `DetectedPublic*` (Sum, 5분)
* 임계치: 베이스라인 대비 비정상 급증 시 경고

---

## 부록 D — 최소권한 IAM 정책 스니펫

> 실제 리소스 ARN으로 **반드시 제한**하세요. 아래는 개념 예시입니다.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow",
      "Action": [
        "s3:GetBucketAcl","s3:PutBucketAcl",
        "s3:GetBucketPolicy","s3:PutBucketPolicy","s3:DeleteBucketPolicy",
        "s3:GetPublicAccessBlock","s3:PutPublicAccessBlock",
        "s3:GetBucketEncryption","s3:PutBucketEncryption",
        "s3:GetBucketTagging","s3:PutBucketTagging"
      ],
      "Resource": ["arn:aws:s3:::<대상-버킷-이름>"]
    },
    { "Effect": "Allow",
      "Action": ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],
      "Resource": ["arn:aws:logs:<region>:<account-id>:log-group:/aws/lambda/s3pb-sentinel-remediator*:*"]
    },
    { "Effect": "Allow",
      "Action": ["cloudwatch:PutMetricData"],
      "Resource": "*",
      "Condition": { "StringEquals": { "cloudwatch:namespace": "S3PublicBucketSentinel" } }
    },
    { "Effect": "Allow",
      "Action": ["sns:Publish"],
      "Resource": ["arn:aws:sns:<region>:<account-id>:<sentinel-topic-name>"]
    }
  ]
}
```

---

### 공개 전 최종 체크리스트

* [ ] `template.yaml` 파라미터명 ↔ README 표 **동일** 확인
* [ ] 로그 그룹/함수명(`s3pb-sentinel-remediator`) **실제와 일치**
* [ ] `scripts/demo_public_bucket.py` 유무에 따라 `make demo` 타겟 조정
* [ ] `.env.example` 제공(가짜 값), **민감값 커밋 금지**
* [ ] `LICENSE`, `SECURITY.md`, `CHANGELOG.md`(또는 Releases) 준비
* [ ] Mermaid 다이어그램 GitHub 렌더링 정상
* [ ] CI 배지/라이선스 배지(선택) 상단 추가


