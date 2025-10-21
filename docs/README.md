# S3 Public Bucket Sentinel

## 소개
S3 Public Bucket Sentinel은 AWS 계정 전반에서 S3 버킷의 퍼블릭 노출을 감지하고 차단하는 자동화 파이프라인입니다. 주요 목적은 사고 대응 시간을 최소화하고 거버넌스 체계를 돕는 것입니다.

### 핵심 기능
- **이벤트 감지**: CloudTrail → EventBridge 경로를 통해 퍼블릭 ACL/정책 변경 이벤트를 실시간으로 수신합니다.
- **Public 차단**: ACL, 버킷 정책, Public Access Block(PBA)을 강제해 익명 접근을 제거합니다.
- **SSE 강제**: Predefined 모드(SSE-S3 또는 SSE-KMS)에 따라 서버측 암호화를 자동 적용합니다.
- **SNS 알림**: 조치 결과를 SNS 주제로 발행하여 Slack/Email 등으로 전달할 수 있습니다.

## 빠른 시작
1. 의존성 설치
   ```bash
   make deps
   ```
2. 빌드 및 배포
   ```bash
   sam build
   sam deploy --guided
   ```
3. Allowlist 샘플 구성 확인
   - `config/sentinel-allow.json` 파일을 참고하여 TTL 기반 예외 항목을 정의합니다.
   - 배포 시 `ALLOWLIST_LOCAL_JSON` 환경 변수 또는 SSM Parameter Store 경로를 설정하세요.

## 환경 변수
| 변수 | 설명 |
|------|------|
| `DRY_RUN` | `true`인 경우 실환경에 변경을 적용하지 않고 로그/SNS에만 기록합니다. 기본값 `false`. |
| `SSE_MODE` | `SSE-S3`, `SSE-KMS`, `DISABLED` 중 선택. 암호화 모드를 결정합니다. |
| `KMS_KEY_ARN` | `SSE-KMS` 모드에서 사용할 KMS 키 ARN. 빈 값이면 조치가 중단됩니다. |
| `ENFORCE_ACCOUNT_PBA` | `true`인 경우 계정 단위 Public Access Block도 함께 설정합니다. |
| `ALLOWLIST_SSM_PARAM` | SSM Parameter Store에 저장된 allowlist JSON 경로. |
| `ALLOWLIST_LOCAL_JSON` | Lambda 번들에 포함된 allowlist JSON 경로. 우선순위는 SSM → Local → 버킷 태그입니다. |

## 운영 & 모니터링
- **CloudWatch 지표**: `S3PublicSentinel` 네임스페이스의 EMF 로그(액션/결과/버킷 차원)를 Dashboard로 시각화합니다.
- **SNS 구독**: `SNS_TOPIC_ARN`에 이메일, Slack webhook, EventBridge Pipe 등을 연결해 조치 알림을 수신합니다.
- **로그 예시 확인**: `sam logs -n RemediatorFunction --stack-name <STACK>` 명령으로 Lambda 로그를 tail 하며, 각 액션별 `before/after` 스냅샷과 오류를 점검합니다.

## 보안·컴플라이언스 매핑
| 표준 | 관련 통제 | Sentinel 구현 |
|------|-----------|---------------|
| CIS AWS Foundations | S3.1 (Public Access Block 유지), S3.2 (퍼블릭 정책 차단), S3.5 (기본 암호화 강제) | Remediator가 PBA, 정책, SSE를 자동 보정 |
| NIST SP 800-53 | AC-3, AC-6, SC-7, SC-28 | 접근 제어 강화, 경계 보호, 데이터 암호화를 자동화 |
| ISO/IEC 27001 | A.9 (접근 통제), A.10 (암호화), A.12.6 (시스템 변경 관리) | 자동 정책 집행과 변경 로그로 규정 준수 지원 |

## Definition of Done
- `pytest` 전 테스트케이스 통과 및 최소 커버리지 80% 이상 확보, 목표 90%. `pytest --cov=backend --cov-fail-under=80` 기준.
- Remediator/Scanner 기능에 대해 `DRY_RUN`과 `ENFORCE` 모드를 모두 검증하는 통합 테스트 포함.
- 주요 제약 및 예외 사항(예: 특정 리전에 대한 제한, 수동 승인이 필요한 단계)을 `docs/` 디렉터리에 문서화.
