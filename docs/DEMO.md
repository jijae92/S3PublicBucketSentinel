# S3 Public Bucket Sentinel Demo

This guide walks through a live demonstration of Sentinel’s remediation flow, the allowlist life cycle, and nightly scanning insights.

## 1. Architecture Overview

```mermaid
flowchart LR
    subgraph Event Flow
        EB[EventBridge\nBucket Exposure Event] --> REM[Remediator Lambda]
        REM --> SNS[SNS Notifications]
    end
    subgraph Nightly Cycle
        SCHED[Nightly Schedule] --> SCAN[Nightly Scanner Job]
        SCAN --> SNS
        SCAN --> REPORTS[Reports\n(JSON & CSV)]
    end
```

## 2. Reproduce a Public Exposure

1. **Create Bucket**
   ```bash
   aws s3api create-bucket --bucket demo-sentinel-bucket --region us-east-1
   ```
2. **Make It Public**
   ```bash
   aws s3api put-bucket-acl --bucket demo-sentinel-bucket --acl public-read
   aws s3api put-bucket-policy --bucket demo-sentinel-bucket --policy file://fixtures/public-policy.json
   ```
3. **Trigger Event**
   - Perform an object read via `curl` or `aws s3 cp` to emit a CloudTrail PutBucketAcl/PutBucketPolicy event.

### Capture Evidence

- **Lambda Logs**
  ```bash
  sam logs -n RemediatorFunction --stack-name s3-public-bucket-sentinel --tail
  ```
- **SNS Message**
  - Subscribe an email/Slack webhook or pull from the dead-letter queue (if configured) to capture the JSON summary.
- **Before/After Diff**
  - Use the SNS payload to highlight ACL/Policy/SSE changes, e.g.:
    ```
    ACL: public → private
    Policy: Allow * → deny-all template
    SSE: none → AES256
    ```

## 3. DRY_RUN to ENFORCE Transition

| Step | Action | Expected Outcome |
|------|--------|------------------|
| 1 | Deploy with `DRY_RUN=true` | Notifications show `dry_run=true`, resources unchanged. |
| 2 | Review diff outputs with stakeholders. | Confirms no unintended impact. |
| 3 | Update stack: `sam deploy --parameter-overrides DRY_RUN=false` | Remediator applies changes; SNS marks `dryRun=false`. |
| 4 | Re-run exposure scenario. | Bucket is automatically remediated (ACL/Policy/SSE corrected). |

## 4. Allowlist TTL Demonstration

1. **Add TTL Tag**
   ```bash
   aws s3api put-bucket-tagging --bucket demo-sentinel-bucket \
     --tagging 'TagSet=[{Key=sentinel:public-allow-until,Value=2025-12-31},{Key=sentinel:public-reason,Value=Red Team}]'
   ```
2. **Trigger Exposure**
   - Remediator skips the bucket; SNS message indicates `allowlist_applied=true` with expiration timestamp.
3. **Expire the Allowlist**
   ```bash
   aws s3api put-bucket-tagging --bucket demo-sentinel-bucket \
     --tagging 'TagSet=[{Key=sentinel:public-allow-until,Value=2023-01-01}]'
   ```
4. **Re-trigger Exposure**
   - Remediator now enforces controls automatically, removing public access.

## 5. Nightly Scanner Report Samples

- **JSON**
  ```json
  {
    "timestamp": "2025-10-21T02:10:00Z",
    "scanned": 132,
    "findings": [
      {
        "bucket": "demo-sentinel-bucket",
        "issues": ["PublicAccessBlock disabled", "Public ACL grants detected"],
        "detected_at": "2025-10-21T02:09:58Z"
      }
    ],
    "allowlisted": 4
  }
  ```
- **CSV**
  ```csv
  bucket,issue,detected_at,account_id,region
  demo-sentinel-bucket,PublicAccessBlock disabled; Public ACL grants detected,2025-10-21T02:09:58Z,123456789012,us-east-1
  ```

## 6. Presentation Highlights

- **MTTR Improvement**  
  Show average mean time to remediation dropping from ~45 minutes (manual) to <5 minutes with Sentinel auto-remediation.
- **Log Highlights**
  1. `bucket-acl`: “Public ACL grants removed”
  2. `bucket-policy`: “Bucket policy locked down”
  3. `bucket-encryption`: “Bucket encryption enforced”
- **Key Takeaway**  
  Demonstrate the switch from DRY_RUN to ENFORCE and allowlist TTLs as governance levers, backed by nightly scanner reports and SNS alerts.
