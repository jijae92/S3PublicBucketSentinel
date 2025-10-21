"""AWS Lambda entrypoint that reacts to EventBridge events and enforces S3 access controls."""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Callable, Iterable

from . import allowlist, policy_lib, sse_lib, acl_lib, notifier, metrics
from .types import ActionOutcome, BucketDescriptor, PublicAccessFinding, RemediationSummary, Event

try:  # pragma: no cover - boto3 optional in local development
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:  # pragma: no cover
    boto3 = None
    BotoCoreError = ClientError = Exception  # type: ignore

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)

DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"
SSE_MODE = os.getenv("SSE_MODE", "SSE-S3")
KMS_KEY_ARN = os.getenv("KMS_KEY_ARN", "") or None
ENFORCE_ACCOUNT_PBA = os.getenv("ENFORCE_ACCOUNT_PBA", "true").lower() == "true"
ALLOWLIST_SSM_PARAM = os.getenv("ALLOWLIST_SSM_PARAM", "/security/sentinel/allowlist")
ALLOWLIST_LOCAL_JSON = os.getenv("ALLOWLIST_LOCAL_JSON", "config/sentinel-allow.json")
ALLOW_CROSS_ACCOUNT = os.getenv("ALLOW_CROSS_ACCOUNT", "false").lower() == "true"

if SSE_MODE.upper() == "SSE-KMS" and not KMS_KEY_ARN:
    LOGGER.warning("SSE-KMS mode selected without KMS key ARN; remediation will log but skip KMS enforcement")

ALLOWLIST_CHECKER = allowlist.AllowlistChecker(
    ssm_param=ALLOWLIST_SSM_PARAM,
    local_json=ALLOWLIST_LOCAL_JSON,
)

DESIRED_PBA = policy_lib.DESIRED_PUBLIC_ACCESS_BLOCK


def lambda_handler(event: Event, context: Any) -> dict[str, Any]:
    """AWS Lambda handler compatible with EventBridge invocations."""
    LOGGER.debug("Received event: %s", json.dumps(event))
    bucket = _extract_bucket(event)
    now = metrics.now()

    allow_decision = ALLOWLIST_CHECKER.evaluate(bucket.name, now=now)
    tag_decision = ALLOWLIST_CHECKER.evaluate_tags(bucket.name, bucket.tags)
    skip_decision = allow_decision if allow_decision.matched else tag_decision
    if skip_decision.matched:
        LOGGER.info("Bucket %s allowlisted (%s); skipping remediation", bucket.name, skip_decision.reason)
        summary = RemediationSummary(
            bucket=bucket,
            actions=[],
            status="skip",
            event_name=event.get("detail", {}).get("eventName", "unknown"),
            account_id=bucket.account_id,
            region=bucket.region,
            dry_run=DRY_RUN,
            allowlisted=True,
            skipped=True,
            message=f"Allowlisted until {skip_decision.expires_at}" if skip_decision.expires_at else skip_decision.reason,
            event_detail=event.get("detail", {}),
        )
        notifier.publish_summary(summary)
        metrics.put_metric(
            bucket_name=bucket.name,
            action="allowlist-check",
            result="skip",
            latency_ms=0.0,
            bucket_public_before=None,
            bucket_public_after=None,
            sse_before=None,
            sse_after=None,
        )
        return {"status": "skipped", "reason": "allowlisted"}

    finding = PublicAccessFinding(
        bucket=bucket,
        issue="Public access detected",
        evidence={"raw_event": event},
        detected_at=now,
    )

    actions: list[ActionOutcome] = []
    public_state = True
    sse_state = "unknown"
    status = "success"
    error_message: str | None = None

    pipeline: Iterable[tuple[str, Callable[[], ActionOutcome]]] = [
        (
            "public-access-block",
            lambda: policy_lib.ensure_public_access_block(
                bucket,
                apply=not DRY_RUN,
                desired=DESIRED_PBA,
                enforce_account_level=ENFORCE_ACCOUNT_PBA,
            ),
        ),
        (
            "bucket-acl",
            lambda: acl_lib.revoke_public_acl(bucket, apply=not DRY_RUN),
        ),
        # TODO: detect cross-account principals and honour ALLOW_CROSS_ACCOUNT toggle once policy introspection is wired.
        (
            "bucket-policy",
            lambda: policy_lib.lockdown_bucket_policy(
                bucket,
                apply=not DRY_RUN,
                allow_cross_account=ALLOW_CROSS_ACCOUNT,
            ),
        ),
        (
            "bucket-encryption",
            lambda: sse_lib.ensure_encryption(
                bucket,
                mode=SSE_MODE,
                kms_key_arn=KMS_KEY_ARN,
                apply=not DRY_RUN,
            ),
        ),
        (
            "bucket-tags",
            lambda: _apply_tags(bucket, now, apply=not DRY_RUN),
        ),
    ]

    for name, step in pipeline:
        start = time.perf_counter()
        prev_public_state = public_state
        prev_sse_state = sse_state
        try:
            outcome = step()
        except Exception as exc:  # pragma: no cover - defensive guard
            LOGGER.exception("Remediation step failed for %s", bucket.name)
            duration_ms = (time.perf_counter() - start) * 1000
            outcome = ActionOutcome(
                name=name,
                changed=False,
                error=str(exc),
                message="Step raised exception",
            )
            outcome.duration_ms = duration_ms
            actions.append(outcome)
            status = "error"
            error_message = str(exc)
            metrics.put_metric(
                bucket_name=bucket.name,
                action=name,
                result="error",
                latency_ms=duration_ms,
                bucket_public_before=prev_public_state,
                bucket_public_after=public_state,
                sse_before=prev_sse_state,
                sse_after=sse_state,
            )
            continue

        duration_ms = (time.perf_counter() - start) * 1000
        outcome.duration_ms = duration_ms
        actions.append(outcome)

        if name in {"public-access-block", "bucket-acl", "bucket-policy"} and outcome.changed:
            public_state = False
        if name == "bucket-encryption" and outcome.changed:
            sse_state = outcome.after.get("algorithm", "unknown") if outcome.after else "unknown"
        result_label = "applied" if outcome.changed else ("noop" if not outcome.error else "error")
        metrics.put_metric(
            bucket_name=bucket.name,
            action=name,
            result=result_label,
            latency_ms=duration_ms,
            bucket_public_before=prev_public_state,
            bucket_public_after=public_state,
            sse_before=prev_sse_state,
            sse_after=sse_state,
        )
        if outcome.error:
            status = "error"
            error_message = outcome.error

    message = (
        "Remediation pipeline executed"
        if status == "success"
        else "Remediation pipeline encountered errors"
    )
    if DRY_RUN:
        message = "Dry run - no changes applied"

    summary = RemediationSummary(
        bucket=bucket,
        actions=actions,
        status=status,
        event_name=event.get("detail", {}).get("eventName", "unknown"),
        account_id=bucket.account_id,
        region=bucket.region,
        dry_run=DRY_RUN,
        allowlisted=False,
        skipped=False,
        message=message,
        error=error_message,
        event_detail=event.get("detail", {}),
    )
    notifier.publish_summary(summary)

    return {
        "status": status,
        "actions": [action.name for action in actions],
        "dryRun": DRY_RUN,
        "error": error_message,
    }


def _extract_bucket(event: Event) -> BucketDescriptor:
    detail = event.get("detail", {})
    request_params = detail.get("requestParameters", {})
    bucket_name = request_params.get("bucketName")
    if not bucket_name:
        resources = detail.get("resources") or event.get("resources", [])
        bucket_name = _bucket_name_from_resources(resources)
    account_id = event.get("account", "unknown")
    region = event.get("region", "us-east-1")
    tags = detail.get("tags", {})
    return BucketDescriptor(name=bucket_name, account_id=account_id, region=region, tags=tags)


def _bucket_name_from_resources(resources: Any) -> str:
    if isinstance(resources, list):
        for resource in resources:
            arn = resource.get("ARN") if isinstance(resource, dict) else resource
            if isinstance(arn, str) and ":bucket/" in arn:
                return arn.split(":bucket/")[-1]
    return "unknown"


def _apply_tags(bucket: BucketDescriptor, now: datetime, *, apply: bool) -> ActionOutcome:
    desired_tags = dict(bucket.tags)
    desired_tags["sentinel:lastRemediatedAt"] = now.isoformat()
    desired_tags["sentinel:mode"] = "DRY_RUN" if DRY_RUN else "ENFORCE"
    if apply and boto3:
        client = boto3.client("s3", region_name=bucket.region)
        try:
            client.put_bucket_tagging(
                Bucket=bucket.name,
                Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in desired_tags.items()]},
            )
        except (ClientError, BotoCoreError) as exc:  # pragma: no cover - log guard
            LOGGER.error("Failed to update tags for %s: %s", bucket.name, exc)
            return ActionOutcome(
                name="bucket-tags",
                changed=False,
                before={"tags": dict(bucket.tags)},
                after={"tags": desired_tags},
                error=str(exc),
                message="Failed to update tags",
            )
    elif apply and not boto3:
        LOGGER.warning("boto3 unavailable; skipping tag update")
    else:
        LOGGER.info("Dry run: would apply sentinel tags %s", desired_tags)
    return ActionOutcome(
        name="bucket-tags",
        changed=apply,
        before={"tags": dict(bucket.tags)},
        after={"tags": desired_tags},
        message="Sentinel tags updated" if apply else "Dry run - tags unchanged",
    )
