"""Scheduled full-bucket scan orchestration."""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from ..remediator import acl_lib, allowlist, metrics, notifier, policy_lib, sse_lib
from ..remediator.types import ActionOutcome, BucketDescriptor, PublicAccessFinding

try:  # pragma: no cover - boto3 optional during tests
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:  # pragma: no cover - fallback for local unit tests
    boto3 = None
    BotoCoreError = ClientError = Exception  # type: ignore

LOGGER = logging.getLogger(__name__)

REMEDIATE_ENV = "REMEDIATE_ON_FIND"
SNS_TOPIC_ENV = "SCANNER_SNS_TOPIC"
ENFORCE_ACCOUNT_PBA = os.getenv("ENFORCE_ACCOUNT_PBA", "true").lower() == "true"
ALLOW_CROSS_ACCOUNT = os.getenv("ALLOW_CROSS_ACCOUNT", "false").lower() == "true"
SSE_MODE = os.getenv("SSE_MODE", "SSE-S3")
KMS_KEY_ARN = os.getenv("KMS_KEY_ARN", "") or None


@dataclass(slots=True)
class BucketState:
    bucket: BucketDescriptor
    public_access_block: Mapping[str, bool] | None
    acl_public: bool | None
    policy_public: bool | None
    sse: Mapping[str, str] | None
    allowlist: Mapping[str, object | None]
    issues: Sequence[str]
    actions: Sequence[ActionOutcome]
    remediated: bool


@dataclass(slots=True)
class ScanOutcome:
    states: Sequence[BucketState]
    findings: Sequence[PublicAccessFinding]
    allowlisted: int
    remediated: int


def handler(event, context) -> dict[str, object]:  # type: ignore[no-untyped-def]
    """Lambda entrypoint used by the scheduled scanner."""
    remediate = os.getenv(REMEDIATE_ENV, "false").lower() == "true"
    sns_topic = (
        os.getenv(SNS_TOPIC_ENV)
        or os.getenv(notifier.SNS_TOPIC_ENV)
        or os.getenv(notifier.LEGACY_TOPIC_ENV)
    )
    outcome = run_scan(remediate=remediate, dry_run=False, sns_topic=sns_topic)
    return serialize_outcome(outcome)


def run_scan(
    *,
    remediate: bool,
    dry_run: bool,
    bucket_names: Sequence[str] | None = None,
    session=None,
    aws=None,
    sse_resolver=None,
    sns_topic: str | None = None,
    now=None,
) -> ScanOutcome:
    """Execute a scan across the provided bucket set."""
    facade = aws or AwsFacade(session)
    sse_fn = sse_resolver or sse_lib.get_sse
    timestamp = now or metrics.now()

    descriptors = tuple(_discover_buckets(facade, bucket_names))
    outcome = _scan_descriptors(
        descriptors=descriptors,
        facade=facade,
        timestamp=timestamp,
        remediate=remediate,
        dry_run=dry_run,
        sse_fn=sse_fn,
    )
    summary = serialize_outcome(outcome)
    LOGGER.info("Scan summary: %s", json.dumps(summary, default=str))
    if sns_topic:
        _publish_summary(summary, sns_topic)
    return outcome


def _scan_descriptors(
    *,
    descriptors: Sequence[BucketDescriptor],
    facade,
    timestamp,
    remediate: bool,
    dry_run: bool,
    sse_fn,
) -> ScanOutcome:
    states: list[BucketState] = []
    findings: list[PublicAccessFinding] = []
    allowlisted = 0
    remediated_count = 0

    for bucket in descriptors:
        controls = _collect_controls(bucket, facade, sse_fn)
        decision = allowlist.check(bucket, now=timestamp)
        issues = _enumerate_issues(controls)
        actions: tuple[ActionOutcome, ...] = ()
        remediated_flag = False

        if remediate and issues and not decision["allowed"]:
            actions = _remediate_bucket(bucket, dry_run)
            remediated_flag = any(action.changed for action in actions)

        state = BucketState(
            bucket=bucket,
            public_access_block=controls["pba"],
            acl_public=controls["acl_public"],
            policy_public=controls["policy_public"],
            sse=controls["sse"],
            allowlist=decision,
            issues=issues,
            actions=actions,
            remediated=remediated_flag,
        )
        states.append(state)

        if decision["allowed"]:
            allowlisted += 1
            continue

        if issues:
            findings.append(_build_finding(bucket, issues, controls, timestamp))
        if remediated_flag:
            remediated_count += 1

    return ScanOutcome(
        states=tuple(states),
        findings=tuple(findings),
        allowlisted=allowlisted,
        remediated=remediated_count,
    )


def serialize_outcome(outcome: ScanOutcome) -> dict[str, object]:
    """Return a JSON-serializable representation of the scan outcome."""
    buckets = [
        {
            "bucket": state.bucket.name,
            "region": state.bucket.region,
            "account": state.bucket.account_id,
            "public_access_block": state.public_access_block,
            "acl_public": state.acl_public,
            "policy_public": state.policy_public,
            "sse": state.sse,
            "allowlist": state.allowlist,
            "issues": list(state.issues),
            "remediated": state.remediated,
        }
        for state in outcome.states
    ]
    findings = [
        {
            "bucket": finding.bucket.name,
            "issue": finding.issue,
            "detected_at": finding.detected_at.isoformat(),
            "account_id": finding.bucket.account_id,
            "region": finding.bucket.region,
        }
        for finding in outcome.findings
    ]
    return {
        "scanned": len(outcome.states),
        "findings": len(outcome.findings),
        "remediated": outcome.remediated,
        "allowlisted": outcome.allowlisted,
        "buckets": buckets,
        "findings_detail": findings,
    }


def _discover_buckets(aws_facade, bucket_names: Sequence[str] | None) -> Iterable[BucketDescriptor]:
    names = list(bucket_names) if bucket_names else aws_facade.list_bucket_names()
    account_id = aws_facade.account_id()
    for name in names:
        region = aws_facade.get_bucket_region(name)
        tags = aws_facade.get_bucket_tags(name)
        yield BucketDescriptor(name=name, account_id=account_id, region=region, tags=tags)


def _collect_controls(bucket: BucketDescriptor, aws_facade, sse_fn) -> dict[str, object]:
    pba_cfg = aws_facade.get_public_access_block(bucket.name)
    acl = aws_facade.get_bucket_acl(bucket.name)
    policy = aws_facade.get_bucket_policy(bucket.name)
    sse = sse_fn(bucket)
    return {
        "pba": pba_cfg,
        "pba_enforced": _pba_enforced(pba_cfg),
        "acl": acl,
        "acl_public": acl_lib.has_public_acl(acl) if acl is not None else None,
        "policy": policy,
        "policy_public": policy_lib.is_public_policy(policy) if policy else False,
        "sse": sse,
    }


def _enumerate_issues(controls: Mapping[str, object]) -> list[str]:
    issues: list[str] = []
    if not controls.get("pba_enforced"):
        issues.append("PublicAccessBlock disabled")
    if controls.get("acl_public"):
        issues.append("Public ACL grants detected")
    if controls.get("policy_public"):
        issues.append("Public bucket policy detected")
    if controls.get("sse") is None:
        issues.append("SSE not configured")
    return issues


def _remediate_bucket(bucket: BucketDescriptor, dry_run: bool) -> tuple[ActionOutcome, ...]:
    apply_changes = not dry_run
    actions = (
        policy_lib.ensure_public_access_block(
            bucket,
            apply=apply_changes,
            desired=policy_lib.DESIRED_PUBLIC_ACCESS_BLOCK,
            enforce_account_level=ENFORCE_ACCOUNT_PBA,
        ),
        acl_lib.revoke_public_acl(bucket, apply=apply_changes),
        policy_lib.lockdown_bucket_policy(
            bucket,
            apply=apply_changes,
            allow_cross_account=ALLOW_CROSS_ACCOUNT,
        ),
        sse_lib.ensure_encryption(
            bucket,
            mode=SSE_MODE,
            kms_key_arn=KMS_KEY_ARN,
            apply=apply_changes,
        ),
    )
    return actions


def _build_finding(
    bucket: BucketDescriptor,
    issues: Sequence[str],
    controls: Mapping[str, object],
    timestamp,
) -> PublicAccessFinding:
    evidence = {
        "public_access_block": controls.get("pba"),
        "acl_public": controls.get("acl_public"),
        "policy_public": controls.get("policy_public"),
        "sse": controls.get("sse"),
    }
    return PublicAccessFinding(
        bucket=bucket,
        issue="; ".join(issues),
        evidence=evidence,
        detected_at=timestamp,
    )


def _publish_summary(summary: Mapping[str, object], topic_arn: str) -> None:
    subject = f"[Sentinel][Scan] {summary['scanned']} buckets checked"
    notifier.publish(topic_arn, subject, summary)


def _pba_enforced(config: Mapping[str, bool] | None) -> bool:
    if not config:
        return False
    required = (
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    )
    return all(bool(config.get(key)) for key in required)


class AwsFacade:
    """Thin wrapper around boto3 to simplify testing."""

    def __init__(self, session=None):
        if not boto3:  # pragma: no cover - enforced in runtime
            raise RuntimeError("boto3 is required to perform scans")
        self._session = session or boto3.Session()
        self._s3 = self._session.client("s3")
        self._sts = self._session.client("sts")
        self._account_id: str | None = None

    def account_id(self) -> str:
        if not self._account_id:
            response = self._sts.get_caller_identity()
            self._account_id = response.get("Account", "unknown")
        return self._account_id

    def list_bucket_names(self) -> list[str]:
        response = self._s3.list_buckets()
        return [bucket["Name"] for bucket in response.get("Buckets", [])]

    def get_bucket_region(self, bucket_name: str) -> str:
        try:
            response = self._s3.get_bucket_location(Bucket=bucket_name)
        except (ClientError, BotoCoreError):  # pragma: no cover - logged upstream
            LOGGER.warning("Failed to resolve region for %s", bucket_name)
            return "us-east-1"
        region = response.get("LocationConstraint")
        return region or "us-east-1"

    def get_bucket_tags(self, bucket_name: str) -> Mapping[str, str]:
        try:
            response = self._s3.get_bucket_tagging(Bucket=bucket_name)
        except (ClientError, BotoCoreError):
            return {}
        tag_set = response.get("TagSet", [])
        return {tag.get("Key"): tag.get("Value") for tag in tag_set if tag.get("Key")}

    def get_public_access_block(self, bucket_name: str) -> Mapping[str, bool] | None:
        try:
            response = self._s3.get_public_access_block(Bucket=bucket_name)
        except (ClientError, BotoCoreError):
            return None
        return response.get("PublicAccessBlockConfiguration")

    def get_bucket_acl(self, bucket_name: str):  # type: ignore[no-untyped-def]
        try:
            return self._s3.get_bucket_acl(Bucket=bucket_name)
        except (ClientError, BotoCoreError):
            return None

    def get_bucket_policy(self, bucket_name: str):  # type: ignore[no-untyped-def]
        try:
            response = self._s3.get_bucket_policy(Bucket=bucket_name)
        except (ClientError, BotoCoreError):
            return None
        policy = response.get("Policy")
        if not policy:
            return None
        try:
            return json.loads(policy)
        except json.JSONDecodeError:
            LOGGER.warning("Malformed policy JSON for %s", bucket_name)
            return None


__all__ = [
    "AwsFacade",
    "BucketState",
    "ScanOutcome",
    "handler",
    "run_scan",
    "serialize_outcome",
]
