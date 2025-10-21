"""Formats and publishes SNS notifications for remediation outcomes."""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Mapping, Sequence

from .types import ActionOutcome, RemediationSummary

try:  # pragma: no cover
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:  # pragma: no cover - local dev
    boto3 = None
    BotoCoreError = ClientError = Exception  # type: ignore

LOGGER = logging.getLogger(__name__)
SNS_TOPIC_ENV = "SNS_TOPIC_ARN"
LEGACY_TOPIC_ENV = "NOTIFY_TOPIC_ARN"

ACTION_STATE_FIELDS = {
    "public-access-block": "pba",
    "bucket-policy": "policy",
    "bucket-acl": "acl",
    "bucket-encryption": "sse",
}


def publish(topic_arn: str | None, subject: str, summary_dict: Mapping[str, Any]) -> None:
    """Publish the provided summary payload to the configured SNS topic."""
    message = json.dumps(dict(summary_dict), default=str, ensure_ascii=False)
    LOGGER.info("Publishing remediation summary subject=%s payload=%s", subject, message)

    if not topic_arn:
        LOGGER.warning("SNS topic not configured; skipping publish")
        return
    if not boto3:  # pragma: no cover - local dev fallback
        LOGGER.info("boto3 not available; skipping SNS publish")
        return

    client = boto3.client("sns")
    try:
        client.publish(
            TopicArn=topic_arn,
            Message=message,
            Subject=subject[:100],  # SNS limits subjects to 100 characters
        )
    except (BotoCoreError, ClientError) as exc:  # pragma: no cover - network path
        LOGGER.error("Failed to publish remediation summary: %s", exc)


def publish_summary(summary: RemediationSummary) -> None:
    """Serialize a RemediationSummary and publish it to SNS."""
    topic_arn = os.getenv(SNS_TOPIC_ENV) or os.getenv(LEGACY_TOPIC_ENV)
    subject = _render_subject(summary)
    summary_payload = _format_summary(summary)
    publish(topic_arn, subject, summary_payload)


def publish_result(result) -> None:  # type: ignore[no-untyped-def]
    # Backwards compatibility shim for existing callers.
    summary = RemediationSummary(
        bucket=result.finding.bucket,
        actions=[],
        status="success" if result.succeeded else "failure",
        event_name="unknown",
        account_id=result.finding.bucket.account_id,
        region=result.finding.bucket.region,
        dry_run=False,
        allowlisted=False,
        event_detail={},
    )
    publish_summary(summary)


def _render_subject(summary: RemediationSummary) -> str:
    status = summary.status.upper()
    return f"[Sentinel] {summary.bucket.name} :: {status}"


def _format_summary(summary: RemediationSummary) -> dict[str, Any]:
    event_detail = summary.event_detail or {}
    payload = {
        "bucket": summary.bucket.name,
        "region": summary.bucket.region,
        "account": summary.account_id,
        "eventName": summary.event_name,
        "actor": _extract_actor(event_detail),
        "actions": [_serialize_action(action) for action in summary.actions],
        "before": _collect_state(summary.actions, "before"),
        "after": _collect_state(summary.actions, "after"),
        "allowlist_applied": summary.allowlisted,
        "dry_run": summary.dry_run,
        "skipped": summary.skipped,
        "status": summary.status,
        "message": summary.message,
        "error": summary.error,
    }
    return payload


def _collect_state(actions: Sequence[ActionOutcome], attribute: str) -> dict[str, Any]:
    state: dict[str, Any] = {}
    for action in actions:
        key = ACTION_STATE_FIELDS.get(action.name)
        if not key:
            continue
        snapshot = getattr(action, attribute, None)
        if snapshot is not None:
            state[key] = snapshot
    return state


def _serialize_action(action: ActionOutcome) -> dict[str, Any]:
    return {
        "name": action.name,
        "changed": action.changed,
        "error": action.error,
        "message": action.message,
        "before": action.before,
        "after": action.after,
        "duration_ms": getattr(action, "duration_ms", None),
    }


def _extract_actor(event_detail: Mapping[str, Any]) -> str | None:
    identity = event_detail.get("userIdentity")
    if isinstance(identity, Mapping):
        arn = identity.get("arn")
        if arn:
            return str(arn)
        principal = identity.get("principalId")
        if principal:
            return str(principal)
    source_ip = event_detail.get("sourceIPAddress")
    if source_ip:
        return str(source_ip)
    return None
