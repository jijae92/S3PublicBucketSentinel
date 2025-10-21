"""Reporting utilities for scan outcomes."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

# Avoid runtime circular imports by type-checking only
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .job import ScanOutcome, BucketState


def generate_summary(outcome, timestamp: datetime | None = None) -> dict[str, Any]:
    """Produce a structured summary for scanner outcomes."""
    scanned_at = _timestamp(timestamp)
    states: Sequence = getattr(outcome, "states", ())

    findings = []
    summary_counts = {
        "total": len(states),
        "public_acl": 0,
        "public_policy": 0,
        "no_sse": 0,
        "remediated": 0,
        "skipped_allow": 0,
    }

    for state in states:
        row = _state_to_row(state, scanned_at)
        findings.append(row)

        summary_counts["public_acl"] += int(row["public_acl"])
        summary_counts["public_policy"] += int(row["public_policy"])
        summary_counts["no_sse"] += int(row["sse"] in {"NONE", "UNKNOWN"})
        summary_counts["remediated"] += int(row["action"] == "REMEDIATED")
        summary_counts["skipped_allow"] += int(row["action"] == "SKIPPED")

    payload = {
        "scanned_at": scanned_at,
        "summary": summary_counts,
        "findings": findings,
    }
    return payload


def render(report_payload: Mapping[str, Any], fmt: str = "json") -> str:
    """Render the report payload as JSON or CSV."""
    if fmt == "csv":
        return _render_csv(report_payload.get("findings", []), report_payload.get("scanned_at"))
    return json.dumps(report_payload, indent=2, default=str, ensure_ascii=False)


def _state_to_row(state, timestamp: str) -> dict[str, Any]:
    bucket = getattr(state, "bucket")
    allow_decision = getattr(state, "allowlist", {}) or {}
    action = _derive_action(state, allow_decision)
    sse_info = _normalize_sse(getattr(state, "sse", None))

    row = {
        "bucket": bucket.name if bucket else "unknown",
        "public_acl": bool(getattr(state, "acl_public", False)),
        "public_policy": bool(getattr(state, "policy_public", False)),
        "sse": sse_info,
        "pba": _pba_enforced(getattr(state, "public_access_block", None)),
        "allowlist": bool(allow_decision.get("allowed")),
        "action": action,
        "ts": timestamp,
    }
    return row


def _derive_action(state, allow_decision: Mapping[str, Any]) -> str:
    if allow_decision.get("allowed"):
        return "SKIPPED"
    if getattr(state, "remediated", False):
        return "REMEDIATED"
    return "NONE"


def _normalize_sse(sse: Mapping[str, Any] | None) -> str:
    if not sse:
        return "NONE"
    algorithm = sse.get("algorithm") or sse.get("SSEAlgorithm")
    if not algorithm:
        return "UNKNOWN"
    return str(algorithm).upper()


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


def _render_csv(rows: Sequence[Mapping[str, Any]], timestamp: str | None) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=["bucket", "public_acl", "public_policy", "sse", "pba", "allowlist", "action", "ts"],
    )
    writer.writeheader()
    for row in rows:
        payload = dict(row)
        payload.setdefault("ts", timestamp or "")
        writer.writerow(payload)
    return buffer.getvalue()


def _timestamp(value: datetime | None) -> str:
    when = value or datetime.now(timezone.utc)
    return when.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


__all__ = ["generate_summary", "render"]
