"""Typed value objects shared across remediator modules."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, MutableMapping, Sequence


@dataclass(slots=True)
class BucketDescriptor:
    """Minimal description of an S3 bucket targeted for enforcement."""

    name: str
    account_id: str
    region: str
    tags: Mapping[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class PublicAccessFinding:
    """Represents a public access issue detected on a bucket."""

    bucket: BucketDescriptor
    issue: str
    evidence: Mapping[str, Any]
    detected_at: datetime


@dataclass(slots=True)
class ActionOutcome:
    """Describes the result of a single remediation step."""

    name: str
    changed: bool
    before: Mapping[str, Any] | None = None
    after: Mapping[str, Any] | None = None
    error: str | None = None
    message: str | None = None
    duration_ms: float | None = None

    @property
    def succeeded(self) -> bool:
        return self.error is None


@dataclass(slots=True)
class RemediationSummary:
    """Aggregated outcome for a remediation invocation."""

    bucket: BucketDescriptor
    actions: Sequence[ActionOutcome]
    status: str
    event_name: str
    account_id: str
    region: str
    dry_run: bool
    allowlisted: bool
    skipped: bool = False
    message: str | None = None
    error: str | None = None
    event_detail: Mapping[str, Any] = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        return self.error is None and self.status.lower() == "success"


Event = MutableMapping[str, Any]
"""Alias for raw AWS event payloads used in Lambda handlers."""
