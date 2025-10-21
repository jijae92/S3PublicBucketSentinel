"""Allowlist loading utilities for temporary public bucket exemptions."""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, time, timezone
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from .types import BucketDescriptor

try:  # pragma: no cover - boto3 optional during local runs
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:  # pragma: no cover - local dev fallback
    boto3 = None
    BotoCoreError = ClientError = Exception  # type: ignore

LOGGER = logging.getLogger(__name__)

AWS_MANAGED_BUCKET_PREFIXES = (
    "aws-waf-logs-",
    "aws-cloudtrail-logs-",
)

TAG_ALLOW_UNTIL = "sentinel:public-allow-until"
TAG_ALLOW_REASON = "sentinel:public-reason"
ALLOWLIST_SSM_PARAM_ENV = "ALLOWLIST_SSM_PARAM"
ALLOWLIST_LOCAL_JSON_ENV = "ALLOWLIST_LOCAL_JSON"
DEFAULT_SSM_PARAM = "/security/sentinel/allowlist"
DEFAULT_LOCAL_JSON = "config/sentinel-allow.json"


@dataclass(slots=True)
class AllowlistDecision:
    bucket: str
    matched: bool
    reason: str | None = None
    expires_at: datetime | None = None

    def to_dict(self) -> dict[str, object | None]:
        return {
            "allowed": self.matched,
            "reason": self.reason,
            "until": int(self.expires_at.timestamp()) if self.expires_at else None,
        }


class AllowlistChecker:
    """Helper for evaluating allowlist state using configured sources."""

    def __init__(self, *, ssm_param: str | None, local_json: str | None, tag_fetcher=None):
        self._ssm_param = ssm_param
        self._local_json = local_json
        self._tag_fetcher = tag_fetcher or _fetch_bucket_tags

    def evaluate(self, bucket_name: str, now: datetime | None = None) -> AllowlistDecision:
        now = now or datetime.now(timezone.utc)
        if _is_aws_managed(bucket_name):
            return AllowlistDecision(bucket=bucket_name, matched=True, reason="AWS managed bucket")
        entry = _match_in_entries(self._ssm_entries(), bucket_name, now)
        if entry:
            return AllowlistDecision(bucket=bucket_name, matched=True, reason=entry.reason, expires_at=entry.expires_at)

        entry = _match_in_entries(self._local_entries(), bucket_name, now)
        if entry:
            return AllowlistDecision(bucket=bucket_name, matched=True, reason=entry.reason, expires_at=entry.expires_at)

        tag_entry = _entry_from_tags(bucket_name, self._tag_fetcher(bucket_name))
        if tag_entry and tag_entry.is_active(now):
            return AllowlistDecision(bucket=bucket_name, matched=True, reason=tag_entry.reason, expires_at=tag_entry.expires_at)
        return AllowlistDecision(bucket=bucket_name, matched=False)

    def evaluate_tags(self, bucket_name: str, tags: Mapping[str, str]) -> AllowlistDecision:
        now = datetime.now(timezone.utc)
        if _is_aws_managed(bucket_name):
            return AllowlistDecision(bucket=bucket_name, matched=True, reason="AWS managed bucket")
        tag_data = tags or self._tag_fetcher(bucket_name)
        tag_entry = _entry_from_tags(bucket_name, tag_data)
        if tag_entry and tag_entry.is_active(now):
            return AllowlistDecision(bucket=bucket_name, matched=True, reason=tag_entry.reason, expires_at=tag_entry.expires_at)
        return AllowlistDecision(bucket=bucket_name, matched=False)

    def _ssm_entries(self) -> Sequence[AllowlistedBucket]:
        return _load_ssm_entries(self._ssm_param)

    def _local_entries(self) -> Sequence[AllowlistedBucket]:
        return _load_local_entries(self._local_json)


@dataclass(slots=True)
class AllowlistedBucket:
    name: str
    expires_at: datetime | None
    reason: str | None = None

    def is_active(self, now: datetime) -> bool:
        if self.expires_at is None:
            return True
        return now <= self.expires_at


def check(bucket: BucketDescriptor, now: datetime | None = None) -> dict[str, object | None]:
    """Evaluate allowlist sources for the bucket, returning match metadata.

    The lookup order follows the allowlist source priority:
      1. SSM Parameter Store (JSON payload referenced by ALLOWLIST_SSM_PARAM)
      2. Local bundled JSON file (configured via ALLOWLIST_LOCAL_JSON)
      3. Bucket-level TTL tags (sentinel:public-allow-until / sentinel:public-reason)
    """
    now = now or datetime.now(timezone.utc)
    if _is_aws_managed(bucket.name):
        return {"allowed": True, "reason": "AWS managed bucket", "until": None}

    decision = _match_in_entries(_load_ssm_entries(), bucket.name, now)
    if decision:
        return _decision_to_dict(decision)

    decision = _match_in_entries(_load_local_entries(), bucket.name, now)
    if decision:
        return _decision_to_dict(decision)

    tag_entry = _entry_from_tags(bucket.name, bucket.tags)
    if tag_entry and tag_entry.is_active(now):
        return _decision_to_dict(tag_entry)

    return {"allowed": False, "reason": None, "until": None}


def load_from_ssm(parameter_value: str) -> Sequence[AllowlistedBucket]:
    """Parse an SSM parameter payload into allowlist entries."""
    try:
        payload = json.loads(parameter_value)
    except json.JSONDecodeError as exc:  # pragma: no cover - log-only branch
        LOGGER.error("Failed to decode SSM allowlist: %s", exc)
        return []
    return load_from_dict(payload)


def load_from_bucket_tags(bucket_name: str, tags: Mapping[str, str]) -> Iterable[AllowlistedBucket]:
    """Yield allowlist entries based on bucket-level TTL tags."""
    ttl = tags.get(TAG_ALLOW_UNTIL)
    if not ttl:
        return []
    expires_at = _parse_until(ttl)
    if not expires_at:
        LOGGER.warning("Invalid TTL tag value: %s", ttl)
        return []
    reason = tags.get(TAG_ALLOW_REASON)
    return [AllowlistedBucket(name=bucket_name, expires_at=expires_at, reason=reason)]


def load_from_dict(payload: Mapping[str, object]) -> Sequence[AllowlistedBucket]:
    buckets = []
    for bucket in payload.get("buckets", []):
        if not isinstance(bucket, Mapping):
            continue
        name = str(bucket.get("name") or "").strip()
        until_raw = bucket.get("until")
        reason = bucket.get("reason")
        if not name or not until_raw:
            LOGGER.debug("Skipping malformed allowlist entry: %s", bucket)
            continue
        expires_at = _parse_until(str(until_raw))
        if expires_at is None:
            LOGGER.warning("Invalid until value for bucket %s", name)
            continue
        buckets.append(AllowlistedBucket(name=name, expires_at=expires_at, reason=str(reason) if reason else None))
    return buckets


def _load_ssm_entries(param_name: str | None = None) -> Sequence[AllowlistedBucket]:
    if param_name is None:
        param_name = os.getenv(ALLOWLIST_SSM_PARAM_ENV, DEFAULT_SSM_PARAM)
    if not param_name or not boto3:
        return []
    return _fetch_ssm_entries(param_name)


@lru_cache(maxsize=4)
def _fetch_ssm_entries(param_name: str) -> Sequence[AllowlistedBucket]:
    client = boto3.client("ssm")
    try:
        response = client.get_parameter(Name=param_name, WithDecryption=False)
    except (client.exceptions.ParameterNotFound, ClientError) as exc:  # type: ignore[attr-defined]
        LOGGER.warning("SSM parameter %s not found: %s", param_name, exc)
        return []
    except BotoCoreError as exc:
        LOGGER.error("Failed to retrieve SSM parameter %s: %s", param_name, exc)
        return []
    return load_from_ssm(response["Parameter"]["Value"])


def _load_local_entries(path: str | None = None) -> Sequence[AllowlistedBucket]:
    if path is None:
        path = os.getenv(ALLOWLIST_LOCAL_JSON_ENV, DEFAULT_LOCAL_JSON)
    if not path:
        return []
    return _read_local_entries(path)


@lru_cache(maxsize=4)
def _read_local_entries(path: str) -> Sequence[AllowlistedBucket]:
    file_path = Path(path)
    if not file_path.exists():
        LOGGER.debug("Local allowlist file %s not found", path)
        return []

    try:
        payload = json.loads(file_path.read_text())
    except json.JSONDecodeError as exc:
        LOGGER.error("Invalid local allowlist JSON at %s: %s", path, exc)
        return []
    return load_from_dict(payload)


def _entry_from_tags(bucket_name: str, tags: Mapping[str, str]) -> AllowlistedBucket | None:
    entries = list(load_from_bucket_tags(bucket_name, tags))
    return entries[0] if entries else None


def _match_in_entries(
    entries: Sequence[AllowlistedBucket],
    bucket_name: str,
    now: datetime,
) -> AllowlistedBucket | None:
    for entry in entries:
        if entry.name == bucket_name and entry.is_active(now):
            return entry
    return None


def _parse_until(value: str) -> datetime | None:
    value = value.strip()
    try:
        if len(value) == 10:  # YYYY-MM-DD
            dt = datetime.fromisoformat(value)
            dt = datetime.combine(dt, time(hour=23, minute=59, second=59))
        else:
            dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _is_aws_managed(bucket_name: str) -> bool:
    return any(bucket_name.startswith(prefix) for prefix in AWS_MANAGED_BUCKET_PREFIXES)


def _decision_to_dict(entry: AllowlistedBucket) -> dict[str, object | None]:
    until = int(entry.expires_at.timestamp()) if entry.expires_at else None
    return {"allowed": True, "reason": entry.reason, "until": until}


def _fetch_bucket_tags(bucket_name: str) -> Mapping[str, str]:
    if not boto3:
        return {}
    client = boto3.client("s3")
    try:
        response = client.get_bucket_tagging(Bucket=bucket_name)
    except ClientError:
        return {}
    tag_set = response.get("TagSet", [])
    return {tag.get("Key"): tag.get("Value") for tag in tag_set if tag.get("Key")}


__all__ = [
    "AllowlistedBucket",
    "check",
    "load_from_ssm",
    "load_from_bucket_tags",
    "load_from_dict",
    "AllowlistDecision",
    "AllowlistChecker",
]
