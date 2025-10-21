"""Tests for the scheduled scanner job orchestration."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from backend.scanner import job
from backend.remediator import allowlist


class FakeAws:
    def __init__(self, buckets):
        self._buckets = buckets

    def account_id(self) -> str:
        return "123456789012"

    def list_bucket_names(self) -> list[str]:
        return list(self._buckets.keys())

    def get_bucket_region(self, name: str) -> str:
        return self._buckets[name]["region"]

    def get_bucket_tags(self, name: str):  # type: ignore[no-untyped-def]
        return self._buckets[name].get("tags", {})

    def get_public_access_block(self, name: str):  # type: ignore[no-untyped-def]
        return self._buckets[name].get("pba")

    def get_bucket_acl(self, name: str):  # type: ignore[no-untyped-def]
        return self._buckets[name].get("acl")

    def get_bucket_policy(self, name: str):  # type: ignore[no-untyped-def]
        return self._buckets[name].get("policy")


def _clear_allowlist(monkeypatch):
    allowlist._fetch_ssm_entries.cache_clear()  # type: ignore[attr-defined]
    allowlist._read_local_entries.cache_clear()  # type: ignore[attr-defined]
    monkeypatch.setenv("ALLOWLIST_SSM_PARAM", "")
    monkeypatch.setenv("ALLOWLIST_LOCAL_JSON", "")


def test_run_scan_flags_public_bucket(monkeypatch):
    _clear_allowlist(monkeypatch)
    buckets = {
        "public-bucket": {
            "region": "us-east-1",
            "tags": {},
            "pba": {"BlockPublicAcls": False},
            "acl": {"Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]},
            "policy": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}],
            },
        },
        "private-bucket": {
            "region": "us-west-2",
            "tags": {},
            "pba": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "acl": {"Grants": []},
            "policy": None,
        },
    }
    aws = FakeAws(buckets)
    now = datetime(2025, 10, 21, tzinfo=timezone.utc)

    def _sse(bucket):
        if bucket.name == "private-bucket":
            return {"algorithm": "AES256"}
        return None

    outcome = job.run_scan(
        remediate=True,
        dry_run=False,
        aws=aws,
        sse_resolver=_sse,
        now=now,
        sns_topic=None,
    )

    assert len(outcome.findings) == 1
    finding = outcome.findings[0]
    assert finding.bucket.name == "public-bucket"
    assert "PublicAccessBlock disabled" in finding.issue
    expected_remediated = 1 if job.policy_lib.boto3 else 0
    assert outcome.remediated == expected_remediated

    summary = job.serialize_outcome(outcome)
    assert summary["scanned"] == 2
    assert isinstance(summary["buckets"], list)


def test_run_scan_respects_allowlist(monkeypatch):
    _clear_allowlist(monkeypatch)
    buckets = {
        "allowlisted-bucket": {
            "region": "us-east-1",
            "tags": {
                "sentinel:public-allow-until": "2999-01-01",
                "sentinel:public-reason": "fixture",
            },
            "pba": None,
            "acl": None,
            "policy": None,
        }
    }
    aws = FakeAws(buckets)
    now = datetime(2025, 10, 21, tzinfo=timezone.utc)

    outcome = job.run_scan(
        remediate=True,
        dry_run=False,
        aws=aws,
        sse_resolver=lambda bucket: None,
        now=now,
        sns_topic=None,
    )

    assert outcome.allowlisted == 1
    assert not outcome.findings
