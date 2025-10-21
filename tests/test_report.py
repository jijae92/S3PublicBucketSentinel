"""Unit tests for scanner reporting helpers."""
from __future__ import annotations

from datetime import datetime, timezone

from backend.scanner import report


class DummyBucket:
    def __init__(self, name: str, account: str = "123456789012", region: str = "us-east-1"):
        self.name = name
        self.account_id = account
        self.region = region


class DummyState:
    def __init__(
        self,
        *,
        bucket: DummyBucket,
        acl_public: bool,
        policy_public: bool,
        sse: dict[str, str] | None,
        pba_config: dict[str, bool] | None,
        allowlist: dict[str, object],
        remediated: bool,
    ):
        self.bucket = bucket
        self.acl_public = acl_public
        self.policy_public = policy_public
        self.sse = sse
        self.public_access_block = pba_config
        self.allowlist = allowlist
        self.remediated = remediated


class DummyOutcome:
    def __init__(self, states):
        self.states = tuple(states)


def test_generate_summary_schema():
    timestamp = datetime(2025, 10, 21, 3, 0, tzinfo=timezone.utc)
    states = [
        DummyState(
            bucket=DummyBucket("public-bucket"),
            acl_public=True,
            policy_public=False,
            sse=None,
            pba_config=None,
            allowlist={"allowed": False},
            remediated=True,
        ),
        DummyState(
            bucket=DummyBucket("allowlisted"),
            acl_public=False,
            policy_public=False,
            sse={"algorithm": "AES256"},
            pba_config={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            allowlist={"allowed": True},
            remediated=False,
        ),
    ]
    outcome = DummyOutcome(states)

    payload = report.generate_summary(outcome, timestamp=timestamp)

    assert payload["scanned_at"] == "2025-10-21T03:00:00Z"
    assert payload["summary"]["total"] == 2
    assert payload["summary"]["public_acl"] == 1
    assert payload["summary"]["skipped_allow"] == 1
    assert len(payload["findings"]) == 2
    first = payload["findings"][0]
    assert first["bucket"] == "public-bucket"
    assert first["action"] == "REMEDIATED"
    second = payload["findings"][1]
    assert second["pba"] is True
    assert second["action"] == "SKIPPED"


def test_render_csv_uses_expected_header():
    outcome = DummyOutcome(
        [
            DummyState(
                bucket=DummyBucket("sample"),
                acl_public=False,
                policy_public=False,
                sse=None,
                pba_config=None,
                allowlist={"allowed": False},
                remediated=False,
            )
        ]
    )
    payload = report.generate_summary(outcome, timestamp=datetime(2025, 10, 21, tzinfo=timezone.utc))
    csv_output = report.render(payload, fmt="csv").strip().splitlines()
    assert csv_output[0] == "bucket,public_acl,public_policy,sse,pba,allowlist,action,ts"
    assert csv_output[1].startswith("sample,")
