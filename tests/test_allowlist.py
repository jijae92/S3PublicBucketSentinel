"""Allowlist-driven flow tests for the remediation handler."""
from __future__ import annotations

import importlib
import json

import pytest

boto3 = pytest.importorskip("boto3")
pytest.importorskip("botocore")
from botocore.stub import Stubber

pytest.importorskip("moto")
from moto import mock_aws

from backend.remediator import allowlist, policy_lib


ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


def _reload_handler(monkeypatch, *, local_allowlist: str | None, dry_run: bool, sns_topic: str | None) -> object:
    allowlist._fetch_ssm_entries.cache_clear()  # type: ignore[attr-defined]
    allowlist._read_local_entries.cache_clear()  # type: ignore[attr-defined]
    env = {
        "ALLOWLIST_SSM_PARAM": "",
        "ALLOWLIST_LOCAL_JSON": local_allowlist or "",
        "DRY_RUN": "true" if dry_run else "false",
        "SSE_MODE": "SSE-S3",
        "KMS_KEY_ARN": "",
        "ENFORCE_ACCOUNT_PBA": "false",
        "SNS_TOPIC_ARN": sns_topic or "",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    import backend.remediator.handler as handler

    return importlib.reload(handler)


def _bucket_event(name: str, tags: dict[str, str] | None = None) -> dict[str, object]:
    return {
        "account": ACCOUNT_ID,
        "region": REGION,
        "detail": {
            "eventName": "PutBucketPolicy",
            "requestParameters": {"bucketName": name},
            "tags": tags or {},
        },
    }


def _stub_account_level(monkeypatch):
    control = boto3.client("s3control", region_name=REGION)
    stubber = Stubber(control)
    stubber.add_response(
        "put_public_access_block",
        {},
        {
            "AccountId": ACCOUNT_ID,
            "PublicAccessBlockConfiguration": policy_lib.DESIRED_PUBLIC_ACCESS_BLOCK,
        },
    )
    stubber.activate()
    monkeypatch.setattr(policy_lib, "_s3control_client", lambda region=None: control)
    return stubber


@mock_aws
def test_allowlisted_bucket_skips_and_sends_notification(monkeypatch, tmp_path):
    allow_payload = {"buckets": [{"name": "allow-bucket", "until": "2999-01-01", "reason": "maintenance"}]}
    allow_path = tmp_path / "allow.json"
    allow_path.write_text(json.dumps(allow_payload))
    topic_arn = "arn:aws:sns:us-east-1:123456789012:sentinel"
    handler = _reload_handler(monkeypatch, local_allowlist=str(allow_path), dry_run=False, sns_topic=topic_arn)
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="allow-bucket")

    sns = boto3.client("sns", region_name=REGION)
    with Stubber(sns) as sns_stubber:
        sns_stubber.add_response(
            "publish",
            {"MessageId": "msg-123"},
            {
                "TopicArn": topic_arn,
                "Message": Stubber.ANY,
                "Subject": Stubber.ANY,
            },
        )
        monkeypatch.setattr("backend.remediator.notifier.boto3", type("Proxy", (), {"client": lambda *_args, **_kwargs: sns}))
        result = handler.lambda_handler(_bucket_event("allow-bucket"), None)
        assert result["status"] == "skip"


@mock_aws
def test_expired_allowlist_triggers_remediation(monkeypatch, tmp_path):
    allow_payload = {"buckets": [{"name": "expired-bucket", "until": "2020-01-01", "reason": "legacy"}]}
    allow_path = tmp_path / "allow.json"
    allow_path.write_text(json.dumps(allow_payload))
    handler = _reload_handler(monkeypatch, local_allowlist=str(allow_path), dry_run=False, sns_topic=None)
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="expired-bucket")

    stubber = _stub_account_level(monkeypatch)
    try:
        result = handler.lambda_handler(_bucket_event("expired-bucket"), None)
    finally:
        stubber.assert_no_pending_responses()
        stubber.deactivate()

    assert result["status"] == "success"
