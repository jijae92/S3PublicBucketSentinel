"""Validate bucket policy lockdown behaviour for the remediation handler."""
from __future__ import annotations

import importlib
import json

import pytest

boto3 = pytest.importorskip("boto3")
pytest.importorskip("moto")
from moto import mock_aws

from backend.remediator import policy_lib


ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


def _reload_handler(monkeypatch, **env):
    from backend.remediator import allowlist

    allowlist._fetch_ssm_entries.cache_clear()  # type: ignore[attr-defined]
    allowlist._read_local_entries.cache_clear()  # type: ignore[attr-defined]
    defaults = {
        "ALLOWLIST_SSM_PARAM": "",
        "ALLOWLIST_LOCAL_JSON": "",
        "SSE_MODE": "DISABLED",
        "KMS_KEY_ARN": "",
    }
    defaults.update(env)
    for key, value in defaults.items():
        monkeypatch.setenv(key, value)
    import backend.remediator.handler as handler

    return importlib.reload(handler)


def _bucket_event(name: str) -> dict[str, object]:
    return {
        "account": ACCOUNT_ID,
        "region": REGION,
        "detail": {
            "eventName": "PutBucketPolicy",
            "requestParameters": {"bucketName": name},
            "tags": {},
        },
    }


def _default_policy(bucket: str) -> dict[str, object]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*"}
        ],
    }


@mock_aws
def test_public_policy_is_replaced_with_min_deny(monkeypatch):
    handler = _reload_handler(monkeypatch, DRY_RUN="false")
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="policy-bucket")
    s3.put_bucket_policy(Bucket="policy-bucket", Policy=json.dumps(_default_policy("policy-bucket")))

    response = handler.lambda_handler(_bucket_event("policy-bucket"), None)
    assert response["status"] == "success"

    policy_response = s3.get_bucket_policy(Bucket="policy-bucket")
    applied_policy = json.loads(policy_response["Policy"])
    expected = policy_lib.normalize_min_deny(f"arn:aws:s3:::policy-bucket", account_id=ACCOUNT_ID)
    assert applied_policy == expected


@mock_aws
def test_public_policy_unchanged_in_dry_run(monkeypatch):
    handler = _reload_handler(monkeypatch, DRY_RUN="true")
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="policy-bucket")
    public_policy = _default_policy("policy-bucket")
    s3.put_bucket_policy(Bucket="policy-bucket", Policy=json.dumps(public_policy))

    handler.lambda_handler(_bucket_event("policy-bucket"), None)
    policy_response = s3.get_bucket_policy(Bucket="policy-bucket")
    assert json.loads(policy_response["Policy"]) == public_policy
