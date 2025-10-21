"""End-to-end ACL remediation tests covering dry-run and enforce modes."""
from __future__ import annotations

import importlib

import pytest

boto3 = pytest.importorskip("boto3")
pytest.importorskip("botocore")
from botocore.stub import Stubber

pytest.importorskip("moto")
from moto import mock_aws

from backend.remediator import acl_lib, policy_lib


ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


def _reload_handler(monkeypatch, **env):
    from backend.remediator import allowlist

    allowlist._fetch_ssm_entries.cache_clear()  # type: ignore[attr-defined]
    allowlist._read_local_entries.cache_clear()  # type: ignore[attr-defined]
    base_env = {
        "ALLOWLIST_SSM_PARAM": "",
        "ALLOWLIST_LOCAL_JSON": "",
        "ALLOW_CROSS_ACCOUNT": "false",
        "SSE_MODE": "SSE-S3",
        "KMS_KEY_ARN": "",
    }
    base_env.update(env)
    for key, value in base_env.items():
        monkeypatch.setenv(key, value)
    import backend.remediator.handler as handler

    return importlib.reload(handler)


def _bucket_event(name: str) -> dict[str, object]:
    return {
        "account": ACCOUNT_ID,
        "region": REGION,
        "detail": {
            "eventName": "PutBucketAcl",
            "requestParameters": {"bucketName": name},
            "tags": {},
        },
    }


def _stub_account_level_pba(monkeypatch):
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
def test_acl_public_grant_is_revoked(monkeypatch):
    handler = _reload_handler(monkeypatch, DRY_RUN="false", ENFORCE_ACCOUNT_PBA="true")
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="public-bucket")
    s3.put_bucket_acl(Bucket="public-bucket", ACL="public-read")

    stubber = _stub_account_level_pba(monkeypatch)
    try:
        response = handler.lambda_handler(_bucket_event("public-bucket"), None)
    finally:
        stubber.assert_no_pending_responses()
        stubber.deactivate()

    assert response["status"] == "success"
    acl = s3.get_bucket_acl(Bucket="public-bucket")
    assert acl_lib.has_public_acl(acl) is False


@mock_aws
def test_acl_public_grant_remains_in_dry_run(monkeypatch):
    handler = _reload_handler(monkeypatch, DRY_RUN="true", ENFORCE_ACCOUNT_PBA="true")
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="public-bucket")
    s3.put_bucket_acl(Bucket="public-bucket", ACL="public-read")

    stubber = _stub_account_level_pba(monkeypatch)
    try:
        result = handler.lambda_handler(_bucket_event("public-bucket"), None)
    finally:
        stubber.deactivate()

    assert result["status"] == "success"
    acl = s3.get_bucket_acl(Bucket="public-bucket")
    assert acl_lib.has_public_acl(acl) is True
