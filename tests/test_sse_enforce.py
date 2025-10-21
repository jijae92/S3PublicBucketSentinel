"""Server-side encryption enforcement tests."""
from __future__ import annotations

import importlib

import pytest

boto3 = pytest.importorskip("boto3")
pytest.importorskip("botocore")
from botocore.stub import Stubber

pytest.importorskip("moto")
from moto import mock_aws


ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


def _reload_handler(monkeypatch, **env):
    from backend.remediator import allowlist

    allowlist._fetch_ssm_entries.cache_clear()  # type: ignore[attr-defined]
    allowlist._read_local_entries.cache_clear()  # type: ignore[attr-defined]
    defaults = {
        "ALLOWLIST_SSM_PARAM": "",
        "ALLOWLIST_LOCAL_JSON": "",
        "DRY_RUN": "false",
        "ENFORCE_ACCOUNT_PBA": "false",
        "ALLOW_CROSS_ACCOUNT": "false",
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
            "eventName": "PutBucketEncryption",
            "requestParameters": {"bucketName": name},
            "tags": {},
        },
    }


def _expected_sse_config(algorithm: str, kms_arn: str | None) -> dict[str, object]:
    payload: dict[str, object] = {"SSEAlgorithm": algorithm}
    if kms_arn:
        payload["KMSMasterKeyID"] = kms_arn
    return payload


@mock_aws
def test_sse_s3_enforced(monkeypatch):
    handler = _reload_handler(monkeypatch, DRY_RUN="false", SSE_MODE="SSE-S3")
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="encrypted-bucket")

    with Stubber(s3) as stubber:
        stubber.add_client_error(
            "get_bucket_encryption",
            service_error_code="ServerSideEncryptionConfigurationNotFoundError",
            expected_params={"Bucket": "encrypted-bucket"},
        )
        stubber.add_response(
            "put_bucket_encryption",
            {},
            {
                "Bucket": "encrypted-bucket",
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": _expected_sse_config("AES256", None),
                        }
                    ]
                },
            },
        )
        stubber.add_response(
            "get_bucket_encryption",
            {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": _expected_sse_config("AES256", None),
                        }
                    ]
                }
            },
            {"Bucket": "encrypted-bucket"},
        )
        monkeypatch.setattr("backend.remediator.sse_lib.boto3", type("Proxy", (), {"client": lambda *_args, **_kw: s3}))
        handler.lambda_handler(_bucket_event("encrypted-bucket"), None)


@mock_aws
def test_sse_kms_enforced(monkeypatch):
    kms_arn = "arn:aws:kms:us-east-1:123456789012:key/example"
    handler = _reload_handler(monkeypatch, DRY_RUN="false", SSE_MODE="SSE-KMS", KMS_KEY_ARN=kms_arn)
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="kms-bucket")

    with Stubber(s3) as stubber:
        stubber.add_client_error(
            "get_bucket_encryption",
            service_error_code="ServerSideEncryptionConfigurationNotFoundError",
            expected_params={"Bucket": "kms-bucket"},
        )
        stubber.add_response(
            "put_bucket_encryption",
            {},
            {
                "Bucket": "kms-bucket",
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": _expected_sse_config("aws:kms", kms_arn),
                        }
                    ]
                },
            },
        )
        stubber.add_response(
            "get_bucket_encryption",
            {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": _expected_sse_config("aws:kms", kms_arn),
                        }
                    ]
                }
            },
            {"Bucket": "kms-bucket"},
        )
        monkeypatch.setattr("backend.remediator.sse_lib.boto3", type("Proxy", (), {"client": lambda *_args, **_kw: s3}))
        handler.lambda_handler(_bucket_event("kms-bucket"), None)


@mock_aws
def test_sse_not_applied_in_dry_run(monkeypatch):
    handler = _reload_handler(monkeypatch, DRY_RUN="true", SSE_MODE="SSE-S3")
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="dry-run-bucket")

    with Stubber(s3) as stubber:
        stubber.add_client_error(
            "get_bucket_encryption",
            service_error_code="ServerSideEncryptionConfigurationNotFoundError",
            expected_params={"Bucket": "dry-run-bucket"},
        )
        monkeypatch.setattr("backend.remediator.sse_lib.boto3", type("Proxy", (), {"client": lambda *_args, **_kw: s3}))
        handler.lambda_handler(_bucket_event("dry-run-bucket"), None)
