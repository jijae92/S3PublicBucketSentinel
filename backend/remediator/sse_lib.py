"""Server-side encryption enforcement for S3 buckets."""
from __future__ import annotations

import logging
from typing import Mapping

from .types import ActionOutcome, BucketDescriptor

try:  # pragma: no cover - optional dependency for local dev
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:  # pragma: no cover
    boto3 = None
    BotoCoreError = ClientError = Exception  # type: ignore

LOGGER = logging.getLogger(__name__)


def get_sse(bucket: BucketDescriptor) -> Mapping[str, str] | None:
    """Fetch the current server-side encryption configuration for the bucket."""
    if not boto3:
        return None
    client = boto3.client("s3", region_name=bucket.region)
    try:
        response = client.get_bucket_encryption(Bucket=bucket.name)
    except client.exceptions.ServerSideEncryptionConfigurationNotFoundError:  # type: ignore[attr-defined]
        return None
    except (ClientError, BotoCoreError) as exc:  # pragma: no cover - defensive logging
        LOGGER.warning("Unable to get SSE configuration for %s: %s", bucket.name, exc)
        return None
    rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
    if not rules:
        return None
    rule = rules[0].get("ApplyServerSideEncryptionByDefault", {})
    algorithm = rule.get("SSEAlgorithm")
    kms_key = rule.get("KMSMasterKeyID") or rule.get("KMSMasterKeyId")
    if not algorithm:
        return None
    return {"algorithm": algorithm, "kms_key": kms_key}


def desired_sse(env: Mapping[str, str]) -> Mapping[str, str] | None:
    """Return the desired SSE configuration derived from environment variables."""
    mode = env.get("SSE_MODE", "SSE-S3").upper()
    if mode == "DISABLED":
        return None
    if mode == "SSE-KMS":
        return {"algorithm": "aws:kms", "kms_key": env.get("KMS_KEY_ARN") or None}
    return {"algorithm": "AES256", "kms_key": None}


def needs_change(current: Mapping[str, str] | None, desired: Mapping[str, str] | None) -> bool:
    """Determine whether bucket SSE config needs to be updated."""
    if desired is None:
        return False
    if current is None:
        return True
    if current.get("algorithm", "").lower() != desired.get("algorithm", "").lower():
        return True
    if desired.get("algorithm", "").lower() == "aws:kms":
        return (current.get("kms_key") or "") != (desired.get("kms_key") or "")
    return False


def diff_sse(before: Mapping[str, str] | None, after: Mapping[str, str] | None) -> str:
    """Provide a summary string describing SSE changes."""
    if before == after:
        return "SSE unchanged"
    if before is None and after is not None:
        return f"Enabled SSE ({after.get('algorithm')})"
    if before is not None and after is None:
        return "Removed SSE configuration"
    return "SSE changed from {0} to {1}".format(
        _format_sse(before),
        _format_sse(after),
    )


def ensure_encryption(
    bucket: BucketDescriptor,
    *,
    mode: str,
    kms_key_arn: str | None = None,
    apply: bool,
) -> ActionOutcome:
    """Enable the configured server-side encryption when missing."""
    normalized_mode = mode.upper()
    LOGGER.info("Ensuring SSE for %s with mode %s", bucket.name, normalized_mode)
    if normalized_mode == "DISABLED":
        return ActionOutcome(
            name="bucket-encryption",
            changed=False,
            before=get_sse(bucket),
            after={"algorithm": "disabled"},
            message="SSE enforcement disabled by configuration",
        )
    algorithm = "AES256" if normalized_mode == "SSE-S3" else "aws:kms"
    desired = {"algorithm": algorithm, "kms_key": kms_key_arn if algorithm == "aws:kms" else None}
    before_state = get_sse(bucket)
    original_before = dict(before_state) if isinstance(before_state, dict) else before_state
    changed = False
    message = "Dry run - SSE unchanged"
    error: str | None = None

    if apply and not boto3:
        LOGGER.warning("boto3 unavailable; cannot enforce SSE on %s", bucket.name)
        error = "boto3 unavailable"
    elif apply and needs_change(before_state, desired):
        if algorithm == "aws:kms" and not kms_key_arn:
            error = "KMS key required for SSE-KMS mode"
            LOGGER.error("KMS key ARN required for SSE-KMS mode on %s", bucket.name)
        else:
            config = {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": algorithm,
                            **({"KMSMasterKeyID": kms_key_arn} if kms_key_arn and algorithm == "aws:kms" else {}),
                        },
                    }
                ]
            }
            try:
                client = boto3.client("s3", region_name=bucket.region)
                client.put_bucket_encryption(
                    Bucket=bucket.name,
                    ServerSideEncryptionConfiguration=config,
                )
                changed = True
                message = "Bucket encryption enforced"
            except (ClientError, BotoCoreError) as exc:  # pragma: no cover
                LOGGER.error("Failed to enforce SSE on %s: %s", bucket.name, exc)
                error = str(exc)
    elif apply:
        LOGGER.info("Desired SSE already configured for %s", bucket.name)
        message = "SSE already compliant"
    else:
        LOGGER.info("Dry run: would configure SSE %s", after)
    after_state = get_sse(bucket) if changed else before_state or desired
    return ActionOutcome(
        name="bucket-encryption",
        changed=changed,
        before=original_before,
        after=after_state,
        message=message,
        error=error,
    )


def _format_sse(config: Mapping[str, str] | None) -> str:
    if not config:
        return "none"
    algo = config.get("algorithm", "unknown")
    key = config.get("kms_key")
    if key:
        return f"{algo} ({key})"
    return algo
