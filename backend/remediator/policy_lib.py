"""Helpers for tightening S3 bucket policies and public access settings."""
from __future__ import annotations

import json
import logging
from typing import Iterable, Mapping

from .types import ActionOutcome, BucketDescriptor

try:  # pragma: no cover - boto3 optional in unit tests
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:  # pragma: no cover
    boto3 = None
    BotoCoreError = ClientError = Exception  # type: ignore

LOGGER = logging.getLogger(__name__)


DESIRED_PUBLIC_ACCESS_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def ensure_public_access_block(
    bucket: BucketDescriptor,
    *,
    apply: bool,
    desired: Mapping[str, bool] | None = None,
    enforce_account_level: bool = True,
) -> ActionOutcome:
    """Ensure account/bucket public access block settings are enforced."""
    desired = desired or DESIRED_PUBLIC_ACCESS_BLOCK
    LOGGER.info("Enforcing Public Access Block for %s", bucket.name)
    before_cfg = _get_public_access_block(bucket)
    after_cfg = dict(desired)
    changed = False
    message = "Dry run - PBA unchanged"
    error: str | None = None

    if apply and not boto3:
        LOGGER.warning("boto3 unavailable; cannot enforce PBA for %s", bucket.name)
        error = "boto3 unavailable"
    elif apply and before_cfg != after_cfg:
        try:
            client = _s3_client(bucket.region)
            client.put_public_access_block(
                Bucket=bucket.name,
                PublicAccessBlockConfiguration=after_cfg,
            )
            changed = True
            message = "Public Access Block enforced"
        except (ClientError, BotoCoreError) as exc:  # pragma: no cover
            LOGGER.error("Failed to apply bucket PBA for %s: %s", bucket.name, exc)
            error = str(exc)

        if changed and enforce_account_level and not error:
            try:
                s3control = _s3control_client(bucket.region)
                s3control.put_public_access_block(
                    AccountId=bucket.account_id,
                    PublicAccessBlockConfiguration=after_cfg,
                )
            except (ClientError, BotoCoreError) as exc:  # pragma: no cover
                LOGGER.warning("Account-level PBA enforcement failed for %s: %s", bucket.account_id, exc)
    elif apply:
        LOGGER.info("PBA already enforced for %s", bucket.name)
        message = "Public Access Block already enforced"
    else:
        LOGGER.info("Dry run: would apply Public Access Block %s", desired)
    return ActionOutcome(
        name="public-access-block",
        changed=changed,
        before={"settings": before_cfg},
        after={"settings": after_cfg},
        message=message,
        error=error,
    )


def lockdown_bucket_policy(
    bucket: BucketDescriptor,
    *,
    apply: bool,
    allow_cross_account: bool = False,
) -> ActionOutcome:
    """Replace or delete bucket policies that allow public access."""
    LOGGER.info("Locking down bucket policy for %s", bucket.name)
    bucket_arn = f"arn:aws:s3:::{bucket.name}"
    before_policy = _fetch_bucket_policy(bucket)
    is_public = is_public_policy(before_policy or {})
    after_policy = None
    changed = False
    message = "Dry run - policy unchanged"
    error: str | None = None

    if allow_cross_account:
        LOGGER.debug("Cross-account policies allowed for %s", bucket.name)

    if apply and not boto3:
        LOGGER.warning("boto3 unavailable; cannot enforce policy for %s", bucket.name)
        error = "boto3 unavailable"
    elif apply and is_public:
        desired_policy = normalize_min_deny(bucket_arn, None if allow_cross_account else bucket.account_id)
        try:
            client = _s3_client(bucket.region)
            client.put_bucket_policy(Bucket=bucket.name, Policy=json.dumps(desired_policy))
            after_policy = desired_policy
            changed = True
            message = "Bucket policy locked down"
        except (ClientError, BotoCoreError) as exc:  # pragma: no cover
            LOGGER.error("Failed to lock down policy for %s: %s", bucket.name, exc)
            error = str(exc)
    elif apply and before_policy and not is_public:
        LOGGER.info("Bucket policy already private for %s", bucket.name)
        message = "Bucket policy already compliant"
        after_policy = before_policy
    elif apply and not before_policy:
        LOGGER.info("No bucket policy present for %s", bucket.name)
        message = "No bucket policy present"
    else:
        LOGGER.info("Dry run: would replace bucket policy with deny-all template")
        after_policy = before_policy

    if after_policy is None and before_policy:
        after_policy = before_policy
    return ActionOutcome(
        name="bucket-policy",
        changed=changed,
        before={"policy": before_policy},
        after={"policy": after_policy},
        message=message,
        error=error,
    )


def is_public_policy(policy: Mapping[str, object]) -> bool:
    """Detect whether a policy allows anonymous or wildcard access."""
    statements = policy.get("Statement", [])
    if isinstance(statements, Mapping):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, Mapping):
            continue
        effect = statement.get("Effect")
        if effect != "Allow":
            continue
        principal = statement.get("Principal")
        condition = statement.get("Condition")
        if _principal_is_public(principal):
            return True
        if principal in (None, {}, "AWS") and not condition:
            return True
    return False


def _get_public_access_block(bucket: BucketDescriptor) -> Mapping[str, bool] | None:
    if not boto3:
        return None
    client = _s3_client(bucket.region)
    try:
        response = client.get_public_access_block(Bucket=bucket.name)
    except getattr(client, "exceptions", object()).NoSuchPublicAccessBlockConfiguration:  # type: ignore[attr-defined]
        return None
    except (ClientError, BotoCoreError):
        LOGGER.warning("Unable to fetch PBA for %s", bucket.name)
        return None
    return response.get("PublicAccessBlockConfiguration")


def _fetch_bucket_policy(bucket: BucketDescriptor) -> Mapping[str, object] | None:
    if not boto3:
        return None
    client = _s3_client(bucket.region)
    try:
        response = client.get_bucket_policy(Bucket=bucket.name)
    except (ClientError, BotoCoreError):
        return None
    policy = response.get("Policy")
    if not policy:
        return None
    try:
        return json.loads(policy)
    except json.JSONDecodeError:
        LOGGER.warning("Invalid policy JSON for %s", bucket.name)
        return None


def _s3_client(region: str):
    if not boto3:  # pragma: no cover
        raise RuntimeError("boto3 unavailable")
    return boto3.client("s3", region_name=region)


def _s3control_client(region: str | None = None):
    if not boto3:  # pragma: no cover
        raise RuntimeError("boto3 unavailable")
    kwargs = {}
    if region:
        kwargs["region_name"] = region
    return boto3.client("s3control", **kwargs)


def normalize_min_deny(bucket_arn: str, account_id: str | None = None) -> Mapping[str, object]:
    """Create a minimal deny policy blocking anonymous access."""
    resources: Iterable[str] = (bucket_arn, f"{bucket_arn}/*")
    statements: list[Mapping[str, object]] = [
        {
            "Sid": "DenyPublicRead",
            "Effect": "Deny",
            "Principal": "*",
            "Action": ["s3:GetObject", "s3:GetObjectVersion"],
            "Resource": list(resources),
        },
        {
            "Sid": "DenyPublicList",
            "Effect": "Deny",
            "Principal": "*",
            "Action": ["s3:ListBucket"],
            "Resource": bucket_arn,
        },
    ]
    if account_id:
        for stmt in statements:
            stmt.setdefault("Condition", {})
            stmt["Condition"].setdefault("ArnNotLike", {})
            stmt["Condition"]["ArnNotLike"]["aws:PrincipalArn"] = f"arn:aws:iam::{account_id}:*"
    return {
        "Version": "2012-10-17",
        "Statement": statements,
    }


def diff_policy(before: Mapping[str, object] | None, after: Mapping[str, object] | None) -> str:
    """Return a succinct textual diff between two policies."""
    if before == after:
        return "policy unchanged"
    if not before and after:
        return "applied deny policy with actions: {}".format(
            ", ".join(_summarize_actions(after))
        )
    if before and not after:
        return "removed bucket policy"
    return "policy actions changed from [{}] to [{}]".format(
        ", ".join(_summarize_actions(before)),
        ", ".join(_summarize_actions(after)),
    )


def _summarize_actions(policy: Mapping[str, object] | None) -> Iterable[str]:
    if not policy:
        return []
    statements = policy.get("Statement", [])
    if isinstance(statements, Mapping):
        statements = [statements]
    actions: list[str] = []
    for statement in statements:
        if not isinstance(statement, Mapping):
            continue
        action = statement.get("Action")
        if isinstance(action, str):
            actions.append(action)
        elif isinstance(action, Iterable):
            actions.extend([str(a) for a in action])
    return actions


def _principal_is_public(principal: object) -> bool:
    if principal is None:
        return True
    if isinstance(principal, str):
        return principal == "*" or principal.lower() == "aws"
    if isinstance(principal, Mapping):
        for value in principal.values():
            if _value_has_wildcard(value):
                return True
    if isinstance(principal, Iterable):
        return any(_value_has_wildcard(item) for item in principal)
    return False


def _value_has_wildcard(value: object) -> bool:
    if isinstance(value, str):
        return value == "*"
    if isinstance(value, Iterable):
        return any(_value_has_wildcard(item) for item in value)
    return False
