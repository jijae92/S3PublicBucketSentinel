"""ACL normalization utilities for removing public grants."""
from __future__ import annotations

import logging
from typing import Mapping

from .types import ActionOutcome, BucketDescriptor

try:  # pragma: no cover - optional dependency for local testing
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:  # pragma: no cover
    boto3 = None
    BotoCoreError = ClientError = Exception  # type: ignore

LOGGER = logging.getLogger(__name__)


PUBLIC_GRANTEES = {"AllUsers", "AuthenticatedUsers"}


def has_public_acl(acl: Mapping[str, object] | None) -> bool:
    """Return True when the ACL grants public group access."""
    if not acl:
        return False
    grants = acl.get("Grants", [])
    if isinstance(grants, Mapping):  # pragma: no cover - defensive
        grants = [grants]
    for grant in grants:
        if not isinstance(grant, Mapping):
            continue
        grantee = grant.get("Grantee", {})
        if not isinstance(grantee, Mapping):
            continue
        uri = grantee.get("URI") or grantee.get("Uri")
        if isinstance(uri, str) and uri.lower().endswith("allusers"):
            return True
        if isinstance(uri, str) and uri.lower().endswith("authenticatedusers"):
            return True
        display_name = grantee.get("DisplayName")
        if isinstance(display_name, str) and display_name in PUBLIC_GRANTEES:
            return True
    return False


def make_private_acl() -> Mapping[str, object]:
    """Return a minimal private ACL payload."""
    return {
        "CannedACL": "private",
        "Grants": [],
    }


def diff_acl(before: Mapping[str, object] | None, after: Mapping[str, object] | None) -> str:
    """Produce a concise summary of ACL changes."""
    if before == after:
        return "ACL unchanged"
    before_public = has_public_acl(before)
    after_public = has_public_acl(after)
    if before_public and not after_public:
        return "Removed public ACL grants"
    if not before_public and after_public:
        return "Introduced public ACL grants"
    return "ACL grants updated"


def revoke_public_acl(bucket: BucketDescriptor, *, apply: bool) -> ActionOutcome:
    """Strip public ACL grants from the bucket."""
    LOGGER.info("Revoking public ACLs for %s", bucket.name)
    before_acl = _get_bucket_acl(bucket)
    before = {"grants": _summarize_grants(before_acl)}
    changed = False
    message = "Dry run - ACL unchanged"
    error: str | None = None
    after_acl = before_acl

    if apply and not boto3:
        LOGGER.warning("boto3 unavailable; cannot modify ACLs for %s", bucket.name)
        error = "boto3 unavailable"
    elif apply and before_acl and has_public_acl(before_acl):
        try:
            client = _s3_client(bucket.region)
            client.put_bucket_acl(Bucket=bucket.name, ACL="private")
            after_acl = client.get_bucket_acl(Bucket=bucket.name)
            changed = True
            message = "Public ACL grants removed"
        except (ClientError, BotoCoreError) as exc:  # pragma: no cover - network path
            LOGGER.error("Failed to revoke ACL for %s: %s", bucket.name, exc)
            error = str(exc)
    elif apply:
        LOGGER.info("ACL already private for %s", bucket.name)
        message = "ACL already private"

    after = {"grants": _summarize_grants(after_acl)}
    return ActionOutcome(
        name="bucket-acl",
        changed=changed,
        before=before,
        after=after,
        message=message,
        error=error,
    )


def _get_bucket_acl(bucket: BucketDescriptor):  # type: ignore[no-untyped-def]
    if not boto3:
        return None
    client = _s3_client(bucket.region)
    try:
        return client.get_bucket_acl(Bucket=bucket.name)
    except (ClientError, BotoCoreError):
        LOGGER.warning("Unable to fetch ACL for %s", bucket.name)
        return None


def _summarize_grants(acl: Mapping[str, object] | None) -> list[str]:
    if not acl:
        return []
    grants = acl.get("Grants", [])
    summaries: list[str] = []
    if isinstance(grants, Mapping):  # pragma: no cover
        grants = [grants]
    for grant in grants:
        if not isinstance(grant, Mapping):
            continue
        grantee = grant.get("Grantee", {})
        if isinstance(grantee, Mapping):
            uri = grantee.get("URI") or grantee.get("Uri")
            if uri:
                summaries.append(str(uri))
            else:
                display = grantee.get("DisplayName") or grantee.get("ID")
                if display:
                    summaries.append(str(display))
    return summaries


def _s3_client(region: str):
    if not boto3:  # pragma: no cover
        raise RuntimeError("boto3 unavailable")
    return boto3.client("s3", region_name=region)
