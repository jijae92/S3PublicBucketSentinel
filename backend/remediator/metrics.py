"""Utility helpers for emitting AWS EMF metrics."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

import json
import logging
import time

LOGGER = logging.getLogger(__name__)

NAMESPACE = "S3PublicSentinel"
DIMENSIONS = [["Bucket", "Action", "Result"]]


def now() -> datetime:
    """Return a timezone-aware timestamp used for findings."""
    return datetime.now(timezone.utc)


def put_metric(
    *,
    bucket_name: str,
    action: str,
    result: str,
    latency_ms: float,
    bucket_public_before: bool | None,
    bucket_public_after: bool | None,
    sse_before: str | None,
    sse_after: str | None,
) -> None:
    """Emit an Embedded Metric Format (EMF) log entry for the remediation pipeline."""
    bucket_value = str(bucket_name or "unknown")
    metric = {
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [
                {
                    "Namespace": NAMESPACE,
                    "Dimensions": DIMENSIONS,
                    "Metrics": [
                        {"Name": "Latency", "Unit": "Milliseconds"},
                        {"Name": "PublicBefore", "Unit": "Count"},
                        {"Name": "PublicAfter", "Unit": "Count"},
                    ],
                }
            ],
        },
        "Bucket": bucket_value,
        "Action": action,
        "Result": result,
        "Latency": latency_ms,
        "PublicBefore": int(bucket_public_before) if bucket_public_before is not None else None,
        "PublicAfter": int(bucket_public_after) if bucket_public_after is not None else None,
        "SseBefore": sse_before,
        "SseAfter": sse_after,
    }
    LOGGER.info("EMF %s", json.dumps({k: v for k, v in metric.items() if v is not None}))


def flush(metrics_batch: Iterable[dict[str, object]]) -> None:
    """Placeholder for future buffered metric publishing."""
    for metric in metrics_batch:
        LOGGER.debug("Buffered metric: %s", metric)
