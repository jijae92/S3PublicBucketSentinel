"""Command-line interface for the S3 Public Bucket Sentinel scanner."""
from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
from typing import Sequence

from ..remediator import allowlist
from . import job, report

try:  # pragma: no cover - optional dependency for unit tests
    import boto3
except ImportError:  # pragma: no cover - fallback when boto3 absent
    boto3 = None


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    _configure_logging(args.log_level)
    _prepare_allowlist(args.allowlist)
    remediate = args.remediate or args.mode == "fix"

    session = _resolve_session(args.profile, args.region)
    outcome = job.run_scan(
        remediate=remediate,
        dry_run=args.dry_run,
        bucket_names=args.bucket or None,
        session=session,
        sns_topic=args.sns_topic,
    )

    _emit_outputs(outcome, args)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run ad-hoc S3 public bucket scans")
    parser.add_argument("--mode", choices=("report", "fix"), default="report")
    parser.add_argument("--out", help="Write JSON summary to path", default=None)
    parser.add_argument("--csv", help="Write CSV findings to path", default=None)
    parser.add_argument("--remediate", action="store_true", help="Attempt remediation during scan")
    parser.add_argument("--dry-run", action="store_true", help="Log intended actions without applying")
    parser.add_argument("--profile", help="AWS profile name", default=None)
    parser.add_argument("--region", help="Default AWS region", default=None)
    parser.add_argument("--bucket", action="append", help="Target a specific bucket", default=[])
    parser.add_argument("--allowlist", help="Path to allowlist JSON", default=None)
    parser.add_argument("--sns-topic", help="Override SNS topic ARN for results", default=None)
    parser.add_argument("--log-level", default="INFO", help="Logging level (default: INFO)")
    return parser


def _configure_logging(level: str) -> None:
    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(level=log_level, format="%(asctime)s %(levelname)s %(name)s - %(message)s")


def _prepare_allowlist(path: str | None):  # type: ignore[no-untyped-def]
    if not path:
        return []
    os.environ[allowlist.ALLOWLIST_LOCAL_JSON_ENV] = path  # type: ignore[attr-defined]
    payload = Path(path).read_text()
    config = json.loads(payload)
    return allowlist.load_from_dict(config)


def _resolve_session(profile: str | None, region: str | None):  # type: ignore[no-untyped-def]
    if boto3 is None:
        raise RuntimeError("boto3 is required to execute scans from the CLI")
    return boto3.Session(profile_name=profile, region_name=region)


def _emit_outputs(outcome: job.ScanOutcome, args) -> None:  # type: ignore[no-untyped-def]
    report_payload = report.generate_summary(outcome)
    if not args.out and not args.csv:
        print(json.dumps(report_payload, indent=2, default=str))
    if args.out:
        _write_file(args.out, report.render(report_payload, fmt="json"))
    if args.csv:
        _write_file(args.csv, report.render(report_payload, fmt="csv"))


def _write_file(path: str, data: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(data)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
