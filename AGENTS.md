# Repository Guidelines

## Project Structure & Module Organization
- Keep application code in `src/sentinel/`; group AWS integrations under service-specific packages.
- Mirror business domains with subpackages (e.g., `buckets/`, `alerts/`) and expose shared utilities from `src/sentinel/lib/`.
- Put automated tests in `tests/`, with reusable fixtures in `tests/fixtures/` and config samples in `config/`.
- House infrastructure-as-code in `infra/` and helper shell or Python scripts in `scripts/`.
- Capture ADRs and security notes in `docs/`; cross-link major diagrams from the README.

## Build, Test, and Development Commands
- `python -m venv .venv && source .venv/bin/activate` creates the isolated development environment.
- `pip install -r requirements.txt` installs runtime and dev dependencies; update `requirements.lock` when pins change.
- `pytest` runs the unit suite; add `-m slow` for cloud-backed checks and `--maxfail=1` during triage.
- `python -m sentinel.cli scan --config config/example.yaml` performs a local dry run against bundled sample policies.

## Coding Style & Naming Conventions
- Target Python 3.12+, enable type hints, and prefer `dataclass` models for structured payloads.
- Format with `black` (line length 100) and lint with `ruff`; wire both through `.pre-commit-config.yaml`.
- Use `snake_case` for modules and functions, `PascalCase` for classes, and `kebab-case` for configuration files.
- Keep functions under 40 lines and move shared helpers into `lib/` packages once duplicated.

## Testing Guidelines
- Use pytest with GIVEN/WHEN/THEN comments to clarify intent; isolate AWS services with `moto` or `localstack`.
- Name test files `test_<feature>.py` and mark AWS-integration suites with `@pytest.mark.slow`.
- Target ≥90% statement coverage and enforce locally via `pytest --cov=src/sentinel --cov-fail-under=90`.
- Store sanitized bucket policies and IAM docs under `tests/fixtures/` for reproducible scenarios.

## Commit & Pull Request Guidelines
- Follow Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`) with subjects ≤72 characters.
- Squash personal WIP commits and document user impact or mitigated risk in the commit body.
- Open PRs after local tests pass; include purpose, validation steps, and any AWS screenshots or logs.
- Link issues, Terraform plans, or CloudTrail evidence that supports the change; request at least one peer review.

## Security & Configuration Tips
- Never commit live AWS identifiers; use redacted examples and environment variables.
- Keep secrets in `config/example.yaml` placeholders and load real values from deployment tooling.
- Run `scripts/check_public_access.sh` (add during hardening) before releases to verify default policies.
- Document new IAM permissions in `docs/security-matrix.md` and highlight them in PR descriptions.
