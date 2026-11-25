# SentinelAI coding standards

Use the [glossary](../GLOSSARY.md) in UI copy, documentation, and new code.
Preserve established serialized names, migrations, and research fingerprints.
Keep review focused on correctness, recovery, compatibility, security, and
testable behavior. Update this guide, the pins, and CI when the stack changes.

## Python

Use Python 3.12 conventions, descriptive names, explicit error handling, and
type annotations at new application boundaries where they clarify the contract.
Ruff enforces correctness, Bugbear, and targeted security rules for dynamic
execution, weak hashes, unsafe YAML, suspicious SQL construction, and shell
wildcards. Import ordering is enforced in the backend and migrations. The
Ruff configuration lists deferred research and test rules to preserve
historical fingerprints and keep the first increment focused. Formatting
covers the database boundary and its tests. Expand formatting with substantive
edits. Treat any new enabled diagnostic as a failed check.

```powershell
& .\.venv\Scripts\python.exe -m pip install --only-binary=:all: -r requirements-dev.txt
& .\.venv\Scripts\python.exe -m ruff check backend migrations ml tests verification tools/herdr
& .\.venv\Scripts\python.exe -m ruff format --check backend/database.py tests/test_database.py
& .\.venv\Scripts\python.exe -m ruff check --select C901 --exit-zero backend
& .\.venv\Scripts\python.exe -m pip_audit --progress-spinner off --timeout 15
```

Run the Herdr controller tests with Python 3.12 before submitting controller
changes. The suite uses simulated CLI responses and a temporary SQLite database,
so it runs without live agents or provider access.

```powershell
& .\.venv\Scripts\python.exe -m ruff format --check tools/herdr
& .\.venv\Scripts\python.exe -B -m unittest discover -s tools/herdr -v
```

## TypeScript and React

Keep strict TypeScript checks enabled. Handle asynchronous results at the
component or request boundary and keep the rendered analyst workflows under
test. ESLint enforces selected typed checks, the Rules of Hooks, and JSX
accessibility semantics. Prettier checks the CSV batch planner. Keep the lockfile
and lint plugins in sync. The JSX accessibility plugin currently declares
support through ESLint 9. Recheck compatibility before updating the major.

```powershell
Set-Location frontend
npm.cmd ci
npm.cmd run format:check
npm.cmd run lint
npm.cmd run typecheck
npm.cmd test
npm.cmd run build
npm.cmd audit --audit-level=high
```

## Report-only checks and promotion

| Check | Initial scope and promotion criteria |
| --- | --- |
| Pyright standard mode | Database, request limits, and batch processing. Require a zero-diagnostic baseline on Windows and Linux before enabling the CI gate. Assess additional files individually. |
| Complexity | Report Python backend and TypeScript functions above 10. Start with 3 Python and 11 frontend functions above the threshold. Review each newly introduced or worsened breach. Gate zero new breaches once the baseline can distinguish individual functions across edits. |
| React exhaustive dependencies | Report the 6 existing warnings where a revision intentionally changes a callback's identity to trigger a reload. Preserve refresh tests before tightening the rule. Gate zero new warnings after recording narrow, reviewed exceptions for intentional triggers. |
| jscpd exact duplication | Report blocks of at least 6 lines and 50 tokens in the backend and frontend production sources. The initial scan found 0 clones in 23 files. After establishing comparable results on at least three matched CI runs, enforce zero new reviewed production clones using the same options and the base revision. |
| Python dependency advisories | `pip-audit` reports on the installed dependency tree, including transitive releases. Review new reachable high-impact findings before merging changes that introduce them. Move to enforcement when advisory baseline and service reliability are established, with zero unreviewed high-impact findings. Record any temporary exception with an owner, rationale, and expiry. |

From the repository root after installing both dependency sets, run the Pyright
and duplication probes locally using the lockfile tools.

```powershell
& .\frontend\node_modules\.bin\pyright.cmd --pythonpath .\.venv\Scripts\python.exe
& .\frontend\node_modules\.bin\jscpd.cmd --min-lines 6 --min-tokens 50 --format python,typescript,tsx --ignore '**/*.test.ts,**/*.test.tsx,**/__pycache__/**' --fail-on-empty --no-colors --no-tips backend frontend/src
```

JavaScript advisory results at high or critical severity fail CI. The scanner
reports lower severities for review. Gitleaks scans checked-out commit history,
including merge commit patches, with secret values redacted. It fails on findings
and uses the pinned default rules independently of checkout-local ignore files.
Prefer native GitHub secret scanning and push protection to catch credentials before they
land. [Workflow](../.github/workflows/ci.yml) · [GitHub push protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection)

Static checks identify code patterns. Use functional and integration tests for
transaction outcomes, exact retries, file recovery, browser behavior, and access
boundaries. Use profiles and reproducible benchmarks for resource and latency
claims. [G37 verification cases](RELIABILITY_TESTING.md#g37-verification-to-implement)

## Future Rust components

When Rust enters the repository, pin the toolchain and add `cargo fmt --check`,
`cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked`,
and RustSec dependency auditing against the committed lockfile to CI. Exercise
supported feature sets. Require independent review of `unsafe` invariants and
failure cases, with focused tests and benchmarks for performance-sensitive paths.
For every new language, add its pinned tools, CI checks, and stack-specific
review requirements with the first component.
