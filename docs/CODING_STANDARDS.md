# SentinelAI coding standards

Use the [glossary](../GLOSSARY.md) in UI copy, documentation, and new code.
Preserve established serialized names, migrations, and research fingerprints.
Keep review focused on correctness, recovery, compatibility, security, and
testable behavior. Update this guide, the pins, and CI when the stack changes.

## Python

Use Python 3.12 conventions, descriptive names, explicit error handling, and
type annotations at new application boundaries where they clarify the contract.
Ruff checks imports, undefined names, and basic Python errors across the
backend, migrations, research code, and tests. Formatting checks cover the
database boundary and its tests. Expand that scope when modules are edited
for a substantive reason. A separate repository-wide type checker is deferred
until its stubs and configuration can cover the existing SQLAlchemy and
scientific Python boundaries without a blanket suppression baseline.

```powershell
& .\.venv\Scripts\python.exe -m pip install --only-binary=:all: -r requirements-dev.txt
& .\.venv\Scripts\python.exe -m ruff check backend migrations ml tests
& .\.venv\Scripts\python.exe -m ruff format --check backend/database.py tests/test_database.py
```

## TypeScript and React

Keep strict TypeScript checks enabled. Handle asynchronous results at the
component or request boundary and keep the rendered analyst workflows under
test. Prettier checks the new CSV batch planner using the existing single-quote,
semicolon-free style. ESLint would add a separate parser and plugin stack.
Reevaluate it when there are concrete cross-component rules to enforce beyond
strict types and behavioral tests.

```powershell
Set-Location frontend
npm.cmd ci
npm.cmd run format:check
npm.cmd run typecheck
npm.cmd test
npm.cmd run build
```

## Future Rust components

When Rust enters the repository, pin the toolchain and add `cargo fmt --check`,
Clippy, `cargo test`, and locked dependency and advisory checks to CI. Include
the new language boundary, compatibility, and security checks in code review.
