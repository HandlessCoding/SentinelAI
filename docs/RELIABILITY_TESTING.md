# G11 reliability and local security

## Local prerequisites and checks

Follow the [database setup](DATABASE_SETUP.md) and
[dashboard setup](DASHBOARD_SETUP.md) to prepare the Python environment,
the local PostgreSQL databases, and the trusted G5 model package.
Run these checks from the repository root:

```powershell
& .\.venv\Scripts\python.exe -B -m alembic current
& .\.venv\Scripts\python.exe -B -m alembic check
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
Set-Location frontend
npm.cmd test
npm.cmd run build
```

The integration tests use fresh schemas in `sentinelai_test`. Alembic
creates the tables in each test schema, and teardown removes only the
schema that the test created. The CSV workflow test validates synthetic
records, scores them, saves suspected alerts, creates and updates an
incident, and retrieves its note after an application restart. The
model artifact is reused for scoring.

## GitHub regression checks

One workflow runs Python checks against a disposable PostgreSQL service
container, alongside frontend tests and the TypeScript and Vite build.
The action commits, Python and Node versions, PostgreSQL image version,
Python dependency pins, and npm lockfile control the setup. The database
credentials are ephemeral for each CI attempt. CI runs synthetic evaluator,
ingest, API, and migration cases with no private capture or model files.
[Workflow](../.github/workflows/ci.yml) ·
[GitHub service containers](https://docs.github.com/en/actions/tutorials/use-containerized-services/create-postgresql-service-containers)

CI sets `SENTINELAI_CI_SYNTHETIC_ONLY=1` to skip the four tests that load the
locally frozen Level 1 package. Real Zeek and the recorded G26, G27, and G29
checks are opt-in locally. Set `SENTINELAI_ZEEK_BINARY` on a supported host
for the real Zeek fixture. Set `SENTINELAI_G26_LAB_ROOT`,
`SENTINELAI_G27_LAB_ROOT`, and `SENTINELAI_G29_LAB_ROOT` to the authorized
local registries to include recorded checks in the Python command above.
[Lab procedure](LAB_GUIDE.md#verify-the-sensor-offline)

## G37 verification to implement

[ADR 0002](adr/0002-g37-sensor-local-postgresql.md#hard-acceptance-gates) owns the pilot workload and hard gates. The approved pilot uses guest-side verification after an offline installation rehearsal. Run the browser path separately on a local disposable stack with synthetic input. Schedule sensor-to-dashboard integration after live ingestion, persistence, recovery, and sensor health are verified.

The [G37 run manifest](../examples/g37_run_manifest.json) pins the G27 fixture revision and LF-normalized digest, planned identifiers, Zeek baseline settings, and measurement bounds. Confirm the guest's actual versions and observation point before bundle preparation. The independent observer derives the existing connected-sensor key from the UID and exact integer-nanosecond timestamp. Its PostgreSQL tests use a fresh reader to verify persisted identities and checkpoints. [Observer](../verification/g37.py)

CI runs the Linux recovery tests and a Chromium test against the built dashboard, a loopback FastAPI server, and a migrated disposable PostgreSQL schema. The browser test rotates a synthetic log and drops a response after the second CSV batch commits. It checks the retried alert IDs and the database counts. To reproduce locally, run the existing frontend installation and build, use `npx playwright install chromium --only-shell` in `frontend`, and set `SENTINELAI_G37_BROWSER=1` for `python -B -m unittest discover -s tests -p test_g37_browser.py -v` from the repository root.

The report-only Linux benchmark uses `SENTINELAI_G37_BENCHMARK=1` with that same unittest command and pattern `test_g37_benchmark.py`. CI repeats it five times with fresh schemas. Each `G37_BENCHMARK` record identifies the pinned run environment, monotonic persistence bounds, a paced 200 flows/s input, 10,000- and 25,000-row burst load, API query percentiles, PostgreSQL execution and buffer observations, and recorded backlog. CPU and peak RSS cover the worker and Python harness in the same process. The benchmark establishes synthetic regression evidence. The guest, packet, and native Zeek acceptance evidence comes from the separately authorized pilot.

The original 100,000-row synthetic tier exceeded its 90-second drain observation window. It produced no verified completion time or capacity result at that size. The five-trial 10,000- and 25,000-row baseline completed on the hosted Linux runner. Check that a single larger trial fits the observation and job budgets before adopting a higher tier. [Timeout evidence](https://github.com/HandlessCoding/SentinelAI/actions/runs/45044367748/job/137275607101) · [Five-trial baseline](https://github.com/HandlessCoding/SentinelAI/actions/runs/45044724909/job/137276706610)

| Acceptance case | Fixture and expected result |
| --- | --- |
| Zeek → PostgreSQL → API → dashboard | Start one worker with a fresh ingestion source and migrated disposable PostgreSQL. Append deterministic Zeek JSON records with known UID, first-packet timestamp, observation point, and ordering. Use the synthetic API startup fixture and a real browser on the same-origin path. Assert one committed row per expected key, matching API and Traffic detail data, correct source and checkpoint health, and `unknown` reviewed ground truth. Insert another complete record between pages. Assert no missing or repeated rows in the pinned view in either direction, and verify that Resume live reveals the new record. |
| Rotation and recovery | On Linux, coordinate writes, worker reads, and transaction failure with explicit test barriers. Allow a partial line to become complete, retain the closed generation as `conn.log.1`, and append to the successor. Stop and restart the worker at controlled handoff points. Assert the committed checkpoint remains behind uncommitted rows, drains both generations exactly once, and acknowledges the original file identity before it is removed. A missing archive must report a blocked state until restored. Confirm duplicate replay advances the checkpoint and duplicate count without inserting another flow. Retain the open-descriptor rename regression. |
| Browser analyst workflow | With a real local API and disposable database, score synthetic records, save suspected alerts, create an incident, and retrieve it with its note after refresh. Hold a response until the analyst navigates away and verify the current page stays selected. Simulate a stale incident link and verify that the valid incident list remains available. |
| CSV retry and historical receipts | Use a fixed CSV containing a batch split by the JSON byte cap. Commit one batch and drop its response at a local test adapter. Retry the same upload and assert stable keys, exactly one stored receipt per committed batch, unchanged alert IDs, and completion of the remaining records. Exercise a legacy receipt from an oversized original row window, plus an altered payload at a reused key returning 409. Verify the final browser result and persistent state. |
| Accessibility and keyboard | Run axe in the browser for Traffic, CSV, Alerts, and Incidents, with zero unresolved serious or critical violations in these flows. Use Tab, Shift+Tab, Enter, and Escape to verify skip navigation, menu operation, visible focus, labels, status announcements, and focus return from detail views. Exercise desktop and a narrow viewport. |

Use synthetic fixtures, a database created for the test, explicit waits on committed observations, and controlled response failures. Save expected keys and counts, migration revision, test/browser versions, sanitized logs, and timing traces. Existing Python and component tests cover individual boundaries. These proposed vertical and browser tests would verify their integration. [Existing Python integration cases](../tests/test_zeek_stream.py) · [Existing browser-component cases](../frontend/src/reliability.test.tsx)

### Reproducible benchmark baseline

- Pin the commit, migration revision, runtime and PostgreSQL versions, host resource limits, input seed, ingestion options, page sizes, and table cardinalities. Record warm-up, startup, and steady-state windows. Run at least five matched iterations on the same runner configuration, each with isolated database state.
- Measure sustained committed flows per second and backlog growth at a fixed input rate. Record p50 and p95 from complete-line availability to fresh committed reads, and separately to API visibility. Use monotonic clocks and independent readers. Keep the ADR's conservative, per-row timing method for the live pilot.
- Measure p50 and p95 query latency for summary, filtered first and subsequent pages in both sort orders, and flow details. Run at fixed sizes such as 10,000 and 100,000 synthetic rows and page sizes 25 and 100. Retain sanitized `EXPLAIN (ANALYZE, BUFFERS)` plans from the disposable database and record scans, reads, and sorting. Keep browser render timing distinct from query latency.
- Record worker and PostgreSQL CPU and peak RSS, I/O, disk growth, and maximum backlog by workload. Start with a report-only flag when the median of five matched runs shows more than 20% degradation in throughput, latency, or resource use relative to a pinned baseline. Reproduce and attribute regressions before setting a CI budget. Live pilot resource and recovery limits come from the ADR.

### Independent Security review

Use the Security perspective for changes to input validation, authentication or authorization, deserialization, artifact identity, database or filesystem access, ingestion, dependencies, secrets, or isolation. Review the authorized observation boundary, effective database destination, migration privileges, untrusted log and CSV handling, retry integrity, and evidence redaction. Cite the affected interface, realistic reachability, impact, and a regression test or other verification for each finding. Use disposable local fixtures and honor the [human-first review gate](../AGENTS.md#human-first-review-gate).

## Recover a saved G32.2 report

Use a separate checkout at `72468836e15d9224fbbeb251269a8cb98eb33cd0` to
recover or verify G32.2. It contains the checkpoint verifier and the same
fingerprinted runner modules as the G32.2 source revision `d7441cb`. From the
original run's working directory, set `PYTHONPATH` to the pinned checkout for
this command and run `python -P -B -m ml.run_unsw_extended report` for a finished
run that lacks its report. Use its original `--output` directory if it was customized and
redirect the result to a separate file in ignored local storage. The command
reads saved results without fitting. Keep its output for inspection.
Checkpoint verification requires the original `report.json` and matching
run state. Use the pinned checkout for verification because the current
Level 1 guard changes the fingerprint of `ml/inference.py`.
[G32.2 procedure and results](research/level-2/LEVEL_2_EXPERIMENTAL_BASELINE.md#g322-extended-overnight-study)

## Failure and integrity coverage

| Check | Expected behavior |
|---|---|
| Unsupported upload format or invalid CSV | Useful format, column, or row validation error |
| Oversized request | HTTP 413 for bodies over 2 MiB on CSV and JSON write endpoints, even when a length is absent |
| Too many records | CSV preview accepts at most 1,000 rows. Each prediction or analyze request accepts 1–100 records. |
| Malformed JSON or invalid input | HTTP 400 for malformed JSON, 415 for the wrong media type, and 422 for invalid inputs |
| Unreachable PostgreSQL | Database operations return a generic 503. Health checks, CSV validation, and stateless predictions remain available. |
| Missing or incompatible model package | API startup fails. Restore the trusted G5 package before restarting. |
| Repeated or concurrent submission | A matching idempotency key and batch returns the original receipt. A changed payload with the same key returns 409. |
| Failed database write | The batch and alerts are rolled back together. Incident assignment protects conflicts with row locks. |

The tests simulate the database outage with an unreachable local
connection, so the development PostgreSQL service can stay available.
The application logs the database exception class and returns a generic
client error. SQLAlchemy constructs queries with bound data values and
hides SQL parameters in database error output.

The G11 run passed **71 Python tests** and **22 frontend tests**. The
TypeScript check and Vite production build also passed. The dependency
review updated Vite, Vitest, esbuild, FastAPI, Starlette, and python-dotenv.
The final npm dependency audit reported zero known advisories, and
`pip check` reported no dependency conflicts. Starlette's test client
currently emits a deprecation warning for its HTTPX compatibility path.

The live Edge run validated a four-row synthetic CSV, saved two
suspected-attack alerts, replayed the same receipt, and retrieved the
updated investigation and its note. Browser testing also confirmed
invalid-file feedback and recovery from an injected 503 response.
At a 390-pixel viewport the keyboard menu closed with Escape, returned
focus to its trigger, and fit the viewport after the transition settled.
Direct loopback requests with chunked oversized CSV and JSON bodies
returned 413. The running API and Vite proxy returned no cross-origin
allow header for a separate origin.

## Local access boundaries

- Bind PostgreSQL to `127.0.0.1,::1`, run FastAPI on `127.0.0.1:8001`,
  and run Vite on `127.0.0.1:5173`. On the development machine, verify
  active listeners rather than inferring a bind address from the
  application connection string.
- The dashboard uses Vite's same-origin `/api/` proxy. Vite disables
  CORS, and FastAPI serves the documented local workflow without CORS
  allowances. The Host allowlist validates the HTTP header after a connection
  reaches the API. The loopback bind controls network reachability, and the
  capture lab uses its own isolated link.
- Keep `.env`, both dataset partitions, model artifacts, and dependency
  directories in ignored local paths. The frontend uses local HTTP
  routes for access and the database connection stays in FastAPI.

This application assumes a trusted local user and machine. A process
that can access the loopback API can submit records and read or change
investigation data. Analyst names are supplied by the client. Before
sharing an instance beyond the local machine, add authenticated access,
authorization, transport protection, and deployment-specific resource
controls.

## Model limitations

At the frozen threshold of 0.5, G10 flagged **12,140 of 37,000 normal test
records (32.81%)** as attacks. Its **99.35% attack recall** came with that
false-alarm burden. The dashboard labels the model's alerts **suspected
attacks** for analyst review.

UNSW-NB15 is a prepared cyber-range benchmark. In G10, 10.37% of the
official test rows shared an exact predictor vector with training, and the
false-positive rate among rows without an exact match was still 32.73%.
The evaluation measures results on prepared benchmark records. Live
traffic feature extraction, alert burden on an operational network, and
detection effectiveness there require independent validation.
[G10 evaluation report](FINAL_MODEL_EVALUATION.md)
