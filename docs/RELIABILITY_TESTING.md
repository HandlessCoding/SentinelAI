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

CI sets `SENTINELAI_CI_SYNTHETIC_ONLY=1` to skip the three tests that load the
locally frozen Level 1 package. Real Zeek and the recorded G26, G27, and G29
checks are opt-in locally. Set `SENTINELAI_ZEEK_BINARY` on a supported host
for the real Zeek fixture. Set `SENTINELAI_G26_LAB_ROOT`,
`SENTINELAI_G27_LAB_ROOT`, and `SENTINELAI_G29_LAB_ROOT` to the authorized
local registries to include recorded checks in the Python command above.
[Lab procedure](LAB_GUIDE.md#verify-the-sensor-offline)

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
