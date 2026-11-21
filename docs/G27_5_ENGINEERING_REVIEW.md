# G27.5 engineering review

## Executive summary

The review started with local and GitHub `main` at `1622a01`. The Level 1
application has a coherent local boundary, tested migration and transaction
paths, and a frozen inference contract. The Level 2 research scripts retain
negative results and gate claims on capture provenance. The highest-value
changes are to make the existing local HTTP guard apply consistently, keep
original labeling evidence verifiable, and make current setup instructions
easier to find. The project remains a trusted-user local tool, and the G27
recordings share one device pair and environment.

## Prioritized findings before implementation

| Priority | Affected files or environment | Finding and proposed change | Effort and regression risk |
| --- | --- | --- | --- |
| P1 | `backend/main.py`, API tests | The exported ASGI app rejects untrusted Host values, while the application factory omits the guard. Install it in the factory so both supported entry points share the local boundary. | Small. Update in-process clients to use legitimate loopback URLs and verify module and factory behavior. |
| P1 | `ml/lab_registry.py`, `ml/lab_benign_audit.py` | The G27 review file is pinned, and its source-log hashes live inside that review file. Registry verification of the label window alone does not rehash these original logs. Add an optional manifest field for directly pinned evidence files. Preserve the established manifest rules for existing captures. | Small. Test tamper detection and rerun the saved G27 audit against the existing registry. |
| P1 | Local Python environment, `README.md` | OSV matched twelve advisory records and aliases for installed pip 24.0. No other installed application or research dependency matched in this query. Verify a compatible current pip release and update only the installer if a checked wheel is available. | Small. Keep the existing model dependency pins and verify them after the installer change. |
| P2 | `backend/request_limits.py`, `backend/csv_uploads.py` | The two body readers apply different declared-length checks. Share the strict header checks while retaining per-endpoint media, error, and byte limits. | Small. Use the existing streamed, exact-limit, and database-free preview tests and cover duplicate declared lengths. |
| P2 | `backend/routes.py`, `backend/investigations.py`, `backend/csv_uploads.py` | Request hashing and prediction utilities live in routers that import one another. Move them into one batch-processing module while preserving serialized digests and error behavior. | Small. Existing idempotency, CSV, and inference tests cover the public contracts. |
| P2 | `frontend/src/api.ts`, alert consumers | The shared alert loader can repeatedly fetch identical full pages without advancing the set of alerts. Detect pages with zero new IDs and use the existing error UI. Keep the current endpoint and offset semantics. | Small. Cover repeating and overlapping-but-progressing pages. Stable server-side pagination remains a later API design task. |
| P2 | `.gitignore`, tracked inventory | Data and artifact directories are ignored, with gaps for VM media, dumps, and environment variants copied to other locations. Add targeted ignore patterns and retain tracked source fixtures. | Small. Verify representative local files and the entire staged tree. |
| P2 | `README.md`, `docs/` | Setup and research outcomes are mixed in one flat directory, and three lab milestone documents duplicate operational instructions. Publish one current lab guide and navigation index. Move original research records with working cross-links. | Medium. Audit relative paths and anchors. Preserve the inputs, sizes, hashes, metrics, and failed experiments. |
| P3 | `backend/investigations.py`, `frontend/src/api.ts` | Loading all alert pages and attaching all notes works for the local prototype. Larger datasets would benefit from server-side filtering and pagination designed around a stable key. | Medium. Defer the contract and UX change. |
| P3 | `ml/run_*.py`, `ml/audit_*.py`, `ml/lab_benign.py` | Several research scripts are large, and some contain source-specific parsing and metrics code. Similar interfaces have different label semantics and capture assumptions. Retain their entry points and avoid consolidation based only on line count. | Medium to high. Extract shared logic only after an additional consumer demonstrates matching semantics. |
| P3 | `backend/requirements.txt`, `ml/requirements-baseline.txt`, `frontend/package-lock.json` | Frontend installs have a complete lockfile. Python pins direct dependencies and the model runtime versions. Other transitive versions can differ on a fresh install. | Medium. Design a cross-platform lock or constraints workflow separately. A frozen model package requires the recorded runtime. |
| P3 | Repository root and GitHub | There is no CI configuration or repository license. A portable smoke job using synthetic inputs would be useful. License selection requires the owner's decision and a review of institutional and dataset terms. | Medium. Keep PostgreSQL, real Zeek, and private artifacts out of the default CI runner. |

## Review scope and boundaries

- **Application.** Reviewed the API assembly, routing, request limits,
  inference boundary, SQLAlchemy session and transaction handling,
  idempotency, and dashboard data loading. SQLAlchemy builds parameterized
  queries. Alembic uses the local database contract and tests use disposable
  schemas in the dedicated test database.
- **Machine learning.** Reviewed ingestion, schema validation, train-only
  grouping and threshold selection, frozen artifact verification, official
  held-out evaluation, and the dataset audit and split scripts. G4 validation
  and G10 testing remain separate. The local pickle evaluates only trusted
  operator-generated packages. Its digest is a consistency check. Model
  distribution and public deployment would require a different trust design.
- **Collection.** Reviewed the capture registry, Zeek feature extractor,
  bounded spill-to-disk overlap audit, G27 evidence review, route checks, and
  serial transfer. Four same-environment benign sessions verify the
  collection pipeline. They provide no estimate of live false-positive rate
  or transfer to independent devices.
- **Repository.** Reviewed tracked source, fixture files, plots and screenshots,
  the complete Markdown inventory, setup commands, pins, ignore rules, and
  reachable Git history. The largest tracked item was a 262,128-byte dashboard
  screenshot. The G27 baseline scan checked 22 reachable commits and 161
  distinct path and blob pairs. It found no matches for the configured
  credential and private-artifact checks. Pattern scanning has finite coverage.

`npm audit` reported zero findings for the existing lockfile. The Python
compatibility check passed. OSV queried 41 installed PyPI distributions and
matched only pip 24.0. [npm audit scope](https://docs.npmjs.com/cli/audit/) ·
[OSV batch queries](https://google.github.io/osv.dev/post-v1-querybatch/)

The baseline suite ran 167 Python tests with 166 passes and one skip for the
real Zeek executable on Windows. The G26 recorded-capture integration ran on
Windows against its checksum-pinned artifacts. No benchmark or lab capture
was regenerated for the baseline review.

## Changes made

1. `backend/main.py` applies the loopback Host allowlist to both ASGI entry
   points. API tests use an allowed Host and cover rejection on both paths.
2. `backend/batch_processing.py` centralizes the request digest and prediction
   error handling used by the three routers. The digest format and prediction
   responses are preserved. The regression suite caught a logger-name change
   during extraction, so the shared code keeps the previous logger name.
3. `backend/request_limits.py` shares content type, encoding, and length
   validation between JSON and CSV consumers. It rejects duplicate headers and
   invalid declared lengths before reading the body. The existing per-endpoint
   media, streaming byte limit, and error details are retained.
4. `frontend/src/api.ts` reports an error when full alert pages stop adding
   alert IDs. Regression tests cover repeated pages and overlapping pages that
   still make progress.
5. `ml/lab_registry.py` and `ml/lab_benign_audit.py` directly pin the local
   event and review files in new G27-style manifests. Verification rehashes
   those files, including for a capture with no reviewed label window. The
   manifest field is optional for compatibility with sealed legacy captures.
6. `.gitignore` excludes additional VM media, local dump formats, environment
   variants, and model artifact extensions. The local installer was updated to
   pip 26.3 from a wheel verified against PyPI's published SHA-256. The other 40
   installed Python distributions retained their original versions, and OSV
   returned no advisory matches for the new installer. Application and model
   dependency pins were preserved. [Verified installer release](https://pypi.org/project/pip/26.3/)

## Documentation structure

| Before | After |
| --- | --- |
| Root README carried application setup and a small selection of milestone links. | The [root README](../README.md) gives a status and setup overview. The [documentation index](README.md) routes readers to application, research, and graduation materials. |
| Application setup and project reports shared a flat `docs/` namespace with milestone experiments. | Application and database setup, architecture, the technical report, G10 official results, and presentation materials stay in `docs/`. Existing screenshots and diagrams remain available. |
| Dataset and experiment reports were listed individually alongside current setup. | The [research archive](research/README.md) groups original reports under `research/level-1/`, `research/level-2/`, and `research/lab/`. |
| Lab setup steps appeared in several milestone reports. | The [lab guide](LAB_GUIDE.md) covers offline provisioning and verified benign collection. Original provisioning, experimental results, and capture procedures stay accessible in the lab archive. |
| The Level 2 roadmap reflected an earlier research stage. | The [status and roadmap](ROADMAP.md) identifies the current state and proposed next experiment. The earlier roadmap remains available in the archive. |

The archive contains 19 moved Markdown records and one original threshold
figure. Comparison with G27 found only the intended relative-link changes in
the moved documents and exact byte equality for the figure. The application,
ML, test, and migration directories keep their established roles.

## Verification

| Check | Result |
| --- | --- |
| Full Python suite on Windows | 169 run, 168 passed, one skipped because real Zeek is unavailable on Windows. No failures. |
| Real Zeek on the isolated Ubuntu sensor | One passed. The synthetic PCAP was processed by Zeek and the resulting flows were registered. The sensor powered off and its original boot media was restored. |
| Frontend | 24 tests passed across three files. TypeScript checks and the Vite production build passed. |
| PostgreSQL and Alembic | The persistence and concurrency tests used the dedicated test database. The CSV workflow passed through alert persistence, incident, and notes. The database was at `0001_alert_investigations`, Alembic detected no missing migrations, and offline SQL generation passed. |
| Public API schema | The OpenAPI JSON matched G27 exactly. |
| Existing G27 captures | The audit reproduced the recorded report. All 33 checked capture, registry, log, and evidence files retained their SHA-256 values. |
| Frozen Level 1 artifact | `unsw-nb15-rf-v1` retained pipeline SHA-256 `8c37b095dba6cd0f58931ff91e713b0a05f84678b4829c387c788e196b8e1cd6`. The recorded threshold is 0.5. |
| Static and dependency checks | All 66 Python source files parsed. `pip check` passed, npm reported zero advisories, and `git diff --check` passed for the staged changes. |
| Repository and documentation | All 281 checked relative link and heading targets resolved across 35 Markdown files. The staged tree and reachable history were checked for configured secret and private-artifact patterns with no matches. |

The Zeek check used a synthetic fixture in the existing isolated guest. It
exercised extraction and registration without collecting a new live session.
The existing G27 records supplied the regression check for reviewed evidence.

## Remaining work and readiness

SentinelAI is ready for review before G28's proposed replication of benign
collection in a distinct authorized environment. G27's four sessions share a
VM pair and observation point. A second environment is needed to assess
coverage and feature stability. The available collection still lacks the
independently reviewed positive runs and held-out cohorts required for fitting
and evaluating a Level 2 model. The reserved benchmark remains sealed.
[Proposed next experiment](ROADMAP.md#proposed-next-research-step)

A synthetic CI smoke job and a repository license decision would improve
public reproducibility. Stable server-side alert pagination and a portable
Python lock can follow as separate changes when their compatibility can be
tested. Level 1 remains a loopback application for trusted local operators.
Its 32.81% official benchmark false-positive rate and absence of live
network validation remain material deployment limitations.
[Official evaluation](FINAL_MODEL_EVALUATION.md)
