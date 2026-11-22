# G7 PostgreSQL and analyst investigations

## Local setup

Use the native Windows PostgreSQL service and the existing Python 3.12.3
virtual environment. Both the API and Alembic read local environment
variables. They use the Git-ignored `.env` in the repository root for
settings that are absent from the process environment.

| Variable | Default |
|---|---|
| `SENTINELAI_DB_HOST` | `127.0.0.1` |
| `SENTINELAI_DB_PORT` | `5432` |
| `SENTINELAI_DB_USER` | `sentinelai_user` |
| `SENTINELAI_DB_NAME` | `sentinelai_dev` |
| `SENTINELAI_DB_TEST_NAME` | `sentinelai_test` |
| `SENTINELAI_DB_PASSWORD` | Required. Set it privately in `.env` or the local process environment. |

Use separate development and test databases owned by the local application
role. Keep the password in the local configuration. The backend builds the
connection URL from its separate components, including when the password
contains URL punctuation.

For this local setup, set `listen_addresses = '127.0.0.1,::1'` in the
active PostgreSQL configuration and restart the Windows service if the
setting changes. Verify the running value with SQL and the active listeners
with Windows networking tools. [PostgreSQL connection settings](https://www.postgresql.org/docs/18/runtime-config-connection.html#GUC-LISTEN-ADDRESSES)

Run these commands from the repository root in PowerShell:

```powershell
& .\.venv\Scripts\python.exe -B -m pip install --only-binary=:all: -r ml/requirements-baseline.txt -r backend/requirements.txt
& .\.venv\Scripts\python.exe -B -m alembic upgrade head
& .\.venv\Scripts\python.exe -B -m alembic current
& .\.venv\Scripts\python.exe -B -m uvicorn backend.main:app --host 127.0.0.1 --port 8001
```

The commands install the pinned dependencies, migrate the development
database, print its applied revision, and serve the API locally. The
expected head revision is `0002_zeek_traffic`. Port 8001 matches
the dashboard's local proxy target. Open
[Swagger UI](http://127.0.0.1:8001/docs) to explore the routes.

The backend loads the existing [trusted model package](MODEL_PACKAGING.md)
once at startup. Its original health, model-info, and prediction routes
work independently of PostgreSQL. Use `POST /predict` for scores without
creating database records.

## Database and API behavior

| Endpoint | Behavior |
|---|---|
| `POST /analyze` | Score a batch of 1–100 prepared UNSW-NB15 records and atomically save the batch and its suspected-attack alerts |
| `GET /alerts` | List alerts, optionally filtered by `batch_id`, `status`, or `min_probability`. Use `limit` (1–100) and `offset` to page. |
| `GET /alerts/{alert_id}` | Read an alert with its model version, attack probability, prediction time, batch reference, and investigation status |
| `POST /incidents` | Open an investigation with a title and one or more unassigned alert IDs |
| `GET /incidents/{incident_id}` | Read an investigation with its linked alerts and analyst notes |
| `PATCH /incidents/{incident_id}` | Change the title, description, or status |
| `POST /incidents/{incident_id}/notes` | Append a note with an analyst name and note text |

Alerts are labeled `suspected_attack`. Each alert stores its zero-based
record index and probability. Its batch stores the shared model version,
threshold, and prediction timestamp. An unassigned alert is `unreviewed`.
A linked alert reflects its analyst-created incident's `open`,
`investigating`, or `resolved` status. The analyst note author is
client-supplied in this local phase.

Supply an `Idempotency-Key` for each logical submission to `POST /analyze`.
Use 1–128 letters, digits, dots, underscores, colons, or hyphens. A new batch
returns HTTP 201. Reuse the same key with the same predictors to receive
the original receipt and alert IDs with HTTP 200. A changed batch with the
same key returns HTTP 409. The request fingerprint ignores object key order
and optional `id`, `label`, and `attack_cat` columns. It preserves record
order and the JSON types of feature values. PostgreSQL's unique constraint
and the transaction covering batch and alert writes protect concurrent
submissions. [SQLAlchemy PostgreSQL conflict handling](https://docs.sqlalchemy.org/en/20/dialects/postgresql.html#insert-on-conflict-upsert)

Malformed JSON returns 400, invalid inputs return 422, and missing alerts
or incidents return 404. A conflicting alert assignment returns 409.
Database failures return a generic 503, and logs report the exception class.

## Import reviewed Zeek flows offline

Apply `alembic upgrade head` as shown above. From the repository root, import
one capture from the [local registry](LAB_GUIDE.md#register-and-review-evidence).
This example uses the authorized G29 capture if it is present on this machine.

```powershell
& .\.venv\Scripts\python.exe -B -m backend.zeek_ingest --root data/level2/capture-lab/g29 g29-control-01
```

The importer verifies the registry hashes, original PCAP, offline Zeek receipt,
and connection log. It accepts up to 10,000 flows, 64 MiB each for the PCAP and
connection log, and 32 evidence files up to 1 MiB each. Synthetic manifests,
invalid present fields, and oversized captures are rejected before writing.
Missing optional fields stay null. A retry of the same registered capture
returns `replayed: true`. Reusing its ID or source bytes with different
provenance is rejected. Concurrent imports share the same uniqueness checks.
The capture and all its flows commit together.

| Endpoint | Behavior |
|---|---|
| `GET /traffic/summary` | Count imported flows, rule findings, and flows by protocol |
| `GET /traffic/flows` | Filter by `capture_id`, `protocol`, `connection_state`, or `has_finding`. Page with `limit` (1–100) and `offset` (0–100,000). |
| `GET /traffic/flows/{flow_id}` | Read exact UTC timestamp, endpoints, counters, rule explanation, reviewed label, and capture provenance |

Timestamps retain nanosecond precision. The detail API returns counter and
duration values as decimal strings to preserve their full precision in the
browser. IP-level byte counts and payload byte estimates stay separate.
Import stays a local command. Raw PCAPs and evidence files stay on D:.
[Zeek connection fields](https://docs.zeek.org/en/v8.0.11/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info)

## Demonstrate the workflow

In a second PowerShell terminal, run from the repository root:

```powershell
$api = 'http://127.0.0.1:8001'
$batch = @{ records = @(Import-Csv -LiteralPath examples/unsw_nb15_inference.csv) }
$headers = @{ 'Idempotency-Key' = "g7-demo-$([guid]::NewGuid())" }
$payload = ConvertTo-Json $batch -Depth 5
$receipt = Invoke-RestMethod "$api/analyze" -Method Post -Headers $headers -ContentType 'application/json' -Body $payload
$replay = Invoke-RestMethod "$api/analyze" -Method Post -Headers $headers -ContentType 'application/json' -Body $payload
$alert = Invoke-RestMethod "$api/alerts/$($receipt.alert_ids[0])"
$case = @{ title = 'Synthetic investigation'; alert_ids = @($alert.id) } | ConvertTo-Json
$incident = Invoke-RestMethod "$api/incidents" -Method Post -ContentType 'application/json' -Body $case
$incidentUrl = "$api/incidents/$($incident.id)"
Invoke-RestMethod $incidentUrl -Method Patch -ContentType 'application/json' -Body '{"status":"investigating"}'
Invoke-RestMethod "$incidentUrl/notes" -Method Post -ContentType 'application/json' -Body '{"author":"Demo analyst","text":"Synthetic record review."}'
Invoke-RestMethod $incidentUrl
```

The bundled records are synthetic. The G7 run created two suspected-attack
alerts, verified that replay returned the same IDs, retrieved a filtered
alert, opened and updated an incident, and retrieved its saved note.

## Run tests

```powershell
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

The integration tests connect to `sentinelai_test`. Each test creates a
temporary schema, applies Alembic there, and removes its own schema on
cleanup. They cover migration downgrade and re-upgrade, saved-model
persistence across app lifespans, concurrent submissions, input validation,
and transaction rollback. The full G7 run passed 49 tests.
