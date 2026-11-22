# SentinelAI dashboard

## Run locally

Use Node.js 22.12 or newer and the existing Python virtual environment,
PostgreSQL service, and saved model package. Complete the
[database setup](DATABASE_SETUP.md) before starting the API.

From the repository root in the first PowerShell terminal:

```powershell
& .\.venv\Scripts\python.exe -B -m alembic upgrade head
& .\.venv\Scripts\python.exe -B -m uvicorn backend.main:app --host 127.0.0.1 --port 8001
```

In a second terminal:

```powershell
Set-Location frontend
npm.cmd ci
npm.cmd run dev
```

Open [SentinelAI](http://127.0.0.1:5173). The first terminal runs FastAPI on
port 8001. The second serves React via Vite on port 5173. Use Ctrl+C to stop
each service.

The browser sends requests to its own origin under `/api/`. The local Vite
proxy forwards these requests to `127.0.0.1:8001`, so this workflow needs no
FastAPI CORS exceptions. Both services bind to loopback. PostgreSQL and its
credentials are handled by FastAPI.

## Dashboard workflows

- **Overview** derives totals, investigation coverage, and a seven-day
  alert chart from the persisted alerts returned by FastAPI. The UI walks
  the alert pages, since the API provides neither aggregate statistics nor
  a separate incident-list endpoint.
- **Alerts** searches and filters the retrieved alerts. Open a row to
  retrieve its details from the alert endpoint. A detection remains a
  suspected attack, and the detail view shows the model probability.
- **Network Traffic** displays offline imports and incoming Zeek flows.
  Recent activity, protocol counts, source health, and the first connection
  page refresh every five seconds. Filter by protocol, capture ID, rule finding,
  or source, and choose **Recently ingested** to follow replay or sensor arrivals.
  Open a row for endpoints, timing, counters, review label, and rule and source
  details. The dashboard identifies recorded replay and connected sensor inputs.
  [Offline import](DATABASE_SETUP.md#import-reviewed-zeek-flows-offline) ·
  [Continuous replay and worker setup](DATABASE_SETUP.md#run-continuous-zeek-ingestion)
- **Incidents** discovers investigations through alert links. Select
  **New incident** to give an investigation a title and link unassigned
  alerts. Select an existing incident to edit its title, description,
  or status.
- **Analyst Notes** displays the selected incident's notes and accepts an
  analyst name and note. The analyst name is entered by the user in this
  local workflow.
- **Analyze** offers **Manual JSON** and **CSV upload**. Manual JSON accepts
  pasted or imported JSON as either a `records` object or an array containing
  1–100 prepared UNSW-NB15 records. **Preview predictions** uses `/predict`
  for scores without saving. **Analyze and save alerts** uses `/analyze` and
  shows the backend receipt. Retrying unchanged manual inputs within the page
  reuses the submission's idempotency key.

To demonstrate, select **Load synthetic example**, preview the three
records, then save and open one of the returned alert links. Create an
incident from that alert, set its status to **Investigating**, and select
**View notes** to add a note. The example input is labeled synthetic. Its
saved detections are actual local database records and count toward the
overview figures. G7's API does not store a per-record source label for
those saved alerts.

The connection indicator reflects API health. A database request can
still fail independently and will display its own error on the affected
page. Refresh the dashboard after restoring the local service.

### Interpret predictions

At threshold 0.5, the frozen model falsely flagged **32.81% of normal rows**
on the official UNSW-NB15 test partition. The dashboard is a local analyst
prototype for prepared records. Live-network detection and alert volume
remain unvalidated. See the [model evaluation](FINAL_MODEL_EVALUATION.md)
and [reliability checks](RELIABILITY_TESTING.md).

## Upload and analyze CSV

1. In **Analyze**, select **CSV upload**. Choose or drop a CSV file. For a
   demonstration, use [the bundled synthetic CSV](../examples/unsw_nb15_inference.csv).
2. Review the validated record preview before selecting **Analyze CSV**.
   The dashboard scores each batch in order and reports progress by records
   completed. Review the total, normal, and suspected-attack counts, and
   inspect a record to see its features and attack probability.
3. Select **Save suspected alerts** to send the validated batches through
   the existing alert-management endpoint. Open a returned alert link to
   review the stored detection.

The upload accepts one comma-separated UTF-8 file with a header, up to
**2 MiB and 1,000 records**. Column order is flexible. All 42 model features
are required. The server ignores optional `id`, `label`, and `attack_cat`
columns, validates each record using the inference schema, and rejects
the upload before scoring if its CSV, columns, or values are invalid.
See the [prediction contract](MODEL_PACKAGING.md#prediction-contract).

`POST /csv/preview` takes the CSV as a raw `text/csv` request body.
It returns validated predictors and the scoring batch limit (currently
100). The preview step performs validation without fitting or scoring a
model. The dashboard calls `/predict` for scores and `/analyze` only when
the user chooses to save. Each save request is transactional for its batch.
If a later batch fails, successful batches remain saved and the upload can
be retried. Retry keys derive from the ordered predictor records and batch
position. Re-uploading the same records, even after a reload, reuses the
existing receipts. Changing predictor values or record order creates a
different submission.

## Build and test

From `frontend/`:

```powershell
npm.cmd test
npm.cmd run build
```

From the repository root with the saved model and test database configured:

```powershell
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

The frontend suite covers backend errors and recovery, statistics, search
and filters, paging, request validation, idempotency, investigation actions,
and CSV workflows. Python tests cover CSV validation and limits using
synthetic records. This dashboard operates on prepared feature records
through the local API.
