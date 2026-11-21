# G8 React dashboard

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
- **Incidents** discovers investigations through alert links. Select
  **New incident** to give an investigation a title and link unassigned
  alerts. Select an existing incident to edit its title, description,
  or status.
- **Analyst Notes** displays the selected incident's notes and accepts an
  analyst name and note. The analyst name is entered by the user in this
  local workflow.
- **Analyze** accepts pasted or imported JSON as either a `records` object
  or an array containing 1–100 prepared UNSW-NB15 records. **Preview
  predictions** uses `/predict` for scores without saving. **Analyze and
  save alerts** uses `/analyze` and shows the backend receipt. Retrying the
  same records within the page reuses the submission's idempotency key.

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
and filters, paging, request validation, idempotency, and investigation
actions. This dashboard operates on prepared feature records through the
local API.
