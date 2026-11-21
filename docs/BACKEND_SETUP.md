# Local FastAPI backend and API

## Install and start

Run from the repository root in PowerShell with the existing Python 3.12.3
virtual environment and the trusted package at
`artifacts/unsw-nb15-rf-v1/`. See the [G5 packaging guide](MODEL_PACKAGING.md)
for the package layout and explicit build command.

```powershell
& .\.venv\Scripts\python.exe -B -m pip install --only-binary=:all: -r ml/requirements-baseline.txt -r backend/requirements.txt
& .\.venv\Scripts\python.exe -B -m uvicorn backend.main:app --host 127.0.0.1 --port 8001
```

FastAPI defines the routes and OpenAPI docs, Pydantic validates JSON envelopes
and response types, Uvicorn serves the app, and HTTPX supports the automated
tests. Startup loads the local model once per server process. An absent,
incompatible, or corrupt package causes startup to fail. The startup and
prediction paths use the existing inference module and its artifact checks.
Use Ctrl+C in the Uvicorn terminal to stop the server.

## Try the API

Open [Swagger UI](http://127.0.0.1:8001/docs). Expand an operation, choose
**Try it out**, then **Execute**. The prediction operation includes a
complete synthetic example. The generated OpenAPI contract is available at
[openapi.json](http://127.0.0.1:8001/openapi.json).

| Method and path | Result |
|---|---|
| `GET /health` | `{"status":"ok"}` after successful startup |
| `GET /model/info` | Model version, expected feature count (42), and decision threshold (0.5) |
| `POST /predict` | Model version, threshold, and an ordered list of predictions with binary labels, class names, and attack probabilities |

For a three-record batch using the bundled synthetic CSV, run this in a second
PowerShell terminal at the repository root:

```powershell
$batch = @{ records = @(Import-Csv -LiteralPath examples/unsw_nb15_inference.csv) }
Invoke-RestMethod -Uri http://127.0.0.1:8001/predict -Method Post `
  -ContentType 'application/json' -Body (ConvertTo-Json $batch -Depth 5)
```

Send a JSON object containing a `records` array of 1 to 100 objects.
Records need all 42 prepared UNSW-NB15 predictors. Field order is flexible
and `id`, `label`, and `attack_cat` are optional. The inference module
validates values and preserves trained category handling. Details are in the
[prediction contract](MODEL_PACKAGING.md#prediction-contract).

| HTTP status | Meaning |
|---|---|
| `400` | Malformed JSON or invalid body length |
| `413` | Body exceeds 2 MiB |
| `415` | Wrong content type or compressed body |
| `422` | Invalid request structure, record count, feature names, or values |
| `500` | Unexpected prediction failure |

Responses contain short error messages. Unexpected prediction exceptions are
logged on the server. Both the exported ASGI app and factory enforce the
local Host guard. Bind Uvicorn to loopback as shown above. A prediction is a
model estimate for a prepared record.

## Tests

```powershell
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

The suite covers the existing ML workflow, mocked API requests, and
integration with the saved package using the synthetic CSV.

For investigation routes and the PostgreSQL test prerequisites, see the
[database setup](DATABASE_SETUP.md) and [reliability testing](RELIABILITY_TESTING.md).
