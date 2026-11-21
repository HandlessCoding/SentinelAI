# G5 Random Forest packaging and inference

## Build and use the local package

Run from the repository root in PowerShell with Python 3.12.3 and the prepared
training CSV at `data/UNSW_NB15_training-set.csv`.

```powershell
& .\.venv\Scripts\python.exe -B -m pip install --only-binary=:all: -r ml/requirements-baseline.txt
& .\.venv\Scripts\python.exe -B -m ml.train_model
& .\.venv\Scripts\python.exe -B -m ml.inference examples/unsw_nb15_inference.csv
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

The commands install the pinned G4 dependencies, explicitly train and package
the model, score the bundled synthetic records, and run the tests.
Training uses the complete official training partition. The test partition
is reserved for final evaluation. The training command publishes both package
files together and refuses to overwrite an existing package for this version.
Inference uses the saved pipeline directly.

## Package contents and training record

The provisional Level 1 model is `unsw-nb15-rf-v1`. Its package lives under
`artifacts/unsw-nb15-rf-v1/`, which is excluded from Git along with `data/`.

| File | Contents |
|---|---|
| `pipeline.pkl` | Fitted scikit-learn preprocessing and Random Forest in one pipeline |
| `metadata.json` | Artifact format and model versions, ordered feature schema, threshold and class mapping, training file identity and counts, parameters, runtime versions, and pipeline size and SHA-256 |

The build processed **175,341 records** (56,000 normal and 119,341 attack)
using the [G4 configuration](research/level-1/MODEL_COMPARISON.md). It used 48 trees, seed 42,
depth capped at 14, a maximum of 512 leaves per tree, minimum leaf size 5,
bootstrap draws of 75% of the training count, and one worker. The fitted
pipeline was **3,437,242 bytes** (3.28 MiB). The local fit took about 63 seconds.

- Training CSV SHA-256 is `bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa`.
- Pipeline SHA-256 for this build is `8c37b095dba6cd0f58931ff91e713b0a05f84678b4829c387c788e196b8e1cd6`.
- Runtime was Python 3.12.3, scikit-learn 1.7.2, NumPy 2.2.6, SciPy 1.15.3,
  joblib 1.5.2, and threadpoolctl 3.6.0.

## Prediction contract

- Supply each of the 42 predictors listed in the manifest. The module accepts
  mappings or a UTF-8 CSV with a header and aligns fields by name. It accepts
  and ignores optional `id`, `label`, and `attack_cat` fields.
- Supply nonempty text for `proto`, `service`, and `state`. Preserve the
  literal service `-`. Pass `is_ftp_login` as an integer code or its string
  form. Codes such as `2` and `4` remain categories. The fitted encoder
  ignores categories it has never seen.
- Supply finite numbers or their CSV string forms for decimal features.
  Integer fields require integer values or integer strings. The module
  raises `InputValidationError` for missing or unexpected features, invalid
  values, duplicate or malformed CSV headers, or malformed rows. The entire
  batch is validated before scoring.
- Each output includes `label` (0 or 1), `classification`
  (`normal` or `attack`), and `attack_probability`. An attack probability
  strictly greater than **0.5** maps to attack. The score is the model's
  estimated probability. Operational calibration remains unverified.

The three demonstration records are synthetic and illustrate the interface.
They are independent of the published dataset and carry no evaluation labels.
A live Zeek or network traffic source needs a validated feature mapping
to this schema before scoring.

## Future FastAPI integration

Load the package once per worker in the application's startup lifespan. Pass
an operator-configured local path to `load_model` and keep the resulting model
in application state. Client payloads supply only predictor records. A
missing or incompatible package should fail startup so prediction requests
cannot trigger training or an artifact download.

```python
from pathlib import Path
from ml.inference import load_model

# At startup, from trusted service configuration.
model = load_model(Path("artifacts/unsw-nb15-rf-v1"))

# In a scoring handler, with a bounded batch of validated request mappings.
response = {
    "model_version": model.model_version,
    "decision_threshold": model.decision_threshold,
    "predictions": model.predict(records),
}
```

Map `InputValidationError` to an HTTP 422 response. Treat artifact and
unexpected runtime failures as service errors. Run batch prediction in a
synchronous handler or a worker thread when serving from an async handler.

Pickle requires a trusted source. Use packages created locally by the
training command and keep the artifact directory under operator control.
The loader checks schema, exact runtime versions, and the pipeline digest
before deserialization. The digest detects mismatches with the manifest,
while trust comes from the local build and control of the package directory.
[Scikit-learn model persistence guidance](https://scikit-learn.org/1.7/model_persistence.html#security-maintainability-limitations)
