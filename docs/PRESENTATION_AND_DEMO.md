# Graduation presentation and live demonstration

## Suggested 12½-minute presentation

| Time | Topic | What to show |
| --- | --- | --- |
| 0:00–0:50 | Problem and objective | Explain how SentinelAI turns prepared network-flow records into detections an analyst can investigate. |
| 0:50–2:30 | Dataset and leakage prevention | Introduce the official training and test partitions. Explain how identical predictor vectors stayed together in validation and why label fields were excluded from the model inputs. |
| 2:30–3:45 | System architecture | Trace a CSV through React, FastAPI, the saved Random Forest pipeline and PostgreSQL. Explain where analyst decisions enter the workflow. [Architecture diagrams](ARCHITECTURE.md) |
| 3:45–5:30 | Model choice and evaluation | Explain why the 48-tree Random Forest was selected in G4 using training-only validation. Show the G4 and G10 results side by side. [Model comparison](MODEL_COMPARISON.md) · [Final evaluation](FINAL_MODEL_EVALUATION.md) |
| 5:30–10:30 | Live demonstration | Upload, preview and score a synthetic CSV. Save the suspected attacks, retry the submission, then open an investigation and add a note. |
| 10:30–12:30 | Limitations and future work | Explain what the false-positive rate means for an analyst and why external validation comes before using the model on network logs. End with the scope of the completed Level 1 workflow. [Level 2 roadmap](LEVEL_2_ROADMAP.md) |

For a 10-minute slot, shorten the architecture and dataset sections and demonstrate retries verbally. With 15 minutes, use the remaining time for questions.

## Results to present

| Evaluation at threshold 0.5 | Attack recall | False-positive rate |
| --- | ---: | ---: |
| G4 pooled validation predictions from three training-only, group-aware folds | 98.84% | 14.06% |
| G10 official test predictions from the frozen model fitted on the full training partition | 99.35% | 32.81% |

In G10, the model detected **45,036 of 45,332 attack records** and flagged **12,140 of 37,000 normal records**. The false-positive rate describes the share of normal records incorrectly flagged. On the official benchmark, that was roughly one in three normal records. The workload a real analyst would face remains unmeasured and would depend on traffic mix as well as error rates. [Official test results](FINAL_MODEL_EVALUATION.md#official-test-results)

The official test file was held out from fitting, model selection and threshold tuning. G1 checked its file structure and row count. G10 subsequently found **1,302 distinct predictor vectors** shared between the two official partitions, covering **8,541 test rows**. This limits how broadly to interpret the test as evidence about previously unseen traffic. The false-positive rate was 32.735% even among test rows whose exact predictors were absent from training. [Hold-out audit and overlap analysis](FINAL_MODEL_EVALUATION.md)

## Before presenting

1. Start the local PostgreSQL service, the API on port 8001 and the dashboard on port 5173. Confirm the database schema is migrated and the frozen `unsw-nb15-rf-v1` model is available. [Dashboard setup](DASHBOARD_SETUP.md#run-locally) · [Database setup](DATABASE_SETUP.md)
2. Open [the dashboard](http://127.0.0.1:5173/) and [API health](http://127.0.0.1:8001/health) in separate tabs. Confirm that **Overview** can retrieve its alerts. The health response covers the API, while successfully retrieving alerts also exercises PostgreSQL.
3. Keep [the bundled three-record synthetic CSV](../examples/unsw_nb15_inference.csv) easy to select. Rehearse in the local development database. If both alerts are already linked, open their existing investigation during the demo or prepare a separate synthetic fixture with at least one unassigned alert. Keep configuration tabs and credentials outside the shared screen.

## Live script

| Step | On screen | What to say |
| --- | --- | --- |
| 1. Preview | Select **Analyze → CSV upload**. Drop the synthetic fixture or use **Choose CSV file**. Show **Record preview**. | “The server checks the CSV and its 42 model features. These three records are synthetic, and the preview validates them before scoring.” |
| 2. Score | Select **Analyze CSV**. Expect three records, one normal prediction and two suspected attacks. Select **Inspect** beside one result to show its measured features and attack probability. | “The backend uses a frozen pipeline. A score above 0.5 produces a suspected attack, which is a finding for an analyst to review.” |
| 3. Persist | Select **Save suspected alerts**. Point to **CSV analysis saved**, the two saved alerts and their links. | “Scoring alone leaves the database untouched. Choosing to save records the prediction batch and creates alerts for the suspected attacks.” |
| 4. Retry | Choose the same file again, score it and select **Save suspected alerts**. Compare the alert links against the first receipt. | “Retrying the same submission returns the existing alert references, which protects the analyst queue from duplicate writes.” |
| 5. Investigate | Follow an alert link. Show its probability, model version and status. Select **Create investigation**, enter `Synthetic defense demo`, confirm the linked alert and select **Create incident**. Set **Status** to **Investigating** and select **Save changes**. If it is already linked, select **View investigation**. | “The investigation links the model finding to a case the analyst can manage.” |
| 6. Record context | Select **View notes**. Enter `Demo analyst` and `Reviewed the synthetic alert and recorded it for demonstration.` Select **Add note**. Reload and reopen the incident or note to show that it persisted. | “The alert, investigation and note are now stored together in the local system. The name is a label entered by the local user.” |

If the saving or note request fails during the presentation, show the on-screen error and continue with a previously captured walkthrough, labeled as a rehearsal. If the API or model is unavailable, use the architecture diagram and official evaluation table to explain the workflow and name the step you could not demonstrate. The dashboard totals reflect local stored alerts, including synthetic demonstration records.

## Questions to rehearse

- **Why group identical predictors?** Row-level random splits could put indistinguishable inputs on both sides. Keeping them together makes internal validation a more demanding test. Conflicting-label groups stayed intact because their ambiguity is present in the benchmark.
- **Why keep the threshold at 0.5?** G4 compared both models at their default thresholds and explored lower false-positive budgets using inner training splits. G5 froze the operating point before any official test scoring. Reusing G10 to choose a new cutoff would spend the test set on development. [Model comparison](MODEL_COMPARISON.md) · [Final evaluation](FINAL_MODEL_EVALUATION.md)
- **What did the test teach you?** High attack recall coexisted with a high false-positive rate. Fuzzers accounted for 285 of the 296 missed attack records. Misclassification rates and deployment alert volume need fresh evidence before use with live network data. [Final evaluation](FINAL_MODEL_EVALUATION.md)
