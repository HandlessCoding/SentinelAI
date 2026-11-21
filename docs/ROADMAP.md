# Project status and roadmap

## Implemented through G27

- Level 1 scores prepared UNSW-NB15 records, persists suspected-attack alerts,
  and supports incident review and analyst notes in a local dashboard.
- The frozen 48-tree forest was evaluated at threshold 0.5. The official test
  measured 99.35% attack recall and a 32.81% false-positive rate. Live traffic
  compatibility and operational alert burden remain unvalidated.
  [Official evaluation](FINAL_MODEL_EVALUATION.md)
- Level 2 research established dataset cataloguing, quality/overlap checks,
  a provenance-aware registry, and real Zeek feature extraction. G27 collected
  16 verified benign flows in four sessions using one isolated VM pair.
  [Research archive](research/README.md) · [Collection results](research/lab/LEVEL_2_G27_BENIGN_COLLECTION.md)

## Proposed next research step

The proposed G28 experiment is to repeat a frozen benign plan under a
separately authorized environment with a different device lineage and
observation point. Use the same verified feature definitions, preserve
original recordings, and review application evidence before comparing
coverage, missingness, or repeated vectors.

Further Level 2 work depends on enough independently reviewed benign and
positive captures, frozen device/session cohorts, and the prespecified
coverage requirements. Multiclass detection, explanations, additional datasets,
Rust ingestion, and network-log integration remain planned. Check feature
parity before transferring a model between exporters or integrating it into
the dashboard. [Capture evaluation gates](research/level-2/LEVEL_2_CAPTURE_DATA_STRATEGY.md#feasibility-gates-before-fitting)

## Engineering follow-up

Start with a synthetic smoke job in CI and agree on a repository license.
Stable alert pagination and cross-platform dependency locking can follow
as separately verified changes. [Engineering review](G27_5_ENGINEERING_REVIEW.md)
