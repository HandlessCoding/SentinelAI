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

**G28 physical-environment validation is deferred.** Preflight confirmed the
G26 sensor/client VM pair on one physical host and the original `sensor-lab0`
observation point. Independent hardware is unavailable. The protocol below
remains available for a future authorized session, for example on two loaned
university lab machines with the lab owner's written permission.

Use two separately provisioned Linux machines joined by a dedicated Ethernet
cable with no uplink. One runs the client. The other runs the service and
records at its physical lab-interface ingress, matching G27's observation
role. Confirm ownership, authorized interfaces and services, offline software
availability, and capture storage on D:. Keep other network interfaces and
forwarding disabled. Verify local routes and peer connectivity before opening
the recorder. [Lab isolation and collection guide](LAB_GUIDE.md)

Repeat the G27 pilot with the same workload, seed, protocol mix, extractor,
and Zeek version. Use fresh capture and session IDs and confirmed device,
environment, and observation-point IDs. The G27 audit hardcodes its original
lineage. Before collection, validate a new profile for those IDs while
preserving the existing registry schema, label rules, and G27 audit results.
Preserve the PCAP, Zeek logs and receipt, both application logs, timestamps,
recorder diagnostics, and authorization record with their checksums. Keep
ambiguous flows `unknown`. [Frozen pilot plan](../examples/lab_benign_pilot.json)

| Comparison | Verified G27 pilot | Check on the independent pilot |
| --- | --- | --- |
| Feature completeness | Duration and directional counters present on all three flows. `service` absent on the fixture UDP flow. | Compare missing and invalid fields by transport. Require duration and both directional packet and byte counters. Report optional fields separately. |
| Protocol behavior | Two TCP flows, one UDP flow, five completed transactions. | Require the planned flow and transaction counts. Compare service, connection state, history, duration, packets, and bytes by transport. |
| Capture quality | Tcpdump and Zeek both accounted for 36 packets, with zero kernel drops. | Require zero kernel drops and matching counts within the new capture. Report cross-environment changes in packet counts and exact feature overlap. |
| Labeling consistency | All three flows reviewed as benign from matching client and service evidence. | Require matching transaction IDs, lengths, payload hashes, and capture time bounds. Report benign and unknown counts. |

Approval is needed for the named hardware and recording scope, and any software
installation or network changes required for that setup. A failed isolation,
capture, or evidence check blocks expansion. The comparison is pending a
verified independent recording. One matched benign pilot can measure feature
portability for this workload. It cannot establish detection performance or
false-positive rates. [G27 baseline](research/lab/LEVEL_2_G27_BENIGN_COLLECTION.md#verified-recordings)

G29 has one verified benign control. Live attack collection is **BLOCKED**
with zero real attack flows. A real positive pilot needs independently reviewed client,
service, and packet evidence. Keep synthetic fixtures outside cohort coverage.
[G29 checks](LAB_GUIDE.md#matched-control-and-label-validation)

G30 adds offline import and dashboard triage for reviewed Zeek captures.
The G29 control imports as three reviewed benign flows, with zero rule
findings. G31 audits five G27 and G29 sessions and adds GitHub regression
checks. Reviewed positive coverage and independent environments are still
unavailable. A future audit needs prespecified, independently annotated
captures with both classes across different environments.
[Offline traffic workflow](LAB_GUIDE.md#triage-recorded-flows-in-sentinelai)

G32 compares experimental models and operating points on group-separated
subsets of the official UNSW-NB15 training CSV. The results describe
within-dataset development and leave live flow validation pending.
[G32 development protocol](research/level-2/LEVEL_2_EXPERIMENTAL_BASELINE.md#g32-unsw-nb15-development-restart)

Further Level 2 work depends on enough independently reviewed benign and
positive captures, frozen device/session cohorts, and the prespecified
coverage requirements. Multiclass detection, explanations, additional datasets,
Rust ingestion, and network-log integration remain planned. Check feature
parity before transferring a model between exporters or integrating it into
the dashboard. [Capture evaluation gates](research/level-2/LEVEL_2_CAPTURE_DATA_STRATEGY.md#feasibility-gates-before-fitting)

## Engineering follow-up

Agree on a repository license.
Stable alert pagination and cross-platform dependency locking can follow
as separately verified changes. [Engineering review](G27_5_ENGINEERING_REVIEW.md)
