# Store G37 flows in sensor-local PostgreSQL

**Accepted topology.** Provisioning and execution require separate authorization. The pilot pass/fail criteria below are proposed for review.

## Decision and rationale

For the first isolated monitoring pilot, run Zeek, one ingestion worker, and a dedicated PostgreSQL instance on the existing Ubuntu sensor VM. Bind PostgreSQL only to `127.0.0.1` inside the guest. Keep the existing VirtualBox Internal Network isolation. NAT, bridged, host-only, and external networking require explicit approval. Start with one vCPU and 2 GiB RAM and use guest-side verification. Keep the Windows application intact and defer dashboard integration until live ingestion, persistence, recovery, and sensor health are verified. [Approved pilot scope](0001-passive-single-site-zeek-pilot.md)

G36 verified ingestion from recorded replay. The current worker requires local PostgreSQL and commits flow inserts, file checkpoints, and health together. Co-location lets G37 exercise that transaction against native Zeek logs within the lab boundary. Offline transfer to Windows can support delayed review, but it would leave sensor-local persistence and recovery untested. The combined workload on the sensor VM remains unmeasured. The pilot will provide evidence for one bounded workload at one site. [G36 replay evidence](../LAB_GUIDE.md#g36-continuous-replay-verification) · [Database host restriction](../../backend/database.py#L16-L35) · [Worker contract](../DATABASE_SETUP.md#run-continuous-zeek-ingestion)

## Proposed pass/fail criteria

Before implementation, agree on the benign workload, expected transactions, measurement windows, and thresholds. Compare a Zeek-only baseline with the combined workload on the same VM allocation. A missing required measurement leaves the result inconclusive.

| Check | Proposed pass condition |
| --- | --- |
| Isolation | Verify the existing adapter and routes, the guest-only PostgreSQL listener, and that all test traffic stays within the approved lab. Stop if any boundary check fails. |
| Capture and persistence | Reconcile the planned transactions with independent packet and application evidence, complete native Zeek JSON records, and persisted rows. Require zero observed capture drops, zero unexplained rejections or missing rows, and one stored row per in-scope `(source, Zeek UID, first-packet timestamp)` tuple. |
| Restart and rotation | Restart the worker with a known backlog and exercise one rename rotation. Confirm it resumes at the committed checkpoint and drains the original `conn.log.1` before that file is moved or replaced. A controlled duplicate in a disposable verification run must increment the duplicate counter without adding a flow row. Require zero pending bytes after the recovery window and verify SHA-256 digests for the closed evidence files. |
| Delay and health | During the normal-load window, require every expected complete row to become visible in PostgreSQL within 5 seconds of its log line becoming readable. After worker restart, require the checkpoint heartbeat to recover within the existing 15-second freshness window and the bounded backlog to clear within 60 seconds. Record delay and backlog throughout the run. |
| Guest capacity | Record guest and process CPU, memory, swap activity, and disk use, including log and database growth. Require CPU below 90% on average in each one-minute normal-load window, at least 256 MiB of available guest memory, no swap I/O or out-of-memory events, and at least 1 GiB free on each guest filesystem holding logs or database data throughout the run. Recommend resizing only when measurements attribute a missed gate to resource pressure. |

The timing and resource limits apply to the declared pilot workload. Keep original captures, closed log generations, and digests in authorized local storage. Record the guest configuration, source and observation point, Zeek version, and test timestamps with the evidence. Keep unreviewed flows labeled `unknown`.

## Path to multiple sensors

If centralized review is needed while the lab remains isolated, evaluate approved, integrity-verified export of closed batches. For an authorized connected deployment, evaluate authenticated delivery to a central ingestion endpoint using a versioned batch format and stable site, sensor, observation point, and source-record identities. Keep file checkpoints local to each sensor. Make central ingestion idempotent per source and acknowledge batches after durable commit, so sensors can retry while preserving observations from different vantage points. Choose transport, retention, and capacity limits when measured demand and deployment approvals justify them. Central integration remains future work.
