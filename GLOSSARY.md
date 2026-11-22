# SentinelAI network monitoring and investigation

SentinelAI observes network activity, surfaces evidence for analyst review, and supports investigations.

## Monitoring

**Site**:
The authorized network environment covered by a monitoring deployment. The isolated lab is the site for the first pilot.

**Sensor**:
An instance that observes traffic at an observation point and produces network telemetry.

**Observation point**:
The location within a site from which a sensor observes traffic. It identifies the vantage point that produced the observation.

**Ingestion source**:
An identified stream of observations submitted for ingestion. It can carry observations from a connected sensor or from a recorded replay.

**Checkpoint**:
The durable progress record for an ingestion source, used to resume processing after an interruption.

**Passive monitoring**:
Observation of traffic exchanged by other systems, without probing or intervening in those exchanges.

**Recorded replay**:
A run that feeds previously collected observations through the monitoring workflow to check how the workflow processes them.

**Zeek flow**:
A connection-level observation recorded by Zeek from one observation point.

## Evidence and investigation

**Reviewed ground truth**:
A flow label supported by reviewed source evidence. A flow remains `unknown` when the evidence cannot support a `benign` or `attack` label.

**Rule finding**:
A match between an observation and a versioned detection rule. It is evidence for review and is tracked separately from ground truth.

**Alert**:
A record of suspected activity surfaced for analyst review.

**Incident**:
An analyst investigation that brings together one or more alerts and can include notes.
