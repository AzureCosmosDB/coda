# What CODA detects

[Getting started](../README.md) | [Permissions](permissions.md) | [Log Analytics setup](detections/log-analytics-readiness.md)

CODA contains **24 read-only detectors** for Azure Cosmos DB. The local web experience discovers
NoSQL accounts. Checks run only where their resource type, throughput mode, configuration, and
available data make them applicable; 24 registered detectors does not mean 24 checks on every container.

## Data and interpretation

**Configuration** comes from ARM; **metrics** come from Azure Monitor without diagnostic settings.
**Logs** require resource-specific `CDB*` tables. Twenty checks do not require Log Analytics, but
that does **not** mean they all work immediately: metrics history, sample counts, and resource age
can still be prerequisites.

The table gives each detector's normal **production** window. Configuration-led checks use current
settings, with optional enrichment where noted. Evaluation mode available through programmatic
interfaces uses a shorter shared window and disables resource-age guards; it is not equivalent to
production coverage. The browser uses production mode.

| ID | Detector | Main evidence | Production window |
|---|---|---|---|
| DX-001 | Manual over-provisioning | Metrics + throughput configuration | 30 days |
| DX-002 | Cross-partition query fan-out | Query statistics + request logs | 1 day |
| DX-003 | Shared-throughput starvation | Request logs + shared-pool configuration | 1 day |
| DX-004 | Idle throughput | Metrics + throughput configuration | 30 days |
| DX-005 | Global under-provisioning | Request/partition utilization metrics | 7 days |
| DX-006 | Hot partition | Per-partition utilization metrics | 7 days |
| DX-007 | Shard-key misalignment | Query statistics + request logs | 1 day |
| DX-008 | Multi-region writes antipattern | Account configuration + throughput offers | Current configuration |
| DX-009 | Partition merge candidate | Partition count/storage metrics + throughput | 6 hours |
| DX-010 | Uncontrolled ingestion | Request logs | 1 day |
| DX-011 | Autoscale maximum too high | Metrics + autoscale configuration | 30 days |
| DX-012 | Manual-to-autoscale candidate | Utilization metrics + manual throughput | 30 days |
| DX-013 | Autoscale-to-manual candidate | Utilization metrics + autoscale throughput | 30 days |
| DX-014 | Serverless candidate | Account utilization metrics + configuration | 30 days |
| DX-015 | Partition storage skew | Per-partition storage metrics | 7 days |
| DX-016 | Expensive consistency | Account configuration; optional request logs | Current configuration; 1 day enrichment |
| DX-017 | Rapid storage growth | Per-partition storage trend | 30 days |
| DX-018 | Serverless throttling | Serverless request/utilization metrics | 7 days |
| DX-019 | Paid continuous backup on non-production | Backup/environment configuration; optional storage/prices | Current configuration |
| DX-020 | Non-throttling errors | Account requests by status | 7 days |
| DX-021 | Throttling by operation | Account requests by operation/status | 7 days |
| DX-022 | Per-region autoscale opportunity | Region/autoscale configuration | Current configuration |
| DX-023 | Reserved-capacity candidate | Provisioned-throughput baseline | Current configuration |
| DX-024 | Indexing cost risk | Index/data storage metrics + indexing policy | 6 hours (latest value) |

Windows describe what is requested, not a guarantee of complete collected history. For example,
DX-004 has a seven-day minimum resource-age guard while requesting 30 days of metrics; several
seven-day performance/storage checks have one-day age guards. Data sufficiency checks also vary.
DX-020 and DX-021 require at least 1,000 requests in their window. Missing/quiet data can produce
an abstention; access or query failures can produce errors. Neither is a clean health result.

The current registry labels DX-020, DX-021, and DX-023 thresholds **proposal**. Other registry labels
are **validated**, which describes threshold policy, not fresh validation of your account or proof
that every supported workload has been tested. Inspect report evidence before acting.

## Cost and capacity

### DX-001 - Manual over-provisioning

Finds manual-throughput units whose observed utilization supports a lower RU/s allocation. It uses
high-percentile demand rather than average utilization to account for bursts. Review the suggested
capacity against workload peaks, growth, and minimum throughput limits before reducing it.
Reports recoverable RU/s and, when an applicable amortized rate is available, estimated monthly savings.

### DX-004 - Idle throughput

Looks for provisioned units with sustained near-zero activity. Unlike right-sizing, it can identify
capacity recoverable by retiring an unused resource even when throughput is already at its minimum.
Age and data guards reduce false positives, but you must check seasonal/batch workloads and retention
obligations before decommissioning, archiving, or changing TTL.

### DX-011 - Autoscale maximum too high

Compares observed demand with the configured autoscale maximum and minimum billable floor. Recommends
a lower maximum where warranted, subject to service floors and headroom. Recoverable capacity and
eligible cost estimates respect autoscale billing; an idle resource may be better addressed by DX-004.

### DX-012 - Manual-to-autoscale candidate

Flags a manual-throughput workload with a spiky duty cycle: capacity is reserved for peaks but lightly
used much of the time. Evaluate autoscale against actual hourly demand and rates. This is a mode-change
recommendation, not an assured currency saving.

### DX-013 - Autoscale-to-manual candidate

Flags steady, sustained-high autoscale utilization with limited benefit from scaling down. Evaluate
manual capacity and its pricing against peak demand and operational requirements before switching.
The finding is qualitative rather than a guaranteed saving.

### DX-014 - Serverless candidate

An account-level check for low, sporadic provisioned demand with idle periods. It suggests evaluating
serverless and its feature, region, throughput, and migration constraints. It does not migrate the
account or claim that a configuration toggle is sufficient; confirm current service support and prices.

### DX-019 - Paid continuous backup on non-production

Flags paid `Continuous30Days` or `Continuous35Days` backup on an account inferred to be non-production
from tags, subscription, or name. Production and `Continuous7Days` accounts are not flagged; unknown
tiers abstain. Confirm that the environment inference and shorter retention meet your recovery policy.
Optional savings use storage evidence and public retail backup prices, not the throughput billing rate.
Restore charges are separate.

### DX-023 - Reserved-capacity candidate

An account-level **proposal-threshold** recommendation for a material provisioned baseline
(at least 3,000 RU/s in the current rule). A configuration snapshot does not prove future demand or
unused reservation coverage. Check existing commitments, utilization, eligibility, and negotiated
rates before buying a one- or three-year reservation. No guaranteed saving is asserted.

## Throughput and access patterns

### DX-002 - Cross-partition query fan-out

Finds containers where a material share of queries (at least 10%) fan out across partitions (average
fan-out of at least 1.5 partitions per query). Requires **both `CDBQueryRuntimeStatistics` and
`CDBDataPlaneRequests`**, and at least 50 queries in the window. Fan-out is flagged structurally:
latency grows with every partition checked even when the RU charge is low, so request charge is
reported as evidence rather than used as a gate. Severity scales with physical partition count and
fan-out query rate; below 0.1 fan-out queries per second the result is reported as occasional, not a
finding. Review partition-key filters, indexes, and access patterns.

### DX-003 - Shared-throughput starvation

Runs at shared-database scope. Looks for a throttling pool where one active container dominates RU
consumption while a low-consumption sibling also throttles. Prefers **`CDBDataPlaneRequests5M`**,
with **`CDBDataPlaneRequests`** compatibility when five-minute logs are unavailable.
This is evidence of unfair contention, not visibility into Cosmos DB's exact internal pool allocation.
Evaluate dedicated throughput or workload isolation/rebalancing.

### DX-005 - Global under-provisioning

Correlates throttling with broad partition saturation to distinguish insufficient overall throughput
from a localized hot spot. Review workload shaping and required RU/s; raising throughput may be
appropriate for global pressure but is not automatically the right response to every 429.

### DX-006 - Hot partition

Finds utilization concentrated on a physical partition while others have headroom. Review partition-key
distribution, high-volume keys, and workload patterns. More total throughput may temporarily help but
does not remove uneven demand. Physical-partition metrics alone do not identify the exact logical key.

### DX-007 - Shard-key misalignment

Escalates widespread fan-out into a possible partition-key/access-pattern mismatch rather than a
single inefficient query. Requires **both `CDBQueryRuntimeStatistics` and `CDBDataPlaneRequests`**;
it flags when at least 60% of queries fan out across two or more physical partitions at a material
rate, with the same partition-count × rate severity as DX-002. Review the model and query patterns
before undertaking repartitioning.

### DX-009 - Partition merge candidate

Compares actual physical partitions with the estimated need from throughput and storage, using
10,000 RU/s and 50 GiB per physical partition and a minimum of one partition. Excess partitions can
leave each with a small share of capacity. Check current service eligibility and workload skew before
requesting a merge; CODA does not perform it.

### DX-010 - Uncontrolled ingestion

Prefers **`CDBDataPlaneRequests5M`**, with raw **`CDBDataPlaneRequests`** compatibility, to identify
write-dominant throttling: current gates include at least
80% write RU, 10% throttled requests, and 1,000 total requests. Burstiness and client user-agent are
supporting evidence, not proof of a particular connector or a required burst gate. Review bounded
concurrency, throughput control, queue smoothing, and retry-after handling. Burst evidence is
explicitly five-minute when using aggregates and one-minute when using raw logs; those factors
are not interchangeable. Counts use represented requests, not aggregate rows.

### DX-018 - Serverless throttling

Evaluates throttling on serverless resources, where there is no provisioned RU/s setting to raise.
Review partition distribution, per-partition capacity, workload shaping, and whether provisioned
throughput would be more suitable. A 429 does not by itself identify the exact offending logical key.

### DX-020 - Non-throttling errors

An account-level **proposal-threshold** analysis of non-429 status patterns, such as malformed requests,
missing resources, conflicts, optimistic-concurrency failures, or service errors. Identifies dominant
codes to guide investigation; it does not prove a client-side root cause, and 5xx can be service-side.
Increasing throughput is not a general remedy.

### DX-021 - Throttling by operation

An account-level **proposal-threshold** analysis of which categories dominate 429s: writes, reads,
queries, execution, or other operations. Helps prioritize ingestion control, query investigation,
partition distribution, or capacity review. Operation mix guides investigation; it is not proof that
one particular detector's root cause is present.

## Configuration and storage risks

### DX-008 - Multi-region writes antipattern

Flags multi-write configuration on inferred non-production accounts or the engine's MongoDB API case.
The public web discovery path targets NoSQL; production NoSQL multi-write can be legitimate and is
not flagged solely for having multiple write regions. Confirm availability/conflict requirements.
**Retaining regions**, not the multi-write toggle alone, repeats regional capacity; only defensible
all-manual removable-region capacity is quantified.

### DX-015 - Partition storage skew

Finds disproportionate storage on physical partitions. Review key cardinality, large logical keys,
and data distribution before redesigning the key. A physical-partition measurement does not establish
that an individual logical partition has reached its size limit.

### DX-016 - Expensive consistency

Flags Strong or Bounded Staleness consistency across multiple regions. Review consistency and
latency/availability requirements before relaxing them; a single-region account is not flagged by
this configuration rule. Optional enrichment prefers `CDBDataPlaneRequests5M`, with raw
`CDBDataPlaneRequests` compatibility, to summarize read/query charges
and a labelled half-charge upper bound, not a promised bill reduction.

### DX-017 - Rapid storage growth

Projects a per-physical-partition storage trend toward 50 GiB using the observed history.
Use it for capacity and data-model planning, not as proof of an inevitable outage: growth can change
and physical partitions can split. Inspect trend quality and logical-key distribution.

### DX-022 - Per-region autoscale opportunity

Identifies multi-region provisioned accounts without per-region/per-partition autoscale enabled.
Confirm that the relevant throughput is autoscale and that regional/partition demand differs before
acting. This configuration-led recommendation does not measure or guarantee a saving.

### DX-024 - Indexing cost risk

Compares a container's latest index storage with its data storage. Every indexed path adds write RU
to each insert and replace, and the default policy indexes every property. Flags **Low** when the
index exceeds 30% of the data and **Medium** when the index is larger than the data. Runs on every
NoSQL container (dedicated, shared-throughput, and serverless) and is not suppressed when the policy
already excludes paths; the exclusion count is reported as evidence. Containers with indexing mode
`none` are not flagged. A high ratio can be legitimate (e.g. composite, spatial, or vector indexes
your queries need), so confirm which paths are queried before excluding any.

## Acting on findings

CODA never changes resources. Structured reports retain remediation identifiers linking to the
[Cosmos DB Agent Kit](https://github.com/azurecosmosdb/cosmosdb-agent-kit); the browser emphasizes
recommendations rather than those rule links.

Currency estimates require usable cost evidence and are not additive across overlapping findings.
Recommendations and capacity-only findings remain useful without cost access. Review applicability,
incomplete evaluations, evidence, and operational constraints before applying any change.
