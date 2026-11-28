# What CODA detects

[Getting started](../README.md) | [Permissions](permissions.md) | [Log Analytics setup](detections/log-analytics-readiness.md)

CODA contains **24 read-only detectors** for Azure Cosmos DB. The local web experience discovers
NoSQL accounts. Checks run only where their resource type, throughput mode, configuration, and
available data make them applicable; 24 registered detectors does not mean 24 checks on every container.

Select a detector name in the catalog table below to open its detailed customer methodology.
Each methodology page links back to this catalog. The same pages are included in the installed
package and returned offline by the MCP `explain_finding` tool. See
[agent integration](agent-integration.md) for client setup and on-demand Agent Kit guidance.

## Data and interpretation

**Configuration** comes from ARM; **metrics** come from Azure Monitor without diagnostic settings.
**Logs** require resource-specific `CDB*` tables. Twenty checks do not require Log Analytics, but
that does **not** mean they all work immediately: metrics history, sample counts, and resource age
can still be prerequisites.

The table gives each detector's normal **production** window. Configuration-led checks use current
settings, with optional enrichment where noted. Evaluation mode available through programmatic
interfaces uses a shorter shared window and disables resource-age guards; it is not equivalent to
production coverage. The browser uses production mode.

| ID | Detector and detailed methodology | Main evidence | Production window |
|---|---|---|---|
| DX-001 | [Manual over-provisioning](detector-methodology/dx-001.md) | Metrics + throughput configuration | 30 days |
| DX-002 | [Cross-partition query fan-out](detector-methodology/dx-002.md) | Query statistics + request logs | 1 day |
| DX-003 | [Shared-throughput starvation](detector-methodology/dx-003.md) | Request logs + shared-pool configuration | 1 day |
| DX-004 | [Idle throughput](detector-methodology/dx-004.md) | Metrics + throughput configuration | 30 days |
| DX-005 | [Global under-provisioning](detector-methodology/dx-005.md) | Request/partition utilization metrics | 7 days |
| DX-006 | [Hot partition](detector-methodology/dx-006.md) | Per-partition utilization metrics | 7 days |
| DX-007 | [Shard-key misalignment](detector-methodology/dx-007.md) | Query statistics + request logs | 1 day |
| DX-008 | [Multi-region writes antipattern](detector-methodology/dx-008.md) | Account configuration + throughput offers | Current configuration |
| DX-009 | [Partition merge candidate](detector-methodology/dx-009.md) | Partition count/storage metrics + ARM throughput/backup policy | 6 hours |
| DX-010 | [Uncontrolled ingestion](detector-methodology/dx-010.md) | Request logs | 1 day |
| DX-011 | [Autoscale maximum too high](detector-methodology/dx-011.md) | Metrics + autoscale configuration | 30 days |
| DX-012 | [Manual-to-autoscale candidate](detector-methodology/dx-012.md) | Utilization metrics + manual throughput | 30 days |
| DX-013 | [Autoscale-to-manual candidate](detector-methodology/dx-013.md) | Utilization metrics + autoscale throughput | 30 days |
| DX-014 | [Serverless candidate](detector-methodology/dx-014.md) | Account compatibility, consumed RU and comparable billing | 30 days |
| DX-015 | [Partition storage skew](detector-methodology/dx-015.md) | Physical storage metrics; optional logical-key logs | 7 days |
| DX-016 | [Expensive consistency](detector-methodology/dx-016.md) | Account configuration; optional request logs | Current configuration; 1 day enrichment |
| DX-017 | [Container storage growth](detector-methodology/dx-017.md) | Measured container data size | 30 days |
| DX-018 | [Serverless throttling](detector-methodology/dx-018.md) | Serverless requests by status | 7 days |
| DX-019 | [Paid continuous backup on non-production](detector-methodology/dx-019.md) | Backup/environment configuration; optional storage/prices | Current configuration |
| DX-020 | [Non-throttling errors](detector-methodology/dx-020.md) | Account requests by status | 7 days |
| DX-021 | [Throttling by operation](detector-methodology/dx-021.md) | Account requests by operation/status | 7 days |
| DX-022 | [Per-region autoscale opportunity](detector-methodology/dx-022.md) | Region/autoscale configuration | Current configuration |
| DX-023 | [Reservation coverage review](detector-methodology/dx-023.md) | Verified provisioned capacity mode | Current configuration |
| DX-024 | [Indexing cost risk](detector-methodology/dx-024.md) | Index/data storage metrics + indexing policy | 6 hours (latest value) |

Windows describe what is requested, not a guarantee of complete collected history. For example,
DX-004 evaluates young offers, but retirement requires 30 consecutive days of measured zero RU
on the same resource (8,640 five-minute buckets). Data sufficiency checks vary by detector.
In production, the database or container being measured must meet its own age floor; an unknown
minimum age abstains only age-gated checks. A database and its shared members form one allocation;
dedicated siblings are evaluated separately. Partial member data cannot establish a pool-wide total.
DX-020 requires 1,000 requests in a completed hour before grading 5xx; DX-021 reports verified
429 observations without a minimum volume. Missing/quiet data can produce
an abstention; access or query failures can produce errors. Neither is a clean health result.

**Example: which requests used the shared throughput?** Suppose containers A and B share the
database's provisioned capacity (RU/s), while C has its own. Azure Monitor lets CODA ask how busy
the shared pool was (percent utilization) by selecting the pool itself. For **RU consumed** and
**request counts**, those metrics have no pool selector. CODA uses ARM to identify A and B,
then reads their Azure Monitor metrics, not their documents. If A consumed 100 RU, B consumed
200 RU and C consumed 900 RU in the same five minutes, the shared pool consumed **300 RU**, not
the database-wide 1,200 RU. If B reports zero, the pool consumed 100 RU. If B's reading is
missing, the pool total is unknown; that does not invalidate C's readings or the pool's
independently measured utilization.

The registry distinguishes **proposal** from **validated**. Threshold labels
describe policy grounding, not fresh validation of your account or proof
that every supported workload has been tested. Inspect report evidence before acting.

## Cost and capacity

Recoverable RU/s describes the **offer**, not the number of units on the bill. For example,
reducing manual throughput by 1,000 RU/s in two ordinary regions still recovers **1,000 RU/s**
on the offer, but removes **20 units of 100 RU/s per hour** across those regions. CODA prices
those units using the customer's matching amortized throughput meter and a 730-hour month.
A zone premium applies only in confirmed zone-redundant regions for single-write manual
offers. Single-write autoscale has a quantity premium instead. If the billed quantity or
matching unit price is unknown, the capacity finding remains without a currency estimate.

### DX-001 - Manual over-provisioning

[Detailed methodology](detector-methodology/dx-001.md)

Show measured utilization immediately; seven fully measured days can prompt review and 30 are
required before specifying a lower setting. An observed saturation peak vetoes a downsize. Review the suggested
capacity against workload peaks, growth, and minimum throughput limits before reducing it.
Reports recoverable RU/s and, when an applicable amortized rate is available, estimated monthly savings.

### DX-004 - Idle throughput

[Detailed methodology](detector-methodology/dx-004.md)

Looks for provisioned units with sustained near-zero activity. Unlike right-sizing, it can identify
capacity recoverable by retiring an unused resource even when throughput is already at its minimum.
Age and data guards reduce false positives, but you must check seasonal/batch workloads and retention
obligations before decommissioning, archiving, or changing TTL.

### DX-011 - Autoscale maximum too high

[Detailed methodology](detector-methodology/dx-011.md)

Compares actual scaled demand with the configured maximum. Seven complete days can prompt review;
only the latest 720 fully measured completed hours, including all partition contributions, permit
a lower maximum where warranted, subject to service floors and headroom. Recoverable capacity and
eligible cost estimates respect autoscale billing; an idle resource may be better addressed by DX-004.

### DX-012 - Manual-to-autoscale candidate

[Detailed methodology](detector-methodology/dx-012.md)

Compares manual throughput with an equal autoscale maximum at the applicable rates. A favorable
measured week warrants review; a favorable complete 30 days warrants a switch recommendation.
Spikes are not required. This **proposal-threshold** review is not a forecast of savings.

### DX-013 - Autoscale-to-manual candidate

[Detailed methodology](detector-methodology/dx-013.md)

Compares actual hourly scaled throughput with fixed manual throughput at the same maximum.
A favorable measured week warrants review; a favorable complete month warrants evaluating a
switch. Do not mix a downsize into this **proposal-threshold** comparison or assume a multi-write rate advantage.

### DX-014 - Serverless candidate

[Detailed methodology](detector-methodology/dx-014.md)

Checks eligibility before reading usage or pricing. Multiple regions or known incompatible features
are not applicable; unknown eligibility abstains. For compatible accounts compare the cost of consumed
RU at a matching serverless rate with provisioned throughput for the same 30 fully measured days.
A favorable estimate is a reason to evaluate, not a migration directive.

### DX-019 - Paid continuous backup on non-production

[Detailed methodology](detector-methodology/dx-019.md)

Flags paid `Continuous30Days` or `Continuous35Days` backup on an account inferred to be non-production
from tags, subscription, or name. Production and `Continuous7Days` accounts are not flagged; unknown
tiers abstain. Confirm that the environment inference and shorter retention meet your recovery policy.
The review is ungraded. An optional retail estimate is the cost of backup storage, not savings.
Restore charges are separate.

### DX-023 - Reserved-capacity candidate

[Detailed methodology](detector-methodology/dx-023.md)

An ungraded prompt to review reservations in Cost Management on provisioned accounts of any
size. The **proposal-threshold** label is a review policy, not a purchase threshold. A configuration snapshot
does not prove billable usage, future demand or existing reservation coverage.

## Throughput and access patterns

### DX-002 - Cross-partition query fan-out

[Detailed methodology](detector-methodology/dx-002.md)

Finds containers where a material share of queries (at least 10%) fan out across partitions (average
fan-out of at least 1.5 partitions per query). Requires **both `CDBQueryRuntimeStatistics` and
`CDBDataPlaneRequests`**, and at least 50 queries in the window. Fan-out is flagged structurally:
latency grows with every partition checked even when the RU charge is low, so request charge is
reported as evidence rather than used as a gate. Severity scales with physical partition count and
fan-out query rate; below 0.1 fan-out queries per second the result is reported as occasional, not a
finding. The report shows observed fan-out immediately but requires 24 hours of verified
container and logging history before assigning severity. Quiet hours count; missing history
is not a clean result. Review partition-key filters, indexes, and access patterns.

### DX-003 - Shared-throughput starvation

[Detailed methodology](detector-methodology/dx-003.md)

Runs at shared-database scope. Looks for a throttling pool where one active container dominates RU
consumption while a low-consumption sibling also throttles. Prefers **`CDBDataPlaneRequests5M`**,
with **`CDBDataPlaneRequests`** compatibility when five-minute logs are unavailable.
One completed five-minute interval is an observation. High requires the same pair to qualify in
two consecutive completed intervals; daily totals alone never establish contention.
Investigate pacing or scheduling first. Only evaluate dedicated throughput if the workloads
must coexist and need isolation.

### DX-005 - Global under-provisioning

[Detailed methodology](detector-methodology/dx-005.md)

Correlates throttling with broad partition saturation to distinguish insufficient overall throughput
from a localized hot spot. Global capacity advice requires two consecutive completed hours, each
with material throttling, sufficient request volume and verified broad saturation in every
configured region; partial observations can still establish regional skew. Raising throughput may be
appropriate for global pressure but is not automatically the right response to every 429.
The report shows measured throttling even below the alert threshold or when complete partition
measurements do not explain the 429s.

### DX-006 - Hot partition

[Detailed methodology](detector-methodology/dx-006.md)

Finds utilization concentrated on a physical partition while another in the same region has headroom.
Incomplete coverage is not proof of balance or a single partition. Review partition-key
distribution, high-volume keys, and workload patterns. More total throughput may temporarily help but
does not remove uneven demand. Physical-partition metrics alone do not identify the exact logical key.
A single hourly contrast is an observation regardless of age. Medium needs the same hot partition
in two consecutive completed hours; High additionally requires at least 1,000 requests and 1%
offer-level throttling in each of those same hours.

### DX-007 - Shard-key misalignment

[Detailed methodology](detector-methodology/dx-007.md)

Requires **both `CDBQueryRuntimeStatistics` and `CDBDataPlaneRequests`**. Mixed workloads get
an ungraded design review if the same pattern fans out at least an hour apart. High recommends
re-keying only if every observed query fans out over a verified day and query starts occupy
three or more distinct UTC hours spanning at least four actual hours. DX-002 remains visible.
This is a **proposal-threshold** policy: recurrence is measured, not proof of migration benefit.

### DX-009 - Partition merge candidate

[Detailed methodology](detector-methodology/dx-009.md)

Compares actual physical partitions with the estimated need from throughput and storage, using
10,000 RU/s and 50 GiB per physical partition and a minimum of one partition. Excess partitions can
leave each with a small share of capacity. Missing storage is not zero; CODA shows the observed
partition count without estimating the need. Continuous backup (PITR) currently blocks merge, and cannot be
reverted to periodic backup on that account. CODA retains the structural finding but removes the
merge instruction. Unknown/migrating backup state also withholds merge instructions; periodic backup
still requires the Portal eligibility checker and all platform/SDK/connector checks. Optional
full-fidelity enablement is dependency context, not proof of active consumption. Mirroring is not
assessed. CODA does not merge partitions or recommend disabling protection/dependent features.

### DX-010 - Uncontrolled ingestion

[Detailed methodology](detector-methodology/dx-010.md)

Prefers **`CDBDataPlaneRequests5M`**, with raw **`CDBDataPlaneRequests`** compatibility, to identify
write-dominant throttling in the same completed five-minute interval. The **proposal-threshold**
proxy requires at least 80% of measured RU on writes. At least 10 server-side 429s and 10% of the
affected group's attempts qualify: Medium for write-only impact, High for material impact on
other operations. Counts use represented requests, not aggregate rows. Overlap is not causation.

### DX-018 - Serverless throttling

[Detailed methodology](detector-methodology/dx-018.md)

Evaluates throttling on serverless resources, where there is no provisioned RU/s setting to raise.
Investigate individual affected hours; the **proposal-threshold** is two consecutive material hours or material hours on three
distinct UTC days for an account-level capacity review if traffic was representative.
A 429 does not by itself identify the exact offending logical key.

### DX-020 - Non-throttling errors

[Detailed methodology](detector-methodology/dx-020.md)

Show counts and rates for the affected hour. The **proposal-threshold** severity bands apply to
5xx alone; 4xx responses such as 404, 409 and 412 are ungraded without independent corroboration.
Do not infer client failures or a remediation from status counts alone. Excludes 429s.

### DX-021 - Throttling by operation

[Detailed methodology](detector-methodology/dx-021.md)

Show an ungraded breakdown for each affected hour, even without another finding. The
**proposal-threshold** label does not imply a minimum request volume. Only show operation counts
and shares when they reconcile with measured 429s for the same interval. A share of 429s is not
that operation's throttle rate. Missing attribution does not erase the status total.

## Configuration and storage risks

### DX-008 - Multi-region writes antipattern

[Detailed methodology](detector-methodology/dx-008.md)

For MongoDB, Cassandra, Gremlin and Table, a **Low** advisory asks the application owner to verify
client write failover. API family alone does not justify disabling multi-write. Separate checks
cover single write regions and non-production NoSQL accounts.
The public web discovery path targets NoSQL; production NoSQL multi-write can be legitimate and is
not flagged solely for having multiple write regions. Confirm availability/conflict requirements.
Non-production NoSQL with multiple writable regions gets an ungraded configuration review.
**Retaining regions**, not the multi-write toggle alone, repeats regional capacity. A verified
all-manual footprint is not removable capacity or estimated savings.

### DX-015 - Partition storage skew

[Detailed methodology](detector-methodology/dx-015.md)

Physical imbalance is ungraded and visible without an age gate. If enabled, optional logical-key
statistics are read even when the physical sizes are balanced. A recent sampled key above 14 GiB
warrants an early warning; at 18 GiB or more the finding is High relative to the default 20 GiB
limit. This is a **proposal-threshold** policy, not a prediction of failed writes.

### DX-016 - Expensive consistency

[Detailed methodology](detector-methodology/dx-016.md)

Single-region Strong or Bounded Staleness warrants High-priority review when Session's
read-your-writes is sufficient. Distinguish single- and multi-write topologies when reviewing
multi-region Bounded Staleness. Cross-region write latency is a
separate trade-off. Review application guarantees and Session token continuity before relaxing
consistency; Session read-your-writes is not global Strong consistency. "Premium" is not a pricing
SKU. Optional enrichment prefers `CDBDataPlaneRequests5M`, with raw
`CDBDataPlaneRequests` compatibility, to summarize read/query charges
and a labelled half-charge upper bound, not a promised bill reduction.

### DX-017 - Rapid storage growth

[Detailed methodology](detector-methodology/dx-017.md)

Show measured container-total storage change and elapsed time. Three consecutive fully measured
UTC days that each end higher than they begin can prompt ungraded retention review. A one-time
import is not a forecast; the three-day **proposal-threshold** is not a write-failure deadline.

### DX-022 - Per-region autoscale opportunity

[Detailed methodology](detector-methodology/dx-022.md)

High-priority cost recommendation when dynamic autoscale is explicitly disabled and at least one
autoscale offer is confirmed. Applies in one or more regions. No savings amount is inferred.

### DX-024 - Indexing cost risk

[Detailed methodology](detector-methodology/dx-024.md)

Compares a container's index storage with its data storage in the same interval. Prompts an
**ungraded review** when the index exceeds 30% of the data, even above 100%. Runs on every
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
