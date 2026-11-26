"""Combine regional skew witnesses without treating a missing partition or region as balanced."""

from __future__ import annotations

from dataclasses import replace

from coda_core.providers.partition_metrics import coverage_evidence


def regional_verdict(histories, classify_series, *, skew_cause: str, observations):
    """Return the strongest co-observed regional witness, or require full coverage for a negative."""
    evidence = coverage_evidence(histories)
    witnesses = []
    negatives = []
    for history, row in zip(histories, evidence["partition_coverage"]):
        if history.series:
            row.update(observations(classify_series(history.series)))
        for cohort in history.comparisons():
            verdict = classify_series(cohort)
            if verdict.root_cause == skew_cause:
                witnesses.append((verdict, history.region, len(next(iter(cohort.values())).points)))
            elif history.complete:
                negatives.append(verdict)
    if witnesses:
        rank = {"high": 3, "medium": 2, "low": 1, "none": 0}
        best, region, buckets = max(witnesses, key=lambda w: (rank[w[0].severity], w[2]))
        evidence.update(witness_region=region, comparable_buckets=buckets,
                        witness_regions=sorted({w[1] for w in witnesses}))
        scope = f"Observed in {region} across {best.partition_count} identified partitions"
        if not evidence["coverage_complete"]:
            return replace(best, methodology={**best.methodology, **evidence},
                           recommended_action=f"{scope} over {buckets} comparable buckets. "
                           "Coverage is partial; review this region's observed skew and "
                           "partition-key distribution before changing capacity or keys.")
        return replace(best, methodology={**best.methodology, **evidence},
                       recommended_action=f"{scope}. {best.recommended_action}")
    if evidence["coverage_complete"] and negatives:
        verdict = negatives[0]
        cause = (verdict.root_cause if all(v.root_cause == verdict.root_cause for v in negatives)
                 else "no_regional_skew")
        return replace(verdict, root_cause=cause, methodology={**verdict.methodology, **evidence})
    empty = classify_series({})
    return replace(empty, methodology={**empty.methodology, **evidence,
                                       "abstained": "incomplete_partition_coverage"})
