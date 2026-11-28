"""Combine regional skew witnesses without treating a missing partition or region as balanced."""

from __future__ import annotations

from dataclasses import replace
from collections import defaultdict

from coda_core.providers.partition_metrics import coverage_evidence


def regional_verdict(histories, classify_series, *, skew_cause: str, observations):
    """Return the strongest co-observed regional witness, or require full coverage for a negative."""
    evidence = coverage_evidence(histories)
    witnesses = []
    negatives = []
    for history, row in zip(histories, evidence["partition_coverage"]):
        if history.series:
            row.update(observations(classify_series(history.series)))
        buckets = defaultdict(dict)
        for key, series in history.series.items():
            for point in series.points:
                if point.value is not None:
                    buckets[point.timestamp][key] = replace(series, points=(point,))
        for stamp, cohort in buckets.items():
            verdict = classify_series(cohort)
            if verdict.root_cause == skew_cause:
                witnesses.append((verdict, history.region, stamp))
            elif history.complete:
                negatives.append(verdict)
    if witnesses:
        best, region, stamp = max(witnesses, key=lambda w: (w[2], w[0].max_bytes, w[1]))
        evidence.update(witness_region=region, witness_hour=stamp.isoformat(), comparable_buckets=1,
                        witness_regions=sorted({w[1] for w in witnesses}))
        scope = f"Observed in {region} across {best.partition_count} identified partitions"
        if not evidence["coverage_complete"]:
            return replace(best, methodology={**best.methodology, **evidence},
                           recommended_action=f"{scope} at {stamp.isoformat()}. "
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
