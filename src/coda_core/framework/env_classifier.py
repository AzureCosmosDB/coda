"""Cosmos DB account environment classifier (prod / non-prod / specific env).

Single source of truth for "is this account production or non-production?" from its Azure resource
tags, subscription name, and account name. Used by environment-dependent detections (e.g. DX-008
multi-region writes), where treating a production account as non-prod — or vice versa — produces a
wrong recommendation.

Why this is not a simple substring check:
* **Asymmetric substring matching is wrong.** Matching non-prod tokens by substring (``"dev" in
  name``) without also recognising ``prod`` mis-classifies names like ``stagecoach-prod`` (contains
  "stage"), ``prod-devbox`` (contains "dev"), and ``qatar-prod`` (contains "qa").
* **Embedded tokens have no separators.** Real account names concatenate env tokens with no
  delimiters (e.g. ``...nonprodjpe01``), so ``nonprod`` must be matched *before* the bare ``prod``
  substring inside it.

Approach:
1. **Tags** (highest priority) — values are normalised through a synonym table to a canonical token;
   values that aren't environments (``premium``, ``ga``) are ignored rather than misread.
2. **Subscription name** — more deliberately curated than the account name; ranks above it.
3. **Account name** — an ordered, boundary-aware regex chain. Non-prod and negation patterns run
   first; ``prod`` runs last so it never wins over an embedded ``nonprod``.

A *specific* account-level non-prod env (e.g. ``uat``) overrides a broad subscription ``prod`` — the
account name carries the more specific signal. An account named ``prod`` inside a non-prod
subscription is treated as non-prod (a naming mistake is more likely than a true exception, and
non-prod is the safer default for these advisory findings). Unknown stays unknown, and callers treat
unknown as production (conservative — never assert a wasteful verdict without a positive signal).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Tag keys consulted, in priority order. Comparison is case-insensitive.
_TAG_KEY_PRIORITY = (
    "environment", "env", "stage", "tier", "deployment", "deploymentenvironment",
    "envname", "environmenttype", "env_type", "app_env", "application_env",
    "applicationenvironment", "workload_environment",
)

# Every recognised tag/name value maps to a canonical environment. Values not in this map are ignored
# (so SKU-class values like "premium" or "ga" never leak through as an environment).
_VALUE_SYNONYMS: dict[str, str] = {
    "prod": "prod", "production": "prod", "prd": "prod", "live": "prod",
    "dev": "dev", "development": "dev", "develop": "dev",
    "nonprod": "dev", "non-prod": "dev", "nprd": "dev", "nonprd": "dev",
    "test": "test", "tst": "test", "qa": "test", "quality": "test",
    "integration": "test", "int": "test", "e2e": "test", "sit": "test", "smoke": "test",
    "canary": "test", "pilot": "test", "ring1": "test", "ring2": "test", "r1": "test", "r2": "test",
    "staging": "staging", "stag": "staging", "stg": "staging",
    "preprod": "preprod", "pre-prod": "preprod", "preprd": "preprod", "pp": "preprod", "ppr": "preprod",
    "uat": "uat", "useracceptance": "uat",
    "perf": "perf", "performance": "perf", "load": "perf", "loadtest": "perf", "stresstest": "perf",
    "sandbox": "sandbox", "sbox": "sandbox", "demo": "sandbox", "poc": "sandbox",
    "trial": "sandbox", "experiment": "sandbox", "lab": "sandbox", "labs": "sandbox",
}

# Ordered name-pattern chain — earlier matches win. Boundary-required patterns precede no-separator
# catch-alls; non-prod/negation precede prod so an embedded "prod" inside "nonprod" never wins.
_NAME_REGEXES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"(?i)(?<![a-z])(non-?prod|nprd|nonprd)(?![a-z])"), "dev", "name contains nonprod/nprd"),
    (re.compile(r"^not-(prod|production|prd)([-_.]|$)", re.IGNORECASE), "dev", "name starts with not-prod"),
    (re.compile(r"(?i)(?<![a-z])(pre-?prod|preprd|ppr)(?![a-z])"), "preprod", "name contains preprod"),
    (re.compile(r"(?i)(^|[-_.])(pp)([-_.0-9]|$)"), "preprod", "name contains pp token"),
    (re.compile(r"(?i)(?<![a-z])(stag(?:ing)?|stg)(?![a-z])"), "staging", "name contains staging/stg"),
    (re.compile(r"(?i)(?<![a-z])uat(?![a-z])"), "uat", "name contains uat token"),
    (re.compile(r"(?i)(?<![a-z])(perf(?:ormance)?|loadtest|stresstest)(?![a-z])"), "perf",
     "name contains perf/loadtest"),
    (re.compile(r"(?i)(?<![a-z])load(?![a-z])"), "perf", "name contains load token"),
    (re.compile(r"(?i)(?<![a-z])(sandbox|sbox|demo|poc|trial|lab)(?![a-z])"), "sandbox",
     "name contains sandbox-class token"),
    (re.compile(r"(?i)(?<![a-z])(test|tst|qa)(?![a-z])"), "test", "name contains test/tst/qa token"),
    (re.compile(r"(?i)(?<![a-z])(e2e|sit|int(?:eg(?:ration)?)?)(?![a-z])"), "test",
     "name contains e2e/sit/int token"),
    (re.compile(r"(?i)(?<![a-z])(canary|pilot)(?![a-z])"), "test", "name contains canary/pilot"),
    (re.compile(r"(?i)(^|[-_.])(ring[0-9]+|r[12])([-_.]|$)"), "test", "name contains ring token"),
    # Prod — after every narrower non-prod pattern above. Separator-bounded first, then prodNN.
    (re.compile(r"(?i)(^|[-_.])(prod(?:uction)?|prd)([-_.]|$)"), "prod",
     "name contains prod token with separators"),
    (re.compile(r"(?i)(?<![a-z])prod[0-9]+"), "prod", "name contains prodNN"),
    (re.compile(r"^prod[a-z]*$", re.IGNORECASE), "prod", "name starts with prod"),
    (re.compile(r"(?i)(^|[-_.])(dev(?:elopment)?)([-_.]|$)"), "dev", "name contains dev token with separators"),
    (re.compile(r"(?i)(?<![a-z])dev[0-9]+"), "dev", "name contains devNN"),
    # No-separator catch-alls (LAST): embedded env tokens in concatenated names. Non-prod precede prod
    # so "nonprodjpe01" classifies as non-prod, not on its embedded "prod".
    (re.compile(r"(?i)nonprod"), "dev", "embedded nonprod"),
    (re.compile(r"(?i)nprd"), "dev", "embedded nprd"),
    (re.compile(r"(?i)preprod(?![a-z])"), "preprod", "embedded preprod"),
    (re.compile(r"(?i)loadtest"), "perf", "embedded loadtest"),
    (re.compile(r"(?i)staging"), "staging", "embedded staging"),
    (re.compile(r"(?i)uat"), "uat", "embedded uat"),
    (re.compile(r"(?i)prod(?![a-z]{4,})"), "prod", "embedded prod token"),
    (re.compile(r"(?i)dev(?![a-z]{4,})"), "dev", "embedded dev token"),
    (re.compile(r"(?i)qa(?![a-z])"), "test", "embedded qa token"),
]

# Account-level envs specific enough to override a broad subscription "prod".
_SPECIFIC_NON_PROD = {"dev", "test", "uat", "staging", "preprod", "perf", "sandbox"}
# Any inferred env outside this set is non-production. "unknown" is treated as production by callers.
_PROD_OR_UNKNOWN = {"prod", "unknown"}


@dataclass(frozen=True)
class EnvClassification:
    inferred_env: str   # prod | dev | test | staging | preprod | uat | perf | sandbox | unknown
    is_non_prod: bool   # inferred_env not in {prod, unknown}
    signal: str         # short prose: which signal fired
    tag_env: str        # env from tags only ("" if none)
    name_env: str       # env from account name only ("unknown" if none)
    sub_env: str        # env from subscription name only ("unknown" if none)


def _normalize_tag_value(value) -> str | None:
    if value is None:
        return None
    s = str(value).strip().lower()
    if not s or s == "null":
        return None
    if s in _VALUE_SYNONYMS:
        return _VALUE_SYNONYMS[s]
    s2 = re.sub(r"[^a-z0-9]", "", s)
    return _VALUE_SYNONYMS.get(s2)


def _classify_from_tags(tags: dict) -> tuple[str | None, str | None]:
    lowered = {str(k).lower(): v for k, v in (tags or {}).items() if v is not None}
    for key in _TAG_KEY_PRIORITY:
        if key in lowered:
            env = _normalize_tag_value(lowered[key])
            if env:
                return env, f"tag {key}={lowered[key]!r}"
    return None, None


def _classify_from_name(name: str) -> tuple[str | None, str | None]:
    if not name:
        return None, None
    for pattern, env, reason in _NAME_REGEXES:
        if pattern.search(name):
            return env, reason
    return None, None


def classify_environment(
    account_name: str, tags: dict | None = None, subscription_name: str | None = None
) -> EnvClassification:
    """Classify an account's environment from tags, subscription name, then account name."""
    tag_env, tag_reason = _classify_from_tags(tags or {})
    name_env, name_reason = _classify_from_name(account_name or "")
    sub_env, sub_reason = _classify_from_name(subscription_name or "")

    if tag_env:
        inferred, signal = tag_env, tag_reason or "tag-based"
    elif name_env in _SPECIFIC_NON_PROD and sub_env == "prod":
        # A specific account-level non-prod env beats a broad subscription "prod".
        inferred = name_env
        signal = f"account name ({name_reason}) overrides subscription ({sub_reason})"
    elif sub_env and sub_env != "unknown":
        inferred, signal = sub_env, f"subscription name: {sub_reason}"
    elif name_env and name_env != "unknown":
        inferred, signal = name_env, name_reason or "name-based"
    else:
        inferred, signal = "unknown", "no recognized tag, subscription, or name signal"

    return EnvClassification(
        inferred_env=inferred, is_non_prod=inferred not in _PROD_OR_UNKNOWN, signal=signal,
        tag_env=tag_env or "", name_env=name_env or "unknown", sub_env=sub_env or "unknown",
    )
