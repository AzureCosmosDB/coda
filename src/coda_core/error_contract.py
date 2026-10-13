"""Stable, adapter-neutral error descriptors for authentication resilience.

The module accepts only bounded local command text or an explicit hosted evidence
record. It deliberately keeps classification separate from HTTP transport and
never carries external error prose into the returned descriptor.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, replace
from types import MappingProxyType
from typing import Literal, Mapping

MAX_LOCAL_CLI_TEXT_LENGTH = 16_384
MAX_RETRY_AFTER_SECONDS = 3_600
MAX_IDENTIFIER_LENGTH = 128
MAX_STRUCTURED_MARKER_LENGTH = 64

AzureFailureStage = Literal[
    "hosted_ingress",
    "hosted_signing_keys",
    "hosted_obo",
    "azure_operation",
    "scope_validation",
]
AzureFailureSignal = Literal[
    "unknown",
    "tenant_mismatch",
    "token_expired",
    "invalid_token",
    "signing_keys_unavailable",
    "token_protection",
    "conditional_access",
    "consent_required",
    "rbac_forbidden",
    "subscription_mismatch",
    "timeout",
    "malformed_response",
]

_HOSTED_STAGES = frozenset({
    "hosted_ingress",
    "hosted_signing_keys",
    "hosted_obo",
    "azure_operation",
    "scope_validation",
})
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_DUPLICATE_CACHE_MARKERS = (
    "multiple accounts found in the cache with the same username",
    "multiple account records found in the cache with the same username",
    "more than one account found in the cache for username",
)
_TOKEN_PROTECTION_MARKER = re.compile(r"(?<![0-9])530084(?![0-9])", re.ASCII)
_TOKEN_PROTECTION_CODES = frozenset({"530084", "aadsts530084"})
_CONDITIONAL_ACCESS_CODES = frozenset({"conditional_access"})
_CONSENT_CODES = frozenset({"consent_required", "aadsts65001"})
_RBAC_CODES = frozenset({"authorizationfailed", "rbac_forbidden"})


@dataclass(frozen=True, slots=True)
class StableError:
    """One immutable safe error suitable for presentation or automation."""

    code: str
    category: str
    retryable: bool
    message: str
    user_action: str
    admin_action: str
    retry_after_seconds: int | None = None
    request_id: str | None = None
    correlation_id: str | None = None

    def as_dict(self) -> dict[str, object]:
        """Serialize only the public allowlist and omit absent optional values."""
        return {
            key: value
            for key, value in asdict(self).items()
            if value is not None
        }


@dataclass(frozen=True, slots=True)
class AzureFailureEvidence:
    """Bounded named evidence supplied by a hosted adapter, never external prose."""

    stage: AzureFailureStage | str
    signal: AzureFailureSignal | str = "unknown"
    http_status: int | None = None
    service_error_code: str | None = None
    suberror: str | None = None
    retry_after_seconds: int | None = None
    request_id: str | None = None
    correlation_id: str | None = None


def _stable(
    code: str,
    category: str,
    retryable: bool,
    message: str,
    user_action: str,
    admin_action: str,
) -> StableError:
    """Build a catalog prototype while keeping catalog declarations compact."""
    return StableError(code, category, retryable, message, user_action, admin_action)


ERROR_CATALOG: Mapping[str, StableError] = MappingProxyType({
    "local.azure_cli.duplicate_account_cache": _stable(
        "local.azure_cli.duplicate_account_cache",
        "local_credential_cache",
        False,
        "Azure CLI authentication has duplicate account records.",
        (
            "Stop repeated attempts. If organization policy permits, an operator may run "
            "`az account clear` and then `az login --tenant <tenant>` outside CODA."
        ),
        "Confirm the approved tenant and sign-in method before the operator changes local CLI state.",
    ),
    "auth.conditional_access.token_protection": _stable(
        "auth.conditional_access.token_protection",
        "authentication_policy",
        False,
        "Access was blocked by an organization authentication policy.",
        "Do not keep retrying. Use the sign-in method approved by your organization.",
        "Review the Entra sign-in event and applicable Conditional Access policy.",
    ),
    "auth.conditional_access": _stable(
        "auth.conditional_access",
        "authentication_policy",
        False,
        "Access was blocked by an organization authentication policy.",
        "Do not keep retrying. Follow your organization's approved sign-in guidance.",
        "Review the Entra sign-in event and applicable Conditional Access policy.",
    ),
    "auth.tenant_mismatch": _stable(
        "auth.tenant_mismatch",
        "authentication_configuration",
        False,
        "The authenticated tenant does not match the configured tenant.",
        "Sign in through the application configured for the required tenant.",
        "Verify the application's pinned tenant configuration and authorized access path.",
    ),
    "auth.token_expired": _stable(
        "auth.token_expired",
        "authentication_session",
        False,
        "The current sign-in session has expired.",
        "Use the application's explicit sign-in action before trying again.",
        "No administrator action is required unless session expiration is unexpected.",
    ),
    "auth.invalid_token": _stable(
        "auth.invalid_token",
        "authentication_session",
        False,
        "The presented access token could not be validated.",
        "Use the application's explicit sign-in action to obtain a new session.",
        "Review token validation configuration if valid users repeatedly receive this error.",
    ),
    "auth.consent_required": _stable(
        "auth.consent_required",
        "authentication_authorization",
        False,
        "The requested delegated permission has not been consented.",
        "Use the organization's approved explicit consent process.",
        "Review the requested delegated permission and grant consent only if policy permits.",
    ),
    "authorization.rbac_forbidden": _stable(
        "authorization.rbac_forbidden",
        "authorization",
        False,
        "Azure denied access to the requested operation.",
        "Do not keep retrying. Ask an administrator to verify access to the requested scope.",
        "Verify the least-privilege role required at the requested scope.",
    ),
    "scope.subscription_mismatch": _stable(
        "scope.subscription_mismatch",
        "request_scope",
        False,
        "The requested subscription does not match the configured scope.",
        "Select the configured subscription before trying again.",
        "Verify the application scope configuration without substituting another subscription.",
    ),
    "service.throttled": _stable(
        "service.throttled",
        "service",
        True,
        "The downstream service temporarily limited the request rate.",
        "Wait for the bounded retry interval before trying again.",
        "Review request rate and retry behavior if throttling persists.",
    ),
    "service.unavailable": _stable(
        "service.unavailable",
        "service",
        True,
        "A required downstream service is temporarily unavailable.",
        "Wait for the bounded retry interval before trying again.",
        "Review service health if the failure persists.",
    ),
    "network.timeout": _stable(
        "network.timeout",
        "network",
        True,
        "A required operation did not complete within its time limit.",
        "Wait for the bounded retry interval before trying again.",
        "Review dependency availability and configured time limits if failures persist.",
    ),
    "azure.malformed_response": _stable(
        "azure.malformed_response",
        "downstream_response",
        False,
        "Azure returned a response that CODA could not safely process.",
        "Stop the current action and wait for a controlled recovery probe.",
        "Review the operation using safe correlation metadata when available.",
    ),
    "auth.signing_keys_unavailable": _stable(
        "auth.signing_keys_unavailable",
        "authentication_dependency",
        True,
        "Token validation is temporarily unavailable.",
        "Wait for the bounded retry interval before trying again.",
        "Review issuer metadata and signing-key service availability.",
    ),
    "unknown": _stable(
        "unknown",
        "unknown",
        False,
        "CODA could not safely classify the failure.",
        "Stop repeated attempts and provide the safe correlation metadata to support.",
        "Review sanitized structured evidence before adding or changing a classification.",
    ),
})


def normalize_retry_after(value: object) -> int | None:
    """Accept only positive built-in integers and cap them to the shared maximum."""
    if type(value) is not int or value <= 0:
        return None
    return min(value, MAX_RETRY_AFTER_SECONDS)


def normalize_identifier(value: object) -> str | None:
    """Accept one bounded ASCII request identifier from an explicitly named field."""
    if not isinstance(value, str) or len(value) > MAX_IDENTIFIER_LENGTH:
        return None
    return value if _IDENTIFIER_PATTERN.fullmatch(value) else None


def error_for(
    code: str,
    *,
    retry_after_seconds: object = None,
    request_id: object = None,
    correlation_id: object = None,
) -> StableError:
    """Return a fresh catalog descriptor with only normalized request metadata."""
    prototype = ERROR_CATALOG.get(code, ERROR_CATALOG["unknown"])
    retry_after = normalize_retry_after(retry_after_seconds) if prototype.retryable else None
    return replace(
        prototype,
        retry_after_seconds=retry_after,
        request_id=normalize_identifier(request_id),
        correlation_id=normalize_identifier(correlation_id),
    )


def classify_local_cli_failure(cli_text: str) -> StableError:
    """Classify exact markers only within the adapter's bounded local text prefix."""
    if not isinstance(cli_text, str):
        return error_for("unknown")
    bounded = cli_text[:MAX_LOCAL_CLI_TEXT_LENGTH].casefold()
    if any(marker in bounded for marker in _DUPLICATE_CACHE_MARKERS):
        return error_for("local.azure_cli.duplicate_account_cache")
    if _TOKEN_PROTECTION_MARKER.search(bounded):
        return error_for("auth.conditional_access.token_protection")
    return error_for("unknown")


def _normalized_marker(value: object) -> str | None:
    """Normalize one short structured code without interpreting free-form content."""
    if not isinstance(value, str) or len(value) > MAX_STRUCTURED_MARKER_LENGTH:
        return None
    marker = value.strip().casefold()
    return marker or None


def _normalized_http_status(value: object) -> int | None:
    """Accept only a valid built-in integer HTTP status supplied by the adapter."""
    if type(value) is not int or not 100 <= value <= 599:
        return None
    return value


def _metadata(evidence: AzureFailureEvidence) -> dict[str, object]:
    """Select only named request metadata fields from hosted evidence."""
    return {
        "retry_after_seconds": evidence.retry_after_seconds,
        "request_id": evidence.request_id,
        "correlation_id": evidence.correlation_id,
    }


def classify_azure_failure(evidence: AzureFailureEvidence) -> StableError:
    """Classify hosted evidence with typed signals before codes and HTTP status.

    Stage-specific typed signals have highest precedence, followed by exact
    structured service markers, then structured 429/5xx status. Bare 401/403
    and evidence from an unknown stage remain unknown.
    """
    if not isinstance(evidence, AzureFailureEvidence):
        raise TypeError("classify_azure_failure requires AzureFailureEvidence")

    stage = evidence.stage if evidence.stage in _HOSTED_STAGES else None
    signal = _normalized_marker(evidence.signal)
    metadata = _metadata(evidence)
    typed_codes = {
        ("hosted_ingress", "tenant_mismatch"): "auth.tenant_mismatch",
        ("hosted_ingress", "token_expired"): "auth.token_expired",
        ("hosted_ingress", "invalid_token"): "auth.invalid_token",
        ("hosted_signing_keys", "signing_keys_unavailable"): "auth.signing_keys_unavailable",
        ("hosted_obo", "token_protection"): "auth.conditional_access.token_protection",
        ("hosted_obo", "conditional_access"): "auth.conditional_access",
        ("hosted_obo", "consent_required"): "auth.consent_required",
        ("azure_operation", "rbac_forbidden"): "authorization.rbac_forbidden",
        ("scope_validation", "subscription_mismatch"): "scope.subscription_mismatch",
        ("hosted_obo", "timeout"): "network.timeout",
        ("azure_operation", "timeout"): "network.timeout",
        ("azure_operation", "malformed_response"): "azure.malformed_response",
    }
    if code := typed_codes.get((stage, signal)):
        return error_for(code, **metadata)

    service_code = _normalized_marker(evidence.service_error_code)
    suberror = _normalized_marker(evidence.suberror)
    markers = frozenset(marker for marker in (service_code, suberror) if marker)
    if stage == "hosted_obo":
        if markers & _TOKEN_PROTECTION_CODES:
            return error_for("auth.conditional_access.token_protection", **metadata)
        if markers & _CONDITIONAL_ACCESS_CODES:
            return error_for("auth.conditional_access", **metadata)
        if markers & _CONSENT_CODES:
            return error_for("auth.consent_required", **metadata)
    if stage == "azure_operation" and markers & _RBAC_CODES:
        return error_for("authorization.rbac_forbidden", **metadata)

    status = _normalized_http_status(evidence.http_status)
    if stage in {"hosted_obo", "azure_operation"}:
        if status == 429:
            return error_for("service.throttled", **metadata)
        if status is not None and 500 <= status <= 599:
            return error_for("service.unavailable", **metadata)
    return error_for(
        "unknown",
        request_id=evidence.request_id,
        correlation_id=evidence.correlation_id,
    )


__all__ = [
    "AzureFailureEvidence",
    "AzureFailureSignal",
    "AzureFailureStage",
    "ERROR_CATALOG",
    "MAX_IDENTIFIER_LENGTH",
    "MAX_LOCAL_CLI_TEXT_LENGTH",
    "MAX_RETRY_AFTER_SECONDS",
    "StableError",
    "classify_azure_failure",
    "classify_local_cli_failure",
    "error_for",
    "normalize_identifier",
    "normalize_retry_after",
]
