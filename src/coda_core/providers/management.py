"""Bounded read-only ARM requests and permission evidence using the caller's SDK credential."""

from __future__ import annotations

import base64
import fnmatch
import json
import urllib.error
import urllib.parse
import urllib.request
import uuid

from azure.core.credentials import TokenCredential

from coda_core.error_contract import normalize_identifier

MANAGEMENT_URL = "https://management.azure.com"
MANAGEMENT_SCOPE = MANAGEMENT_URL + "/.default"


class ManagementReadError(RuntimeError):
    """Retain safe structured failure metadata without exposing response bodies or tokens."""

    def __init__(self, status_code=None, code=None):
        super().__init__("Azure management read could not be completed.")
        self.status_code = status_code
        self.code = normalize_identifier(code)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward an ARM bearer token to a redirect destination."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def token_subject(token: str) -> dict[str, str] | None:
    """Read identity hints only from a token acquired by our credential, never for authorization."""
    try:
        if len(token) > 65536:
            return None
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return {"object_id": str(uuid.UUID(claims["oid"])), "tenant_id": str(uuid.UUID(claims["tid"]))}
    except (IndexError, KeyError, ValueError, TypeError):
        return None


class BoundCredential:
    """Detect a changed token subject while one pre-check is building requester-specific guidance."""

    def __init__(self, credential: TokenCredential):
        self.inner = credential
        self.identity = token_subject(credential.get_token(MANAGEMENT_SCOPE).token)
        self.changed = False
        self.unverifiable = False

    def get_token(self, *scopes, **kwargs):
        token = self.inner.get_token(*scopes, **kwargs)
        subject = token_subject(token.token)
        if self.identity is not None and subject is None:
            self.unverifiable = True
        if self.identity is not None and subject is not None and subject != self.identity:
            self.changed = True
            raise ManagementReadError(code="CredentialIdentityChanged")
        return token


class ManagementReader:
    """Read ARM metadata or query ARG; no write method is exposed."""

    def __init__(self, credential: TokenCredential):
        self.credential = credential
        self._permissions: dict[str, dict] = {}

    @staticmethod
    def _url(path: str) -> str:
        url = path if path.startswith("https://") else MANAGEMENT_URL + path
        parsed = urllib.parse.urlsplit(url)
        if (
            parsed.scheme != "https" or parsed.netloc.casefold() != "management.azure.com"
            or parsed.fragment or not parsed.path.startswith("/")
            or ".." in parsed.path.split("/")
        ):
            raise ValueError("Only the fixed Azure management endpoint is allowed.")
        return url

    def request(self, path: str, body: dict | None = None) -> dict:
        """Issue a bounded metadata GET or the one allowlisted read-only ARG POST."""
        url = self._url(path)
        if body is not None and urllib.parse.urlsplit(url).path.casefold() != "/providers/microsoft.resourcegraph/resources":
            raise ValueError("This client permits only read-only Resource Graph queries.")
        token = self.credential.get_token(MANAGEMENT_SCOPE).token
        request = urllib.request.Request(
            url, data=json.dumps(body).encode() if body is not None else None,
            method="POST" if body is not None else "GET",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.build_opener(_NoRedirect()).open(request, timeout=20) as response:
                content = response.read(8 * 1024 * 1024 + 1)
                if len(content) > 8 * 1024 * 1024:
                    raise ManagementReadError(code="ResponseTooLarge")
                result = json.loads(content)
                if not isinstance(result, dict):
                    raise ManagementReadError(code="InvalidResponse")
                return result
        except urllib.error.HTTPError as exc:
            try:
                code = json.loads(exc.read(65536)).get("error", {}).get("code")
            except (ValueError, AttributeError):
                code = None
            raise ManagementReadError(exc.code, code) from exc

    def permissions(self, scope: str) -> dict:
        """Collect reported management permissions; conditions/incomplete reads stay uncertain."""
        if scope in self._permissions:
            return self._permissions[scope]
        entries = []
        path = scope + "/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
        seen = set()
        try:
            for _ in range(20):
                if path in seen:
                    raise ManagementReadError(code="RepeatedPage")
                seen.add(path)
                result = self.request(path)
                if not isinstance(result.get("value"), list):
                    raise ManagementReadError(code="InvalidPermissions")
                entries.extend(result["value"])
                path = result.get("nextLink")
                if not path:
                    value = {"status": "observed", "entries": entries}
                    self._permissions[scope] = value
                    return value
            raise ManagementReadError(code="PermissionPageLimit")
        except Exception:  # noqa: BLE001 - uncertainty is explicit and never authorizes a script
            value = {"status": "unknown", "entries": []}
            self._permissions[scope] = value
            return value

    def action(self, scope: str, action: str, *, data: bool = False) -> str:
        """Return reported allowed/absent/unknown; Azure Policy, PIM and denies still apply."""
        result = self.permissions(scope)
        if result["status"] != "observed":
            return "unknown"
        uncertain = False
        for entry in result["entries"]:
            if not isinstance(entry, dict):
                uncertain = True
                continue
            allows = entry.get("dataActions" if data else "actions")
            excludes = entry.get("notDataActions" if data else "notActions", [])
            if not isinstance(allows, list) or not isinstance(excludes, list):
                uncertain = True
                continue
            if not all(isinstance(value, str) for value in [*allows, *excludes]):
                uncertain = True
                continue
            match = any(fnmatch.fnmatchcase(action.casefold(), value.casefold()) for value in allows)
            excluded = any(fnmatch.fnmatchcase(action.casefold(), value.casefold()) for value in excludes)
            if match and not excluded:
                if entry.get("condition"):
                    uncertain = True
                else:
                    return "allowed"
        return "unknown" if uncertain else "absent"
