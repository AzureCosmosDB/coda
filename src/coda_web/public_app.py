"""The single customer-safe FastAPI application factory used by every CODA web launch.

The app exposes local explicit sign-in plus read-only diagnostic routes and serves the frozen
``public_static`` tree. It deliberately has no hosted-auth, load-generation, alternate-assets, or
caller-extension seam. There is no module-level ``app`` object: launchers use
``uvicorn --factory coda_web.public_app:create_public_app``.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any

from azure.mgmt.subscription import SubscriptionClient
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict

from coda_core import mcp_tools
from coda_core.error_contract import StableError, error_for
from coda_core.log_readiness import ReadinessError, check_log_readiness
from coda_core.prechecks import run_prechecks
from coda_core.scan import list_accounts
from coda_core.providers.resource_graph import list_graph_accounts
from coda_web.local_auth import LocalIdentity, is_signed_in, require_local_identity, sign_in

_DEFAULT_STATIC_DIRECTORY = Path(__file__).with_name("public_static")
_RESOURCE_GROUP_RE = re.compile(r"^[\w().-]{1,90}$")
_ACCOUNT_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,42}[a-z0-9])?$")


class _ApiError(Exception):
    """A safe status + catalog descriptor; never carries raw prose back to the client."""

    def __init__(self, status: int, failure: StableError | None = None) -> None:
        failure = failure or error_for("unknown")
        super().__init__(failure.message)
        self.status = status
        self.failure = failure


class DiagnoseRequest(BaseModel):
    """Single-account diagnosis request; the public build never accepts ``resource_mode``."""

    subscription: str
    resource_group: str
    account: str
    mode: str = "production"
    depth: str = "deep"


class ScanRequest(BaseModel):
    """Require one resource group so web scans cannot expand to a whole subscription."""

    subscription: str
    resource_group: str
    mode: str = "production"
    depth: str = "shallow"


class LogReadinessRequest(BaseModel):
    """One explicit account or group; no subscription-wide, mutation or credential inputs."""

    model_config = ConfigDict(extra="forbid")
    subscription: str
    resource_group: str
    account: str | None = None


def _validate_uuid(value: str) -> str:
    """Validate canonical Azure subscription identifiers before they reach an Azure SDK call."""
    try:
        return str(uuid.UUID(value.strip()))
    except (ValueError, AttributeError) as exc:
        raise _ApiError(400) from exc


def _validate_resource_group(value: str) -> str:
    """Validate a resource-group path component before passing it to Azure SDKs."""
    trimmed = value.strip()
    if not _RESOURCE_GROUP_RE.fullmatch(trimmed) or trimmed.endswith("."):
        raise _ApiError(400)
    return trimmed


def _validate_account(value: str) -> str:
    """Validate a Cosmos account path component before passing it to Azure SDKs."""
    trimmed = value.strip()
    if not _ACCOUNT_RE.fullmatch(trimmed):
        raise _ApiError(400)
    return trimmed


def _list_subscriptions(credential: Any, *, include_all: bool) -> list[dict[str, str]]:
    """Return visible Azure subscriptions, defaulting to Cosmos-named ones for a focused list."""
    client = SubscriptionClient(credential)
    subscriptions = [
        {"id": s.subscription_id, "name": s.display_name or "", "state": str(s.state)}
        for s in client.subscriptions.list()
    ]
    if not include_all:
        subscriptions = [s for s in subscriptions if "cosmos" in s["name"].lower()]
    return sorted(subscriptions, key=lambda s: (s["name"].lower(), s["id"]))


def _list_accounts_fast(credential, subscription: str, *, max_accounts: int = 5000) -> list[tuple[str, str]]:
    """Use the same SDK identity for ARG discovery as for diagnosis and permission guidance."""
    return list_graph_accounts(credential, subscription, max_accounts=max_accounts)


def _discover_accounts(credential: Any, subscription: str) -> tuple[list[tuple[str, str]], str]:
    """Prefer the fast Resource Graph path; fall back to ARM enumeration without fixture scoping."""
    try:
        return _list_accounts_fast(credential, subscription), "resource-graph"
    except (OSError, RuntimeError, ValueError):
        return sorted(list_accounts(credential, subscription)), "arm"


def _auth_router() -> APIRouter:
    """Unauthenticated bootstrap routes: check or perform the one explicit local sign-in."""
    router = APIRouter(prefix="/api/auth", tags=["auth"])

    @router.get("/status")
    def auth_status() -> dict[str, bool]:
        """Report sign-in state without ever resolving or requiring a credential."""
        return {"signed_in": is_signed_in()}

    @router.post("/sign-in")
    def auth_sign_in() -> dict[str, bool]:
        """The one explicit, user-initiated action that is allowed to resolve a credential."""
        sign_in()
        return {"signed_in": True}

    return router


def _api_router() -> APIRouter:
    """Built-in customer-safe API routes: subscriptions, accounts, detectors, diagnose, scan."""
    router = APIRouter(prefix="/api", tags=["diagnostics"])

    @router.get("/detectors")
    def detectors(identity: LocalIdentity = Depends(require_local_identity)) -> dict[str, Any]:
        """Return the detector catalog from the shared core engine."""
        return mcp_tools.list_detectors()

    @router.get("/subscriptions")
    def subscriptions(
        all_subscriptions: bool = Query(False, alias="all"),
        identity: LocalIdentity = Depends(require_local_identity),
    ) -> list[dict[str, str]]:
        """Return subscriptions visible through the signed-in local credential."""
        return _list_subscriptions(identity.credential, include_all=all_subscriptions)

    @router.get("/accounts")
    def accounts(
        subscription: str,
        identity: LocalIdentity = Depends(require_local_identity),
    ) -> dict[str, Any]:
        """Return the Cosmos DB account inventory for one subscription."""
        subscription_id = _validate_uuid(subscription)
        pairs, source = _discover_accounts(identity.credential, subscription_id)
        inventory = [{"resource_group": rg, "account": account} for rg, account in pairs]
        return {
            "subscription": subscription_id, "accounts": inventory,
            "source": source, "count": len(inventory),
        }

    @router.post("/diagnose")
    def diagnose(
        body: DiagnoseRequest,
        identity: LocalIdentity = Depends(require_local_identity),
    ) -> Any:
        """Run one shallow or deep diagnosis with the signed-in local credential."""
        subscription_id = _validate_uuid(body.subscription)
        resource_group = _validate_resource_group(body.resource_group)
        account = _validate_account(body.account)
        if body.depth not in {"shallow", "deep"}:
            raise _ApiError(400)
        if body.mode not in {"production", "eval"}:
            raise _ApiError(400)
        if body.depth == "shallow":
            return {
                "depth": "shallow",
                **mcp_tools.diagnose_account_shallow(
                    subscription_id, resource_group, account, credential=identity.credential,
                ),
            }
        return mcp_tools.diagnose_account(
            subscription_id, resource_group, account,
            mode=body.mode, credential=identity.credential,
        )

    @router.post("/scan")
    def scan(
        body: ScanRequest,
        identity: LocalIdentity = Depends(require_local_identity),
    ) -> Any:
        """Scan only the requested resource group with the signed-in local credential."""
        subscription_id = _validate_uuid(body.subscription)
        resource_group = _validate_resource_group(body.resource_group)
        if body.depth not in {"shallow", "deep"}:
            raise _ApiError(400)
        if body.mode not in {"production", "eval"}:
            raise _ApiError(400)
        if body.depth == "deep":
            result = mcp_tools.scan_subscription(
                subscription_id, resource_groups=[resource_group],
                mode=body.mode, concurrency=8, per_account_timeout=120,
                credential=identity.credential,
            )
        else:
            result = mcp_tools.scan_subscription_shallow(
                subscription_id, resource_groups=[resource_group],
                concurrency=24, credential=identity.credential,
            )
        return {**result, "resource_group": resource_group}

    @router.post("/log-readiness")
    def log_readiness(
        body: LogReadinessRequest,
        identity: LocalIdentity = Depends(require_local_identity),
    ) -> dict[str, Any]:
        """Check logging without diagnosing, enabling categories, or expanding the selected scope."""
        subscription = _validate_uuid(body.subscription)
        group = _validate_resource_group(body.resource_group)
        account = _validate_account(body.account) if body.account is not None else None
        try:
            return check_log_readiness(identity.credential, subscription, group, account)
        except ReadinessError as exc:
            status = (
                403 if exc.failure.code == "readiness.access_denied"
                else 400 if exc.failure.code == "readiness.unsupported_api" else 502
            )
            raise _ApiError(status, exc.failure) from exc

    @router.post("/pre-checks")
    def pre_checks(
        body: LogReadinessRequest,
        identity: LocalIdentity = Depends(require_local_identity),
    ) -> dict[str, Any]:
        """Run read-only access probes and return copy-only guidance, never executing scripts."""
        subscription = _validate_uuid(body.subscription)
        group = _validate_resource_group(body.resource_group)
        account = _validate_account(body.account) if body.account is not None else None
        try:
            return run_prechecks(identity.credential, subscription, group, account)
        except ReadinessError as exc:
            raise _ApiError(502, exc.failure) from exc

    return router


def _public_api_routers() -> tuple[APIRouter, ...]:
    """Built-in customer-safe routers, registered first and in this fixed order."""
    return (_auth_router(), _api_router())


def _register_error_handlers(app: FastAPI) -> None:
    """Keep every response on the shared stable-error contract; never leak raw exception text."""

    @app.exception_handler(_ApiError)
    async def _api_error(_request: Request, exc: _ApiError) -> JSONResponse:
        return JSONResponse({"error": exc.failure.as_dict()}, status_code=exc.status)

    @app.exception_handler(HTTPException)
    async def _http_exception(_request: Request, exc: HTTPException) -> JSONResponse:
        # 401 only ever means "sign in first" here; local_auth never raises it for any other
        # reason, so this is the one place that distinguishes it from a generic failure.
        failure = (
            StableError(
                code="auth.local_sign_in_required",
                category="local_identity",
                retryable=False,
                message="Sign in with your local Azure identity to use CODA.",
                user_action="Select Sign in and complete the explicit local credential sign-in.",
                admin_action="No administrative action required; this is a local, per-process sign-in only.",
            )
            if exc.status_code == 401
            else error_for("unknown")
        )
        return JSONResponse({"error": failure.as_dict()}, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def _validation_exception(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        """Avoid reflecting framework/pydantic validation internals to callers."""
        return JSONResponse({"error": error_for("unknown").as_dict()}, status_code=400)

    @app.exception_handler(Exception)
    async def _unhandled_exception(_request: Request, _exc: Exception) -> JSONResponse:
        """Collapse every other failure (Azure SDK, network, programming) into one safe shape."""
        return JSONResponse({"error": error_for("unknown").as_dict()}, status_code=500)


def create_public_app() -> FastAPI:
    """Build CODA's closed local app, registering APIs before the catch-all static mount."""
    app = FastAPI(title="CODA", docs_url=None, redoc_url=None, openapi_url=None)
    _register_error_handlers(app)

    for router in _public_api_routers():
        app.include_router(router)
    app.mount(
        "/",
        StaticFiles(directory=str(_DEFAULT_STATIC_DIRECTORY), html=True),
        name="static",
    )
    return app
