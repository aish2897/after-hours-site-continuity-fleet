"""The human approval surface. Deliberately a separate service.

Why separate at all
-------------------

Autonomous identities must not be able to approve autonomous decisions. On a
shared service that is a property of the code; on a separate service it is a
property of Google Cloud IAM, because the fleet's service accounts simply hold
no `run.invoker` on this one. A bug in the orchestrator cannot grant approval
authority it was never given.

So this exposes the two approval operations and nothing else. There is no
incident intake here, no routing, no executor call, no resume — reaching this
service buys a caller the ability to answer one pending question, and only if
Google let them in.

How the human is identified
---------------------------

Identity-Aware Proxy, when the deployment has it. IAP puts a signed JWT in
`X-Goog-IAP-JWT-Assertion`, and this service verifies the signature, the issuer
and the audience before reading the principal from the claims. That is an
assertion the caller cannot author.

The plain `X-Goog-Authenticated-User-Email` header is never trusted on its own:
without IAP in front it is an ordinary request header that anyone may set.

When IAP is not in front, this service does not pretend to know who the human
is. It records the authority that actually applies — Google Cloud IAM on this
service — rather than inventing a name for the audit chain.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from scf.obs import log_event, trace_id_from_header
from scf.state.firestore_repo import ApprovalNotFound

app = FastAPI(title="SCF Human Approval", version="0.1.0")

#: The IAP audience for this service, as
#: `/projects/<number>/global/backendServices/<id>` or the Cloud Run form. An
#: assertion minted for a DIFFERENT application is not an assertion about this
#: one, so the audience is checked rather than assumed.
IAP_AUDIENCE = os.environ.get("SCF_IAP_AUDIENCE", "")

#: role -> principals. Exact match, never a pattern.
def _load_bindings() -> dict[str, frozenset[str]]:
    raw = os.environ.get("SCF_APPROVER_BINDINGS", "")
    bindings: dict[str, frozenset[str]] = {}
    for clause in filter(None, (part.strip() for part in raw.split(";"))):
        role, _, members = clause.partition(":")
        if role and members:
            bindings[role.strip()] = frozenset(
                m.strip().lower() for m in members.split(",") if m.strip()
            )
    return bindings


APPROVER_ROLE_BINDINGS = _load_bindings()
DEFAULT_APPROVAL_ROLE = "incident_commander"

#: What the record says when IAP is not in front. Not a person, not an email —
#: the authority that genuinely applied.
PLATFORM_IAM_AUTHORITY = "PLATFORM_IAM"


class ApprovalDecisionRequest(BaseModel):
    """A note, and nothing else.

    No approver identity, no decision id, no target, no revision. Untrusted
    input does not get to choose what it authorizes or who it claims to be.
    """

    model_config = ConfigDict(extra="forbid")

    note: str | None = Field(default=None, max_length=500)


def verified_iap_principal(assertion: str | None) -> str:
    """The email IAP signed for, or "" when there is no verifiable assertion."""
    if not assertion:
        return ""
    try:
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token as google_id_token

        claims = google_id_token.verify_token(
            assertion,
            google_requests.Request(),
            audience=IAP_AUDIENCE or None,
            certs_url="https://www.gstatic.com/iap/verify/public_key",
            clock_skew_in_seconds=60,
        )
    except Exception as exc:  # noqa: BLE001 - an unverifiable assertion names nobody
        log_event(
            "iap_assertion_unverified",
            severity="WARNING",
            error_type=type(exc).__name__,
            detail=str(exc)[:160],
        )
        return ""
    if claims.get("iss") != "https://cloud.google.com/iap":
        return ""
    return str(claims.get("email") or "").lower()


def authorize(assertion: str | None, required_role: str | None) -> tuple[str, str]:
    """(principal, authority). Raises when the caller may not approve this."""
    role = required_role or DEFAULT_APPROVAL_ROLE
    principal = verified_iap_principal(assertion)
    if principal:
        permitted = APPROVER_ROLE_BINDINGS.get(role, frozenset())
        if principal not in permitted:
            raise HTTPException(status_code=403, detail="approver_not_authorized")
        return principal, "IAP_VERIFIED_IDENTITY"

    # No verifiable assertion. Google Cloud IAM on this service is then the
    # authorization boundary, and it is a real one: no fleet identity holds
    # run.invoker here, so an autonomous agent cannot reach this code at all.
    # The record says that, instead of naming somebody.
    return f"{PLATFORM_IAM_AUTHORITY} (role {role}, service scf-approval)", (
        "PLATFORM_IAM"
    )


async def _decide(
    approval_id: str,
    state: str,
    assertion: str | None,
    trace_header: str | None,
) -> dict[str, Any]:
    from scf.app import main as orchestrator

    trace_id = trace_id_from_header(trace_header)
    repo = orchestrator.repository()
    try:
        approval = await run_in_threadpool(repo.get_approval, approval_id)
    except ApprovalNotFound as missing:
        raise HTTPException(status_code=404, detail="approval_not_found") from missing

    principal, authority = authorize(
        assertion, approval.get("required_approval_role")
    )
    log_event(
        "approval_authorized",
        trace_id=trace_id,
        approval_id=approval_id,
        incident_id=approval.get("incident_id"),
        approval_authority=authority,
        approval_role=approval.get("required_approval_role") or DEFAULT_APPROVAL_ROLE,
        approval_service="scf-approval",
    )
    # The same transaction the orchestrator used. One approval model, one
    # idempotency guarantee, one audit chain.
    return await orchestrator._record_approval_decision(
        approval_id, state=state, trace_id=trace_id, approver=principal
    )


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "scf-approval",
        "role": "human_approval_surface",
        "iap_audience_configured": bool(IAP_AUDIENCE),
        "roles_configured": sorted(APPROVER_ROLE_BINDINGS),
        "revision": os.environ.get("K_REVISION"),
    }


@app.post("/approvals/{approval_id}/approve")
async def approve(
    approval_id: str,
    request: ApprovalDecisionRequest | None = None,
    x_goog_iap_jwt_assertion: str | None = Header(default=None),
    x_cloud_trace_context: str | None = Header(default=None),
) -> dict[str, Any]:
    return await _decide(
        approval_id, "APPROVED", x_goog_iap_jwt_assertion, x_cloud_trace_context
    )


@app.post("/approvals/{approval_id}/reject")
async def reject(
    approval_id: str,
    request: ApprovalDecisionRequest | None = None,
    x_goog_iap_jwt_assertion: str | None = Header(default=None),
    x_cloud_trace_context: str | None = Header(default=None),
) -> dict[str, Any]:
    return await _decide(
        approval_id, "REJECTED", x_goog_iap_jwt_assertion, x_cloud_trace_context
    )
