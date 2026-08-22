"""Network and Security/Identity Investigator runtimes.

Both are read-only specialists in the same shape as the Systems Investigator:
stateless, no Firestore write, no mutation capability, returning typed evidence
over authenticated HTTP under their own service accounts. The orchestrator
persists on their behalf, which is what makes their lack of write permission a
demonstrable boundary rather than a convention.

Two services rather than one because they are two identities. Sharing a runtime
would mean sharing a service account, and the whole argument of this fleet is
that an agent can only do what its identity permits.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from scf import config, faults
from scf.obs import log_event, trace_id_from_header
from scf.tools import network_evidence, security_evidence

#: Bounded work, same reasoning as the Systems Investigator: these make a small
#: number of real network and API calls, so anything approaching this ceiling is
#: a loop rather than thoroughness.
MAX_TOOL_CALLS = int(os.environ.get("SCF_SPECIALIST_MAX_TOOL_CALLS", "8"))


class EvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=3)
    service: str = config.DISPATCH_WEB_SERVICE
    #: The URL to test. Supplied by the orchestrator from its own configuration,
    #: never by a duty manager — untrusted text does not get to choose what this
    #: agent probes.
    target_url: str = Field(default="", max_length=300)


def _build(role: str, gather) -> FastAPI:
    app = FastAPI(title=f"SCF {role.title()} Investigator", version="0.1.0")

    @app.get("/health")
    def health() -> dict[str, Any]:
        body = {
            "ok": True,
            "service": f"scf-agent-{role}",
            "role": f"{role}_investigator",
            "read_only": True,
            "may_propose_actions": False,
            "revision": os.environ.get("K_REVISION"),
            "max_tool_calls": MAX_TOOL_CALLS,
            "fault_mode": faults.active() or None,
        }
        return faults.banner(body) if faults.enabled() else body

    @app.post("/evidence")
    async def evidence(
        request: EvidenceRequest,
        x_cloud_trace_context: str | None = Header(default=None),
    ) -> dict[str, Any]:
        trace_id = trace_id_from_header(x_cloud_trace_context)

        if faults.is_mode(f"{role}_5xx"):
            log_event("fault_injection", severity="WARNING", trace_id=trace_id,
                      incident_id=request.incident_id, label=faults.LABEL,
                      fault_mode=faults.active())
            raise HTTPException(status_code=503, detail="FAULT INJECTION")

        log_event(
            "specialist_evidence_requested",
            trace_id=trace_id,
            incident_id=request.incident_id,
            specialist=role,
            served_by_revision=os.environ.get("K_REVISION"),
        )
        collected = await run_in_threadpool(gather, request)
        payload = {
            "incident_id": request.incident_id,
            "agent": role,
            "evidence": [item.model_dump(mode="json") for item in collected],
            # These specialists describe; they never propose. The registry
            # records `may_propose_actions: false` for both, and the closed
            # action enum plus the deterministic gate would refuse anything
            # they produced anyway.
            "proposal": None,
            "trace_id": trace_id,
            "served_by_revision": os.environ.get("K_REVISION"),
        }
        log_event(
            "specialist_evidence_collected",
            trace_id=trace_id,
            incident_id=request.incident_id,
            specialist=role,
            evidence_count=len(collected),
        )
        return payload

    return app


def _network(request: EvidenceRequest):
    target = request.target_url or config.dispatch_web_url()
    return network_evidence.gather_evidence(target)


def _security(request: EvidenceRequest):
    return security_evidence.gather_evidence(request.service)


network_app = _build("network", _network)
security_app = _build("security", _security)
