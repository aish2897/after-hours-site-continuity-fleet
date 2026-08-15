"""Systems Investigator runtime. Read-only.

Runs as sa-agent-systems, which holds run.viewer on dispatch-web and nothing
else. It cannot write Firestore, cannot authorize, and cannot execute. It
gathers evidence and may propose from the closed enum; the proposal is inert
until the deterministic policy gate authorizes it.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, Header
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from scf import config
from scf.obs import log_event, trace_id_from_header
from scf.tools.cloud_run_evidence import gather_evidence, propose_remediation

app = FastAPI(title="SCF Systems Investigator", version="0.4.0")


class EvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=3)
    service: str = config.DISPATCH_WEB_SERVICE


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "scf-agent-systems",
        "role": "investigator",
        "read_only": True,
        "revision": os.environ.get("K_REVISION"),
    }


@app.post("/evidence")
async def collect_evidence(
    request: EvidenceRequest,
    x_cloud_trace_context: str | None = Header(default=None),
) -> dict[str, Any]:
    trace_id = trace_id_from_header(x_cloud_trace_context)
    log_event(
        "investigator_invoked",
        trace_id=trace_id,
        incident_id=request.incident_id,
        service=request.service,
        agent="systems",
    )

    evidence = await run_in_threadpool(gather_evidence, request.service)
    proposal = propose_remediation(evidence, request.service)

    log_event(
        "investigator_evidence_collected",
        trace_id=trace_id,
        incident_id=request.incident_id,
        evidence_count=len(evidence),
        proposed=proposal.action_type.value if proposal else None,
    )

    return {
        "incident_id": request.incident_id,
        "agent": "systems",
        "evidence": [item.model_dump(mode="json") for item in evidence],
        "proposal": proposal.model_dump(mode="json") if proposal else None,
        "trace_id": trace_id,
        "served_by_revision": os.environ.get("K_REVISION"),
    }
