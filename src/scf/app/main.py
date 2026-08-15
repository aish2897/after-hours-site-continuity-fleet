from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from scf import config
from scf.domain.enums import IncidentStatus, TrustLevel
from scf.domain.ids import new_incident_id
from scf.domain.models import Evidence, IncidentDoc, IncidentReport
from scf.obs import log_event, trace_id_from_header
from scf.state import IncidentNotFound, IncidentRepository

app = FastAPI(
    title="After-Hours Site Continuity Fleet — Orchestrator",
    version="0.3.0",
)


@lru_cache(maxsize=1)
def repository() -> IncidentRepository:
    return IncidentRepository()


class IncidentIntake(BaseModel):
    """What a non-technical duty manager can actually tell us.

    Deliberately narrow: the caller supplies a site and a description in plain
    words. They cannot name the affected service, a category, a specialist, a
    root cause, or a remediation. The system infers routing itself.
    """

    model_config = ConfigDict(extra="forbid")

    description: str = Field(min_length=10, max_length=4000)
    site_id: str = Field(default="MEL-WAREHOUSE-01", min_length=3, max_length=64)
    reported_by: str = Field(default="duty-manager", max_length=64)


class RouteOut(BaseModel):
    specialist: str
    required: bool
    why: str


class IncidentCreated(BaseModel):
    incident_id: str
    status: str
    summary: str
    required_specialists: list[str]
    routes: list[RouteOut]
    trace_id: str | None = None


# Not /healthz: Google Frontend intercepts that exact path ahead of the
# container and returns its own 404, so the route never reaches FastAPI.
@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "scf-orchestrator",
        "core_region": config.CORE_REGION,
        "model_location": config.MODEL_LOCATION,
        "model": config.VERIFIED_MODEL_ID,
        "revision": os.environ.get("K_REVISION"),
    }


@app.post("/incidents", status_code=201, response_model=IncidentCreated)
async def create_incident(
    intake: IncidentIntake,
    x_cloud_trace_context: str | None = Header(default=None),
) -> IncidentCreated:
    from scf.agents.routing import route_incident

    trace_id = trace_id_from_header(x_cloud_trace_context)
    incident_id = new_incident_id()
    repo = repository()

    log_event(
        "request_received",
        trace_id=trace_id,
        incident_id=incident_id,
        site_id=intake.site_id,
        description_chars=len(intake.description),
    )

    # The report is untrusted input. It is recorded with that provenance and
    # can never satisfy a policy condition later.
    report_evidence = Evidence(
        key="duty_manager_report",
        value=intake.description,
        supports="incident intake",
        source_agent="intake",
        trust_level=TrustLevel.UNTRUSTED_INPUT,
    )

    incident = IncidentDoc(
        incident_id=incident_id,
        report=IncidentReport(
            site_id=intake.site_id,
            description=intake.description,
            reported_by=intake.reported_by,
        ),
        trace_id=trace_id,
        current_step="intake",
        untrusted_content_flags=[report_evidence.trust_level.value],
    )

    await run_in_threadpool(repo.create, incident)
    log_event(
        "incident_persisted",
        trace_id=trace_id,
        incident_id=incident_id,
        status=incident.status.value,
    )

    log_event("adk_invocation_started", trace_id=trace_id, incident_id=incident_id,
              model=config.VERIFIED_MODEL_ID, model_location=config.MODEL_LOCATION)
    try:
        decision = await route_incident(intake.description)
    except Exception as exc:  # noqa: BLE001 - surfaced to caller and logged
        log_event(
            "adk_invocation_failed",
            severity="ERROR",
            trace_id=trace_id,
            incident_id=incident_id,
            error_type=type(exc).__name__,
        )
        raise HTTPException(status_code=502, detail="routing failed") from exc

    required = [s.value for s in decision.required_specialists()]
    log_event(
        "routing_decision",
        trace_id=trace_id,
        incident_id=incident_id,
        required_specialists=required,
        model_id=decision.model_id,
    )

    await run_in_threadpool(repo.save_routing, incident_id, decision, trace_id=trace_id)
    await run_in_threadpool(
        repo.transition, incident_id, IncidentStatus.INVESTIGATING, trace_id=trace_id
    )
    log_event(
        "state_persisted",
        trace_id=trace_id,
        incident_id=incident_id,
        status=IncidentStatus.INVESTIGATING.value,
    )

    return IncidentCreated(
        incident_id=incident_id,
        status=IncidentStatus.INVESTIGATING.value,
        summary=decision.summary,
        required_specialists=required,
        routes=[
            RouteOut(specialist=r.specialist.value, required=r.required, why=r.why)
            for r in decision.routes
        ],
        trace_id=trace_id,
    )


@app.get("/incidents/{incident_id}")
async def get_incident(
    incident_id: str,
    x_cloud_trace_context: str | None = Header(default=None),
) -> dict[str, Any]:
    """Read state back from Firestore, proving it outlives the process."""
    trace_id = trace_id_from_header(x_cloud_trace_context)
    repo = repository()
    try:
        document = await run_in_threadpool(repo.get, incident_id)
    except IncidentNotFound as exc:
        raise HTTPException(status_code=404, detail="incident not found") from exc

    audit = await run_in_threadpool(repo.audit_trail, incident_id)
    log_event(
        "incident_read",
        trace_id=trace_id,
        incident_id=incident_id,
        served_by_revision=os.environ.get("K_REVISION"),
        audit_records=len(audit),
    )
    document["audit_record_count"] = len(audit)
    document["served_by_revision"] = os.environ.get("K_REVISION")
    return document
