from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from scf import config
from scf.app.invoke import call_service
from scf.domain.enums import Decision, IncidentStatus, SpecialistName, TrustLevel
from scf.domain.ids import new_incident_id
from scf.domain.models import (
    ActionRecord,
    Evidence,
    IncidentDoc,
    IncidentReport,
    Proposal,
)
from scf.obs import log_event, trace_id_from_header
from scf.policy import evaluate, trusted_evidence_map
from scf.state import IncidentNotFound, IncidentRepository

INVESTIGATOR_URL = os.environ.get("SCF_INVESTIGATOR_URL", "")
EXECUTOR_URL = os.environ.get("SCF_EXECUTOR_URL", "")
VERIFIER_URL = os.environ.get("SCF_VERIFIER_URL", "")

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
    remediation: dict[str, Any] = {}
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

    remediation: dict[str, Any] = {"attempted": False, "reason": "systems_not_routed"}
    if SpecialistName.SYSTEMS in decision.required_specialists():
        remediation = await _autonomous_remediation(
            repo, incident_id, trace_id, x_cloud_trace_context
        )
    else:
        await run_in_threadpool(
            repo.transition, incident_id, IncidentStatus.ESCALATED, trace_id=trace_id
        )

    final = await run_in_threadpool(repo.get, incident_id)

    return IncidentCreated(
        incident_id=incident_id,
        status=final["status"],
        summary=decision.summary,
        required_specialists=required,
        routes=[
            RouteOut(specialist=r.specialist.value, required=r.required, why=r.why)
            for r in decision.routes
        ],
        remediation=remediation,
        trace_id=trace_id,
    )


async def _autonomous_remediation(
    repo: IncidentRepository,
    incident_id: str,
    trace_id: str | None,
    trace_header: str | None,
) -> dict[str, Any]:
    """Investigate, authorize, execute, verify. No operator step anywhere."""
    outcome: dict[str, Any] = {"attempted": True}

    # 1. Systems Investigator, its own service under its own identity.
    response = await run_in_threadpool(
        call_service,
        INVESTIGATOR_URL,
        "/evidence",
        {"incident_id": incident_id, "service": config.DISPATCH_WEB_SERVICE},
        trace_header=trace_header,
    )
    response.raise_for_status()
    body = response.json()

    evidence = [Evidence.model_validate(item) for item in body["evidence"]]
    await run_in_threadpool(repo.save_evidence, incident_id, evidence, trace_id=trace_id)
    outcome["evidence_count"] = len(evidence)

    if not body.get("proposal"):
        outcome["reason"] = "no_proposal"
        await run_in_threadpool(
            repo.transition, incident_id, IncidentStatus.ESCALATED, trace_id=trace_id
        )
        return outcome

    proposal = Proposal.model_validate(body["proposal"])
    outcome["proposal"] = proposal.action_type.value
    await run_in_threadpool(
        repo.transition, incident_id, IncidentStatus.PROPOSED, trace_id=trace_id
    )

    # 2. Deterministic authorization over TRUSTED_TOOL evidence only.
    policy_decision = evaluate(proposal, evidence)
    facts = trusted_evidence_map(evidence)
    await run_in_threadpool(
        repo.transition, incident_id, IncidentStatus.POLICY_EVALUATED, trace_id=trace_id
    )
    await run_in_threadpool(
        repo.save_decision,
        incident_id,
        proposal,
        policy_decision,
        parameters={"target_revision": facts.get("last_good_revision")},
        trace_id=trace_id,
    )
    outcome["decision"] = policy_decision.decision.value
    outcome["reason_code"] = policy_decision.reason_code
    outcome["decision_id"] = policy_decision.decision_id

    if policy_decision.decision is not Decision.AUTO_ALLOWED:
        target = (
            IncidentStatus.WAITING_FOR_APPROVAL
            if policy_decision.decision is Decision.APPROVAL_REQUIRED
            else IncidentStatus.DENIED
        )
        await run_in_threadpool(repo.transition, incident_id, target, trace_id=trace_id)
        return outcome

    await run_in_threadpool(
        repo.transition, incident_id, IncidentStatus.AUTO_ALLOWED, trace_id=trace_id
    )

    # 3. Scoped executor. The orchestrator may call it but holds none of its
    #    infrastructure rights, and passes identifiers only.
    await run_in_threadpool(
        repo.transition, incident_id, IncidentStatus.EXECUTING, trace_id=trace_id
    )
    execution = await run_in_threadpool(
        call_service,
        EXECUTOR_URL,
        "/execute",
        {
            "incident_id": incident_id,
            "decision_id": policy_decision.decision_id,
            "attempt_intent": 1,
        },
        trace_header=trace_header,
    )
    execution.raise_for_status()
    receipt = execution.json()
    outcome["execution"] = receipt

    # The executor cannot write the control plane. The orchestrator, which is
    # an authoritative writer, records what the executor reported.
    if receipt.get("duplicate"):
        await run_in_threadpool(
            repo.append_audit,
            incident_id,
            actor="executor",
            event="duplicate_suppressed",
            payload={
                "decision_id": policy_decision.decision_id,
                "idempotency_key": receipt.get("idempotency_key"),
                "execution_database": receipt.get("execution_database"),
            },
            actor_identity="sa-executor",
            trace_id=trace_id,
        )
    elif receipt.get("action"):
        await run_in_threadpool(
            repo.record_action,
            incident_id,
            ActionRecord.model_validate(receipt["action"]),
        )
        await run_in_threadpool(
            repo.append_audit,
            incident_id,
            actor="executor",
            event="action_executed",
            payload={
                "action_id": receipt["action"].get("action_id"),
                "decision_id": policy_decision.decision_id,
                "target_ref": receipt["action"].get("target_ref"),
                "target_revision": receipt.get("target_revision"),
                "accepted": bool(receipt.get("mutated")),
                "idempotency_key": receipt.get("idempotency_key"),
                "execution_database": receipt.get("execution_database"),
            },
            actor_identity="sa-executor",
            trace_id=trace_id,
        )

    if not receipt.get("mutated"):
        await run_in_threadpool(
            repo.transition, incident_id, IncidentStatus.EXECUTION_FAILED, trace_id=trace_id
        )
        await run_in_threadpool(
            repo.transition, incident_id, IncidentStatus.ESCALATED, trace_id=trace_id
        )
        return outcome

    await run_in_threadpool(
        repo.transition, incident_id, IncidentStatus.EXECUTED, trace_id=trace_id
    )

    # 4. Independent verification under a different, read-only identity.
    await run_in_threadpool(
        repo.transition, incident_id, IncidentStatus.VERIFYING, trace_id=trace_id
    )
    verification = await run_in_threadpool(
        call_service,
        VERIFIER_URL,
        "/verify",
        {"incident_id": incident_id, "service": config.DISPATCH_WEB_SERVICE},
        trace_header=trace_header,
    )
    verification.raise_for_status()
    verdict = verification.json()
    outcome["verification"] = verdict

    await run_in_threadpool(
        repo.append_audit,
        incident_id,
        actor="verifier",
        event="verification",
        payload={
            "verdict": verdict.get("verdict"),
            "http_status": verdict.get("http_status"),
            "active_revision": verdict.get("active_revision"),
        },
        trace_id=trace_id,
    )

    if verdict.get("verdict") == "RECOVERED":
        await run_in_threadpool(
            repo.transition, incident_id, IncidentStatus.RESOLVED, trace_id=trace_id
        )
    else:
        await run_in_threadpool(
            repo.transition,
            incident_id,
            IncidentStatus.REMEDIATION_FAILED,
            trace_id=trace_id,
        )
        await run_in_threadpool(
            repo.transition, incident_id, IncidentStatus.ESCALATED, trace_id=trace_id
        )
    return outcome


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
