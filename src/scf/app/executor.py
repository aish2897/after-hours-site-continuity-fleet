"""Remediation Executor runtime.

Runs as sa-executor. Being able to *call* this service is not authorization to
mutate anything: the caller supplies only identifiers, and the executor loads
the authoritative decision from Firestore itself. A caller cannot assert
AUTO_ALLOWED, cannot change the target, and cannot change the action.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

from fastapi import FastAPI, Header
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from scf.domain.enums import ActionState, ActionType, Decision
from scf.domain.ids import derive_idempotency_key, new_action_id, utc_now
from scf.domain.models import ActionRecord
from scf.executor.cloud_run import flip_traffic_to_revision
from scf.obs import log_event, trace_id_from_header
from scf.policy import default_policy, default_registry
from scf.state import IncidentRepository
from scf.state.firestore_repo import DecisionNotFound

app = FastAPI(title="SCF Remediation Executor", version="0.4.0")

EXECUTOR_IDENTITY = "sa-executor"
EXECUTABLE = {Decision.AUTO_ALLOWED.value, "APPROVED"}


@lru_cache(maxsize=1)
def repository() -> IncidentRepository:
    return IncidentRepository()


class ExecuteRequest(BaseModel):
    """Identifiers only. Deliberately carries no authorization claim."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=3)
    decision_id: str = Field(min_length=3)
    attempt_intent: int = Field(default=1, ge=1, le=100)


def _refuse(reason: str, **fields: Any) -> dict[str, Any]:
    return {"executed": False, "mutated": False, "refused": True, "reason": reason, **fields}


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "scf-executor",
        "role": "executor",
        "identity": EXECUTOR_IDENTITY,
        "revision": os.environ.get("K_REVISION"),
    }


def _validate(decision: dict[str, Any], request: ExecuteRequest) -> str | None:
    """Every check reads the stored decision, never the request body."""
    if decision.get("incident_id") != request.incident_id:
        return "decision_incident_mismatch"
    if decision.get("revoked"):
        return "decision_revoked"
    if decision.get("decision") not in EXECUTABLE:
        return f"decision_not_executable:{decision.get('decision')}"
    action_type = decision.get("action_type")
    if action_type not in {a.value for a in ActionType}:
        return "action_type_not_in_closed_enum"
    if action_type != ActionType.FLIP_TRAFFIC_TO_LAST_GOOD.value:
        return f"unsupported_action_type:{action_type}"
    target = decision.get("target_ref")
    if target not in default_policy().targets:
        return "target_not_registry_approved"
    if not default_registry().allows_tool("executor", "flip_traffic_to_last_good"):
        return "executor_tool_not_permitted"
    if not (decision.get("parameters") or {}).get("target_revision"):
        return "missing_authorized_parameters"
    return None


@app.post("/execute")
async def execute(
    request: ExecuteRequest,
    x_cloud_trace_context: str | None = Header(default=None),
) -> dict[str, Any]:
    trace_id = trace_id_from_header(x_cloud_trace_context)
    repo = repository()

    log_event(
        "execution_requested",
        trace_id=trace_id,
        incident_id=request.incident_id,
        decision_id=request.decision_id,
        attempt_intent=request.attempt_intent,
    )

    try:
        decision = await run_in_threadpool(
            repo.get_decision, request.incident_id, request.decision_id
        )
    except DecisionNotFound:
        log_event(
            "execution_refused",
            severity="WARNING",
            trace_id=trace_id,
            incident_id=request.incident_id,
            reason="decision_not_found",
        )
        return _refuse("decision_not_found", decision_id=request.decision_id)

    problem = _validate(decision, request)
    if problem:
        log_event(
            "execution_refused",
            severity="WARNING",
            trace_id=trace_id,
            incident_id=request.incident_id,
            decision_id=request.decision_id,
            reason=problem,
        )
        return _refuse(problem, decision_id=request.decision_id)

    action_type = decision["action_type"]
    target_ref = decision["target_ref"]
    target_revision = decision["parameters"]["target_revision"]

    key = derive_idempotency_key(
        incident_id=request.incident_id,
        action_type=action_type,
        target_ref=target_ref,
        decision_id=request.decision_id,
        attempt_intent=request.attempt_intent,
    )
    action_id = new_action_id()

    claimed = await run_in_threadpool(
        repo.claim_idempotency,
        key,
        incident_id=request.incident_id,
        decision_id=request.decision_id,
        action_id=action_id,
    )

    if not claimed:
        log_event(
            "execution_duplicate_suppressed",
            trace_id=trace_id,
            incident_id=request.incident_id,
            decision_id=request.decision_id,
            idempotency_key=key[:16],
        )
        await run_in_threadpool(
            repo.append_audit,
            request.incident_id,
            actor="executor",
            event="duplicate_suppressed",
            payload={"decision_id": request.decision_id, "idempotency_key": key},
            actor_identity=EXECUTOR_IDENTITY,
            trace_id=trace_id,
        )
        return {
            "executed": False,
            "mutated": False,
            "duplicate": True,
            "state": ActionState.DUPLICATE_SUPPRESSED.value,
            "idempotency_key": key,
        }

    action = ActionRecord(
        action_id=action_id,
        decision_id=request.decision_id,
        action_type=ActionType(action_type),
        target_ref=target_ref,
        idempotency_key=key,
        state=ActionState.EXECUTING,
        attempt_intent=request.attempt_intent,
        executor_identity=EXECUTOR_IDENTITY,
        started_at=utc_now(),
    )
    await run_in_threadpool(repo.record_action, request.incident_id, action)

    result = await run_in_threadpool(
        flip_traffic_to_revision, target_ref, target_revision
    )

    action.state = ActionState.SUCCEEDED if result.get("accepted") else ActionState.FAILED
    action.result = result
    action.error = None if result.get("accepted") else str(result.get("error"))[:400]
    action.finished_at = utc_now()
    await run_in_threadpool(repo.record_action, request.incident_id, action)
    await run_in_threadpool(
        repo.append_audit,
        request.incident_id,
        actor="executor",
        event="action_executed",
        payload={
            "action_id": action.action_id,
            "decision_id": request.decision_id,
            "target_ref": target_ref,
            "target_revision": target_revision,
            "accepted": bool(result.get("accepted")),
            "idempotency_key": key,
        },
        actor_identity=EXECUTOR_IDENTITY,
        trace_id=trace_id,
    )

    log_event(
        "action_executed",
        trace_id=trace_id,
        incident_id=request.incident_id,
        decision_id=request.decision_id,
        target_ref=target_ref,
        target_revision=target_revision,
        changed=bool(result.get("accepted")),
    )

    return {
        "executed": True,
        "mutated": bool(result.get("accepted")),
        "duplicate": False,
        "action_id": action.action_id,
        "state": action.state.value,
        "idempotency_key": key,
        "target_revision": target_revision,
        "result": result,
    }
