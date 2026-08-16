"""Remediation Executor runtime.

Runs as sa-executor. Being able to *call* this service is not authorization to
mutate anything: the caller supplies only identifiers, and the executor loads
the authoritative decision from Firestore itself.

Honest property: this is duplicate-safe, recoverable, effect-idempotent
execution with reconciliation. It is NOT globally exactly-once distributed
execution — Firestore and the Cloud Run Admin API cannot be committed
together. A crashed execution is resolved by inspecting real infrastructure.
"""

from __future__ import annotations

import os
import uuid
from functools import lru_cache
from typing import Any

from fastapi import FastAPI, Header
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from scf.domain.enums import ActionState, ActionType, Decision, ExecutionState
from scf.domain.ids import derive_execution_id, new_action_id, utc_now
from scf.domain.models import ActionRecord
from scf.executor.cloud_run import flip_traffic_to_revision
from scf.obs import log_event, trace_id_from_header
from scf.policy import default_policy, default_registry
from scf.state import DecisionNotFound, ExecutionStore, IncidentRepository
from scf.state.execution_store import ALREADY_FINISHED, HELD_BY_OTHER
from scf.tools.cloud_run_evidence import describe_service, probe_health

app = FastAPI(title="SCF Remediation Executor", version="0.5.0")

EXECUTOR_IDENTITY = "sa-executor"
EXECUTABLE = {Decision.AUTO_ALLOWED.value, "APPROVED"}
WORKER_ID = f"{os.environ.get('K_REVISION', 'local')}:{uuid.uuid4().hex[:8]}"


@lru_cache(maxsize=1)
def authoritative() -> IncidentRepository:
    """Read-only here. IAM refuses writes; this is not enforced in code."""
    return IncidentRepository()


@lru_cache(maxsize=1)
def execution() -> ExecutionStore:
    return ExecutionStore()


class ExecuteRequest(BaseModel):
    """Identifiers only.

    There is deliberately no attempt or retry field. One authoritative decision
    has exactly one execution identity, so no caller input can mint a second
    infrastructure execution for the same authorization. A genuine retry is
    driven by authoritative recovery state, not by a caller-chosen value.
    """

    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=3)
    decision_id: str = Field(min_length=3)


def _refuse(reason: str, **fields: Any) -> dict[str, Any]:
    return {
        "executed": False,
        "mutated": False,
        "refused": True,
        "reason": reason,
        **fields,
    }


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "scf-executor",
        "role": "executor",
        "identity": EXECUTOR_IDENTITY,
        "worker": WORKER_ID,
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
    if decision.get("target_ref") not in default_policy().targets:
        return "target_not_registry_approved"
    if not default_registry().allows_tool("executor", "flip_traffic_to_last_good"):
        return "executor_tool_not_permitted"
    if not (decision.get("parameters") or {}).get("authorized_target_revision"):
        return "missing_authorized_target_revision"
    return None


def _observe(service: str) -> dict[str, Any]:
    """Read real infrastructure. Used for both precondition and reconciliation."""
    described = describe_service(service)
    active = ""
    for entry in described.get("trafficStatuses") or []:
        if entry.get("percent") == 100:
            active = (entry.get("revision") or "").rsplit("/", 1)[-1]
            break
    status_code, body = probe_health(described.get("uri", ""))
    return {
        "active_revision": active,
        "etag": described.get("etag", ""),
        "http_status": status_code,
        "healthy": status_code == 200 and "healthy" in body.lower(),
    }


@app.post("/execute")
async def execute(
    request: ExecuteRequest,
    x_cloud_trace_context: str | None = Header(default=None),
) -> dict[str, Any]:
    trace_id = trace_id_from_header(x_cloud_trace_context)
    repo = authoritative()
    store = execution()

    log_event(
        "execution_requested",
        trace_id=trace_id,
        incident_id=request.incident_id,
        decision_id=request.decision_id,
        worker=WORKER_ID,
    )

    try:
        decision = await run_in_threadpool(
            repo.get_decision, request.incident_id, request.decision_id
        )
    except DecisionNotFound:
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

    params = decision["parameters"]
    target_ref = decision["target_ref"]
    authorized_revision = params["authorized_target_revision"]
    expected_source = params.get("expected_source_revision")
    expected_etag = params.get("expected_etag")

    execution_id = derive_execution_id(
        incident_id=request.incident_id,
        action_type=decision["action_type"],
        target_ref=target_ref,
        decision_id=request.decision_id,
    )

    outcome, existing = await run_in_threadpool(
        store.acquire,
        execution_id,
        owner=WORKER_ID,
        incident_id=request.incident_id,
        decision_id=request.decision_id,
        action_type=decision["action_type"],
        target_ref=target_ref,
        authorized_target_revision=authorized_revision,
        expected_source_revision=expected_source,
        expected_etag=expected_etag,
    )

    base: dict[str, Any] = {
        "execution_id": execution_id,
        "authorized_target_revision": authorized_revision,
        "execution_database": store.database,
        "authoritative_database": repo.database,
        "outcome": outcome,
    }

    if outcome in (ALREADY_FINISHED, HELD_BY_OTHER):
        log_event(
            "execution_duplicate_suppressed",
            trace_id=trace_id,
            incident_id=request.incident_id,
            decision_id=request.decision_id,
            outcome=outcome,
            state=(existing or {}).get("state"),
        )
        return {
            "executed": False,
            "mutated": False,
            "duplicate": True,
            "state": (existing or {}).get(
                "state", ActionState.DUPLICATE_SUPPRESSED.value
            ),
            **base,
        }

    # Reconcile against real infrastructure before touching anything. This is
    # what closes the crash window: we never assume what a dead process did.
    observed = await run_in_threadpool(_observe, target_ref)
    base["observed_active_revision"] = observed["active_revision"]

    if observed["active_revision"] == authorized_revision:
        # CASE B: the mutation already landed, possibly before a crash.
        await run_in_threadpool(
            store.advance,
            execution_id,
            ExecutionState.MUTATED,
            reconciled=True,
            observed_active_revision=observed["active_revision"],
        )
        log_event(
            "execution_reconciled_no_mutation",
            trace_id=trace_id,
            incident_id=request.incident_id,
            execution_id=execution_id,
            active_revision=observed["active_revision"],
        )
        return {
            "executed": True,
            "mutated": False,
            "duplicate": False,
            "reconciled": True,
            "state": ExecutionState.MUTATED.value,
            **base,
        }

    if expected_source and observed["active_revision"] != expected_source:
        # CASE C: infrastructure is neither the authorized pre-state nor the
        # target. Something else changed it. Fail closed.
        await run_in_threadpool(
            store.advance,
            execution_id,
            ExecutionState.STALE,
            observed_active_revision=observed["active_revision"],
        )
        log_event(
            "execution_precondition_failed",
            severity="WARNING",
            trace_id=trace_id,
            incident_id=request.incident_id,
            execution_id=execution_id,
            expected_source_revision=expected_source,
            observed_active_revision=observed["active_revision"],
        )
        return _refuse(
            "STALE_EVIDENCE",
            precondition="expected_source_revision",
            expected=expected_source,
            observed=observed["active_revision"],
            **base,
        )

    if expected_etag and observed["etag"] and observed["etag"] != expected_etag:
        log_event(
            "execution_etag_drift",
            severity="NOTICE",
            trace_id=trace_id,
            incident_id=request.incident_id,
            execution_id=execution_id,
        )
        base["etag_drift"] = True

    action_id = new_action_id()
    action = ActionRecord(
        action_id=action_id,
        decision_id=request.decision_id,
        action_type=ActionType(decision["action_type"]),
        target_ref=target_ref,
        idempotency_key=execution_id,
        state=ActionState.EXECUTING,
        executor_identity=EXECUTOR_IDENTITY,
        started_at=utc_now(),
    )
    await run_in_threadpool(
        store.advance,
        execution_id,
        ExecutionState.MUTATION_REQUESTED,
        action_id=action_id,
        observed_etag=observed["etag"],
    )

    result = await run_in_threadpool(
        flip_traffic_to_revision, target_ref, authorized_revision
    )

    accepted = bool(result.get("accepted"))
    action.state = ActionState.SUCCEEDED if accepted else ActionState.FAILED
    action.result = result
    action.error = None if accepted else str(result.get("error"))[:400]
    action.finished_at = utc_now()

    await run_in_threadpool(
        store.advance,
        execution_id,
        ExecutionState.MUTATED if accepted else ExecutionState.FAILED,
        action_id=action_id,
        accepted=accepted,
    )
    await run_in_threadpool(
        store.record_receipt,
        action_id,
        {**action.model_dump(mode="json"), "incident_id": request.incident_id},
    )

    log_event(
        "action_executed",
        trace_id=trace_id,
        incident_id=request.incident_id,
        execution_id=execution_id,
        target_ref=target_ref,
        authorized_target_revision=authorized_revision,
        accepted=accepted,
    )

    return {
        "executed": True,
        "mutated": accepted,
        "duplicate": False,
        "reconciled": False,
        "action_id": action_id,
        "state": action.state.value,
        "result": result,
        "action": action.model_dump(mode="json"),
        **base,
    }
