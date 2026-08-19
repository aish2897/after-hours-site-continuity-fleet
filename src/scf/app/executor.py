"""Remediation Executor runtime.

Runs as sa-executor. Being able to *call* this service is not authorization to
mutate anything: the caller supplies only identifiers, and the executor loads
the authoritative decision from Firestore itself.

## The property this defends

Not globally exactly-once distributed execution — Firestore and the Cloud Run
Admin API cannot be committed together, and no amount of code changes that.
What is defended, in layers:

1. **Firestore fencing.** Only the current lease owner, presenting the current
   lease epoch, may advance authoritative execution state.
2. **Cloud Run resourceVersion OCC.** An obsolete Service snapshot cannot
   overwrite a newer Service version; Google rejects it with 409 ABORTED.
3. **Exact target pinning.** Every duplicate request can only ever request the
   same authorized revision, so any surviving race is effect-idempotent.
4. **Reconciliation.** Crash boundaries are resolved by reading real
   infrastructure, never by assuming what a dead process did.
5. **Terminal execution state.** A verified execution can never be re-run.

The honest residual: a worker that lost its lease could still reach the Cloud
Run API after its final ownership check if the Service has not changed in the
interim. It cannot advance execution state, and it can only request the exact
same authorized target, so the effect is idempotent — but this window is real
and is documented rather than denied.
"""

from __future__ import annotations

import os
import uuid
from functools import lru_cache
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from scf import faults
from scf.domain.enums import (
    ActionState,
    ActionType,
    Decision,
    ExecutionState,
    IncidentStatus,
)
from scf.domain.ids import (
    derive_authorization_fingerprint,
    derive_execution_id,
    new_action_id,
    utc_now,
)
from scf.domain.models import ActionRecord
from scf.executor.cloud_run import (
    flip_traffic_to_revision,
    read_service_v1,
    resource_version_of,
)
from scf.obs import log_event, trace_id_from_header
from scf.policy import default_policy, default_registry
from scf.domain.state_machine import TERMINAL_STATES as CLOSED_INCIDENT_STATES
from scf.state import (
    DecisionNotFound,
    ExecutionStore,
    IncidentNotFound,
    IncidentRepository,
)
from scf.state.firestore_repo import ApprovalNotFound
from scf.state.execution_store import TERMINAL_STATES as TERMINAL_EXECUTION_STATES
from scf.state.execution_store import (
    ACQUIRED,
    ADVANCED,
    ALREADY_FINISHED,
    ALREADY_TERMINAL,
    CONFLICT,
    HELD_BY_OTHER,
    LEASE_LOST,
    RECOVERED,
)
from scf.tools.cloud_run_evidence import (
    KNOWN_GOOD_TAG,
    body_is_healthy,
    describe_service,
    probe_health,
    serves_exclusively,
    traffic_allocation,
)

app = FastAPI(title="SCF Remediation Executor", version="0.6.0")

EXECUTOR_IDENTITY = "sa-executor"
EXECUTABLE = {Decision.AUTO_ALLOWED.value, "APPROVED"}
WORKER_ID = f"{os.environ.get('K_REVISION', 'local')}:{uuid.uuid4().hex[:8]}"

#: States from which a fresh precondition check may proceed. MUTATED is
#: included so a recovered execution can re-check and reconcile; terminal
#: states are absent by construction.
PRE_MUTATION_STATES = (
    ExecutionState.CLAIMED,
    ExecutionState.PRECONDITION_CHECKED,
    ExecutionState.MUTATION_REQUESTED,
    ExecutionState.MUTATED,
)

#: States meaning "this execution has already got as far as issuing its
#: mutation". `MUTATION_REQUESTED` is written immediately *before* the Cloud
#: Run call, so it does not prove the call was made — which is exactly why it
#: belongs here. If the call was accepted but the success write was fenced, the
#: record never advances past this state, and treating it as "not yet
#: attempted" would let the same authorization fire a second time. Failing
#: closed costs a rare escalation; failing open costs a duplicate
#: infrastructure change.
ATTEMPTED_STATES = frozenset(
    {ExecutionState.MUTATION_REQUESTED.value, ExecutionState.MUTATED.value}
)

#: The only state a successful verification may close.
#:
#: `MUTATION_REQUESTED` is deliberately NOT here. It is written *before* the
#: Cloud Run call, so it does not prove a mutation was ever issued — accepting
#: it would let an execution be closed as VERIFIED on the strength of a healthy
#: service that some other actor produced. Reconciliation is what converts a
#: half-recorded execution into `MUTATED`, by observing that the authorized
#: target really is live, and the incident stays reconcilable until it does.
TERMINALIZABLE_STATES = frozenset({ExecutionState.MUTATED.value})


@lru_cache(maxsize=1)
def authoritative() -> IncidentRepository:
    """Read-only here. IAM refuses writes; this is not enforced in code."""
    return IncidentRepository()


@lru_cache(maxsize=1)
def execution() -> ExecutionStore:
    return ExecutionStore()


class ExecuteRequest(BaseModel):
    """Identifiers only.

    There is deliberately no attempt or retry field, no target, no revision and
    no precondition token. One authoritative decision has exactly one execution
    identity, so no caller input can mint a second infrastructure execution for
    the same authorization, redirect it at another revision, or supply the
    resourceVersion that guards the mutation.
    """

    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=3)
    decision_id: str = Field(min_length=3)


class TerminalizeRequest(ExecuteRequest):
    """Same surface. The verdict is re-derived, never accepted from a caller."""


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
        **faults.banner(),
    }


def _validate(
    decision: dict[str, Any],
    request: ExecuteRequest,
    incident: dict[str, Any] | None = None,
) -> str | None:
    """Every check reads stored authoritative state, never the request body.

    Control-plane closure is enforced here, at the boundary that mutates. Once
    the orchestrator has driven an incident to a terminal state, its decisions
    are spent: a decision left over from a run that already failed and escalated
    must not become an infrastructure change minutes later just because its
    preconditions happen to hold again.
    """
    if incident is not None:
        status = incident.get("status")
        if status in {s.value for s in CLOSED_INCIDENT_STATES}:
            return f"incident_closed:{status}"
    if decision.get("incident_id") != request.incident_id:
        return "decision_incident_mismatch"
    if decision.get("revoked"):
        return "decision_revoked"
    if decision.get("decision") not in EXECUTABLE:
        # An APPROVAL_REQUIRED decision is executable ONLY on the strength of a
        # human approval this identity has verified for itself. Reaching this
        # service proves Cloud Run let the caller in; it does not prove anybody
        # authorized the action. The orchestrator checks the approval too, and
        # that is defence in depth, not a substitute — a compromised or buggy
        # orchestrator must not be able to talk this executor into mutating
        # something no person agreed to.
        if decision.get("decision") != Decision.APPROVAL_REQUIRED.value:
            return f"decision_not_executable:{decision.get('decision')}"
        problem = _approval_blocks_execution(decision, request.incident_id)
        if problem:
            return problem
    action_type = decision.get("action_type")
    if action_type not in {a.value for a in ActionType}:
        return "action_type_not_in_closed_enum"
    if action_type not in TRAFFIC_MUTATION_ACTIONS:
        return f"unsupported_action_type:{action_type}"
    if decision.get("target_ref") not in default_policy().targets:
        return "target_not_registry_approved"
    if not default_registry().allows_tool("executor", "flip_traffic_to_last_good"):
        return "executor_tool_not_permitted"
    if not (decision.get("parameters") or {}).get("authorized_target_revision"):
        return "missing_authorized_target_revision"
    return None


#: The actions this executor can actually perform. Both are the SAME Cloud Run
#: traffic mutation under the same scoped identity, exact revision pinning and
#: resourceVersion OCC — they differ only in what authorized them.
TRAFFIC_MUTATION_ACTIONS = frozenset(
    {
        ActionType.FLIP_TRAFFIC_TO_LAST_GOOD.value,
        ActionType.SHIFT_TRAFFIC_TO_APPROVED_CANDIDATE.value,
    }
)


def _approval_blocks_execution(decision: dict[str, Any], incident_id: str) -> str | None:
    """Verify the human approval independently, from the authoritative plane.

    Returns a refusal reason, or None when a valid approval genuinely permits
    this exact decision. The fingerprint check is what makes the approval
    specific: it binds incident, action, target, exact revision, policy version
    and evidence snapshot together, so an approval cannot be carried across to a
    different decision, a different revision, or a re-issued authorization.
    """
    # From the decision document this identity already read. A query would be
    # refused — `scfDecisionReader` grants `datastore.entities.get` and not
    # `list` — and that refusal is the isolation boundary, not an obstacle to
    # route around.
    approval_id = str(decision.get("approval_id") or "")
    if not approval_id:
        return "no_approval_for_decision"
    try:
        approval = authoritative().get_approval(approval_id)
    except ApprovalNotFound:
        return "approval_not_found"
    if approval.get("state") != "APPROVED":
        return f"approval_state:{approval.get('state')}"
    if str(approval.get("expires_at") or "") <= utc_now().isoformat():
        return "approval_expired"

    params = decision.get("parameters") or {}
    expected = derive_authorization_fingerprint(
        incident_id=incident_id,
        action_type=str(decision.get("action_type") or ""),
        target_ref=str(decision.get("target_ref") or ""),
        authorized_target_revision=str(params.get("authorized_target_revision") or ""),
        policy_version=str(decision.get("policy_version") or ""),
        evidence_snapshot_hash=str(decision.get("evidence_snapshot_hash") or ""),
    )
    if approval.get("decision_fingerprint") != expected:
        return "approval_fingerprint_mismatch"
    return None


def _identity(decision: dict[str, Any], incident_id: str, decision_id: str) -> tuple[str, str]:
    """(execution_id, authorization_fingerprint), both derived from stored truth."""
    params = decision.get("parameters") or {}
    execution_id = derive_execution_id(
        incident_id=incident_id,
        action_type=decision["action_type"],
        target_ref=decision["target_ref"],
        decision_id=decision_id,
    )
    fingerprint = derive_authorization_fingerprint(
        incident_id=incident_id,
        action_type=decision["action_type"],
        target_ref=decision["target_ref"],
        authorized_target_revision=params["authorized_target_revision"],
        policy_version=str(decision.get("policy_version") or ""),
        evidence_snapshot_hash=str(decision.get("evidence_snapshot_hash") or ""),
    )
    return execution_id, fingerprint


def _observe(service: str, authorized_revision: str = "") -> dict[str, Any]:
    """Read real infrastructure. Used for precondition and reconciliation.

    Also re-probes the target through its own tag URL, so freshness is
    established at execution time rather than inherited from an investigation
    that may be minutes old.

    Which target depends on what was authorized. A rollback is authorized
    against the operator's `known-good` tag and must still find it there — an
    operator who withdraws the tag has withdrawn the premise. A human-approved
    shift is authorized against one exact revision the person was shown, so the
    check is that *that* revision is still addressable and still healthy,
    whatever tag carries it.
    """
    described = describe_service(service)
    allocation = traffic_allocation(described)
    active = next((rev for rev, pct in allocation.items() if pct == 100), "")

    candidate_revision = ""
    candidate_uri = ""
    for entry in described.get("trafficStatuses") or []:
        revision = (entry.get("revision") or "").rsplit("/", 1)[-1]
        if entry.get("tag") == KNOWN_GOOD_TAG:
            candidate_revision = revision
            candidate_uri = entry.get("uri") or ""
            break
        # No blessed tag: accept the exact authorized revision if it is still
        # addressable. Never a substitute — only the revision already pinned in
        # the decision a human approved.
        if authorized_revision and revision == authorized_revision and entry.get("uri"):
            candidate_revision = revision
            candidate_uri = entry.get("uri") or ""

    candidate_status, candidate_body = (
        probe_health(candidate_uri) if candidate_uri else (0, "no addressable candidate")
    )
    status_code, body = probe_health(described.get("uri", ""))
    return {
        "active_revision": active,
        "traffic_allocation": allocation,
        "etag": described.get("etag", ""),
        "http_status": status_code,
        "healthy": status_code == 200 and body_is_healthy(body),
        "candidate_revision": candidate_revision,
        "candidate_probe_http_status": candidate_status,
        "candidate_probe_healthy": candidate_status == 200
        and body_is_healthy(candidate_body),
    }


def _candidate_is_fresh(observed: dict[str, Any], authorized_revision: str) -> str | None:
    """Point-in-time precondition on the rollback target. Not a future guarantee.

    Refuses if the operator-approved candidate is no longer the authorized
    revision, or no longer answers healthily on its own tag URL. Nothing is
    mutated on refusal.
    """
    if observed["candidate_revision"] != authorized_revision:
        return "candidate_no_longer_approved"
    if not observed["candidate_probe_healthy"]:
        return "candidate_probe_unhealthy"
    return None


@app.post("/execute")
async def execute(
    request: ExecuteRequest,
    x_cloud_trace_context: str | None = Header(default=None),
) -> dict[str, Any]:
    trace_id = trace_id_from_header(x_cloud_trace_context)
    repo = authoritative()
    store = execution()

    if faults.is_mode(faults.EXECUTOR_5XX):
        log_event("fault_injection", severity="WARNING", trace_id=trace_id,
                  incident_id=request.incident_id, label=faults.LABEL,
                  fault_mode=faults.active())
        raise HTTPException(status_code=503, detail="FAULT INJECTION: executor down")

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

    try:
        incident = await run_in_threadpool(repo.get, request.incident_id)
    except IncidentNotFound:
        return _refuse("incident_not_found", incident_id=request.incident_id)

    problem = _validate(decision, request, incident)
    if problem:
        log_event(
            "execution_refused",
            severity="WARNING",
            trace_id=trace_id,
            incident_id=request.incident_id,
            decision_id=request.decision_id,
            reason=problem,
        )
        extra: dict[str, Any] = {}
        if problem.startswith("incident_closed"):
            # Report the execution's own state too. Control-plane closure is
            # the stronger rule and refuses first, but a replay against a
            # closed incident is also a replay against a terminal execution,
            # and both facts are worth having on the record.
            try:
                closed_id, _ = _identity(
                    decision, request.incident_id, request.decision_id
                )
                closed = await run_in_threadpool(execution().get, closed_id)
                extra = {
                    "execution_id": closed_id,
                    "execution_state": (closed or {}).get("state"),
                    "terminal": (closed or {}).get("state")
                    in {s.value for s in TERMINAL_EXECUTION_STATES},
                }
            except (KeyError, TypeError):  # decision lacks the parameters
                extra = {}
        return _refuse(problem, decision_id=request.decision_id, **extra)

    params = decision["parameters"]
    target_ref = decision["target_ref"]
    authorized_revision = params["authorized_target_revision"]
    expected_source = params.get("expected_source_revision")
    expected_etag = params.get("expected_etag")

    execution_id, fingerprint = _identity(
        decision, request.incident_id, request.decision_id
    )

    base: dict[str, Any] = {
        "execution_id": execution_id,
        "authorization_fingerprint": fingerprint,
        "authorized_target_revision": authorized_revision,
        "execution_database": store.database,
        "authoritative_database": repo.database,
    }

    # One authorization, one execution identity — even if the authorization is
    # re-issued under a different decision id.
    binding, bound = await run_in_threadpool(
        store.bind_authorization,
        fingerprint,
        execution_id=execution_id,
        incident_id=request.incident_id,
        decision_id=request.decision_id,
    )
    if binding == CONFLICT:
        log_event(
            "execution_duplicate_authorization",
            severity="WARNING",
            trace_id=trace_id,
            incident_id=request.incident_id,
            decision_id=request.decision_id,
            bound_execution_id=(bound or {}).get("execution_id"),
        )
        return _refuse(
            "DUPLICATE_AUTHORIZATION",
            bound_execution_id=(bound or {}).get("execution_id"),
            bound_decision_id=(bound or {}).get("decision_id"),
            **base,
        )

    outcome, record = await run_in_threadpool(
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
    base["outcome"] = outcome

    if outcome in (ALREADY_FINISHED, HELD_BY_OTHER):
        log_event(
            "execution_duplicate_suppressed",
            trace_id=trace_id,
            incident_id=request.incident_id,
            decision_id=request.decision_id,
            outcome=outcome,
            state=(record or {}).get("state"),
        )
        return {
            "executed": False,
            "mutated": False,
            "duplicate": True,
            # Inherited, so a duplicate cannot claim work the record it collided
            # with has already disclaimed.
            "effect_predates_execution": bool(
                (record or {}).get("effect_predates_execution")
            ),
            "terminal": outcome == ALREADY_FINISHED,
            "state": (record or {}).get(
                "state", ActionState.DUPLICATE_SUPPRESSED.value
            ),
            **base,
        }

    owner = WORKER_ID
    epoch = int((record or {}).get("lease_epoch") or 0)
    current_state = (record or {}).get("state")
    base["lease_epoch"] = epoch
    base["recovered_state"] = current_state

    def _advance(state: ExecutionState, **fields: Any) -> tuple[str, dict | None]:
        return store.advance(
            execution_id,
            state,
            owner=owner,
            lease_epoch=epoch,
            **fields,
        )

    def _fenced(result: str, stage: str) -> dict[str, Any]:
        log_event(
            "execution_fenced_out",
            severity="WARNING",
            trace_id=trace_id,
            incident_id=request.incident_id,
            execution_id=execution_id,
            lease_epoch=epoch,
            stage=stage,
            fence_result=result,
        )
        return _refuse(result, stage=stage, fenced=True, **base)

    # Reconcile against real infrastructure before touching anything. This is
    # what closes the crash window: we never assume what a dead process did.
    observed = await run_in_threadpool(_observe, target_ref, authorized_revision)
    base["observed_active_revision"] = observed["active_revision"]
    base["observed_traffic_allocation"] = observed["traffic_allocation"]

    if observed["active_revision"] == authorized_revision:
        # CASE B: the authorized revision is already live.
        #
        # Two different situations reach here and they must not be reported the
        # same way. If this execution had already got as far as issuing its
        # mutation, the effect is ours and predates a crash. If it is still at
        # CLAIMED, we never issued anything — somebody else put the service
        # where we wanted it, most likely an operator rolling back by hand. The
        # workflow proceeds identically either way, because the desired state is
        # present and authorized; the handover must not.
        # "Did this execution issue anything?", not "is it exactly CLAIMED?".
        # PRECONDITION_CHECKED is written BEFORE the Cloud Run call and is
        # reached with certainty by the 409 rewind — a write Google provably
        # refused — so testing one state let the second look credit us with an
        # operator's rollback.
        #
        # And it is remembered. A CASE B that correctly disclaims authorship
        # writes MUTATED; without persisting the disclaimer, the very next
        # reconcile reads MUTATED, sees an attempted state, and claims the work
        # after all. The record has to carry what it knows.
        effect_predates_execution = bool(
            (record or {}).get("effect_predates_execution")
        ) or current_state not in ATTEMPTED_STATES
        result, _ = await run_in_threadpool(
            _advance,
            ExecutionState.MUTATED,
            expect_states=PRE_MUTATION_STATES,
            reconciled=True,
            effect_predates_execution=effect_predates_execution,
            observed_active_revision=observed["active_revision"],
        )
        if result != ADVANCED:
            return _fenced(result, "reconcile")
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
            "effect_predates_execution": effect_predates_execution,
            "state": ExecutionState.MUTATED.value,
            **base,
        }

    if current_state in ATTEMPTED_STATES:
        # This execution already issued — or may already have issued — its one
        # authorized mutation, and the authorized target is not live now.
        # Something undid it: an operator rollback, a competing deploy, a fresh
        # failure. Re-applying would make one authorization an open-ended
        # licence to keep changing infrastructure, so it is refused. A new
        # failure needs a new incident and a new authorization.
        #
        # `MUTATION_REQUESTED` counts, deliberately. A mutation Google accepted
        # whose success write was fenced never advances past it, so treating
        # that as "not yet attempted" would let one authorization fire twice.
        #
        # Nothing is terminalized here. A Cloud Run traffic migration is
        # asynchronous, so an observation taken moments after our own mutation
        # can still show the old revision; writing a terminal FAILED on that
        # basis would be a race, not a finding. The execution stays recoverable
        # and reconciliation settles it.
        await run_in_threadpool(
            store.release, execution_id, owner=owner, lease_epoch=epoch
        )
        log_event(
            "execution_mutation_did_not_hold",
            severity="WARNING",
            trace_id=trace_id,
            incident_id=request.incident_id,
            execution_id=execution_id,
            authorized_target_revision=authorized_revision,
            observed_active_revision=observed["active_revision"],
        )
        return _refuse(
            "MUTATION_DID_NOT_HOLD",
            detail=(
                "this execution already mutated"
                if current_state == ExecutionState.MUTATED.value
                else "this execution may already have issued its mutation"
            ),
            observed=observed["active_revision"],
            **base,
        )

    if expected_source and observed["active_revision"] != expected_source:
        # CASE C: infrastructure is neither the authorized pre-state nor the
        # target. Something else changed it. Fail closed.
        await run_in_threadpool(
            _advance,
            ExecutionState.STALE,
            expect_states=PRE_MUTATION_STATES,
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

    # D3.7 — the rollback target must still be healthy right now, not merely at
    # investigation time. No mutation is issued toward a target we cannot see
    # answering.
    stale_candidate = _candidate_is_fresh(observed, authorized_revision)
    if stale_candidate:
        # Nothing was mutated and no state advanced, so holding the lease until
        # it expires would only delay a legitimate retry once the candidate is
        # healthy again.
        await run_in_threadpool(
            store.release, execution_id, owner=owner, lease_epoch=epoch
        )
        log_event(
            "execution_target_no_longer_healthy",
            severity="WARNING",
            trace_id=trace_id,
            incident_id=request.incident_id,
            execution_id=execution_id,
            detail=stale_candidate,
            candidate_probe_http_status=observed["candidate_probe_http_status"],
        )
        return _refuse(
            "TARGET_NO_LONGER_HEALTHY",
            detail=stale_candidate,
            candidate_probe_http_status=observed["candidate_probe_http_status"],
            observed_candidate_revision=observed["candidate_revision"],
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

    # D3.3 — final ownership check. This write succeeds only if the lease is
    # still ours at this instant, so a fenced-out worker never reaches the read
    # below and never obtains a resourceVersion.
    result, _ = await run_in_threadpool(
        _advance,
        ExecutionState.PRECONDITION_CHECKED,
        expect_states=PRE_MUTATION_STATES,
    )
    if result != ADVANCED:
        return _fenced(result, "precondition")

    # Control-plane closure, re-read at the last moment. The first check
    # happened before any of the work above, and an incident can be closed
    # while a request is in flight. Firestore and Cloud Run cannot be committed
    # together, so this narrows the window to the same width as the ownership
    # fence rather than eliminating it — the same honest limitation, stated the
    # same way.
    latest = await run_in_threadpool(repo.get, request.incident_id)
    if latest.get("status") in {s.value for s in CLOSED_INCIDENT_STATES}:
        await run_in_threadpool(
            store.release, execution_id, owner=owner, lease_epoch=epoch
        )
        log_event(
            "execution_incident_closed_mid_flight",
            severity="WARNING",
            trace_id=trace_id,
            incident_id=request.incident_id,
            execution_id=execution_id,
            status=latest.get("status"),
        )
        return _refuse(
            f"incident_closed_during_execution:{latest.get('status')}", **base
        )

    snapshot = await run_in_threadpool(read_service_v1, target_ref)
    base["resource_version_sent"] = resource_version_of(snapshot)

    if faults.is_mode(faults.EXECUTOR_DELAY_BEFORE_MUTATION):
        # Holds the request open AFTER the authorized read, so a controlled
        # second actor can move the Service and Google's own precondition is
        # what refuses the write. The conflict is real, not simulated.
        log_event("fault_injection", severity="WARNING", trace_id=trace_id,
                  incident_id=request.incident_id, label=faults.LABEL,
                  fault_mode=faults.active(),
                  resource_version_sent=base["resource_version_sent"])
        await run_in_threadpool(faults.delay)

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
    result, _ = await run_in_threadpool(
        _advance,
        ExecutionState.MUTATION_REQUESTED,
        expect_states=(ExecutionState.PRECONDITION_CHECKED,),
        action_id=action_id,
        observed_etag=observed["etag"],
        resource_version_sent=base["resource_version_sent"],
    )
    if result != ADVANCED:
        return _fenced(result, "mutation_request")

    mutation = await run_in_threadpool(
        flip_traffic_to_revision, target_ref, authorized_revision, snapshot
    )

    accepted = bool(mutation.get("accepted"))
    conflict = bool(mutation.get("conflict"))

    if conflict:
        # Google refused the write: the Service moved on since our authorized
        # read. A 409 is proof that nothing was applied, so the record is wound
        # back to PRECONDITION_CHECKED. That distinction is load-bearing —
        # leaving it at MUTATION_REQUESTED would mark this execution as having
        # possibly acted and permanently bar a legitimate retry, for a call we
        # know had no effect.
        rewind, _ = await run_in_threadpool(
            _advance,
            ExecutionState.PRECONDITION_CHECKED,
            expect_states=(ExecutionState.MUTATION_REQUESTED,),
            action_id=action_id,
            last_conflict_at=utc_now(),
        )
        if rewind == ADVANCED:
            # Nothing was applied and this worker is not continuing, so holding
            # the lease would make the retry it just declared possible depend on
            # waiting two minutes for expiry. Released only when the rewind
            # succeeded: if it did not, the execution stays marked as attempted
            # and giving the lease away would invite exactly the second attempt
            # we refuse elsewhere.
            await run_in_threadpool(
                store.release, execution_id, owner=owner, lease_epoch=epoch
            )
        log_event(
            "execution_resource_version_conflict",
            severity="WARNING",
            trace_id=trace_id,
            incident_id=request.incident_id,
            execution_id=execution_id,
            resource_version_sent=base["resource_version_sent"],
            rewind=rewind,
        )
        return _refuse(
            "CONCURRENT_MODIFICATION",
            conflict=True,
            http_status=mutation.get("http_status"),
            # Reported rather than assumed: if our lease was taken while the
            # conflicting call was in flight, the rewind is refused and the
            # record stays at MUTATION_REQUESTED — conservative, and visible.
            conflict_rewind=rewind,
            retryable=rewind == ADVANCED,
            result=mutation,
            **base,
        )

    action.state = ActionState.SUCCEEDED if accepted else ActionState.OUTCOME_UNKNOWN
    action.result = mutation
    action.error = None if accepted else str(mutation.get("error"))[:400]
    action.finished_at = utc_now()

    if not accepted:
        # Google answered with something other than 409. Only a 409 ABORTED is
        # proof the write was refused — it is the platform reporting that it
        # declined the precondition. Every other error leaves the outcome
        # genuinely unknown, and Google's own guidance for state-changing calls
        # is that DEADLINE_EXCEEDED can be returned *after* the change was
        # applied. Writing terminal FAILED here would record "nothing happened"
        # about a mutation that may well have happened, and terminal is the one
        # state reconciliation cannot rescue.
        #
        # The record therefore stays at MUTATION_REQUESTED, which already means
        # exactly this: issued, outcome unknown. Reconciliation converts it to
        # MUTATED if the authorized target is observed live, and refuses to
        # re-fire it either way, so one authorization still produces at most one
        # infrastructure effect.
        log_event(
            "execution_outcome_unknown",
            severity="ERROR",
            trace_id=trace_id,
            incident_id=request.incident_id,
            execution_id=execution_id,
            http_status=mutation.get("http_status"),
            resource_version_sent=base["resource_version_sent"],
        )
        # Record it in the execution plane before answering. For an incident
        # class defined entirely by "we do not know what happened", keeping the
        # least evidence about it in the plane that owns execution would be the
        # wrong way round — the only surviving copy would be the one the
        # orchestrator writes to the control plane, which is the plane this
        # identity is deliberately not allowed to write.
        await run_in_threadpool(
            store.record_receipt,
            action_id,
            {**action.model_dump(mode="json"), "incident_id": request.incident_id},
        )
        # And give the lease back. The record stays at MUTATION_REQUESTED, which
        # already refuses a re-fire, so holding the lease for its full term only
        # delays the reconciliation that settles this.
        await run_in_threadpool(
            store.release, execution_id, owner=owner, lease_epoch=epoch
        )
        return _refuse(
            "MUTATION_OUTCOME_UNKNOWN",
            http_status=mutation.get("http_status"),
            retryable=False,
            result=mutation,
            action=action.model_dump(mode="json"),
            **base,
        )

    final_state = ExecutionState.MUTATED
    state_result, _ = await run_in_threadpool(
        _advance,
        final_state,
        expect_states=(ExecutionState.MUTATION_REQUESTED,),
        action_id=action_id,
        accepted=accepted,
        resource_version_after=mutation.get("resource_version_after"),
    )

    if state_result == LEASE_LOST:
        # Our own lease lapsed while the Cloud Run call was in flight, and
        # nobody else has taken over. That is not a fence — re-acquiring is
        # legitimate, and recording what actually happened is strictly better
        # than leaving a successful mutation unaccounted for.
        retake, retaken = await run_in_threadpool(
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
        if retake in (ACQUIRED, RECOVERED):
            epoch = int((retaken or {}).get("lease_epoch") or 0)
            base["lease_epoch"] = epoch
            base["lease_reacquired_after_mutation"] = True
            state_result, _ = await run_in_threadpool(
                _advance,
                final_state,
                expect_states=(ExecutionState.MUTATION_REQUESTED,),
                action_id=action_id,
                accepted=accepted,
                resource_version_after=mutation.get("resource_version_after"),
            )
        log_event(
            "execution_lease_lapsed_during_mutation",
            severity="WARNING",
            trace_id=trace_id,
            incident_id=request.incident_id,
            execution_id=execution_id,
            reacquire=retake,
            state_result=state_result,
        )

    if state_result != ADVANCED:
        # A newer owner exists. We issued the mutation but must not claim it:
        # no receipt is written, and the lifecycle state stays whatever the
        # current owner says it is. Terminalization is gated on re-observed
        # infrastructure, so the authorized effect is still accounted for by
        # whoever holds the execution.
        log_event(
            "execution_state_write_fenced",
            severity="ERROR",
            trace_id=trace_id,
            incident_id=request.incident_id,
            execution_id=execution_id,
            fence_result=state_result,
            mutation_accepted=accepted,
        )
        base["state_write_fenced"] = state_result
    else:
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
        resource_version_sent=base["resource_version_sent"],
    )

    return {
        "executed": True,
        "mutated": accepted,
        "duplicate": False,
        "reconciled": False,
        "action_id": action_id,
        "state": action.state.value,
        "result": mutation,
        "action": action.model_dump(mode="json"),
        **base,
    }


@app.post("/terminalize")
async def terminalize(
    request: TerminalizeRequest,
    x_cloud_trace_context: str | None = Header(default=None),
) -> dict[str, Any]:
    """Close a mutated execution permanently, on re-derived evidence only.

    The caller cannot assert a verdict. The executor re-reads the authoritative
    decision, re-observes the live service, and requires the exact authorized
    revision to hold 100% of traffic with nothing else serving, plus a healthy
    response. Only then does the execution become VERIFIED, which is terminal:
    no later lease expiry, replay or takeover can re-run it.

    The orchestrator calls this only after the independent verifier, running
    under a different read-only identity, has returned RECOVERED. Two separate
    identities must therefore agree before an incident may be resolved.
    """
    trace_id = trace_id_from_header(x_cloud_trace_context)
    repo = authoritative()
    store = execution()

    try:
        decision = await run_in_threadpool(
            repo.get_decision, request.incident_id, request.decision_id
        )
    except DecisionNotFound:
        return _refuse("decision_not_found", decision_id=request.decision_id)

    problem = _validate(decision, request)
    if problem:
        return _refuse(problem, decision_id=request.decision_id)

    authorized_revision = decision["parameters"]["authorized_target_revision"]
    target_ref = decision["target_ref"]
    execution_id, _fingerprint = _identity(
        decision, request.incident_id, request.decision_id
    )

    current = await run_in_threadpool(store.get, execution_id)
    base: dict[str, Any] = {
        "execution_id": execution_id,
        "authorized_target_revision": authorized_revision,
        "state": (current or {}).get("state"),
    }
    if current is None:
        return _refuse("execution_not_found", **base)
    if current.get("state") == ExecutionState.VERIFIED.value:
        # Echo the evidence that closed this execution, from the record.
        #
        # Returning only {verified, terminal, outcome} could never satisfy the
        # caller's contract, which requires `serves_authorized_exclusively` to
        # be exactly True — so an incident whose repair had already been
        # verified and terminalized could never be reported RESOLVED. Every
        # reconcile attempt re-entered here, returned the same unsatisfying
        # payload, and rested the incident right back where it started. A fully
        # repaired site would have stayed open forever.
        #
        # This is a record, not a fresh observation, and says so. Re-probing
        # here would be wrong: whether the service is healthy *now* is a
        # different question from whether this execution was verified, and a
        # later unrelated outage must not un-terminalize a finished execution.
        recorded_allocation = current.get("verified_traffic_allocation") or {}
        return {
            "verified": True,
            "terminal": True,
            "outcome": ALREADY_TERMINAL,
            **base,
            "traffic_allocation": recorded_allocation,
            "serves_authorized_exclusively": bool(
                current.get("verified_serves_exclusively")
                or recorded_allocation == {authorized_revision: 100}
            ),
            "http_status": current.get("verified_http_status"),
            "http_healthy": bool(current.get("verified_http_healthy", True)),
            "evidence_from_record": True,
        }
    # MUTATED only. `MUTATION_REQUESTED` is written *before* the Cloud Run call,
    # so accepting it would let an execution be closed as VERIFIED on the
    # strength of a healthy service some other actor produced. A mutation whose
    # success write was fenced is converted to MUTATED by reconciliation, which
    # observes that the authorized target really is live, and the incident stays
    # reconcilable until it does — so nothing is stranded by being strict here.
    if current.get("state") not in TERMINALIZABLE_STATES:
        return _refuse("execution_not_mutated", **base)

    described = await run_in_threadpool(describe_service, target_ref)
    exclusive = serves_exclusively(described, authorized_revision)
    status_code, body = await run_in_threadpool(probe_health, described.get("uri", ""))
    healthy = status_code == 200 and body_is_healthy(body)
    allocation = traffic_allocation(described)

    evidence = {
        "traffic_allocation": allocation,
        "serves_authorized_exclusively": exclusive,
        "http_status": status_code,
        "http_healthy": healthy,
    }

    if not (exclusive and healthy):
        log_event(
            "execution_terminalization_refused",
            severity="WARNING",
            trace_id=trace_id,
            incident_id=request.incident_id,
            execution_id=execution_id,
            **evidence,
        )
        return _refuse("infrastructure_does_not_match_authorization", **base, **evidence)

    outcome, record = await run_in_threadpool(
        store.terminalize,
        execution_id,
        ExecutionState.VERIFIED,
        expect_states=(ExecutionState.MUTATED,),
        verified_at=utc_now(),
        verified_traffic_allocation=allocation,
        verified_http_status=status_code,
        verified_http_healthy=healthy,
        verified_serves_exclusively=exclusive,
    )
    log_event(
        "execution_terminalized",
        trace_id=trace_id,
        incident_id=request.incident_id,
        execution_id=execution_id,
        outcome=outcome,
        **evidence,
    )
    return {
        "verified": outcome in (ADVANCED, ALREADY_TERMINAL),
        "terminal": True,
        "outcome": outcome,
        **base,
        "state": (record or {}).get("state", ExecutionState.VERIFIED.value),
        **evidence,
    }
