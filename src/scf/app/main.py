from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field, StrictBool, ValidationError

from scf import config
from scf.app.invoke import WorkerResponseTooLarge, call_service
from scf.domain.enums import (
    ActionType,
    Decision,
    IncidentStatus,
    SpecialistName,
    TrustLevel,
)
from scf.domain.failures import (
    FailureCategory,
    build_escalation_package,
    handling,
)
from scf.domain.ids import new_incident_id
from scf.domain.state_machine import path_to
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
    except Exception as exc:  # noqa: BLE001 - categorised, never re-raised raw
        # The incident is already persisted, so failing the HTTP call here would
        # strand it at INTAKE with nobody told and nothing to reconcile. It is
        # escalated instead, with a human handover, and the manager gets an
        # answer rather than a 502.
        log_event(
            "adk_invocation_failed",
            severity="ERROR",
            trace_id=trace_id,
            incident_id=incident_id,
            error_type=type(exc).__name__,
        )
        failed = await _fail(
            repo,
            incident_id,
            WorkflowFailure(
                FailureCategory.MODEL_OUTPUT_INVALID,
                f"routing contract not satisfied ({type(exc).__name__})",
            ),
            trace_id,
            {"attempted": True, "specialists_attempted": []},
        )
        final = await run_in_threadpool(repo.get, incident_id)
        return IncidentCreated(
            incident_id=incident_id,
            status=final["status"],
            summary=failed["escalation"]["impact"],
            required_specialists=[],
            routes=[],
            remediation=failed,
            trace_id=trace_id,
        )

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


#: Actions the closed enum deliberately keeps proposable so the deterministic
#: gate is what refuses them, on the record. A model that hallucinates one of
#: these produces an audited denial, never a capability.
DANGEROUS_ACTIONS = frozenset({ActionType.EXPORT_CREDENTIALS, ActionType.DISABLE_FIREWALL})

#: Executor refusal reasons, mapped onto the taxonomy. Anything unrecognised
#: falls through to REMEDIATION_FAILED, which escalates — failing closed on an
#: unknown refusal rather than inventing a recovery for it.
EXECUTION_FAILURE_CATEGORIES: dict[str, FailureCategory] = {
    "CONCURRENT_MODIFICATION": FailureCategory.EXECUTION_CONFLICT,
    "STALE_EVIDENCE": FailureCategory.STALE_EVIDENCE,
    "TARGET_NO_LONGER_HEALTHY": FailureCategory.TARGET_NO_LONGER_HEALTHY,
    # NOT StaleEvidence. The executor's own detail says "this execution may
    # already have issued its mutation" and that it stays recoverable — mapping
    # that to STALE_EVIDENCE (terminal, not reconcilable) closed the incident on
    # a claim nobody could support, and told the manager "Nothing was changed"
    # about a mutation that may well have landed. A Cloud Run traffic migration
    # is asynchronous, so an observation taken moments after our own write can
    # legitimately still show the old revision.
    "MUTATION_DID_NOT_HOLD": FailureCategory.EXECUTION_OUTCOME_UNKNOWN,
    # Issued, and Google answered with something that is not proof either way.
    "MUTATION_OUTCOME_UNKNOWN": FailureCategory.EXECUTION_OUTCOME_UNKNOWN,
}


def _execution_failure_category(receipt: dict[str, Any]) -> FailureCategory:
    reason = str(receipt.get("reason") or "")
    if reason == "CONCURRENT_MODIFICATION" and not _is_retryable_conflict(receipt):
        # The conflict is real but the executor could not wind its record back,
        # so the execution stays marked as attempted and this is not a clean
        # retry case.
        return FailureCategory.REMEDIATION_FAILED
    return EXECUTION_FAILURE_CATEGORIES.get(reason, FailureCategory.REMEDIATION_FAILED)


def _is_retryable_conflict(receipt: dict[str, Any]) -> bool:
    """A Cloud Run precondition conflict that provably applied nothing.

    Both halves are required. `CONCURRENT_MODIFICATION` means Google refused
    the write with 409 ABORTED, and `retryable` means the executor also
    succeeded in winding its own record back — if its lease was taken while the
    conflicting call was in flight it could not, and the execution stays marked
    as attempted, which must not be treated as a clean retry.
    """
    return (
        receipt.get("reason") == "CONCURRENT_MODIFICATION"
        and receipt.get("retryable") is True
    )


class DownstreamFailure(Exception):
    """A service-to-service call failed. The incident must not hang."""

    def __init__(self, service: str, kind: str, detail: str) -> None:
        super().__init__(f"{service}: {kind}")
        self.service = service
        self.kind = kind
        self.detail = detail[:300]




async def _escalate(
    repo: IncidentRepository, incident_id: str, trace_id: str | None
) -> str:
    """Drive the incident to a terminal state along a legal path."""
    current = IncidentStatus(
        (await run_in_threadpool(repo.get, incident_id))["status"]
    )
    if current in (IncidentStatus.RESOLVED, IncidentStatus.ESCALATED):
        return current.value
    for step in path_to(current, IncidentStatus.ESCALATED):
        await run_in_threadpool(repo.transition, incident_id, step, trace_id=trace_id)
    return IncidentStatus(
        (await run_in_threadpool(repo.get, incident_id))["status"]
    ).value


#: Per-service call bounds. A worker that hangs must be ended by the caller's
#: own clock, not by hope: an outage cannot be allowed to wait on a stuck
#: investigator. Each is comfortably above the healthy path's real duration
#: (investigator ~4 s, executor ~5 s) and well below any human's patience.
#: The verifier's is larger because it deliberately polls a settle window.
#: The caller's bound must sit ABOVE the worker's own deadline, or the worker's
#: budget never gets to fire: the call is abandoned first and a clean, truthful
#: `WORKER_BUDGET_EXCEEDED` contract is replaced by a bare timeout that says
#: nothing about what the worker managed to learn.
CALL_TIMEOUTS: dict[str, float] = {
    "investigator": float(os.environ.get("SCF_INVESTIGATOR_TIMEOUT", "60")),
    "executor": float(os.environ.get("SCF_EXECUTOR_TIMEOUT", "120")),
    "verifier": float(os.environ.get("SCF_VERIFIER_TIMEOUT", "150")),
}

#: Retry budgets, stated as constants so they can be audited rather than
#: inferred. Every one is zero: a failed downstream call is a failure to be
#: handled deterministically, never a reason to try the same thing again in a
#: loop. Recovery is reconciliation against real state, which is a different
#: operation with a different guard.
DOWNSTREAM_RETRY_BUDGET = 0
MODEL_PARSE_RETRY_BUDGET = 0
MUTATION_RETRY_BUDGET = 0


async def _call(
    url: str,
    path: str,
    payload: dict[str, Any],
    *,
    service: str,
    trace_header: str | None,
) -> dict[str, Any]:
    """Bounded, explicitly-typed, single-attempt downstream call.

    One attempt. There is no retry loop here and no back-off: see
    DOWNSTREAM_RETRY_BUDGET.
    """
    if not url:
        raise DownstreamFailure(service, "not_configured", "service URL is empty")
    try:
        response = await run_in_threadpool(
            call_service,
            url,
            path,
            payload,
            trace_header=trace_header,
            timeout=CALL_TIMEOUTS.get(service, 60.0),
        )
    except WorkerResponseTooLarge as exc:
        # Refused unread, and categorised as what it is: a worker that broke the
        # size contract, not a worker that could not be reached.
        raise DownstreamFailure(service, "oversized_response", str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - converted to a typed failure
        raise DownstreamFailure(service, type(exc).__name__, str(exc)) from exc
    if response.status_code >= 400:
        raise DownstreamFailure(
            service, f"http_{response.status_code}", response.text
        )
    try:
        body = response.json()
    except (ValueError, RecursionError) as exc:
        # RecursionError, deliberately. `json.loads` raises it — NOT ValueError —
        # on a deeply nested payload, so a worker answering 200 with
        # `"["*100000` escaped every typed failure path in this module. On the
        # primary path the workflow's catch-all still escalated it; on the
        # RECOVERY path there was no catch-all, so the incident stranded at
        # VERIFYING, which is neither terminal nor reconcilable. The endpoint
        # that exists to rescue incidents was the one that could lose them.
        raise DownstreamFailure(service, "malformed_response", type(exc).__name__) from exc
    if not isinstance(body, dict):
        # A worker may be authenticated, return 200, and still hand back a list,
        # a string or null. Every caller downstream treats this as a mapping, so
        # letting it through would raise an AttributeError deep in the workflow
        # — outside the failure taxonomy, and with the incident left mid-flight.
        raise DownstreamFailure(
            service, "malformed_response", f"expected a JSON object, got {type(body).__name__}"
        )
    return body


#: Transport-level failures that mean "the worker never answered in time".
TIMEOUT_KINDS = frozenset(
    {"ReadTimeout", "ConnectTimeout", "PoolTimeout", "WriteTimeout", "TimeoutException"}
)


def _categorise(failure: DownstreamFailure) -> FailureCategory:
    """Map a downstream failure onto exactly one taxonomy category.

    Which service failed matters more than how. For the executor and the
    verifier — the two components that touch or grade infrastructure — *any*
    failure to reach them means the outcome is unknown, and an unknown outcome
    must stay reconcilable. A timeout is the sharpest case: the executor may
    well have completed the mutation and simply outlived our patience, so
    treating it as a terminal failure would let the fleet fix an outage and
    then report that it had not. That is a false negative, and it is worse than
    a slow answer.

    The investigator is different: it is read-only and changes nothing, so
    failing to reach it can be escalated safely.
    """
    if failure.service == "executor":
        return FailureCategory.EXECUTOR_UNAVAILABLE
    if failure.service == "verifier":
        return FailureCategory.VERIFIER_UNAVAILABLE
    if failure.kind in TIMEOUT_KINDS:
        return FailureCategory.WORKER_TIMEOUT
    if failure.kind in ("malformed_response", "oversized_response"):
        return FailureCategory.WORKER_CONTRACT_INVALID
    return FailureCategory.WORKER_UNAVAILABLE


class WorkflowFailure(Exception):
    """A categorised failure. Every non-happy path raises exactly one of these."""

    def __init__(
        self,
        category: FailureCategory,
        detail: str = "",
        **context: Any,
    ) -> None:
        super().__init__(f"{category.value}: {detail}")
        self.category = category
        self.detail = detail[:300]
        self.context = context


async def _fail(
    repo: IncidentRepository,
    incident_id: str,
    failure: WorkflowFailure,
    trace_id: str | None,
    outcome: dict[str, Any],
) -> dict[str, Any]:
    """The single place a failure becomes state, audit and a human handover.

    Looking up the category in one table is what stops the workflow inventing
    per-site behaviour: where the incident rests, whether it stays reconcilable,
    what the manager is told and what is audited all come from the same row.
    """
    rule = handling(failure.category)
    outcome["failure_category"] = failure.category.value
    outcome["failure_detail"] = failure.detail
    outcome.update(failure.context)

    log_event(
        rule.audit_event,
        severity="ERROR",
        trace_id=trace_id,
        incident_id=incident_id,
        failure_category=failure.category.value,
        detail=failure.detail,
        reconcilable=rule.reconcilable,
    )
    await run_in_threadpool(
        repo.append_audit,
        incident_id,
        actor="orchestrator",
        event=rule.audit_event,
        payload={"failure_category": failure.category.value, "detail": failure.detail},
        trace_id=trace_id,
    )

    # Walk to the resting state along a legal path. A reconcilable failure
    # stops at a non-terminal state on purpose: the outcome is unknown, and an
    # incident whose infrastructure state is unknown must never be closed.
    if rule.reconcilable:
        current = IncidentStatus(
            (await run_in_threadpool(repo.get, incident_id))["status"]
        )
        # Walked, not assumed. A single hop presumed the resting state was
        # always one legal edge away — true of every raise site that existed
        # when it was written, and false the moment a new one appeared. It then
        # raised IllegalTransition from inside the one handler whose job is to
        # guarantee a handover, so the failure it was invoked to report escaped
        # as an unhandled exception and the incident got nothing at all.
        for step in path_to(current, rule.resting_status):
            await run_in_threadpool(repo.transition, incident_id, step, trace_id=trace_id)
        settled = IncidentStatus(
            (await run_in_threadpool(repo.get, incident_id))["status"]
        )
        outcome["awaiting_reconciliation"] = settled in RECONCILABLE_STATES
        outcome["final_status"] = settled.value
    else:
        outcome["final_status"] = await _escalate(repo, incident_id, trace_id)

    observed = _observe_service_state(outcome)
    package = build_escalation_package(
        incident_id=incident_id,
        category=failure.category,
        correlation_id=trace_id,
        specialists_attempted=outcome.get("specialists_attempted", []),
        evidence_keys=outcome.get("evidence_keys", []),
        mutated=bool(outcome.get("mutated_infrastructure")),
        current_service_state=observed["state"],
        operations_restored=observed["restored"],
    ).model_dump(mode="json")
    await run_in_threadpool(repo.save_escalation, incident_id, package, trace_id=trace_id)
    outcome["escalation"] = package
    return outcome


def _observe_service_state(outcome: dict[str, Any]) -> dict[str, Any]:
    """What a human would see, from evidence the fleet actually gathered.

    Deliberately NOT a fresh probe by the orchestrator. The orchestrator holds
    no read permission on the target service — that permission belongs to the
    investigator and the verifier, under their own identities — and widening it
    to populate a status line would trade a real security boundary for a
    cosmetic one. So this reports what was genuinely observed by an identity
    authorized to look, and says plainly when nothing was.
    """
    checked = outcome.get("verification_checked")
    if isinstance(checked, dict):
        restored = checked.get("recovered") is True
        return {
            "state": (
                "the dispatch service is responding normally"
                if restored
                else "the dispatch service is still not responding normally"
            ),
            "restored": restored,
        }

    healthy = outcome.get("service_observed_healthy")
    if isinstance(healthy, bool):
        return {
            "state": (
                "the dispatch service is responding normally"
                if healthy
                else "the dispatch service is still not responding normally"
            ),
            "restored": healthy,
        }

    # No bare 200 may claim recovery. A service can answer 200 with a body
    # saying it is unhealthy, so a status code without the trusted health
    # verdict beside it is not evidence that operations are restored — only
    # evidence that something answered. A non-200 is still allowed to say the
    # service is not responding: that direction cannot overstate the recovery.
    status = outcome.get("service_http_status")
    if isinstance(status, int) and status and status != 200:
        return {
            "state": "the dispatch service is still not responding normally",
            "restored": False,
        }
    # A failure early enough that nobody got to look — a timeout, an
    # unavailable investigator, unusable model output. Saying so is more useful
    # to a duty manager than a confident guess.
    return {"state": "could not be checked automatically", "restored": False}


async def _autonomous_remediation(
    repo: IncidentRepository,
    incident_id: str,
    trace_id: str | None,
    trace_header: str | None,
) -> dict[str, Any]:
    """Investigate, authorize, execute, verify. No operator step anywhere."""
    outcome: dict[str, Any] = {"attempted": True, "specialists_attempted": ["systems"]}
    try:
        return await _run_remediation(repo, incident_id, trace_id, trace_header, outcome)
    except WorkflowFailure as failure:
        return await _fail(repo, incident_id, failure, trace_id, outcome)
    except DownstreamFailure as failure:
        log_event(
            "downstream_failure",
            severity="ERROR",
            trace_id=trace_id,
            incident_id=incident_id,
            failed_service=failure.service,
            error_kind=failure.kind,
        )
        outcome["failed"] = {"service": failure.service, "kind": failure.kind}
        return await _fail(
            repo,
            incident_id,
            WorkflowFailure(_categorise(failure), f"{failure.service}/{failure.kind}"),
            trace_id,
            outcome,
        )
    except Exception as exc:  # noqa: BLE001 - nothing may strand an incident
        # A bug here must not leave an incident mid-flight with no handover.
        # Anything uncategorised is treated as a remediation failure, which
        # escalates: the safe direction when we do not know what happened.
        log_event(
            "workflow_unexpected_error",
            severity="ERROR",
            trace_id=trace_id,
            incident_id=incident_id,
            error_type=type(exc).__name__,
        )
        return await _fail(
            repo,
            incident_id,
            WorkflowFailure(
                FailureCategory.REMEDIATION_FAILED,
                f"unexpected workflow error ({type(exc).__name__})",
            ),
            trace_id,
            outcome,
        )


async def _run_remediation(
    repo: IncidentRepository,
    incident_id: str,
    trace_id: str | None,
    trace_header: str | None,
    outcome: dict[str, Any],
) -> dict[str, Any]:

    # 1. Systems Investigator, its own service under its own identity.
    body = await _call(
        INVESTIGATOR_URL,
        "/evidence",
        {"incident_id": incident_id, "service": config.DISPATCH_WEB_SERVICE},
        service="investigator",
        trace_header=trace_header,
    )

    # A 200 from an authenticated caller is not a reason to trust the payload.
    # Authentication says who is speaking; the contract says whether what they
    # said is usable. Both are required.
    try:
        envelope = InvestigatorEnvelope.model_validate(body)
    except ValidationError as exc:
        raise WorkflowFailure(
            FailureCategory.WORKER_CONTRACT_INVALID,
            "investigator envelope rejected: not the declared shape",
        ) from exc

    if envelope.budget_exceeded:
        raise WorkflowFailure(
            FailureCategory.WORKER_BUDGET_EXCEEDED,
            f"investigator exhausted {envelope.limit}",
            tool_calls=envelope.tool_calls,
        )
    if envelope.evidence is None:
        raise WorkflowFailure(
            FailureCategory.WORKER_CONTRACT_INVALID,
            "investigator returned no evidence field",
        )
    try:
        evidence = [Evidence.model_validate(item) for item in envelope.evidence]
    except (ValidationError, KeyError, TypeError) as exc:
        raise WorkflowFailure(
            FailureCategory.WORKER_CONTRACT_INVALID,
            f"investigator evidence rejected: {type(exc).__name__}",
        ) from exc

    await run_in_threadpool(repo.save_evidence, incident_id, evidence, trace_id=trace_id)
    outcome["evidence_count"] = len(evidence)
    outcome["evidence_keys"] = [item.key for item in evidence]
    # Recorded here so a later failure can tell the manager what the service
    # was actually doing, using evidence gathered by an authorized identity.
    observed = trusted_evidence_map(evidence)
    observed_status = observed.get("http_status")
    if isinstance(observed_status, int):
        outcome["service_http_status"] = observed_status
    # The status code is not the verdict. A service can answer 200 with a body
    # that says it is unhealthy, and the investigator's health reader is what
    # settles that — reporting "responding normally" off the bare 200 would
    # tell the manager the opposite of what the trusted evidence said.
    if isinstance(observed.get("service_unhealthy"), bool):
        outcome["service_observed_healthy"] = observed["service_unhealthy"] is False

    if envelope.proposal is None:
        # Doing nothing is a legitimate outcome. The system is not obliged to
        # change infrastructure just because it was asked to look. An *absent*
        # proposal says that; an empty or malformed one says something else
        # entirely, and falls through to the contract check below.
        raise WorkflowFailure(
            FailureCategory.INSUFFICIENT_EVIDENCE,
            "no remediation is warranted by the trusted evidence",
        )

    try:
        proposal = Proposal.model_validate(envelope.proposal)
    except ValidationError as exc:
        # An action outside the closed enum never becomes a domain object, so
        # it cannot reach the gate, let alone the executor.
        raise WorkflowFailure(
            FailureCategory.WORKER_CONTRACT_INVALID,
            "proposal is not a member of the closed action contract",
            rejected_action=str(envelope.proposal.get("action_type"))[:64],
        ) from exc
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
        parameters={
            # The decision authorizes ONE exact revision. The executor may not
            # substitute another, and the verifier must observe this one.
            "authorized_target_revision": facts.get("candidate_revision"),
            # TOCTOU guards captured from the same trusted evidence snapshot.
            "expected_source_revision": facts.get("active_revision"),
            "expected_etag": facts.get("service_etag"),
        },
        trace_id=trace_id,
    )
    outcome["decision"] = policy_decision.decision.value
    outcome["reason_code"] = policy_decision.reason_code
    outcome["decision_id"] = policy_decision.decision_id

    if policy_decision.decision is Decision.DENIED:
        # The gate refused, on the record, with a reason code. A hallucinated
        # privileged action ends here: it was proposable, it was never
        # authorized, and nothing was touched.
        await run_in_threadpool(
            repo.transition, incident_id, IncidentStatus.DENIED, trace_id=trace_id
        )
        raise WorkflowFailure(
            FailureCategory.DANGEROUS_ACTION_REFUSED
            if proposal.action_type in DANGEROUS_ACTIONS
            else FailureCategory.INSUFFICIENT_EVIDENCE,
            f"policy denied {proposal.action_type.value}: {policy_decision.reason_code}",
            denied_action=proposal.action_type.value,
            reason_code=policy_decision.reason_code,
        )

    if policy_decision.decision is not Decision.AUTO_ALLOWED:
        # Record that approval was required — that is the true state — and then
        # escalate, because nothing in this fleet can grant it yet. Returning
        # here left the incident parked at WAITING_FOR_APPROVAL with no
        # handover, no failure category, and no endpoint able to move it.
        await run_in_threadpool(
            repo.transition,
            incident_id,
            IncidentStatus.WAITING_FOR_APPROVAL,
            trace_id=trace_id,
        )
        raise WorkflowFailure(
            FailureCategory.APPROVAL_REQUIRED_NO_APPROVER,
            f"{proposal.action_type.value} requires "
            f"{policy_decision.required_approval_role or 'an approver'}",
            reason_code=policy_decision.reason_code,
            required_approval_role=policy_decision.required_approval_role,
        )

    await run_in_threadpool(
        repo.transition, incident_id, IncidentStatus.AUTO_ALLOWED, trace_id=trace_id
    )

    # 3. Scoped executor. The orchestrator may call it but holds none of its
    #    infrastructure rights, and passes identifiers only.
    await run_in_threadpool(
        repo.transition, incident_id, IncidentStatus.EXECUTING, trace_id=trace_id
    )
    receipt = await _call(
        EXECUTOR_URL,
        "/execute",
        {"incident_id": incident_id, "decision_id": policy_decision.decision_id},
        service="executor",
        trace_header=trace_header,
    )
    outcome["execution"] = receipt
    try:
        reported = ExecutionReceipt.model_validate(receipt)
    except ValidationError as exc:
        await run_in_threadpool(
            repo.transition, incident_id, IncidentStatus.EXECUTION_FAILED,
            trace_id=trace_id,
        )
        raise WorkflowFailure(
            FailureCategory.WORKER_CONTRACT_INVALID,
            f"executor receipt is not a valid contract ({exc.error_count()})",
        ) from exc

    # The executor cannot write the control plane. The orchestrator, which is
    # an authoritative writer, records what the executor reported.
    if reported.duplicate:
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
                "accepted": reported.mutated,
                "idempotency_key": receipt.get("idempotency_key"),
                "execution_database": receipt.get("execution_database"),
            },
            actor_identity="sa-executor",
            trace_id=trace_id,
        )

    if reported.mutated:
        outcome["mutated_infrastructure"] = True

    if not (reported.progressed() or _execution_already_landed(receipt)):
        # `_execution_already_landed` belongs on BOTH paths, not just recovery.
        # A duplicate-suppressed receipt reports `mutated: False` because *this
        # call* changed nothing — but the execution it collided with is at
        # MUTATED, so the authorized traffic flip has in fact landed. Reading
        # only `progressed()` closed such an incident as REMEDIATION_FAILED,
        # which is terminal and not reconcilable: the site was back up and the
        # duty manager was told the repair had failed, with no route to correct
        # it. That happens whenever a second orchestrator instance, an ingress
        # retry, or a worker that outlived its caller reaches the executor
        # first — not a rare race, and the worst error this system can make.
        await run_in_threadpool(
            repo.transition, incident_id, IncidentStatus.EXECUTION_FAILED, trace_id=trace_id
        )
        raise WorkflowFailure(
            _execution_failure_category(receipt),
            str(receipt.get("reason") or "execution did not complete")[:200],
            execution_reason=receipt.get("reason"),
        )

    await run_in_threadpool(
        repo.transition, incident_id, IncidentStatus.EXECUTED, trace_id=trace_id
    )

    # 4. Independent verification under a different, read-only identity.
    await run_in_threadpool(
        repo.transition, incident_id, IncidentStatus.VERIFYING, trace_id=trace_id
    )
    return await _verify_and_close(
        repo,
        incident_id,
        policy_decision.decision_id,
        facts.get("candidate_revision"),
        trace_id,
        trace_header,
        outcome,
    )


async def _verify_and_close(
    repo: IncidentRepository,
    incident_id: str,
    decision_id: str,
    expected_revision: str | None,
    trace_id: str | None,
    trace_header: str | None,
    outcome: dict[str, Any],
) -> dict[str, Any]:
    """Verify independently, terminalize the execution, then resolve.

    The order matters. An incident is never resolved while its successful
    execution is still recoverable as MUTATED — that would leave a completed
    incident whose execution a later lease expiry could re-enter. Verification
    comes from a different read-only identity; terminalization requires the
    executor to independently re-observe the same infrastructure. Both must
    agree.

    If verification cannot be obtained at all, the incident stops at
    REMEDIATION_FAILED, which is deliberately not terminal: the mutation
    happened, the outcome is unknown, and reconciliation — not a guess — closes
    it. It is never resolved unverified.
    """
    try:
        verdict = await _call(
            VERIFIER_URL,
            "/verify",
            {
                "incident_id": incident_id,
                "service": config.DISPATCH_WEB_SERVICE,
                "expected_revision": expected_revision,
            },
            service="verifier",
            trace_header=trace_header,
        )
    except DownstreamFailure as failure:
        outcome["failed"] = {"service": failure.service, "kind": failure.kind}
        return await _fail(
            repo,
            incident_id,
            WorkflowFailure(
                FailureCategory.VERIFIER_UNAVAILABLE,
                f"verifier/{failure.kind}",
            ),
            trace_id,
            outcome,
        )

    outcome["verification"] = verdict
    try:
        checked = VerifierVerdict.model_validate(verdict)
    except ValidationError as exc:
        return await _fail(
            repo,
            incident_id,
            WorkflowFailure(
                FailureCategory.WORKER_CONTRACT_INVALID,
                f"verifier response is not a valid verdict ({exc.error_count()})",
            ),
            trace_id,
            outcome,
        )
    # Only a verdict that passed the contract may speak for the service. The
    # raw body must never reach the manager-facing summary: a verifier
    # answering `{"verdict": "RECOVERED"}` with none of the three required
    # observations is rejected here, and an escalation package that still read
    # the raw string would have told the manager operations were restored while
    # the incident escalated.
    outcome["verification_checked"] = {"recovered": checked.recovered()}
    await run_in_threadpool(
        repo.append_audit,
        incident_id,
        actor="verifier",
        event="verification",
        payload={
            "verdict": verdict.get("verdict"),
            "http_status": verdict.get("http_status"),
            "active_revision": verdict.get("active_revision"),
            "traffic_allocation_exclusive": verdict.get("traffic_allocation_exclusive"),
        },
        trace_id=trace_id,
    )

    if not checked.recovered():
        await run_in_threadpool(
            repo.transition,
            incident_id,
            IncidentStatus.REMEDIATION_FAILED,
            trace_id=trace_id,
        )
        return await _fail(
            repo,
            incident_id,
            WorkflowFailure(
                FailureCategory.VERIFICATION_FAILED,
                "the authorized revision is not serving healthily",
                verdict=verdict.get("verdict"),
            ),
            trace_id,
            outcome,
        )

    try:
        terminal = await _call(
            EXECUTOR_URL,
            "/terminalize",
            {"incident_id": incident_id, "decision_id": decision_id},
            service="executor",
            trace_header=trace_header,
        )
    except DownstreamFailure as failure:
        # Same rule as an unavailable verifier: the execution is still
        # recoverable as MUTATED, so the incident stays reconcilable rather
        # than being closed either way.
        outcome["failed"] = {"service": failure.service, "kind": failure.kind}
        return await _fail(
            repo,
            incident_id,
            WorkflowFailure(
                FailureCategory.VERIFIER_UNAVAILABLE,
                f"terminalization unreachable: executor/{failure.kind}",
            ),
            trace_id,
            outcome,
        )
    outcome["terminalization"] = terminal
    try:
        closed = TerminalizationReceipt.model_validate(terminal)
    except ValidationError as exc:
        return await _fail(
            repo,
            incident_id,
            WorkflowFailure(
                FailureCategory.WORKER_CONTRACT_INVALID,
                f"terminalization response is not a valid receipt ({exc.error_count()})",
            ),
            trace_id,
            outcome,
        )
    await run_in_threadpool(
        repo.append_audit,
        incident_id,
        actor="executor",
        event="execution_terminalized",
        payload={
            "execution_id": terminal.get("execution_id"),
            "outcome": terminal.get("outcome"),
            "state": terminal.get("state"),
            "serves_authorized_exclusively": terminal.get(
                "serves_authorized_exclusively"
            ),
        },
        actor_identity="sa-executor",
        trace_id=trace_id,
    )

    if not closed.terminal():
        await run_in_threadpool(
            repo.transition,
            incident_id,
            IncidentStatus.REMEDIATION_FAILED,
            trace_id=trace_id,
        )
        # Only a genuine mismatch between infrastructure and the authorization
        # closes the incident. A bookkeeping refusal — the execution record is
        # not where terminalization expected it — means the outcome is unknown,
        # not bad, so the incident stays reconcilable rather than being
        # escalated on the strength of our own record-keeping.
        mismatch = terminal.get("reason") == "infrastructure_does_not_match_authorization"
        return await _fail(
            repo,
            incident_id,
            WorkflowFailure(
                FailureCategory.VERIFICATION_FAILED
                if mismatch
                else FailureCategory.VERIFIER_UNAVAILABLE,
                str(terminal.get("reason") or "terminalization refused")[:200],
            ),
            trace_id,
            outcome,
        )

    await run_in_threadpool(
        repo.transition, incident_id, IncidentStatus.RESOLVED, trace_id=trace_id
    )
    outcome["final_status"] = IncidentStatus.RESOLVED.value
    return outcome


class InvestigatorEnvelope(BaseModel):
    """The investigator's answer, as a contract rather than raw `.get()`.

    Authentication says who is speaking. It does not say that what they said
    means what it appears to mean. Two concrete confusions this closes:

    * `{"budget_exceeded": "false"}` is a truthy string. Read with `.get()` a
      complete, usable investigation would have been thrown away as budget
      exhaustion, and the incident escalated with evidence sitting unused.
    * `{"proposal": {}}` is falsy. Read with `.get()` a malformed proposal
      would have been reported to the manager as "nothing to do here" — a
      contract violation described as a considered decision not to act.

    `evidence` and `proposal` stay loosely typed here on purpose: this envelope
    settles *presence and shape*, and `Evidence` / `Proposal` remain the
    authorities on their own contents, each rejecting into its own category.
    """

    model_config = ConfigDict(extra="ignore")

    evidence: list[Any] | None = None
    proposal: dict[str, Any] | None = None
    budget_exceeded: StrictBool = False
    limit: str | None = None
    tool_calls: int | None = None


class ExecutionReceipt(BaseModel):
    """What the executor reported, as a contract rather than truthiness.

    `{"mutated": "false"}` is a non-empty string and therefore truthy: read with
    `.get()` it would have been taken as a successful mutation, and the incident
    would have advanced toward RESOLVED reporting a change that the receipt
    itself denied. Strict booleans only.
    """

    model_config = ConfigDict(extra="ignore")

    mutated: StrictBool = False
    reconciled: StrictBool = False
    duplicate: StrictBool = False
    refused: StrictBool = False
    state: str | None = None
    reason: str | None = None
    retryable: StrictBool | None = None

    def progressed(self) -> bool:
        """Did the authorized effect actually move forward?"""
        return self.mutated or self.reconciled


class VerifierVerdict(BaseModel):
    """The verifier's answer, as a contract rather than a hopeful `.get()`.

    A 200 from an authenticated verifier is not a verdict. Recovery requires the
    verdict string, the exact authorized revision, an exclusive traffic
    allocation and a healthy response — all four present and all four true.
    """

    # StrictBool, deliberately. Ordinary `bool` coercion accepts "yes", "true"
    # and 1 — so a worker returning a *string* would have satisfied a boolean
    # safety condition. Only a real JSON boolean counts.
    model_config = ConfigDict(extra="ignore")

    verdict: str
    http_healthy: StrictBool
    revision_matches_authorized: StrictBool
    traffic_allocation_exclusive: StrictBool

    def recovered(self) -> bool:
        return (
            self.verdict == "RECOVERED"
            and self.http_healthy
            and self.revision_matches_authorized
            and self.traffic_allocation_exclusive
        )


class TerminalizationReceipt(BaseModel):
    """The executor's terminalization answer, likewise typed.

    `{"verified": true}` alone must never close an incident. The execution has
    to actually be in the terminal state, and the executor has to have
    re-observed the authorized revision serving exclusively.
    """

    model_config = ConfigDict(extra="ignore")

    # Defaults to False so a REFUSAL can be read as one. The executor builds
    # every refusal through a helper that emits no `verified` key at all, so a
    # required field meant each refusal failed validation instead — and the
    # contract-invalid path escalates terminally. A repaired site whose
    # verifier had just confirmed it was closed as ESCALATED, telling the duty
    # manager nothing had changed, while the branch written to handle exactly
    # this case sat unreachable below.
    verified: StrictBool = False
    reason: str | None = None
    state: str | None = None
    serves_authorized_exclusively: StrictBool | None = None

    def terminal(self) -> bool:
        return (
            self.verified
            and self.state == "VERIFIED"
            and self.serves_authorized_exclusively is True
        )


#: Execution states meaning the authorized effect has been issued or completed
#: by somebody. Reconciliation must not read these as failure.
LANDED_EXECUTION_STATES = frozenset({"MUTATED", "VERIFIED", "MUTATION_REQUESTED"})


def _execution_already_landed(receipt: dict[str, Any]) -> bool:
    """Did a worker other than this call already carry the execution forward?

    A duplicate outcome — the execution is held by a live owner, or already
    finished — is not a failed remediation. A worker that outlived the caller
    who was waiting on it still did the work. Escalating on that would close an
    incident whose fix had in fact landed, which is the worst error this system
    can make: it tells a duty manager nothing was done while the shop is back
    up, and leaves no route to correct it.
    """
    try:
        reported = ExecutionReceipt.model_validate(receipt)
    except ValidationError:
        # An unreadable receipt proves nothing landed.
        return False
    if not reported.duplicate:
        return False
    return str(reported.state or "") in LANDED_EXECUTION_STATES


#: Non-terminal states meaning "a mutation may have happened and we could not
#: establish the outcome". Neither may be resolved without reading reality.
RECONCILABLE_STATES = frozenset(
    {IncidentStatus.REMEDIATION_FAILED, IncidentStatus.EXECUTION_FAILED}
)


@app.post("/incidents/{incident_id}/reconcile")
async def reconcile_incident(
    incident_id: str,
    x_cloud_trace_context: str | None = Header(default=None),
) -> dict[str, Any]:
    """Resume an incident whose mutation landed but whose verification did not.

    Takes no authorization input whatsoever: the orchestrator resolves the
    incident's own decision, re-delivers it to the executor — which reconciles
    against real infrastructure rather than mutating blindly — then verifies and
    terminalizes through the normal path.
    """
    trace_id = trace_id_from_header(x_cloud_trace_context)
    repo = repository()
    try:
        document = await run_in_threadpool(repo.get, incident_id)
    except IncidentNotFound as exc:
        raise HTTPException(status_code=404, detail="incident not found") from exc

    status = IncidentStatus(document["status"])
    if status not in RECONCILABLE_STATES:
        return {"incident_id": incident_id, "status": status.value, "reconciled": False,
                "reason": "not_awaiting_reconciliation"}

    decision = await run_in_threadpool(repo.latest_decision, incident_id)
    if not decision:
        raise HTTPException(status_code=409, detail="no decision to reconcile")

    outcome: dict[str, Any] = {"attempted": True, "reconciliation": True}
    try:
        receipt = await _call(
            EXECUTOR_URL,
            "/execute",
            {"incident_id": incident_id, "decision_id": decision["decision_id"]},
            service="executor",
            trace_header=x_cloud_trace_context,
        )
        outcome["execution"] = receipt
        try:
            reported = ExecutionReceipt.model_validate(receipt)
        except ValidationError as exc:
            # Same rule as the primary path: an unreadable receipt from an
            # authenticated worker decides nothing.
            outcome["failure_category"] = FailureCategory.WORKER_CONTRACT_INVALID.value
            outcome["failure_detail"] = (
                f"executor receipt is not a valid contract ({exc.error_count()})"
            )
            final = await run_in_threadpool(repo.get, incident_id)
            outcome.update(
                {"incident_id": incident_id, "status": final["status"],
                 "reconciled": False}
            )
            return outcome
        log_event(
            "reconciliation_execution",
            trace_id=trace_id,
            incident_id=incident_id,
            mutated=reported.mutated,
            reconciled=reported.reconciled,
            state=reported.state,
        )

        if status is IncidentStatus.EXECUTION_FAILED:
            # The incident never left the execution phase, because we could not
            # reach the executor to learn the outcome. Reconciliation does not
            # re-open execution — it establishes what actually happened.
            if not (reported.progressed() or _execution_already_landed(receipt)):
                if _is_retryable_conflict(receipt):
                    # Same rule on the recovery path: a conflict that applied
                    # nothing leaves the incident reconcilable rather than
                    # closing it.
                    outcome["awaiting_reconciliation"] = True
                    outcome["final_status"] = IncidentStatus.EXECUTION_FAILED.value
                    final = await run_in_threadpool(repo.get, incident_id)
                    outcome.update(
                        {"incident_id": incident_id, "status": final["status"],
                         "reconciled": False}
                    )
                    return outcome
                await run_in_threadpool(
                    repo.transition,
                    incident_id,
                    IncidentStatus.ESCALATED,
                    trace_id=trace_id,
                )
                outcome["final_status"] = IncidentStatus.ESCALATED.value
                final = await run_in_threadpool(repo.get, incident_id)
                outcome.update(
                    {"incident_id": incident_id, "status": final["status"],
                     "reconciled": False}
                )
                return outcome
            await run_in_threadpool(
                repo.transition, incident_id, IncidentStatus.EXECUTED, trace_id=trace_id
            )

        await run_in_threadpool(
            repo.transition, incident_id, IncidentStatus.VERIFYING, trace_id=trace_id
        )
        outcome = await _verify_and_close(
            repo,
            incident_id,
            decision["decision_id"],
            (decision.get("parameters") or {}).get("authorized_target_revision"),
            trace_id,
            x_cloud_trace_context,
            outcome,
        )
    except DownstreamFailure as failure:
        outcome["failed"] = {"service": failure.service, "kind": failure.kind}
        outcome["final_status"] = (await run_in_threadpool(repo.get, incident_id))[
            "status"
        ]
    except Exception as exc:  # noqa: BLE001 - recovery must not lose an incident
        # The same catch-all the primary path has, for the same reason, and
        # more urgently: this handler moves the incident to VERIFYING before
        # calling out, and VERIFYING is neither terminal nor reconcilable. An
        # exception escaping here left the incident in a state no endpoint
        # would ever pick up again — the recovery path losing the very incident
        # it was invoked to rescue.
        log_event(
            "reconcile_unexpected_error",
            severity="ERROR",
            trace_id=trace_id,
            incident_id=incident_id,
            error_type=type(exc).__name__,
        )
        outcome = await _fail(
            repo,
            incident_id,
            WorkflowFailure(
                FailureCategory.VERIFIER_UNAVAILABLE,
                f"reconciliation could not complete ({type(exc).__name__})",
            ),
            trace_id,
            outcome,
        )

    final = await run_in_threadpool(repo.get, incident_id)
    outcome["incident_id"] = incident_id
    outcome["status"] = final["status"]
    outcome["reconciled"] = final["status"] == IncidentStatus.RESOLVED.value
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
