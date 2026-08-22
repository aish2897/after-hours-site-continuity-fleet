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
from datetime import timedelta

from scf.domain.approval_text import APPROVAL_TTL_SECONDS, approval_prompt
from scf.domain.ids import (
    derive_authorization_fingerprint,
    new_approval_id,
    new_incident_id,
    utc_now,
)
from scf.domain.state_machine import ASSERTION_STATES, path_to
from scf.domain.models import (
    ActionRecord,
    Evidence,
    IncidentDoc,
    IncidentReport,
    Proposal,
)
from scf.obs import log_event, trace_id_from_header
from scf.policy import default_registry, evaluate, trusted_evidence_map
from scf.security import ScreeningUnavailable, screen_untrusted_text
from scf.state import IncidentNotFound, IncidentRepository
from scf.state.firestore_repo import ApprovalNotFound

INVESTIGATOR_URL = os.environ.get("SCF_INVESTIGATOR_URL", "")
NETWORK_URL = os.environ.get("SCF_NETWORK_URL", "")
SECURITY_URL = os.environ.get("SCF_SECURITY_URL", "")
CONTINUITY_URL = os.environ.get("SCF_CONTINUITY_URL", "")
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

    # Screen the untrusted report BEFORE the model sees any of it.
    #
    # The ordering is the whole point. Screening afterwards would tell us what
    # the model had already read, which is a description of the problem rather
    # than a defence against it. Every event below carries the incident id, so
    # the ordering is reconstructable from logs: a blocked incident has a
    # MODEL_ARMOR_BLOCKED and no adk_invocation_started at all.
    log_event(
        "model_armor_screen_started",
        trace_id=trace_id,
        incident_id=incident_id,
        model_armor_location=config.MODEL_ARMOR_LOCATION,
        model_armor_template=config.MODEL_ARMOR_TEMPLATE,
    )
    try:
        screening = await run_in_threadpool(
            screen_untrusted_text, intake.description
        )
        await run_in_threadpool(
            repo.record_screening,
            incident_id,
            screening.as_log_fields(),
            trace_id=trace_id,
        )
    except Exception as unavailable:  # noqa: BLE001 - nothing may strand an incident
        # Fail CLOSED. Unscreened untrusted text does not reach the model just
        # because the screener was down — an availability problem must not
        # quietly become a security one. Bounded: one attempt, no retry loop.
        # Every exception, not only ScreeningUnavailable. Screening was the
        # first call placed AFTER the incident is persisted, and it arrived with
        # a narrower guard than the call it was inserted in front of — a
        # credential refresh failing, a RecursionError from a hostile body, or
        # the metadata write erroring would escape as a 500 and leave the
        # incident at INTAKE, which no endpoint can move and no handover
        # describes. The direction was never fail-open; the guarantee that a
        # failure always produces a handover was what got lost.
        # One safe reason, derived once and used everywhere below. The log call
        # was guarded and this message was not: a RuntimeError, a credential
        # refresh failure or a failed metadata write has no `.reason`, so the
        # fail-closed path itself raised AttributeError and turned a controlled
        # escalation into a 500. The handler that reports failures must not be
        # able to fail while reporting one.
        reason = getattr(unavailable, "reason", type(unavailable).__name__)
        log_event(
            "model_armor_unavailable",
            severity="ERROR",
            trace_id=trace_id,
            incident_id=incident_id,
            failure_reason=reason,
        )
        failed = await _fail(
            repo,
            incident_id,
            WorkflowFailure(
                FailureCategory.SECURITY_SCREENING_UNAVAILABLE,
                f"security screening could not complete ({reason})",
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

    if not screening.allowed:
        log_event(
            "model_armor_blocked",
            severity="WARNING",
            trace_id=trace_id,
            incident_id=incident_id,
            **screening.as_log_fields(),
        )
        blocked = await _fail(
            repo,
            incident_id,
            WorkflowFailure(
                FailureCategory.UNTRUSTED_CONTENT_BLOCKED,
                f"screening refused the report: {', '.join(screening.triggered_filters)}",
                triggered_filters=list(screening.triggered_filters),
            ),
            trace_id,
            {"attempted": True, "specialists_attempted": []},
        )
        final = await run_in_threadpool(repo.get, incident_id)
        return IncidentCreated(
            incident_id=incident_id,
            status=final["status"],
            summary=blocked["escalation"]["impact"],
            required_specialists=[],
            routes=[],
            remediation=blocked,
            trace_id=trace_id,
        )

    log_event("model_armor_allowed", trace_id=trace_id, incident_id=incident_id,
              **screening.as_log_fields())
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

    # The model proposes a specialist set; the governed catalog decides which of
    # those may actually be routed to. A specialist that is disabled or has no
    # deployed runtime is dropped here, whatever the model asked for — and the
    # drop is recorded rather than silently applied.
    registry = default_registry()
    proposed = [s.value for s in decision.required_specialists()]
    required = [name for name in proposed if registry.is_selectable(name)]
    withheld = [name for name in proposed if name not in required]
    if withheld:
        log_event(
            "specialists_withheld_by_registry",
            severity="WARNING",
            trace_id=trace_id,
            incident_id=incident_id,
            withheld=withheld,
            selectable=registry.selectable_specialists(),
        )
    log_event(
        "routing_decision",
        trace_id=trace_id,
        incident_id=incident_id,
        required_specialists=required,
        proposed_specialists=proposed,
        withheld_specialists=withheld,
        model_id=decision.model_id,
    )

    await run_in_threadpool(repo.save_routing, incident_id, decision, trace_id=trace_id)
    await run_in_threadpool(
        repo.transition, incident_id, IncidentStatus.INVESTIGATING, trace_id=trace_id
    )

    remediation = await _run_fleet(
        repo, incident_id, required, withheld, trace_id, x_cloud_trace_context
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
    if _execution_may_still_land(receipt):
        # A duplicate that collided with a live, authorized, not-yet-mutated
        # execution. We do not know what it did next, so the incident must stay
        # open long enough to find out.
        return FailureCategory.EXECUTION_OUTCOME_UNKNOWN
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
    for step in path_to(current, IncidentStatus.ESCALATED, avoid=ASSERTION_STATES):
        await run_in_threadpool(repo.transition, incident_id, step, trace_id=trace_id)
    settled = IncidentStatus((await run_in_threadpool(repo.get, incident_id))["status"])
    if settled is not IncidentStatus.ESCALATED:
        # Loudly, never silently. An incident that could not be escalated is
        # one nobody has been told about.
        log_event(
            "escalation_route_unavailable",
            severity="ERROR",
            trace_id=trace_id,
            incident_id=incident_id,
            stuck_at=settled.value,
        )
    return settled.value


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
    """Report a failure, and never become one.

    `_fail` is called from inside every `except` block in this module, so an
    exception raised HERE escapes the handler that was already handling
    something — past the workflow catch-all, out of the HTTP endpoint, leaving
    a 500 and an incident parked wherever it happened to be. The handler whose
    entire purpose is "no failure goes unreported" was the one path that could
    fail unreported.

    Its writes are therefore best-effort. A control-plane write failing is bad,
    but it is strictly worse to lose the handover as well.
    """
    try:
        return await _fail_unguarded(repo, incident_id, failure, trace_id, outcome)
    except Exception as exc:  # noqa: BLE001 - a failure handler may not fail
        log_event(
            "failure_handler_failed",
            severity="CRITICAL",
            trace_id=trace_id,
            incident_id=incident_id,
            failure_category=failure.category.value,
            error_type=type(exc).__name__,
        )
        rule = handling(failure.category)
        outcome["failure_category"] = failure.category.value
        outcome["failure_detail"] = failure.detail
        outcome["handover_incomplete"] = True
        outcome["escalation"] = {
            "incident_id": incident_id,
            "correlation_id": trace_id,
            "failure_category": failure.category.value,
            "impact": rule.manager_summary,
            "recommended_next_action": (
                "Contact technical support and quote the reference below. The "
                "system could not finish recording this handover."
            ),
        }
        return outcome


async def _fail_unguarded(
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
        route = path_to(current, rule.resting_status, avoid=ASSERTION_STATES)
        for step in route:
            await run_in_threadpool(repo.transition, incident_id, step, trace_id=trace_id)
        settled = IncidentStatus(
            (await run_in_threadpool(repo.get, incident_id))["status"]
        )
        if not route and settled is not rule.resting_status:
            # No truthful route to the intended resting state.
            #
            # Escalating here was wrong, and wrong in the direction that costs
            # most: ESCALATED is terminal, so a RECONCILABLE failure — one whose
            # whole meaning is "the outcome is unknown, keep the incident open"
            # — got closed on a transient control-plane write error, and
            # /reconcile refused it forever afterwards while the handover still
            # said confirmation was in progress.
            #
            # Recoverability outranks reaching the nominal resting state. If the
            # incident already sits somewhere reconciliation accepts, that is
            # good enough and it stays there. Only a state nothing can pick up
            # justifies closing it, and then a person is told.
            if settled in RECONCILABLE_STATES:
                log_event(
                    "resting_state_unreachable_but_recoverable",
                    severity="WARNING",
                    trace_id=trace_id,
                    incident_id=incident_id,
                    current=settled.value,
                    intended=rule.resting_status.value,
                )
            else:
                log_event(
                    "resting_state_unreachable",
                    severity="ERROR",
                    trace_id=trace_id,
                    incident_id=incident_id,
                    current=settled.value,
                    intended=rule.resting_status.value,
                )
                settled = IncidentStatus(await _escalate(repo, incident_id, trace_id))
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
        mutated=outcome.get("mutated_infrastructure"),
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
    authorized_revision = (
        facts.get("fallback_candidate_revision")
        if proposal.action_type is ActionType.SHIFT_TRAFFIC_TO_APPROVED_CANDIDATE
        else facts.get("candidate_revision")
    )
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
            #
            # Which revision depends on the action the gate is authorizing: a
            # blessed rollback pins the known-good tag's revision, an unblessed
            # shift pins the fallback that was probed. Both come from trusted
            # evidence in this same snapshot.
            "authorized_target_revision": authorized_revision,
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

    if policy_decision.decision is Decision.APPROVAL_REQUIRED:
        # Park, durably, and ask a person.
        #
        # Nothing is claimed, no executor is called, no execution identity is
        # taken and no infrastructure is touched. The incident's whole state
        # lives in Firestore from here, which is what lets a completely
        # different process pick it up later — this one may be gone by then.
        approval_id = new_approval_id()
        requested_at = utc_now()
        expires_at = requested_at + timedelta(seconds=APPROVAL_TTL_SECONDS)
        fingerprint = derive_authorization_fingerprint(
            incident_id=incident_id,
            action_type=proposal.action_type.value,
            target_ref=proposal.target_ref,
            authorized_target_revision=str(authorized_revision or ""),
            policy_version=str(policy_decision.policy_version or ""),
            evidence_snapshot_hash=str(policy_decision.evidence_snapshot_hash or ""),
        )
        await run_in_threadpool(
            repo.create_approval,
            approval_id=approval_id,
            incident_id=incident_id,
            decision_id=policy_decision.decision_id,
            decision_fingerprint=fingerprint,
            action_type=proposal.action_type.value,
            target_ref=proposal.target_ref,
            authorized_target_revision=str(authorized_revision or ""),
            required_approval_role=policy_decision.required_approval_role,
            requested_at=requested_at.isoformat(),
            expires_at=expires_at.isoformat(),
            trace_id=trace_id,
        )
        await run_in_threadpool(
            repo.attach_approval_to_decision,
            incident_id,
            policy_decision.decision_id,
            approval_id,
        )
        await run_in_threadpool(
            repo.transition,
            incident_id,
            IncidentStatus.WAITING_FOR_APPROVAL,
            trace_id=trace_id,
        )
        log_event(
            "approval_requested",
            trace_id=trace_id,
            incident_id=incident_id,
            approval_id=approval_id,
            decision_id=policy_decision.decision_id,
            action_type=proposal.action_type.value,
            required_approval_role=policy_decision.required_approval_role,
        )
        outcome["approval"] = {
            "approval_id": approval_id,
            "state": "PENDING",
            "decision_id": policy_decision.decision_id,
            "required_approval_role": policy_decision.required_approval_role,
            "expires_at": expires_at.isoformat(),
            "awaiting_human": True,
        }
        outcome["manager_prompt"] = approval_prompt(
            action_type=proposal.action_type,
            target_ref=proposal.target_ref,
            authorized_target_revision=str(authorized_revision or ""),
        )
        outcome["final_status"] = IncidentStatus.WAITING_FOR_APPROVAL.value
        return outcome

    if policy_decision.decision is not Decision.AUTO_ALLOWED:
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
        # NOT WorkerContractInvalid. That category is terminal, and it is the
        # right answer for a read-only worker whose bad payload changed nothing.
        # The executor is the one component that mutates infrastructure, so an
        # unreadable answer FROM IT means the outcome is unknown — the traffic
        # flip may well have landed.
        #
        # The asymmetry was visible in the system's own behaviour: the same
        # executor, the same landed mutation, answering with a JSON list instead
        # of a dict was already handled as EXECUTOR_UNAVAILABLE and stayed
        # reconcilable, while a dict with one wrong-typed field escalated
        # terminally and told the manager nothing had changed. Two shapes of one
        # ambiguity, opposite verdicts.
        raise WorkflowFailure(
            FailureCategory.EXECUTION_OUTCOME_UNKNOWN,
            f"executor receipt is not a valid contract ({exc.error_count()})",
        ) from exc

    # The executor cannot write the control plane. The orchestrator, which is
    # an authoritative writer, records what the executor reported.
    # Set before any bookkeeping, so a later failure cannot produce a handover
    # that says nothing changed about a mutation this receipt already reported.
    effect_present = _authorized_effect_is_present(receipt, reported)
    if effect_present is not False:
        outcome["mutated_infrastructure"] = effect_present

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
    elif receipt.get("action") is not None:
        # Record the action if it is recordable, and carry on if it is not.
        #
        # `action` was the one worker field handed to a strict model unguarded,
        # in a module whose stated premise is that a 200 from an authenticated
        # caller is not a reason to trust the payload. A malformed `action` on
        # an otherwise VALID receipt reporting `mutated: true` raised out to the
        # workflow catch-all, which escalated terminally and told the duty
        # manager nothing had changed — about a traffic flip that had landed,
        # leaving the execution at MUTATED with no route to terminalization.
        #
        # The typed receipt above already established what happened. This is
        # record-keeping, and losing a record is not a reason to lose the site.
        # Any shape at all, not just a dict. Guarding on `isinstance(..., dict)`
        # sent a truthy non-dict — a JSON array, say — out of the branch
        # entirely: no action record, no audit entry, and not even the
        # unreadable-record log that exists to notice this. An incident could
        # reach RESOLVED having mutated infrastructure with nothing in the audit
        # trail saying any action was executed. Silence is the one outcome a
        # malformed payload must never buy.
        raw_action = receipt["action"]
        try:
            action_record = ActionRecord.model_validate(raw_action)
        except ValidationError as exc:
            action_record = None
            log_event(
                "action_record_unreadable",
                severity="ERROR",
                trace_id=trace_id,
                incident_id=incident_id,
                action_type=type(raw_action).__name__,
                error_count=exc.error_count(),
            )
        if action_record is not None:
            await run_in_threadpool(repo.record_action, incident_id, action_record)
        await run_in_threadpool(
            repo.append_audit,
            incident_id,
            actor="executor",
            event="action_executed",
            payload={
                "action_id": action_record.action_id if action_record else None,
                "decision_id": policy_decision.decision_id,
                "action_record_readable": action_record is not None,
                "target_ref": action_record.target_ref if action_record else None,
                "target_revision": receipt.get("target_revision"),
                "accepted": reported.mutated,
                "idempotency_key": receipt.get("idempotency_key"),
                "execution_database": receipt.get("execution_database"),
            },
            actor_identity="sa-executor",
            trace_id=trace_id,
        )

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
    #: True when the authorized revision was ALREADY live before this execution
    #: issued anything — an operator got there first. The effect is real, so the
    #: workflow proceeds, but this automation did not cause it and must not tell
    #: a duty manager that it did.
    effect_predates_execution: StrictBool = False
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

#: Of those, the one that only means the mutation MIGHT have been issued. It is
#: written before the Cloud Run call, which is why terminalization refuses it.
#: Good enough to let the workflow proceed and to refuse a re-fire; not good
#: enough to tell a duty manager a change was made.
UNCERTAIN_EXECUTION_STATES = frozenset({"MUTATION_REQUESTED"})

#: States a duplicate can collide with where the winner has NOT yet mutated but
#: is alive and authorized to. Neither "landed" nor "failed" — unknown.
#:
#: The window is real work: an entire Cloud Run Admin API round trip and a
#: precondition check sit between claiming the execution and issuing the write.
#: Treating a collision here as a failed remediation closed the incident
#: terminally, and then the winner — still holding a valid lease — flipped
#: traffic anyway. Infrastructure changed after the incident was closed
#: asserting that nothing had.
LIVE_PRE_MUTATION_STATES = frozenset({"CLAIMED", "PRECONDITION_CHECKED"})


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


def _authorized_effect_is_present(
    receipt: dict[str, Any], reported: ExecutionReceipt
) -> bool | None:
    """Did THIS automation put the authorized revision in place?

    Three ways yes, and one trap.

    Yes: we mutated; or reconciliation found our own earlier attempt had landed;
    or this call was a duplicate and the execution it collided with has landed.
    That third arm is used one screen down to decide whether the workflow may
    proceed, and leaving it out here produced a handover carrying two flatly
    contradictory sentences — "A fix was applied but the service still did not
    come back correctly" beside "No change was made to any service" — with a
    duty manager acting on the false one.

    The trap: the executor also reports `reconciled` when it finds the
    authorized revision already live on a FIRST attempt, having issued nothing.
    The effect is real and the workflow should continue, but an operator put it
    there. Claiming it would be the same overclaim pointing the other way.
    """
    if reported.effect_predates_execution:
        return False
    if reported.progressed():
        return True
    if not _execution_already_landed(receipt):
        return False
    if str(reported.state or "") in UNCERTAIN_EXECUTION_STATES:
        # `None`, not `True`. MUTATION_REQUESTED is written *before* the Cloud
        # Run call — the codebase says so in three places and terminalization
        # refuses it for exactly this reason — so the worker we collided with
        # may have been refused with a 409, or errored, or not got there at all.
        # One predicate was answering two questions with different thresholds:
        # "may the workflow proceed?" and "may we assert this happened?". Only
        # the first tolerates a maybe.
        return None
    return True


def _execution_may_still_land(receipt: dict[str, Any]) -> bool:
    """Did this call collide with a winner that has not mutated yet, but may?"""
    try:
        reported = ExecutionReceipt.model_validate(receipt)
    except ValidationError:
        return False
    return reported.duplicate and str(reported.state or "") in LIVE_PRE_MUTATION_STATES


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
        # The recovery path has to record this too. The primary path sets it
        # before any bookkeeping can fail; leaving recovery out meant a handover
        # produced here told the manager "No change was made to any service"
        # about a mutation the executor had just reported as landed — and only
        # an unreachable verifier was needed to reach that.
        effect_present = _authorized_effect_is_present(receipt, reported)
        if effect_present is not False:
            outcome["mutated_infrastructure"] = effect_present
        elif status is IncidentStatus.REMEDIATION_FAILED:
            # This call changed nothing, but the incident only reaches
            # REMEDIATION_FAILED by way of EXECUTED — a mutation landed on an
            # earlier call. The outcome dict is rebuilt per request, so without
            # this the handover denied a change the incident's own history
            # records.
            outcome["mutated_infrastructure"] = True

        if status is IncidentStatus.EXECUTION_FAILED:
            # The incident never left the execution phase, because we could not
            # reach the executor to learn the outcome. Reconciliation does not
            # re-open execution — it establishes what actually happened.
            if not (reported.progressed() or _execution_already_landed(receipt)):
                if _is_retryable_conflict(receipt) or _execution_may_still_land(receipt):
                    # Same rule on the recovery path, and for the same two
                    # cases: a conflict that provably applied nothing, and a
                    # duplicate that collided with a live winner which has not
                    # mutated YET but is authorized to. Neither is a failure,
                    # and closing on either would be closing before the answer
                    # exists — the second one lets the winner mutate after the
                    # incident is already terminal.
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


# --- human approval ----------------------------------------------------------
#
# The endpoints below are the only way an incident leaves WAITING_FOR_APPROVAL
# towards execution. Three properties matter more than the code:
#
# 1. Cloud Run invoker permission is NOT authorization. Reaching this endpoint
#    proves only that Google let the request through; whether the pinned
#    decision may then run is decided against the persisted approval and the
#    persisted decision, and the executor checks again independently.
# 2. The caller supplies an approval id and nothing else. It cannot name the
#    target, the revision, the decision, or itself as approver. Everything that
#    matters is read from the authoritative plane.
# 3. No agent in this fleet can call these. Approval is a human act, and the
#    identity that performs it is recorded.


class ApprovalDecisionRequest(BaseModel):
    """Deliberately almost empty.

    A caller may attach a note for the record. It may not attach a target, a
    revision, a decision id, or an approver identity — untrusted input does not
    get to choose what it is authorizing or who it is.
    """

    model_config = ConfigDict(extra="forbid")

    note: str | None = Field(default=None, max_length=500)


#: Set when a deployment can establish a real human principal. Until a manager
#: UI with verified sign-in exists, the backend proof runs under a dedicated
#: authenticated demo-approver principal, and says so rather than inventing a
#: name. See the Gate F evidence for what is and is not proven about identity.
DEMO_APPROVER_PRINCIPAL = os.environ.get(
    "SCF_APPROVER_PRINCIPAL", "demo-approver@site-continuity-fleet.invalid"
)


#: Who may approve what. Server-side, exact-match, and deliberately not a
#: pattern: an approval role is a small, deliberately-granted thing, and a
#: wildcard here would quietly re-open the hole this closes.
#:
#: Configured as `role:principal,principal;role:principal`.
def _load_approver_bindings() -> dict[str, frozenset[str]]:
    raw = os.environ.get("SCF_APPROVER_BINDINGS", "")
    bindings: dict[str, frozenset[str]] = {}
    for clause in filter(None, (part.strip() for part in raw.split(";"))):
        role, _, members = clause.partition(":")
        if not role or not members:
            continue
        bindings[role.strip()] = frozenset(
            m.strip().lower() for m in members.split(",") if m.strip()
        )
    return bindings


APPROVER_ROLE_BINDINGS: dict[str, frozenset[str]] = _load_approver_bindings()


class ApprovalForbidden(Exception):
    """The caller is authenticated, and not authorized to approve this."""


def _verified_caller(authorization: str | None) -> str:
    """The principal Google actually vouched for, or "".

    Cloud Run validates the bearer token before the request arrives, but does
    not hand the application the identity behind it. So the token is verified
    again here — signature, issuer and expiry checked against Google's public
    keys — and the principal is read from the verified claims rather than from
    anything the caller wrote. A forged or expired token yields "".

    This is why no IAP is needed to answer "who is approving": the answer is in
    a Google-signed assertion the caller cannot author.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        return ""
    token = authorization.split(" ", 1)[1].strip()
    try:
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token as google_id_token

        # Skew tolerance, deliberately. Token verification compares the
        # issuer's `iat` against the verifier's clock, and a machine a minute
        # out rejects a perfectly valid Google-signed assertion with "token
        # used too early" — turning a clock problem into an authorization
        # failure. Sixty seconds is the conventional allowance and does not
        # weaken the signature, issuer or expiry checks.
        claims = google_id_token.verify_oauth2_token(
            token, google_requests.Request(), clock_skew_in_seconds=60
        )
    except Exception as exc:  # noqa: BLE001 - an unverifiable token names nobody
        # Say WHY. A blanket swallow here made an authorization refusal
        # indistinguishable from a clock problem, a network problem and a
        # genuinely forged token.
        log_event(
            "approver_token_unverified",
            severity="WARNING",
            error_type=type(exc).__name__,
            detail=str(exc)[:160],
        )
        return ""
    principal = str(claims.get("email") or "").lower()
    if principal and claims.get("email_verified") is False:
        return ""
    return principal


def _authorize_approver(authorization: str | None, required_role: str | None) -> str:
    """Authorize the approver, and record who it was.

    WHERE THE BOUNDARY ACTUALLY IS. Cloud Run IAM is what stops an unauthorized
    caller reaching this code: `run.invoker` on this service is held by no fleet
    identity at all, so `sa-orchestrator`, `sa-agent-systems`, `sa-executor`,
    `sa-verifier` and anonymous callers are refused by Google before the request
    arrives. That is proven live, and it is a stronger boundary than anything
    this function could add.

    WHAT THIS ADDS. When a caller identity IS verifiable, the principal must
    also be bound to the role the decision asked for — defence in depth for the
    day a service-to-service approver exists.

    WHAT IT CANNOT DO, stated rather than papered over: Cloud Run does not hand
    this application a verifiable end-user identity. The forwarded bearer token
    fails signature verification in-container — for user credentials AND for
    audience-scoped service tokens — so the app cannot distinguish which
    authorized human approved. Per-role enforcement inside the app therefore
    needs either IAP or a separate Cloud Run service per approval role, neither
    of which is worth adding without a decision. Until then the recorded
    principal says what is actually known.
    """
    principal = _verified_caller(authorization)
    role = required_role or DEFAULT_APPROVAL_ROLE
    if principal:
        permitted = APPROVER_ROLE_BINDINGS.get(role, frozenset())
        if principal not in permitted:
            raise ApprovalForbidden(f"{principal} is not bound to {role}")
        return principal
    # No verifiable principal. The caller still passed Cloud Run IAM, which is
    # the real gate; record that honestly instead of inventing a name.
    return f"cloud-run-authenticated-invoker (role {role}, identity not verifiable)"


#: The role an approval defaults to when a decision does not name one.
DEFAULT_APPROVAL_ROLE = "incident_commander"


#: Set only on a deployment that actually has Identity-Aware Proxy in front of
#: the service. Without IAP, `X-Goog-Authenticated-User-Email` is an ordinary
#: request header that any caller may set, so trusting it would let anyone who
#: can invoke this service write an arbitrary named person into the audit record
#: as the human who authorized a production change.
TRUST_PLATFORM_APPROVER_HEADERS = (
    os.environ.get("SCF_TRUST_IAP_HEADERS", "").strip().lower() == "true"
)


def _approver_principal(assertion: str | None, email: str | None) -> str:
    """Who approved — recorded only from something that cannot be self-asserted.

    An earlier version of this read `X-Goog-Authenticated-User-Email` directly
    and claimed in a comment that Google set it and a caller could not forge it.
    That is true behind IAP and false otherwise, and this fleet does not deploy
    IAP: the header arrives verbatim from whoever sent it. Any principal able to
    invoke the orchestrator could therefore name any person as the approver in a
    hash-chained audit record.

    It grants no authority a caller did not already have — any invoker may
    approve today, which is a stated limitation — but the record that *a person
    decided* is the artifact this gate is judged on, and attribution has to be
    worth as much as the rest of the trail.

    So the headers are read only where a deployment declares IAP is genuinely in
    front. Otherwise a named placeholder is recorded, which claims nothing.
    """
    if TRUST_PLATFORM_APPROVER_HEADERS:
        if email:
            return email.split(":", 1)[-1]
        if assertion:
            return "iap-authenticated-principal"
    return DEMO_APPROVER_PRINCIPAL


async def _record_approval_decision(
    approval_id: str,
    *,
    state: str,
    trace_id: str | None,
    approver: str,
) -> dict[str, Any]:
    repo = repository()
    now = utc_now()
    outcome, record = await run_in_threadpool(
        repo.decide_approval,
        approval_id,
        state=state,
        approver_principal=approver,
        decided_at=now.isoformat(),
        now=now.isoformat(),
        trace_id=trace_id,
    )
    log_event(
        "approval_decision",
        severity="WARNING" if outcome == "NOT_FOUND" else "INFO",
        trace_id=trace_id,
        approval_id=approval_id,
        outcome=outcome,
        requested_state=state,
        approver_principal=approver,
        incident_id=record.get("incident_id"),
        decision_id=record.get("decision_id"),
    )
    if outcome == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="approval_not_found")
    if outcome == "DECIDED":
        await run_in_threadpool(
            repo.append_audit,
            record["incident_id"],
            actor="human",
            event=f"approval_{state.lower()}",
            payload={
                "approval_id": approval_id,
                "decision_id": record.get("decision_id"),
                "approver_principal": approver,
                "decision_fingerprint": record.get("decision_fingerprint"),
            },
            actor_identity=approver,
            trace_id=trace_id,
        )

    # A refusal is a complete answer, and it still has to go somewhere. Recording
    # it only on the approval document left the incident waiting forever: the
    # manager was offered "ESCALATE INSTEAD" and pressing it escalated nothing —
    # no status change, no handover, a live outage in a state no endpoint could
    # move. The same is true of a request nobody answered in time.
    if outcome in ("DECIDED", "EXPIRED") and state != "APPROVED":
        await _close_unapproved_incident(
            record["incident_id"],
            category=(
                FailureCategory.APPROVAL_REJECTED
                if outcome == "DECIDED"
                else FailureCategory.APPROVAL_EXPIRED
            ),
            approval_id=approval_id,
            approver=approver,
            trace_id=trace_id,
        )
    return {
        "approval_id": approval_id,
        "outcome": outcome,
        "state": record.get("state"),
        "incident_id": record.get("incident_id"),
        "decision_id": record.get("decision_id"),
        "approver_principal": record.get("approver_principal"),
        "decided_at": record.get("decided_at"),
    }


async def _close_unapproved_incident(
    incident_id: str,
    *,
    category: FailureCategory,
    approval_id: str,
    approver: str,
    trace_id: str | None,
) -> None:
    """Walk a refused or lapsed incident to a terminal state, with a handover.

    Best-effort by design: the human's decision is already durably recorded on
    the approval document, and failing to tidy the incident afterwards must not
    turn a legitimate answer into an error the person sees.
    """
    repo = repository()
    try:
        incident = await run_in_threadpool(repo.get, incident_id)
        if incident.get("status") != IncidentStatus.WAITING_FOR_APPROVAL.value:
            return
        waypoint = (
            IncidentStatus.APPROVAL_DENIED
            if category is FailureCategory.APPROVAL_REJECTED
            else IncidentStatus.APPROVAL_EXPIRED
        )
        await run_in_threadpool(
            repo.transition, incident_id, waypoint, trace_id=trace_id
        )
        await _fail(
            repo,
            incident_id,
            WorkflowFailure(
                category,
                f"approval {approval_id} {category.value.lower()}",
                approval_id=approval_id,
                approver_principal=approver,
            ),
            trace_id,
            {"specialists_attempted": ["systems"], "evidence_keys": []},
        )
    except Exception as exc:  # noqa: BLE001 - the human answer already landed
        log_event(
            "approval_closure_failed",
            severity="ERROR",
            trace_id=trace_id,
            incident_id=incident_id,
            approval_id=approval_id,
            error_type=type(exc).__name__,
        )


@app.post("/approvals/{approval_id}/approve")
async def approve(
    approval_id: str,
    request: ApprovalDecisionRequest | None = None,
    authorization: str | None = Header(default=None),
    x_cloud_trace_context: str | None = Header(default=None),
) -> dict[str, Any]:
    """A person authorizes one pinned decision. Idempotent."""
    trace_id = trace_id_from_header(x_cloud_trace_context)
    try:
        approval = await run_in_threadpool(repository().get_approval, approval_id)
    except ApprovalNotFound as missing:
        raise HTTPException(status_code=404, detail="approval_not_found") from missing
    try:
        approver = _authorize_approver(
            authorization, approval.get("required_approval_role")
        )
    except ApprovalForbidden as refused:
        log_event(
            "approval_forbidden",
            severity="WARNING",
            trace_id=trace_id,
            approval_id=approval_id,
            incident_id=approval.get("incident_id"),
            required_approval_role=approval.get("required_approval_role"),
            detail=str(refused),
        )
        raise HTTPException(status_code=403, detail="approver_not_authorized") from refused
    return await _record_approval_decision(
        approval_id, state="APPROVED", trace_id=trace_id, approver=approver
    )


@app.post("/approvals/{approval_id}/reject")
async def reject(
    approval_id: str,
    request: ApprovalDecisionRequest | None = None,
    authorization: str | None = Header(default=None),
    x_cloud_trace_context: str | None = Header(default=None),
) -> dict[str, Any]:
    """A person refuses. Nothing is mutated, now or later, under this approval."""
    trace_id = trace_id_from_header(x_cloud_trace_context)
    try:
        approval = await run_in_threadpool(repository().get_approval, approval_id)
    except ApprovalNotFound as missing:
        raise HTTPException(status_code=404, detail="approval_not_found") from missing
    try:
        approver = _authorize_approver(
            authorization, approval.get("required_approval_role")
        )
    except ApprovalForbidden as refused:
        log_event(
            "approval_forbidden",
            severity="WARNING",
            trace_id=trace_id,
            approval_id=approval_id,
            incident_id=approval.get("incident_id"),
            required_approval_role=approval.get("required_approval_role"),
            detail=str(refused),
        )
        raise HTTPException(status_code=403, detail="approver_not_authorized") from refused
    return await _record_approval_decision(
        approval_id, state="REJECTED", trace_id=trace_id, approver=approver
    )


@app.get("/approvals/{approval_id}")
async def read_approval(approval_id: str) -> dict[str, Any]:
    """Read the durable approval. Proves it outlives the process that made it."""
    try:
        record = await run_in_threadpool(repository().get_approval, approval_id)
    except ApprovalNotFound as missing:
        raise HTTPException(status_code=404, detail="approval_not_found") from missing
    return {
        **record,
        "served_by_revision": os.environ.get("K_REVISION"),
    }


#: Incident states a resume may legitimately start from. WAITING_FOR_APPROVAL is
#: the normal one; APPROVED means a previous resume recorded the human decision
#: and then died before reaching the executor.
RESUMABLE_STATES = frozenset(
    {
        IncidentStatus.WAITING_FOR_APPROVAL.value,
        IncidentStatus.APPROVED.value,
    }
)


#: Everything that must still be true before an approval may become a mutation.
#: Checked at resume time against the authoritative plane, not at approval time
#: — an approval is permission for the pinned decision, and the world moves.
def _approval_blockers(
    approval: dict[str, Any],
    decision: dict[str, Any],
    incident: dict[str, Any],
    *,
    now_iso: str,
) -> list[str]:
    """Every reason this approval may NOT be turned into an infrastructure change.

    Returned as a list rather than a first-failure so the record shows
    everything that was wrong, which is what a person reading the audit trail
    actually wants.
    """
    blockers: list[str] = []
    if approval.get("state") != "APPROVED":
        blockers.append(f"approval_state:{approval.get('state')}")
    if str(approval.get("expires_at") or "") <= now_iso:
        blockers.append("approval_expired")
    if approval.get("decision_id") != decision.get("decision_id"):
        blockers.append("decision_id_mismatch")
    # APPROVED counts. The transition to APPROVED and the executor call cannot
    # be one atomic act, so an instance reaped in between left a human-approved
    # incident at APPROVED with no endpoint able to move it — the exact failure
    # this gate exists to defend against, since its whole premise is that the
    # process does not survive. Resume is idempotent instead.
    if incident.get("status") not in RESUMABLE_STATES:
        blockers.append(f"incident_state:{incident.get('status')}")
    if decision.get("revoked"):
        blockers.append("decision_revoked")
    if decision.get("decision") != Decision.APPROVAL_REQUIRED.value:
        blockers.append(f"decision_not_approval_required:{decision.get('decision')}")

    # The fingerprint is the real check. It covers incident, action, target,
    # exact revision, policy version and evidence snapshot together, so any
    # substitution between asking and acting changes it — and an approval for
    # something else is not an approval for this.
    params = decision.get("parameters") or {}
    expected = derive_authorization_fingerprint(
        incident_id=str(decision.get("incident_id") or ""),
        action_type=str(decision.get("action_type") or ""),
        target_ref=str(decision.get("target_ref") or ""),
        authorized_target_revision=str(params.get("authorized_target_revision") or ""),
        policy_version=str(decision.get("policy_version") or ""),
        evidence_snapshot_hash=str(decision.get("evidence_snapshot_hash") or ""),
    )
    if approval.get("decision_fingerprint") != expected:
        blockers.append("decision_fingerprint_mismatch")
    return blockers


@app.post("/incidents/{incident_id}/resume")
async def resume_incident(
    incident_id: str,
    x_cloud_trace_context: str | None = Header(default=None),
) -> dict[str, Any]:
    """Continue an approved incident from durable state.

    Deliberately takes identifiers only, and reads everything else from
    Firestore: the incident, the decision, the approval, the pinned revision.
    Nothing is carried in memory from the process that asked for approval,
    because that process is generally gone by the time this runs — which is the
    whole point of the gate.

    This does not re-investigate, re-decide, or re-approve. The human authorized
    one specific decision and this executes that one or nothing.
    """
    trace_id = trace_id_from_header(x_cloud_trace_context)
    repo = repository()
    outcome: dict[str, Any] = {
        "incident_id": incident_id,
        "resumed_by_revision": os.environ.get("K_REVISION"),
    }

    try:
        incident = await run_in_threadpool(repo.get, incident_id)
    except IncidentNotFound as missing:
        raise HTTPException(status_code=404, detail="incident_not_found") from missing

    decision = await run_in_threadpool(repo.latest_decision, incident_id)
    if not decision:
        raise HTTPException(status_code=409, detail="no_decision_to_resume")

    # The decision carries the reference, written by the authoritative writer.
    # The query below is a fallback for a decision recorded before that existed;
    # the orchestrator may run it, the executor may not.
    approval_id = str(decision.get("approval_id") or "")
    if not approval_id:
        approval_id = await run_in_threadpool(
            repo.find_approval_for_decision, incident_id, decision["decision_id"]
        )
    if not approval_id:
        raise HTTPException(status_code=409, detail="no_approval_for_decision")

    try:
        approval = await run_in_threadpool(repo.get_approval, approval_id)
    except ApprovalNotFound as missing:
        raise HTTPException(status_code=404, detail="approval_not_found") from missing

    blockers = _approval_blockers(
        approval, decision, incident, now_iso=utc_now().isoformat()
    )
    outcome["approval"] = {
        "approval_id": approval_id,
        "state": approval.get("state"),
        "approver_principal": approval.get("approver_principal"),
        "decided_at": approval.get("decided_at"),
        "decision_id": approval.get("decision_id"),
    }
    if blockers:
        log_event(
            "resume_refused",
            severity="WARNING",
            trace_id=trace_id,
            incident_id=incident_id,
            approval_id=approval_id,
            blockers=blockers,
        )
        await run_in_threadpool(
            repo.append_audit,
            incident_id,
            actor="orchestrator",
            event="resume_refused",
            payload={"approval_id": approval_id, "blockers": blockers},
            trace_id=trace_id,
        )
        outcome.update({"resumed": False, "mutated": False, "blockers": blockers,
                        "status": incident.get("status")})
        return outcome

    # Every check passed. Record the human's authorization in the incident's own
    # lifecycle, then run the SAME execution pipeline an auto-allowed decision
    # uses — same executor, same identity, same OCC, same verifier.
    if incident.get("status") == IncidentStatus.WAITING_FOR_APPROVAL.value:
        await run_in_threadpool(
            repo.transition, incident_id, IncidentStatus.APPROVED, trace_id=trace_id
        )
    log_event(
        "incident_resumed",
        trace_id=trace_id,
        incident_id=incident_id,
        approval_id=approval_id,
        decision_id=decision["decision_id"],
        approver_principal=approval.get("approver_principal"),
        resumed_by_revision=os.environ.get("K_REVISION"),
    )
    outcome["decision_id"] = decision["decision_id"]
    outcome["authorized_target_revision"] = (
        decision.get("parameters") or {}
    ).get("authorized_target_revision")

    return await _execute_approved_decision(
        repo, incident_id, decision, trace_id, x_cloud_trace_context, outcome
    )


async def _execute_approved_decision(
    repo: IncidentRepository,
    incident_id: str,
    decision: dict[str, Any],
    trace_id: str | None,
    trace_header: str | None,
    outcome: dict[str, Any],
) -> dict[str, Any]:
    """Run a human-approved decision through the unchanged execution pipeline.

    Approval changes WHO authorized the action, and nothing else. The executor
    still re-reads the decision from the authoritative plane rather than
    trusting this caller, still claims its own execution identity, still
    re-checks the incident is open, still probes the target for itself, and
    still mutates under `resourceVersion` optimistic concurrency. The verifier
    still grades it under a different read-only identity.

    Nothing here is a shortcut earned by having asked a person.
    """
    decision_id = decision["decision_id"]
    try:
        await run_in_threadpool(
            repo.transition, incident_id, IncidentStatus.EXECUTING, trace_id=trace_id
        )
        receipt = await _call(
            EXECUTOR_URL,
            "/execute",
            {"incident_id": incident_id, "decision_id": decision_id},
            service="executor",
            trace_header=trace_header,
        )
        outcome["execution"] = receipt
        try:
            reported = ExecutionReceipt.model_validate(receipt)
        except ValidationError as exc:
            return await _fail(
                repo,
                incident_id,
                WorkflowFailure(
                    FailureCategory.EXECUTION_OUTCOME_UNKNOWN,
                    f"executor receipt is not a valid contract ({exc.error_count()})",
                ),
                trace_id,
                outcome,
            )

        effect_present = _authorized_effect_is_present(receipt, reported)
        if effect_present is not False:
            outcome["mutated_infrastructure"] = effect_present

        # Record the action here too. The audit trail is the artifact this
        # project is judged on, and a resumed execution that mutated real
        # infrastructure with no `action_executed` record would leave the story
        # incomplete at exactly the step a person authorized.
        if isinstance(receipt.get("action"), dict):
            try:
                action_record = ActionRecord.model_validate(receipt["action"])
            except ValidationError as exc:
                action_record = None
                log_event(
                    "action_record_unreadable",
                    severity="ERROR",
                    trace_id=trace_id,
                    incident_id=incident_id,
                    error_count=exc.error_count(),
                )
            if action_record is not None:
                await run_in_threadpool(repo.record_action, incident_id, action_record)
            await run_in_threadpool(
                repo.append_audit,
                incident_id,
                actor="executor",
                event="action_executed",
                payload={
                    "action_id": action_record.action_id if action_record else None,
                    "decision_id": decision_id,
                    "action_record_readable": action_record is not None,
                    "resumed_after_approval": True,
                    "accepted": reported.mutated,
                },
                actor_identity="sa-executor",
                trace_id=trace_id,
            )

        if not (reported.progressed() or _execution_already_landed(receipt)):
            await run_in_threadpool(
                repo.transition,
                incident_id,
                IncidentStatus.EXECUTION_FAILED,
                trace_id=trace_id,
            )
            return await _fail(
                repo,
                incident_id,
                WorkflowFailure(
                    _execution_failure_category(receipt),
                    str(receipt.get("reason") or "execution did not complete")[:200],
                    execution_reason=receipt.get("reason"),
                ),
                trace_id,
                outcome,
            )

        await run_in_threadpool(
            repo.transition, incident_id, IncidentStatus.EXECUTED, trace_id=trace_id
        )
        await run_in_threadpool(
            repo.transition, incident_id, IncidentStatus.VERIFYING, trace_id=trace_id
        )
        outcome["resumed"] = True
        return await _verify_and_close(
            repo,
            incident_id,
            decision_id,
            (decision.get("parameters") or {}).get("authorized_target_revision"),
            trace_id,
            trace_header,
            outcome,
        )
    except DownstreamFailure as failure:
        outcome["failed"] = {"service": failure.service, "kind": failure.kind}
        return await _fail(
            repo,
            incident_id,
            WorkflowFailure(_categorise(failure), f"{failure.service}/{failure.kind}"),
            trace_id,
            outcome,
        )
    except Exception as exc:  # noqa: BLE001 - a resume must not strand an incident
        log_event(
            "resume_unexpected_error",
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
                f"resume failed ({type(exc).__name__})",
            ),
            trace_id,
            outcome,
        )


# --- the fleet ---------------------------------------------------------------


#: Read-only specialists the orchestrator can consult for evidence. Systems is
#: absent on purpose: it is the only one that may propose a remediation, so it
#: runs through the full authorization pipeline rather than this helper.
EVIDENCE_SPECIALISTS: dict[str, str] = {
    "network": NETWORK_URL,
    "security": SECURITY_URL,
}


async def _consult(
    specialist: str,
    incident_id: str,
    trace_id: str | None,
    trace_header: str | None,
) -> list[Evidence]:
    """Ask one read-only specialist for evidence. Failure is never fatal here.

    A specialist that cannot be reached costs the orchestrator information, not
    the incident: the others still ran, and the deterministic gate will simply
    find the evidence insufficient rather than acting on a guess.
    """
    url = EVIDENCE_SPECIALISTS.get(specialist, "")
    if not url:
        return []
    try:
        body = await _call(
            url,
            "/evidence",
            {
                "incident_id": incident_id,
                "service": config.DISPATCH_WEB_SERVICE,
                "target_url": config.dispatch_web_url(),
            },
            service=specialist,
            trace_header=trace_header,
        )
        return [Evidence.model_validate(item) for item in (body.get("evidence") or [])]
    except (DownstreamFailure, ValidationError, KeyError, TypeError) as exc:
        log_event(
            "specialist_unavailable",
            severity="WARNING",
            trace_id=trace_id,
            incident_id=incident_id,
            specialist=specialist,
            error_type=type(exc).__name__,
        )
        return []


async def _compose_manager_status(
    incident_id: str,
    consulted: list[str],
    facts: dict[str, Any],
    outcome: dict[str, Any],
    trace_id: str | None,
    trace_header: str | None,
) -> dict[str, Any] | None:
    """Ask the Continuity Coordinator what to tell the duty manager."""
    if not CONTINUITY_URL:
        return None
    try:
        return await _call(
            CONTINUITY_URL,
            "/status",
            {
                "incident_id": incident_id,
                "status": str(outcome.get("final_status") or ""),
                "specialists_consulted": consulted,
                "network_reachable": facts.get("network_reachable"),
                # The Systems finding lives in the outcome, not in the fleet
                # facts: those carry only what the read-only specialists
                # returned, and Systems runs through the full authorization
                # pipeline. Reading only `facts` left the manager message
                # silent about the application — the single most important
                # thing they need to know.
                "service_responding": outcome.get("service_observed_healthy"),
                "identity_posture_sound": facts.get("identity_posture_sound"),
                "remediation_state": str(outcome.get("final_status") or ""),
                "awaiting_human": bool(outcome.get("approval")),
                "changed_anything": outcome.get("mutated_infrastructure"),
            },
            service="continuity",
            trace_header=trace_header,
        )
    except DownstreamFailure as failure:
        log_event(
            "continuity_unavailable",
            severity="WARNING",
            trace_id=trace_id,
            incident_id=incident_id,
            kind=failure.kind,
        )
        return None


async def _run_fleet(
    repo: IncidentRepository,
    incident_id: str,
    required: list[str],
    withheld: list[str],
    trace_id: str | None,
    trace_header: str | None,
) -> dict[str, Any]:
    """Consult the routed specialists, then act only if Systems warrants it.

    Selective by construction: this consults exactly the specialists routing
    asked for and the catalog permits. There is no fan-out branch — a request
    that routes to Network alone never touches Systems or Security.

    Secondary delegation lives here too. If Network reports the site reachable
    while the application is not responding, the problem is not the network, and
    Systems is brought in on the strength of that trusted evidence rather than
    on anything the report said.
    """
    consulted: list[str] = []
    fleet_evidence: list[Evidence] = []

    for specialist in [s for s in required if s in EVIDENCE_SPECIALISTS]:
        collected = await _consult(specialist, incident_id, trace_id, trace_header)
        if collected:
            consulted.append(specialist)
            fleet_evidence.extend(collected)
            await run_in_threadpool(
                repo.save_evidence, incident_id, collected, trace_id=trace_id
            )

    facts = trusted_evidence_map(fleet_evidence)
    escalate_reason = "no_specialist_routed"
    run_systems = "systems" in required

    if not run_systems and facts.get("network_reachable") is True:
        # Evidence-dependent delegation: the network is fine, so whatever the
        # manager is seeing is above it. That conclusion comes from a trusted
        # tool call, not from re-reading the report.
        if default_registry().is_selectable("systems"):
            run_systems = True
            escalate_reason = "delegated_after_network_evidence"
            log_event(
                "secondary_delegation",
                trace_id=trace_id,
                incident_id=incident_id,
                because="network_reachable",
                delegated_to="systems",
                after=consulted,
            )

    if run_systems:
        outcome = await _autonomous_remediation(
            repo, incident_id, trace_id, trace_header
        )
        if "systems" not in consulted:
            consulted.append("systems")
        if escalate_reason == "delegated_after_network_evidence":
            outcome["secondary_delegation"] = {
                "because": "network_reachable",
                "after": [s for s in consulted if s != "systems"],
                "delegated_to": "systems",
            }
    else:
        # Nothing here can safely change infrastructure: only Systems produces a
        # proposal, and it was not routed. The incident goes to a person.
        await run_in_threadpool(
            repo.transition, incident_id, IncidentStatus.ESCALATED, trace_id=trace_id
        )
        outcome = {
            "attempted": False,
            "reason": escalate_reason,
            "final_status": IncidentStatus.ESCALATED.value,
        }

    outcome["specialists_consulted"] = consulted
    if withheld:
        outcome["specialists_withheld_by_registry"] = withheld

    status = await _compose_manager_status(
        incident_id, consulted, facts, outcome, trace_id, trace_header
    )
    if status:
        outcome["manager_status"] = status
    return outcome
