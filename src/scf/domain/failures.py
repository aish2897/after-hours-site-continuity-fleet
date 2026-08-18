"""Failure taxonomy.

One closed set of failure categories, each mapped in a single table to how the
workflow must react. Free-form failure semantics scattered through the code is
how a system ends up resolving an incident it did not fix, or retrying a
mutation forever; every failure path here resolves to a row in `HANDLING`.

A category answers four questions at once:

- which legal workflow state the incident goes to;
- whether the failure is reconcilable (the outcome is unknown or recoverable)
  or final (we know it failed and no automatic path remains);
- what a non-technical duty manager should be told;
- what the audit records.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from scf.domain.enums import IncidentStatus


class FailureCategory(StrEnum):
    """Closed set. A failure with no category is a bug, not a new category."""

    MODEL_OUTPUT_INVALID = "MODEL_OUTPUT_INVALID"
    DANGEROUS_ACTION_REFUSED = "DANGEROUS_ACTION_REFUSED"
    WORKER_TIMEOUT = "WORKER_TIMEOUT"
    WORKER_UNAVAILABLE = "WORKER_UNAVAILABLE"
    WORKER_BUDGET_EXCEEDED = "WORKER_BUDGET_EXCEEDED"
    WORKER_CONTRACT_INVALID = "WORKER_CONTRACT_INVALID"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    STALE_EVIDENCE = "STALE_EVIDENCE"
    TARGET_NO_LONGER_HEALTHY = "TARGET_NO_LONGER_HEALTHY"
    EXECUTION_CONFLICT = "EXECUTION_CONFLICT"
    EXECUTOR_UNAVAILABLE = "EXECUTOR_UNAVAILABLE"
    EXECUTION_OUTCOME_UNKNOWN = "EXECUTION_OUTCOME_UNKNOWN"
    VERIFIER_UNAVAILABLE = "VERIFIER_UNAVAILABLE"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    REMEDIATION_FAILED = "REMEDIATION_FAILED"


class FailureHandling(BaseModel):
    """How one category is handled. Data, not code paths."""

    model_config = ConfigDict(frozen=True)

    category: FailureCategory
    #: Where the incident stops. A reconcilable failure stops at a NON-terminal
    #: state so recovery can establish the truth; a final one is escalated.
    resting_status: IncidentStatus
    reconcilable: bool
    #: True only where re-running the SAME authorized effect is meaningful.
    #: Never means "retry the model" or "retry the mutation in a loop".
    retry_eligible: bool
    audit_event: str
    #: Plain language. No API names, no status codes, no model text.
    manager_summary: str


def _h(
    category: FailureCategory,
    status: IncidentStatus,
    *,
    reconcilable: bool,
    retry_eligible: bool,
    summary: str,
) -> FailureHandling:
    return FailureHandling(
        category=category,
        resting_status=status,
        reconcilable=reconcilable,
        retry_eligible=retry_eligible,
        audit_event=f"failure_{category.value.lower()}",
        manager_summary=summary,
    )


S = IncidentStatus
C = FailureCategory

#: The single source of truth for failure behaviour.
HANDLING: dict[FailureCategory, FailureHandling] = {
    C.MODEL_OUTPUT_INVALID: _h(
        C.MODEL_OUTPUT_INVALID, S.ESCALATED, reconcilable=False, retry_eligible=False,
        summary="The system could not understand its own analysis of this report, "
                "so it stopped rather than guess. Nothing was changed.",
    ),
    C.DANGEROUS_ACTION_REFUSED: _h(
        C.DANGEROUS_ACTION_REFUSED, S.ESCALATED, reconcilable=False, retry_eligible=False,
        summary="An unsafe action was suggested during analysis and was refused "
                "automatically. Nothing was changed.",
    ),
    C.WORKER_TIMEOUT: _h(
        C.WORKER_TIMEOUT, S.ESCALATED, reconcilable=False, retry_eligible=False,
        summary="A checking step took too long and was stopped. No fix was "
                "attempted, and nothing was changed.",
    ),
    C.WORKER_UNAVAILABLE: _h(
        C.WORKER_UNAVAILABLE, S.ESCALATED, reconcilable=False, retry_eligible=False,
        summary="A checking step was unavailable, so the system could not confirm "
                "what is wrong. Nothing was changed.",
    ),
    C.WORKER_BUDGET_EXCEEDED: _h(
        C.WORKER_BUDGET_EXCEEDED, S.ESCALATED, reconcilable=False, retry_eligible=False,
        summary="A checking step did not finish within its allowed work limit and "
                "was stopped. Nothing was changed.",
    ),
    C.WORKER_CONTRACT_INVALID: _h(
        C.WORKER_CONTRACT_INVALID, S.ESCALATED, reconcilable=False, retry_eligible=False,
        summary="A checking step returned information the system could not trust, "
                "so it was discarded. Nothing was changed.",
    ),
    C.INSUFFICIENT_EVIDENCE: _h(
        C.INSUFFICIENT_EVIDENCE, S.ESCALATED, reconcilable=False, retry_eligible=False,
        summary="The system could not confirm a fault it knows how to fix safely, "
                "so it made no change and asked for a person to look.",
    ),
    C.STALE_EVIDENCE: _h(
        C.STALE_EVIDENCE, S.ESCALATED, reconcilable=False, retry_eligible=False,
        summary="The service changed while the fix was being prepared, so the fix "
                "was cancelled. Nothing was changed.",
    ),
    C.TARGET_NO_LONGER_HEALTHY: _h(
        C.TARGET_NO_LONGER_HEALTHY, S.ESCALATED, reconcilable=False, retry_eligible=False,
        summary="The known-good version the system planned to switch back to was "
                "no longer answering, so the switch was cancelled. Nothing was "
                "changed.",
    ),
    C.EXECUTION_CONFLICT: _h(
        # Google refused the write on its precondition, so nothing was applied
        # and the incident stays open for reconciliation rather than closing.
        C.EXECUTION_CONFLICT, S.EXECUTION_FAILED, reconcilable=True, retry_eligible=True,
        summary="Someone or something else changed the service at the same moment, "
                "so the automatic fix was refused. Nothing was changed.",
    ),
    C.EXECUTOR_UNAVAILABLE: _h(
        # We could not reach the component that acts, so whether it acted is
        # unknown. Never close an incident on an unknown outcome.
        C.EXECUTOR_UNAVAILABLE, S.EXECUTION_FAILED, reconcilable=True, retry_eligible=True,
        summary="The system could not reach the part of itself that applies fixes. "
                "The outcome is being re-checked before anything is reported as "
                "done.",
    ),
    C.EXECUTION_OUTCOME_UNKNOWN: _h(
        # The mutation was issued and Google answered with something other than
        # a 409. Only a 409 ABORTED is proof the write was refused; every other
        # error leaves the outcome genuinely unknown, and Google's own guidance
        # is that a state-changing call can return DEADLINE_EXCEEDED after the
        # change was applied. Recording "it failed" would be a claim, not an
        # observation — and a terminal one, which is the single state
        # reconciliation cannot rescue.
        C.EXECUTION_OUTCOME_UNKNOWN, S.EXECUTION_FAILED,
        reconcilable=True, retry_eligible=False,
        summary="A repair was sent but the system could not confirm whether it "
                "took effect, so it is checking rather than reporting a result.",
    ),
    C.VERIFIER_UNAVAILABLE: _h(
        C.VERIFIER_UNAVAILABLE, S.REMEDIATION_FAILED, reconcilable=True, retry_eligible=False,
        summary="A fix was applied but could not be independently confirmed yet, "
                "so this is not being reported as resolved until it is.",
    ),
    C.VERIFICATION_FAILED: _h(
        C.VERIFICATION_FAILED, S.ESCALATED, reconcilable=False, retry_eligible=False,
        summary="A fix was applied but the service still did not come back "
                "correctly, so a person is needed.",
    ),
    C.REMEDIATION_FAILED: _h(
        C.REMEDIATION_FAILED, S.ESCALATED, reconcilable=False, retry_eligible=False,
        summary="The automatic fix did not succeed. A person is needed.",
    ),
}


def handling(category: FailureCategory) -> FailureHandling:
    return HANDLING[category]


class EscalationPackage(BaseModel):
    """What a human is handed when automation stops.

    Deliberately excludes model rationale, credentials, tokens, stack traces and
    API-level detail. The duty manager needs to know what happened to the shop,
    not which method raised. Technical evidence lives in the incident's evidence
    subcollection and in structured logs, correlated by `correlation_id`.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    incident_id: str
    correlation_id: str | None
    failure_category: FailureCategory
    impact: str
    specialists_attempted: list[str]
    evidence_summary: list[str]
    #: True / False / None. None is load-bearing: for the outcome-unknown
    #: categories the honest answer is "we do not know", and collapsing that to
    #: False told a duty manager as fact the one thing the category exists to
    #: say is unknown — while the impact line two fields up said the opposite.
    automation_changed_anything: bool | None
    what_automation_did: str
    current_service_state: str
    operations_restored: bool
    recommended_next_action: str


#: What the manager is told to do, per category. Kept beside the taxonomy so a
#: new category cannot be added without deciding what a human should do.
NEXT_ACTION: dict[FailureCategory, str] = {
    C.MODEL_OUTPUT_INVALID: "Contact technical support and quote the reference below.",
    C.DANGEROUS_ACTION_REFUSED: "Contact technical support immediately and quote the "
                                "reference below. Do not retry.",
    C.WORKER_TIMEOUT: "Contact technical support and quote the reference below.",
    C.WORKER_UNAVAILABLE: "Contact technical support and quote the reference below.",
    C.WORKER_BUDGET_EXCEEDED: "Contact technical support and quote the reference below.",
    C.WORKER_CONTRACT_INVALID: "Contact technical support and quote the reference below.",
    C.INSUFFICIENT_EVIDENCE: "Describe what staff are seeing in more detail, or contact "
                             "technical support if the problem continues.",
    C.STALE_EVIDENCE: "Re-report the problem if it is still happening.",
    C.TARGET_NO_LONGER_HEALTHY: "Contact technical support and quote the reference below.",
    C.EXECUTION_CONFLICT: "Re-report the problem if it is still happening.",
    C.EXECUTOR_UNAVAILABLE: "No action needed yet. Re-report if the problem continues.",
    C.EXECUTION_OUTCOME_UNKNOWN: "No action needed yet. The result is still being confirmed.",
    C.VERIFIER_UNAVAILABLE: "No action needed yet. Confirmation is still in progress.",
    C.VERIFICATION_FAILED: "Contact technical support and quote the reference below.",
    C.REMEDIATION_FAILED: "Contact technical support and quote the reference below.",
}


#: Failures where "did anything change?" has no truthful yes/no answer.
OUTCOME_UNKNOWN_CATEGORIES: frozenset[FailureCategory] = frozenset(
    {
        FailureCategory.EXECUTION_OUTCOME_UNKNOWN,
        FailureCategory.EXECUTOR_UNAVAILABLE,
    }
)


def build_escalation_package(
    *,
    incident_id: str,
    category: FailureCategory,
    correlation_id: str | None,
    specialists_attempted: list[str],
    evidence_keys: list[str],
    mutated: bool | None,
    current_service_state: str,
    operations_restored: bool,
) -> EscalationPackage:
    """Deterministic, human-consumable handover. No model text, no secrets."""
    rule = handling(category)
    if not mutated and category in OUTCOME_UNKNOWN_CATEGORIES:
        # We did not observe a change. For these categories that is not the
        # same as there having been none, and the handover must not say it was.
        mutated = None
    return EscalationPackage(
        incident_id=incident_id,
        correlation_id=correlation_id,
        failure_category=category,
        impact=rule.manager_summary,
        specialists_attempted=specialists_attempted,
        # Keys only. Values can contain untrusted report text and are already
        # persisted with their provenance; the handover names what was checked.
        evidence_summary=sorted(set(evidence_keys)),
        automation_changed_anything=mutated,
        what_automation_did=(
            "A service change was applied and is recorded."
            if mutated
            else "A change was sent but the system could not confirm whether it "
            "took effect. It is being re-checked."
            if mutated is None
            else "No change was made to any service."
        ),
        current_service_state=current_service_state,
        operations_restored=operations_restored,
        recommended_next_action=NEXT_ACTION[category],
    )
