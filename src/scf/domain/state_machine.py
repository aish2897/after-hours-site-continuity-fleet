from __future__ import annotations

from scf.domain.enums import IncidentStatus

S = IncidentStatus


class IllegalTransition(RuntimeError):
    """Raised when a caller attempts a transition outside the declared table."""

    def __init__(self, current: IncidentStatus, target: IncidentStatus) -> None:
        super().__init__(f"illegal transition {current} -> {target}")
        self.current = current
        self.target = target


LEGAL_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    S.INTAKE: frozenset({S.INVESTIGATING, S.ESCALATED}),
    S.INVESTIGATING: frozenset({S.PROPOSED, S.ESCALATED}),
    S.PROPOSED: frozenset({S.POLICY_EVALUATED, S.ESCALATED}),
    S.POLICY_EVALUATED: frozenset(
        {S.AUTO_ALLOWED, S.WAITING_FOR_APPROVAL, S.DENIED}
    ),
    S.AUTO_ALLOWED: frozenset({S.EXECUTING}),
    S.WAITING_FOR_APPROVAL: frozenset(
        {S.APPROVED, S.APPROVAL_DENIED, S.APPROVAL_EXPIRED}
    ),
    S.APPROVED: frozenset({S.EXECUTING}),
    S.EXECUTING: frozenset({S.EXECUTED, S.EXECUTION_FAILED}),
    S.EXECUTED: frozenset({S.VERIFYING}),
    S.VERIFYING: frozenset({S.RESOLVED, S.REMEDIATION_FAILED}),
    S.DENIED: frozenset({S.ESCALATED}),
    S.APPROVAL_DENIED: frozenset({S.ESCALATED}),
    S.APPROVAL_EXPIRED: frozenset({S.ESCALATED}),
    # Also not terminal, for the same reason as REMEDIATION_FAILED below: if
    # the executor could not be reached, whether it acted is unknown, and
    # reconciliation must be able to establish the truth rather than guess.
    # The edge is to EXECUTED, never back to EXECUTING: entry into EXECUTING
    # stays reachable only from an authorization state, so reconciliation can
    # discover that the mutation did land but can never re-open execution.
    S.EXECUTION_FAILED: frozenset({S.ESCALATED, S.EXECUTED}),
    # REMEDIATION_FAILED is deliberately not terminal. An incident whose
    # infrastructure mutation succeeded but whose verification could not be
    # obtained — the verifier crashed, was unreachable, or timed out — is not
    # closed, and must never be resolved unverified. Reconciliation re-enters
    # VERIFYING to establish the real outcome from live infrastructure.
    S.REMEDIATION_FAILED: frozenset({S.ESCALATED, S.VERIFYING}),
    S.RESOLVED: frozenset(),
    S.ESCALATED: frozenset(),
}

TERMINAL_STATES: frozenset[IncidentStatus] = frozenset({S.RESOLVED, S.ESCALATED})


def is_terminal(status: IncidentStatus) -> bool:
    return status in TERMINAL_STATES


def can_transition(current: IncidentStatus, target: IncidentStatus) -> bool:
    return target in LEGAL_TRANSITIONS[current]


def assert_transition(current: IncidentStatus, target: IncidentStatus) -> None:
    if not can_transition(current, target):
        raise IllegalTransition(current, target)
