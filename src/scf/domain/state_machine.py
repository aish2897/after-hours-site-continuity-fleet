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
    S.EXECUTION_FAILED: frozenset({S.ESCALATED}),
    S.REMEDIATION_FAILED: frozenset({S.ESCALATED}),
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
