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
    # ESCALATED is reachable directly from each of these, and that matters for
    # truthfulness rather than convenience. Escalating from POLICY_EVALUATED
    # used to route through DENIED, permanently recording that the policy gate
    # refused an action it had in fact authorized; escalating from AUTO_ALLOWED
    # or APPROVED routed through EXECUTING and EXECUTION_FAILED, recording an
    # attempted mutation that was never issued. The incident history is part of
    # the audit trail, so a transition written to reach a destination is a
    # claim, and every claim in it has to be true.
    S.POLICY_EVALUATED: frozenset(
        {S.AUTO_ALLOWED, S.WAITING_FOR_APPROVAL, S.DENIED, S.ESCALATED}
    ),
    S.AUTO_ALLOWED: frozenset({S.EXECUTING, S.ESCALATED}),
    # ESCALATED is reachable directly, and deliberately. There is no approval
    # runtime yet, so without this edge an incident that needs authorization
    # parks here and no endpoint in the fleet can ever move it again. Routing
    # it out through APPROVAL_DENIED instead would record that a person refused
    # the repair, which nobody did.
    S.WAITING_FOR_APPROVAL: frozenset(
        {S.APPROVED, S.APPROVAL_DENIED, S.APPROVAL_EXPIRED, S.ESCALATED}
    ),
    S.APPROVED: frozenset({S.EXECUTING, S.ESCALATED}),
    S.EXECUTING: frozenset({S.EXECUTED, S.EXECUTION_FAILED}),
    # ESCALATED direct, so abandoning a completed execution does not have to
    # claim verification began. The mutation landed; what failed was everything
    # after it, and the trail should say exactly that.
    S.EXECUTED: frozenset({S.VERIFYING, S.ESCALATED}),
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


#: States that assert something was done. Passing THROUGH one of these on the
#: way somewhere else writes that assertion into the incident history, so a
#: route that merely wants to reach a destination must not traverse them.
ASSERTION_STATES: frozenset[IncidentStatus] = frozenset(
    {S.AUTO_ALLOWED, S.APPROVED, S.EXECUTING, S.EXECUTED, S.VERIFYING,
     S.DENIED, S.APPROVAL_DENIED, S.APPROVAL_EXPIRED, S.RESOLVED}
)


def path_to(
    current: IncidentStatus,
    target: IncidentStatus,
    *,
    avoid: frozenset[IncidentStatus] = frozenset(),
) -> tuple[IncidentStatus, ...]:
    """The shortest legal sequence of transitions from `current` to `target`.

    Empty when `current` is already `target`, or when no legal path exists.

    This exists because two hand-written mechanisms were answering the same
    question and disagreeing: an escalation path table listing routes by hand,
    and a single-hop write that assumed the resting state was always one edge
    away. The single hop was reachable with an illegal target — and it lived
    inside the very handler whose job is to make sure a failure always produces
    a handover, so it turned a recoverable failure into an unhandled exception
    and no handover at all.

    The transition table is the only description of what is legal, so it should
    be the only thing consulted.
    """
    if current is target:
        return ()
    seen = {current}
    queue: list[tuple[IncidentStatus, tuple[IncidentStatus, ...]]] = [(current, ())]
    while queue:
        node, route = queue.pop(0)
        for nxt in sorted(LEGAL_TRANSITIONS[node], key=lambda s: s.value):
            if nxt in seen or (nxt in avoid and nxt is not target):
                continue
            step = (*route, nxt)
            if nxt is target:
                return step
            seen.add(nxt)
            queue.append((nxt, step))
    return ()
