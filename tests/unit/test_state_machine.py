from __future__ import annotations

import pytest

from scf.domain.enums import IncidentStatus as S
from scf.domain.state_machine import (
    LEGAL_TRANSITIONS,
    TERMINAL_STATES,
    IllegalTransition,
    assert_transition,
    can_transition,
    is_terminal,
)

SLICE_ONE_HAPPY_PATH = [
    S.INTAKE,
    S.INVESTIGATING,
    S.PROPOSED,
    S.POLICY_EVALUATED,
    S.AUTO_ALLOWED,
    S.EXECUTING,
    S.EXECUTED,
    S.VERIFYING,
    S.RESOLVED,
]

APPROVAL_PATH = [
    S.INTAKE,
    S.INVESTIGATING,
    S.PROPOSED,
    S.POLICY_EVALUATED,
    S.WAITING_FOR_APPROVAL,
    S.APPROVED,
    S.EXECUTING,
    S.EXECUTED,
    S.VERIFYING,
    S.RESOLVED,
]

FAILURE_PATH = [
    S.INTAKE,
    S.INVESTIGATING,
    S.PROPOSED,
    S.POLICY_EVALUATED,
    S.AUTO_ALLOWED,
    S.EXECUTING,
    S.EXECUTED,
    S.VERIFYING,
    S.REMEDIATION_FAILED,
    S.ESCALATED,
]


@pytest.mark.parametrize(
    "path",
    [SLICE_ONE_HAPPY_PATH, APPROVAL_PATH, FAILURE_PATH],
    ids=["happy", "approval", "remediation-failed"],
)
def test_declared_paths_are_legal(path):
    for current, target in zip(path, path[1:]):
        assert_transition(current, target)


def test_every_status_appears_in_the_table():
    assert set(LEGAL_TRANSITIONS) == set(S)


def test_terminal_states_have_no_exits():
    for status in TERMINAL_STATES:
        assert LEGAL_TRANSITIONS[status] == frozenset()
        assert is_terminal(status)


def test_only_resolved_and_escalated_are_terminal():
    assert TERMINAL_STATES == frozenset({S.RESOLVED, S.ESCALATED})


@pytest.mark.parametrize(
    "current,target",
    [
        (S.INTAKE, S.EXECUTING),
        (S.INVESTIGATING, S.RESOLVED),
        (S.POLICY_EVALUATED, S.EXECUTING),
        (S.WAITING_FOR_APPROVAL, S.EXECUTING),
        (S.DENIED, S.EXECUTING),
        (S.RESOLVED, S.INVESTIGATING),
        (S.ESCALATED, S.INTAKE),
    ],
    ids=[
        "skip-investigation",
        "resolve-without-acting",
        "execute-without-authorization",
        "execute-without-approval",
        "execute-after-denial",
        "reopen-resolved",
        "reopen-escalated",
    ],
)
def test_illegal_transitions_are_rejected(current, target):
    assert not can_transition(current, target)
    with pytest.raises(IllegalTransition):
        assert_transition(current, target)


def test_execution_requires_authorization_state():
    """EXECUTING is reachable only from AUTO_ALLOWED or APPROVED."""
    entries = {
        status
        for status, targets in LEGAL_TRANSITIONS.items()
        if S.EXECUTING in targets
    }
    assert entries == {S.AUTO_ALLOWED, S.APPROVED}


def test_every_non_terminal_state_can_reach_a_terminal_state():
    reachable_to_terminal = set(TERMINAL_STATES)
    changed = True
    while changed:
        changed = False
        for status, targets in LEGAL_TRANSITIONS.items():
            if status in reachable_to_terminal:
                continue
            if targets & reachable_to_terminal:
                reachable_to_terminal.add(status)
                changed = True
    assert reachable_to_terminal == set(S), (
        f"states that can never terminate: {set(S) - reachable_to_terminal}"
    )
