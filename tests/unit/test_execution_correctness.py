"""Gate D.2 — execution correctness invariants that can be proven offline.

The concurrency, reconciliation and precondition behaviours are proven against
real Firestore and real Cloud Run; see
docs/evidence/gate-d2-execution-correctness.md. These tests lock the contracts
those proofs depend on so they cannot regress silently.
"""

from __future__ import annotations

import inspect

import pytest
from pydantic import ValidationError

from scf.app.executor import ExecuteRequest
from scf.domain.enums import ExecutionState
from scf.domain.ids import derive_execution_id
from scf.state import execution_store, firestore_repo


# --- D2.1 stable, decision-bound execution identity -------------------------

def test_execution_id_has_no_caller_controlled_input():
    params = set(inspect.signature(derive_execution_id).parameters)
    assert params == {"incident_id", "action_type", "target_ref", "decision_id"}


def test_request_cannot_declare_a_new_attempt():
    """Case B: no attacker-supplied field may create a second execution."""
    for field, value in [
        ("attempt_intent", 2),
        ("execution_id", "forged"),
        ("idempotency_key", "forged"),
        ("target_revision", "dispatch-web-00004-jqm"),
        ("authorized_target_revision", "dispatch-web-00004-jqm"),
        ("force", True),
    ]:
        with pytest.raises(ValidationError):
            ExecuteRequest(incident_id="INC-1", decision_id="DEC-1", **{field: value})


def test_request_surface_is_exactly_two_identifiers():
    assert set(ExecuteRequest.model_fields) == {"incident_id", "decision_id"}


# --- D2.2 execution lifecycle ------------------------------------------------

def test_lifecycle_states_exist():
    for name in (
        "CLAIMED",
        "MUTATION_REQUESTED",
        "MUTATED",
        "VERIFIED",
        "FAILED",
        "STALE",
    ):
        assert hasattr(ExecutionState, name)


def test_terminal_states_do_not_include_mid_flight_states():
    terminal = execution_store.TERMINAL_STATES
    assert ExecutionState.VERIFIED in terminal
    assert ExecutionState.FAILED in terminal
    assert ExecutionState.STALE in terminal
    # A crashed execution must remain recoverable, not look finished.
    assert ExecutionState.CLAIMED not in terminal
    assert ExecutionState.MUTATION_REQUESTED not in terminal
    assert ExecutionState.MUTATED not in terminal


def test_execution_records_are_never_deleted():
    source = inspect.getsource(execution_store)
    assert ".delete(" not in source
    surface = {
        name for name, _ in inspect.getmembers(execution_store.ExecutionStore, inspect.isfunction)
    }
    assert not any("delete" in name for name in surface)


# --- D2.3 ownership ----------------------------------------------------------

def test_acquire_is_transactional_and_lease_based():
    source = inspect.getsource(execution_store.ExecutionStore.acquire)
    assert "@firestore.transactional" in source
    assert "lease_expires_at" in source
    assert "lease_owner" in source


def test_acquire_reports_every_ownership_outcome():
    for outcome in (
        execution_store.ACQUIRED,
        execution_store.RECOVERED,
        execution_store.HELD_BY_OTHER,
        execution_store.ALREADY_FINISHED,
    ):
        assert isinstance(outcome, str) and outcome


def test_concurrency_is_not_solved_by_runtime_serialisation():
    """Correctness must not depend on Cloud Run concurrency being 1."""
    source = inspect.getsource(execution_store)
    assert "concurrency=1" not in source
    assert "max-instances=1" not in source


# --- D2.4 reconciliation -----------------------------------------------------

def test_executor_reconciles_before_mutating():
    from scf.app import executor

    source = inspect.getsource(executor.execute)
    observe_at = source.index("_observe")
    mutate_at = source.index("flip_traffic_to_revision")
    assert observe_at < mutate_at, "infrastructure must be re-read before mutating"


def test_executor_skips_mutation_when_target_already_active():
    from scf.app import executor

    source = inspect.getsource(executor.execute)
    assert 'observed["active_revision"] == authorized_revision' in source
    assert "reconciled" in source


def test_executor_fails_closed_on_unexpected_state():
    from scf.app import executor

    source = inspect.getsource(executor.execute)
    assert "STALE_EVIDENCE" in source
    assert "ExecutionState.STALE" in source


# --- D2.6 exact target -------------------------------------------------------

def test_verifier_requires_the_authorized_revision():
    from scf.app import verifier

    source = inspect.getsource(verifier)
    assert "revision_matches_authorized" in source
    assert "responding and revision_matches" in source


def test_verifier_does_not_resolve_on_http_alone():
    from scf.app.verifier import _observe

    source = inspect.getsource(_observe)
    assert '"http_healthy"' in source
    assert "revision_matches" in source


# --- D2.8 state and audit atomicity -----------------------------------------

def test_transition_and_audit_commit_together():
    source = inspect.getsource(firestore_repo.IncidentRepository.transition)
    assert "@firestore.transactional" in source
    assert "_commit_audit" in source
    # The pre-D2.8 bug: transition committed, then audit appended separately.
    assert "self.append_audit(" not in source


def test_audit_sequence_is_allocated_from_the_guarded_document():
    source = inspect.getsource(firestore_repo.IncidentRepository._commit_audit)
    assert "audit_seq" in source
    assert "audit_tail_hash" in source
    assert "transaction.create" in source
    assert "transaction.update" in source


def test_incident_creation_initialises_the_audit_chain():
    source = inspect.getsource(firestore_repo.IncidentRepository.create)
    assert "audit_seq" in source
    assert "GENESIS_HASH" in source


# --- D2.9 downstream failure -------------------------------------------------

def test_downstream_calls_are_typed_and_bounded():
    from scf.app import main

    assert hasattr(main, "DownstreamFailure")
    source = inspect.getsource(main._call)
    assert "DownstreamFailure" in source
    assert "malformed_response" in source
    assert "not_configured" in source


def test_downstream_failure_drives_a_legal_escalation_path():
    from scf.app import main
    from scf.domain.enums import IncidentStatus
    from scf.domain.state_machine import can_transition

    for start, path in main.ESCALATION_PATHS.items():
        current = start
        for step in path:
            assert can_transition(current, step), f"illegal escalation {current}->{step}"
            current = step
        assert current is IncidentStatus.ESCALATED


def test_orchestrator_no_longer_raises_raw_http_errors():
    from scf.app import main

    source = inspect.getsource(main)
    assert "raise_for_status" not in source
