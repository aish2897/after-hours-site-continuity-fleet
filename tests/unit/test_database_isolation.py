"""The execution identity must not be able to rewrite its own authorization."""

from __future__ import annotations

import inspect

import pytest

from scf import config
from scf.state import execution_store, firestore_repo


def test_two_distinct_planes_are_configured():
    assert config.AUTHORITATIVE_DATABASE == "(default)"
    assert config.EXECUTION_DATABASE == "execution-state"
    assert config.AUTHORITATIVE_DATABASE != config.EXECUTION_DATABASE


def test_config_fails_closed_when_planes_collapse(monkeypatch):
    monkeypatch.setattr(config, "EXECUTION_DATABASE", "(default)")
    with pytest.raises(RuntimeError, match="must differ"):
        config.validate_database_config()


@pytest.mark.parametrize("blank", ["", "   "])
def test_config_fails_closed_when_a_plane_is_missing(monkeypatch, blank):
    monkeypatch.setattr(config, "EXECUTION_DATABASE", blank)
    with pytest.raises(RuntimeError, match="not configured"):
        config.validate_database_config()


def test_idempotency_lives_only_in_the_execution_plane():
    """The claim must not be writable in the database holding authorization."""
    assert hasattr(execution_store.ExecutionStore, "acquire")
    assert not hasattr(firestore_repo.IncidentRepository, "acquire")
    assert not hasattr(firestore_repo.IncidentRepository, "claim_idempotency")


def test_execution_store_cannot_write_authorization_state():
    forbidden = {"save_decision", "save_evidence", "append_audit", "transition", "create"}
    surface = {
        name
        for name, _ in inspect.getmembers(
            execution_store.ExecutionStore, inspect.isfunction
        )
    }
    assert not (surface & forbidden), f"execution plane exposes {surface & forbidden}"


def test_execution_store_offers_no_delete():
    """A claim that could be retracted would not be an idempotency guarantee."""
    surface = {
        name
        for name, _ in inspect.getmembers(
            execution_store.ExecutionStore, inspect.isfunction
        )
    }
    assert not any("delete" in name for name in surface)


def test_authoritative_writes_are_declared_on_the_control_plane_only():
    surface = {
        name
        for name, _ in inspect.getmembers(
            firestore_repo.IncidentRepository, inspect.isfunction
        )
    }
    for writer in ("save_decision", "save_evidence", "append_audit", "transition"):
        assert writer in surface


def test_executor_reads_authority_and_writes_only_receipts():
    from scf.app import executor

    source = inspect.getsource(executor)
    # Authority is read from the authoritative plane.
    assert "repo.get_decision" in source
    # Claims and receipts go to the execution plane.
    assert "store.acquire" in source
    assert "store.record_receipt" in source
    # The executor must never write the control plane.
    for forbidden in ("repo.append_audit", "repo.save_decision", "repo.record_action"):
        assert forbidden not in source, f"executor writes control plane via {forbidden}"


def test_executor_cannot_substitute_execution_state_as_authorization_source():
    from scf.app import executor

    source = inspect.getsource(executor)
    assert "store.get_decision" not in source
    assert "store.get_claim" not in source


def test_stores_default_to_their_own_planes():
    assert (
        inspect.signature(firestore_repo.IncidentRepository.__init__)
        .parameters["database"]
        .default
        is None
    )
    reader_source = inspect.getsource(firestore_repo.IncidentRepository.__init__)
    assert "AUTHORITATIVE_DATABASE" in reader_source
    writer_source = inspect.getsource(execution_store.ExecutionStore.__init__)
    assert "EXECUTION_DATABASE" in writer_source


def test_both_stores_validate_configuration_before_connecting():
    for source in (
        inspect.getsource(firestore_repo.IncidentRepository.__init__),
        inspect.getsource(execution_store.ExecutionStore.__init__),
    ):
        assert "validate_database_config()" in source
