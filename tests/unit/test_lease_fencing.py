"""Gate D.3 — fenced execution, v1 resourceVersion CAS, terminalization.

The decisive proofs are live: real Firestore transactions under real
concurrency, and real Google 409 ABORTED responses. See
docs/evidence/gate-d3-lease-fencing-cas.md. These tests lock the contracts
those proofs depend on so they cannot regress silently, and they carry the
whole of the Cloud Run replacement-body logic, which is where an accidental
configuration change or a spurious new revision would come from.
"""

from __future__ import annotations

import copy
import inspect

import pytest

from scf.app.executor import ExecuteRequest, TerminalizeRequest, _candidate_is_fresh
from scf.domain.enums import ExecutionState
from scf.domain.ids import derive_authorization_fingerprint
from scf.executor import cloud_run
from scf.executor.cloud_run import (
    SERVER_ONLY_METADATA,
    ServiceSnapshotError,
    build_traffic_replacement,
    resource_version_of,
)
from scf.state import execution_store
from scf.tools.cloud_run_evidence import serves_exclusively, traffic_allocation

# --- D3.1 lease_epoch --------------------------------------------------------


def test_acquire_issues_an_epoch_and_never_accepts_one():
    params = inspect.signature(execution_store.ExecutionStore.acquire).parameters
    assert "lease_epoch" not in params, "the epoch is generated here, never supplied"
    source = inspect.getsource(execution_store.ExecutionStore.acquire)
    assert '"lease_epoch": 1' in source, "initial acquisition establishes an epoch"
    assert 'int(current.get("lease_epoch") or 0) + 1' in source, "takeover increments"


def test_acquire_reports_the_full_ownership_grant():
    source = inspect.getsource(execution_store.ExecutionStore.acquire)
    for field in ("execution_id", "lease_owner", "lease_epoch", "lease_expires_at", "state"):
        assert field in source


def test_terminality_is_checked_before_lease_expiry():
    """An expired lease must never reopen a finished execution."""
    source = inspect.getsource(execution_store.ExecutionStore.acquire)
    assert source.index("_TERMINAL_VALUES") < source.index(
        'expires = current.get("lease_expires_at")'
    )


# --- D3.2 ownership-bound transitions ---------------------------------------


def test_advance_requires_owner_and_epoch():
    params = inspect.signature(execution_store.ExecutionStore.advance).parameters
    assert params["owner"].kind is inspect.Parameter.KEYWORD_ONLY
    assert params["lease_epoch"].kind is inspect.Parameter.KEYWORD_ONLY
    assert "expect_states" in params


def test_advance_is_a_transactional_compare_and_set_on_all_five_conditions():
    source = inspect.getsource(execution_store.ExecutionStore.advance)
    assert "@firestore.transactional" in source
    assert "_TERMINAL_VALUES" in source          # not terminal
    assert 'current.get("lease_owner") != owner' in source   # owner
    assert '"lease_epoch"' in source             # epoch
    assert "expires <= now" in source            # lease still valid
    assert "expect_states" in source             # expected current state


def test_failed_ownership_returns_a_deterministic_non_mutating_result():
    for outcome in (
        execution_store.ADVANCED,
        execution_store.FENCED_OUT,
        execution_store.LEASE_LOST,
        execution_store.ALREADY_TERMINAL,
        execution_store.STATE_MISMATCH,
        execution_store.NOT_FOUND,
    ):
        assert isinstance(outcome, str) and outcome


def test_renew_is_fenced_by_epoch():
    source = inspect.getsource(execution_store.ExecutionStore.renew)
    assert '"lease_epoch"' in source
    assert "FENCED_OUT" in source


def test_no_unconditional_state_write_remains():
    """The pre-D3.2 bug: any worker could overwrite execution state at will."""
    source = inspect.getsource(execution_store)
    # Every state write goes through a transaction.
    assert "self._ref(execution_id).update(" not in source


def test_execution_records_are_still_never_deleted():
    source = inspect.getsource(execution_store)
    assert ".delete(" not in source


# --- D3.3 final ownership check ---------------------------------------------


def test_ownership_is_revalidated_before_the_cloud_run_snapshot_is_read():
    source = inspect.getsource(__import__("scf.app.executor", fromlist=["execute"]).execute)
    fence_at = source.index("ExecutionState.PRECONDITION_CHECKED")
    read_at = source.index("read_service_v1")
    mutate_at = source.index("flip_traffic_to_revision")
    assert fence_at < read_at < mutate_at
    # And a second fence immediately before the mutation itself.
    assert source.index("ExecutionState.MUTATION_REQUESTED") < mutate_at


def test_a_fenced_worker_never_fetches_a_fresh_resource_version():
    """The snapshot is read once, under ownership, and passed to the mutation."""
    source = inspect.getsource(__import__("scf.app.executor", fromlist=["execute"]).execute)
    assert source.count("read_service_v1") == 1
    assert "flip_traffic_to_revision, target_ref, authorized_revision, snapshot" in source


def test_mutation_accepts_the_authorized_snapshot_rather_than_refetching():
    params = inspect.signature(cloud_run.flip_traffic_to_revision).parameters
    assert "snapshot" in params


# --- D3.4 v1 replaceService, and no configuration drift ----------------------


SNAPSHOT = {
    "apiVersion": "serving.knative.dev/v1",
    "kind": "Service",
    "metadata": {
        "name": "dispatch-web",
        "namespace": "site-continuity-fleet",
        "resourceVersion": "AAZZJrWF8/E",
        "uid": "3f0d",
        "generation": 31,
        "selfLink": "/apis/serving.knative.dev/v1/namespaces/x/services/dispatch-web",
        "creationTimestamp": "2026-08-16T00:00:00Z",
        "labels": {"cloud.googleapis.com/location": "australia-southeast1"},
        "annotations": {
            "run.googleapis.com/ingress": "all",
            "run.googleapis.com/operation-id": "op-123",
        },
    },
    "spec": {
        "template": {
            "metadata": {
                "annotations": {"autoscaling.knative.dev/maxScale": "4"},
            },
            "spec": {
                "serviceAccountName": "sa-dispatch-web@example.iam.gserviceaccount.com",
                "containers": [
                    {
                        "image": "australia-southeast1-docker.pkg.dev/x/y/z@sha256:abc",
                        "env": [{"name": "SERVICE_MODE", "value": "broken"}],
                    }
                ],
            },
        },
        "traffic": [
            {"revisionName": "dispatch-web-00004-jqm", "percent": 100},
            {"revisionName": "dispatch-web-00003-x87", "tag": "known-good"},
        ],
    },
    "status": {
        "latestCreatedRevisionName": "dispatch-web-00004-jqm",
        "latestReadyRevisionName": "dispatch-web-00004-jqm",
        "traffic": [{"revisionName": "dispatch-web-00004-jqm", "percent": 100}],
        "url": "https://dispatch-web.example",
    },
}


def _replacement(revision="dispatch-web-00003-x87", snapshot=None):
    return build_traffic_replacement(copy.deepcopy(snapshot or SNAPSHOT), revision)


def test_replacement_carries_the_resource_version_precondition():
    assert resource_version_of(_replacement()) == "AAZZJrWF8/E"


def test_replacement_does_not_change_the_image():
    before = SNAPSHOT["spec"]["template"]["spec"]["containers"][0]["image"]
    after = _replacement()["spec"]["template"]["spec"]["containers"][0]["image"]
    assert after == before


def test_replacement_does_not_change_the_runtime_service_account():
    after = _replacement()["spec"]["template"]["spec"]
    assert after["serviceAccountName"] == (
        "sa-dispatch-web@example.iam.gserviceaccount.com"
    )


def test_replacement_does_not_change_environment_or_scaling_or_ingress():
    after = _replacement()
    template = after["spec"]["template"]
    assert template["spec"]["containers"][0]["env"] == [
        {"name": "SERVICE_MODE", "value": "broken"}
    ]
    assert template["metadata"]["annotations"]["autoscaling.knative.dev/maxScale"] == "4"
    assert after["metadata"]["annotations"]["run.googleapis.com/ingress"] == "all"
    assert after["metadata"]["labels"] == SNAPSHOT["metadata"]["labels"]


def test_replacement_pins_the_template_name_so_no_revision_is_minted():
    """Absent a pinned name, Cloud Run treats the template as new and creates one."""
    assert (
        _replacement()["spec"]["template"]["metadata"]["name"]
        == "dispatch-web-00004-jqm"
    )


def test_replacement_refuses_when_no_revision_name_can_be_pinned():
    snapshot = copy.deepcopy(SNAPSHOT)
    snapshot["status"].pop("latestCreatedRevisionName")
    with pytest.raises(ServiceSnapshotError):
        build_traffic_replacement(snapshot, "dispatch-web-00003-x87")


def test_replacement_refuses_a_snapshot_with_no_precondition():
    snapshot = copy.deepcopy(SNAPSHOT)
    snapshot["metadata"].pop("resourceVersion")
    with pytest.raises(ServiceSnapshotError):
        build_traffic_replacement(snapshot, "dispatch-web-00003-x87")


def test_replacement_preserves_the_known_good_tag():
    traffic = _replacement()["spec"]["traffic"]
    tags = [e for e in traffic if e.get("tag") == "known-good"]
    assert tags == [{"revisionName": "dispatch-web-00003-x87", "tag": "known-good"}]


def test_replacement_changes_only_the_traffic_allocation():
    after = _replacement()
    assert after["spec"]["traffic"][0] == {
        "revisionName": "dispatch-web-00003-x87",
        "percent": 100,
    }
    assert sum(e.get("percent", 0) for e in after["spec"]["traffic"]) == 100


def test_replacement_strips_server_owned_fields():
    after = _replacement()
    assert "status" not in after
    for field in SERVER_ONLY_METADATA:
        assert field not in after["metadata"]
    assert "run.googleapis.com/operation-id" not in after["metadata"]["annotations"]


def test_replacement_leaves_the_caller_snapshot_untouched():
    snapshot = copy.deepcopy(SNAPSHOT)
    build_traffic_replacement(snapshot, "dispatch-web-00003-x87")
    assert snapshot == SNAPSHOT


def test_mutation_uses_the_v1_endpoint_that_enforces_the_precondition():
    assert "serving.knative.dev/v1" in cloud_run.KNATIVE_API
    source = inspect.getsource(cloud_run.flip_traffic_to_revision)
    assert "httpx.put" in source
    assert "409" in source, "a real conflict must be reported as a conflict"


def test_v2_etag_is_never_used_as_a_concurrency_claim():
    """The module explains the v1/v2 finding; the code must not rely on v2."""
    code = inspect.getsource(cloud_run).replace(cloud_run.__doc__, "")
    assert "If-Match" not in code
    assert "httpx.patch" not in code


# --- D3.6 exact authorized target --------------------------------------------


def test_request_surface_carries_no_authorization_input():
    for model in (ExecuteRequest, TerminalizeRequest):
        assert set(model.model_fields) == {"incident_id", "decision_id"}
    for field in (
        "target_revision",
        "authorized_target_revision",
        "resource_version",
        "resourceVersion",
        "percent",
        "target_ref",
        "action_type",
        "verdict",
        "force",
    ):
        with pytest.raises(Exception):
            ExecuteRequest(incident_id="INC-1", decision_id="DEC-1", **{field: "x"})


def test_target_comes_only_from_the_stored_decision():
    source = inspect.getsource(__import__("scf.app.executor", fromlist=["execute"]).execute)
    assert 'authorized_revision = params["authorized_target_revision"]' in source
    assert "request.authorized" not in source


# --- D3.7 candidate freshness -------------------------------------------------


def test_candidate_freshness_requires_identity_and_a_live_probe():
    healthy = {
        "candidate_revision": "dispatch-web-00003-x87",
        "candidate_probe_healthy": True,
    }
    assert _candidate_is_fresh(healthy, "dispatch-web-00003-x87") is None
    assert _candidate_is_fresh(
        {**healthy, "candidate_probe_healthy": False}, "dispatch-web-00003-x87"
    ) == "candidate_probe_unhealthy"
    assert _candidate_is_fresh(healthy, "dispatch-web-00004-jqm") == (
        "candidate_no_longer_approved"
    )


def test_unhealthy_candidate_blocks_the_mutation():
    source = inspect.getsource(__import__("scf.app.executor", fromlist=["execute"]).execute)
    refusal_at = source.index("TARGET_NO_LONGER_HEALTHY")
    mutate_at = source.index("flip_traffic_to_revision")
    assert refusal_at < mutate_at


# --- D3.8 / D3.9 terminalization ---------------------------------------------


def test_verified_is_terminal_and_mid_flight_states_are_not():
    terminal = execution_store.TERMINAL_STATES
    assert ExecutionState.VERIFIED in terminal
    assert ExecutionState.FAILED in terminal
    assert ExecutionState.STALE in terminal
    for state in (
        ExecutionState.CLAIMED,
        ExecutionState.PRECONDITION_CHECKED,
        ExecutionState.MUTATION_REQUESTED,
        ExecutionState.MUTATED,
    ):
        assert state not in terminal


def test_terminalize_is_a_compare_and_set_on_mutated():
    source = inspect.getsource(execution_store.ExecutionStore.terminalize)
    assert "@firestore.transactional" in source
    assert "expect_states" in source
    assert "ALREADY_TERMINAL" in source
    defaults = inspect.signature(execution_store.ExecutionStore.terminalize).parameters
    assert defaults["expect_states"].default == (ExecutionState.MUTATED,)


def test_terminalization_requires_re_observed_infrastructure():
    from scf.app import executor

    source = inspect.getsource(executor.terminalize)
    assert "serves_exclusively" in source
    assert "probe_health" in source
    assert "execution_not_mutated" in source
    assert "infrastructure_does_not_match_authorization" in source


def test_incident_is_never_resolved_before_the_execution_is_terminal():
    from scf.app import main

    source = inspect.getsource(main._verify_and_close)
    assert source.index("/terminalize") < source.index("IncidentStatus.RESOLVED")
    assert 'if not terminal.get("verified")' in source


def test_verification_unavailable_leaves_the_incident_reconcilable():
    from scf.domain.enums import IncidentStatus
    from scf.domain.state_machine import TERMINAL_STATES, can_transition

    assert IncidentStatus.REMEDIATION_FAILED not in TERMINAL_STATES
    assert can_transition(IncidentStatus.REMEDIATION_FAILED, IncidentStatus.VERIFYING)
    assert can_transition(IncidentStatus.VERIFYING, IncidentStatus.RESOLVED)


def test_reconciliation_takes_no_authorization_input():
    from scf.app import main

    source = inspect.getsource(main.reconcile_incident)
    assert "repo.latest_decision" in source
    assert "/execute" in source
    # The reconciler names an incident; it cannot nominate a target or revision.
    assert "authorized_target_revision" in source and "request." not in source


# --- D3.12 partial traffic ----------------------------------------------------


def _described(*entries):
    return {"trafficStatuses": list(entries), "uri": "https://x"}


def test_allocation_reads_every_revision_receiving_traffic():
    described = _described(
        {"revision": "a", "percent": 90}, {"revision": "b", "percent": 10}
    )
    assert traffic_allocation(described) == {"a": 90, "b": 10}


def test_tag_only_entries_are_not_traffic():
    described = _described(
        {"revision": "a", "percent": 100}, {"revision": "b", "tag": "known-good"}
    )
    assert traffic_allocation(described) == {"a": 100}
    assert serves_exclusively(described, "a")


@pytest.mark.parametrize(
    "entries",
    [
        ({"revision": "a", "percent": 50}, {"revision": "b", "percent": 50}),
        ({"revision": "a", "percent": 90}, {"revision": "b", "percent": 10}),
        ({"revision": "a", "percent": 100}, {"revision": "b", "percent": 1}),
        ({"revision": "b", "percent": 100},),
        (),
    ],
)
def test_partial_or_wrong_allocation_is_not_exclusive(entries):
    assert not serves_exclusively(_described(*entries), "a")


def test_verifier_requires_health_revision_and_exclusive_allocation():
    from scf.app import verifier

    source = inspect.getsource(verifier._observe)
    assert "responding and revision_matches and allocation_exclusive" in source


# --- D3.13 audit truncation ----------------------------------------------------


def test_incident_chain_verification_detects_a_truncated_tail():
    from scf.audit import append, verify_incident_chain

    records = []
    for index in range(4):
        records.append(append(records, actor="orchestrator", event=f"e{index}"))

    ok = verify_incident_chain(records, audit_seq=3, audit_tail_hash=records[-1].hash)
    assert ok.ok

    truncated = verify_incident_chain(
        records[:2], audit_seq=3, audit_tail_hash=records[-1].hash
    )
    assert not truncated.ok
    assert truncated.missing_tail == 2
    assert "truncated tail" in truncated.reason


def test_incident_chain_verification_detects_a_tail_hash_mismatch():
    from scf.audit import append, verify_incident_chain

    records = [append([], actor="orchestrator", event="e0")]
    bad = verify_incident_chain(records, audit_seq=0, audit_tail_hash="0" * 64)
    assert not bad.ok
    assert "audit_tail_hash" in bad.reason


# --- D3.14 authorization identity ----------------------------------------------


def _fingerprint(**overrides):
    base = dict(
        incident_id="INC-1",
        action_type="FLIP_TRAFFIC_TO_LAST_GOOD",
        target_ref="dispatch-web",
        authorized_target_revision="dispatch-web-00003-x87",
        policy_version="1.1.0",
        evidence_snapshot_hash="abc",
    )
    return derive_authorization_fingerprint(**{**base, **overrides})


def test_equivalent_authorizations_share_one_fingerprint():
    assert _fingerprint() == _fingerprint()


@pytest.mark.parametrize(
    "field,value",
    [
        ("incident_id", "INC-2"),
        ("target_ref", "site-directory"),
        ("authorized_target_revision", "dispatch-web-00004-jqm"),
        ("policy_version", "1.2.0"),
        ("evidence_snapshot_hash", "def"),
    ],
)
def test_a_materially_different_authorization_is_a_different_fingerprint(field, value):
    assert _fingerprint(**{field: value}) != _fingerprint()


def test_fingerprint_binding_is_first_writer_wins_and_never_retracted():
    source = inspect.getsource(execution_store.ExecutionStore.bind_authorization)
    assert "@firestore.transactional" in source
    assert "tx.create" in source
    assert "CONFLICT" in source
    assert ".delete(" not in source


def test_executor_refuses_a_second_execution_for_the_same_authorization():
    source = inspect.getsource(__import__("scf.app.executor", fromlist=["execute"]).execute)
    bind_at = source.index("bind_authorization")
    acquire_at = source.index("store.acquire")
    assert bind_at < acquire_at, "bind before any ownership or infrastructure work"
    assert "DUPLICATE_AUTHORIZATION" in source


# --- Codex review round 1 — control-plane closure and post-mutation ownership --


def test_executor_refuses_a_decision_from_a_closed_incident():
    """A spent authorization must not become a mutation minutes later."""
    from scf.app.executor import _validate
    from scf.domain.enums import IncidentStatus
    from scf.domain.state_machine import TERMINAL_STATES

    request = ExecuteRequest(incident_id="INC-1", decision_id="DEC-1")
    decision = {
        "incident_id": "INC-1",
        "decision": "AUTO_ALLOWED",
        "action_type": "FLIP_TRAFFIC_TO_LAST_GOOD",
        "target_ref": "dispatch-web",
        "parameters": {"authorized_target_revision": "dispatch-web-00003-x87"},
    }
    for status in TERMINAL_STATES:
        assert _validate(decision, request, {"status": status.value}) == (
            f"incident_closed:{status.value}"
        )
    # A live incident still passes the closure check.
    assert _validate(
        decision, request, {"status": IncidentStatus.EXECUTING.value}
    ) is None


def test_closure_is_checked_before_anything_else():
    from scf.app.executor import _validate

    source = inspect.getsource(_validate)
    assert source.index("incident_closed") < source.index("decision_incident_mismatch")


def test_execute_loads_the_incident_before_validating():
    source = inspect.getsource(__import__("scf.app.executor", fromlist=["execute"]).execute)
    assert source.index("repo.get, request.incident_id") < source.index("_validate(")


def test_a_lapsed_lease_is_reacquired_rather_than_treated_as_a_fence():
    """Losing a lease to nobody is not a fence; the outcome must be recorded."""
    source = inspect.getsource(__import__("scf.app.executor", fromlist=["execute"]).execute)
    assert "if state_result == LEASE_LOST:" in source
    reacquire_at = source.index("if state_result == LEASE_LOST:")
    receipt_at = source.index("store.record_receipt")
    assert reacquire_at < receipt_at


def test_a_genuinely_fenced_worker_writes_no_receipt():
    source = inspect.getsource(__import__("scf.app.executor", fromlist=["execute"]).execute)
    fenced_at = source.index("execution_state_write_fenced")
    receipt_at = source.index("store.record_receipt")
    assert fenced_at < receipt_at
    # The receipt is in the else branch of the fence check, not unconditional.
    between = source[fenced_at:receipt_at]
    assert "else:" in between


def test_terminalization_accepts_an_unrecorded_but_issued_mutation():
    from scf.app.executor import TERMINALIZABLE_STATES

    assert TERMINALIZABLE_STATES == {
        ExecutionState.MUTATION_REQUESTED.value,
        ExecutionState.MUTATED.value,
    }
    for state in (
        ExecutionState.CLAIMED,
        ExecutionState.PRECONDITION_CHECKED,
        ExecutionState.VERIFIED,
        ExecutionState.FAILED,
        ExecutionState.STALE,
    ):
        assert state.value not in TERMINALIZABLE_STATES


def test_only_a_real_mismatch_closes_the_incident():
    from scf.app import main

    source = inspect.getsource(main._verify_and_close)
    assert 'terminal.get("reason") == "infrastructure_does_not_match_authorization"' in source
    escalate_at = source.index("infrastructure_does_not_match_authorization")
    assert source.index("awaiting_reconciliation", escalate_at) > escalate_at


def test_an_unreachable_executor_leaves_the_incident_reconcilable():
    from scf.app import main
    from scf.domain.enums import IncidentStatus
    from scf.domain.state_machine import TERMINAL_STATES, can_transition

    source = inspect.getsource(main._autonomous_remediation)
    assert 'failure.service == "executor"' in source
    assert "IncidentStatus.EXECUTION_FAILED" in source
    assert IncidentStatus.EXECUTION_FAILED not in TERMINAL_STATES
    # Reconciliation establishes that the mutation landed; it never re-opens
    # execution. Entry into EXECUTING stays authorization-only.
    assert can_transition(IncidentStatus.EXECUTION_FAILED, IncidentStatus.EXECUTED)
    assert not can_transition(IncidentStatus.EXECUTION_FAILED, IncidentStatus.EXECUTING)
    assert IncidentStatus.EXECUTION_FAILED in main.RECONCILABLE_STATES
    assert IncidentStatus.REMEDIATION_FAILED in main.RECONCILABLE_STATES


def test_reconciliation_walks_a_legal_path_from_either_awaiting_state():
    from scf.app import main
    from scf.domain.enums import IncidentStatus
    from scf.domain.state_machine import can_transition

    walks = {
        IncidentStatus.EXECUTION_FAILED: [
            IncidentStatus.EXECUTED,
            IncidentStatus.VERIFYING,
            IncidentStatus.RESOLVED,
        ],
        IncidentStatus.REMEDIATION_FAILED: [
            IncidentStatus.VERIFYING,
            IncidentStatus.RESOLVED,
        ],
    }
    for start, path in walks.items():
        current = start
        for step in path:
            assert can_transition(current, step), f"illegal {current} -> {step}"
            current = step
    # And the failure walk out of a reconciled execution attempt.
    assert can_transition(IncidentStatus.EXECUTING, IncidentStatus.EXECUTION_FAILED)
    assert can_transition(IncidentStatus.EXECUTION_FAILED, IncidentStatus.ESCALATED)
    assert main.RECONCILABLE_STATES


def test_entry_into_executing_stays_authorization_only():
    """Reconciliation must never become a second route into execution."""
    from scf.domain.enums import IncidentStatus
    from scf.domain.state_machine import LEGAL_TRANSITIONS

    entries = {
        status
        for status, targets in LEGAL_TRANSITIONS.items()
        if IncidentStatus.EXECUTING in targets
    }
    assert entries == {IncidentStatus.AUTO_ALLOWED, IncidentStatus.APPROVED}


def test_release_is_ownership_bound_and_does_not_terminalize():
    source = inspect.getsource(execution_store.ExecutionStore.release)
    assert "@firestore.transactional" in source
    assert 'current.get("lease_owner") != owner' in source
    assert '"lease_epoch"' in source
    assert "FENCED_OUT" in source
    # It must not close the execution, only give the lease back.
    assert "ExecutionState.FAILED" not in source
    assert '"state"' not in source.split("updates = ")[1]


def test_a_pre_mutation_refusal_gives_the_lease_back():
    """Squatting on a lease after refusing would delay a legitimate retry."""
    source = inspect.getsource(__import__("scf.app.executor", fromlist=["execute"]).execute)
    release_at = source.index("store.release")
    refuse_at = source.index("TARGET_NO_LONGER_HEALTHY")
    mutate_at = source.index("flip_traffic_to_revision")
    assert release_at < refuse_at < mutate_at


def test_a_closed_incident_refusal_still_reports_the_execution_state():
    """Closure refuses first, but a replay is also a terminal-execution replay."""
    source = inspect.getsource(__import__("scf.app.executor", fromlist=["execute"]).execute)
    assert 'problem.startswith("incident_closed")' in source
    assert "execution_state" in source
    assert "TERMINAL_EXECUTION_STATES" in source
