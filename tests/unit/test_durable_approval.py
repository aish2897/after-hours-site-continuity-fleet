"""Gate F — durable human approval, process restart, and resume.

The property under test is not that an approval endpoint exists. It is that the
authority to change infrastructure comes from a person, survives the death of
the process that asked, and cannot be manufactured by anything that merely
reaches the service.
"""

from __future__ import annotations

import inspect

import pytest
from pydantic import ValidationError

from scf.app import executor, main
from scf.domain.enums import ActionType, Decision, IncidentStatus, TrustLevel
from scf.domain.ids import derive_authorization_fingerprint, new_approval_id
from scf.domain.models import Evidence, Proposal
from scf.domain.state_machine import can_transition
from scf.policy import default_policy, evaluate


def _ev(key, value):
    return Evidence(
        key=key,
        value=value,
        supports="t",
        source_agent="systems",
        trust_level=TrustLevel.TRUSTED_TOOL,
    )


def _high_risk_evidence():
    """No operator-approved rollback target; an unblessed revision answers."""
    return [
        _ev("service_unhealthy", True),
        _ev("candidate_revision_approved", False),
        _ev("fallback_candidate_probe_healthy", True),
        _ev("fallback_candidate_revision", "dispatch-web-00003-x87"),
    ]


def _shift_proposal():
    return Proposal(
        action_type=ActionType.SHIFT_TRAFFIC_TO_APPROVED_CANDIDATE,
        target_ref="dispatch-web",
        confidence=0.7,
        rationale="t",
        proposed_by="agent:systems",
    )


# --- F1: the approval requirement comes from trusted policy, not from input ---


def test_approval_requirement_comes_from_the_policy_not_the_caller():
    decision = evaluate(_shift_proposal(), _high_risk_evidence())
    assert decision.decision is Decision.APPROVAL_REQUIRED
    assert decision.reason_code == "UNBLESSED_CANDIDATE_RISK"
    assert decision.required_approval_role == "incident_commander"

    # And the intake contract gives a caller no way to ask for a regime.
    # A screenshot is input, not authority: it can change which specialist is
    # asked to look and nothing else.
    assert set(main.IncidentIntake.model_fields) == {
        "description",
        "site_id",
        "reported_by",
        "image_base64",
        "image_media_type",
    }
    assert main.IncidentIntake.model_config["extra"] == "forbid"


def test_a_blessed_rollback_is_still_auto_allowed():
    """The high-risk path must not have made the ordinary path need a human."""
    blessed = [
        _ev("service_unhealthy", True),
        _ev("candidate_revision_approved", True),
        _ev("candidate_probe_healthy", True),
    ]
    proposal = Proposal(
        action_type=ActionType.FLIP_TRAFFIC_TO_LAST_GOOD,
        target_ref="dispatch-web",
        confidence=0.9,
        rationale="t",
        proposed_by="agent:systems",
    )
    assert evaluate(proposal, blessed).decision is Decision.AUTO_ALLOWED


def test_both_actions_use_the_same_proven_mutation_primitive():
    assert (
        ActionType.SHIFT_TRAFFIC_TO_APPROVED_CANDIDATE.value
        in executor.TRAFFIC_MUTATION_ACTIONS
    )
    assert (
        ActionType.FLIP_TRAFFIC_TO_LAST_GOOD.value
        in executor.TRAFFIC_MUTATION_ACTIONS
    )
    # No new infrastructure class was invented in order to have something risky.
    assert (
        default_policy().target_type_of("dispatch-web")
        == "cloud_run_service_non_critical"
    )


# --- F3: the durable waiting path --------------------------------------------


def test_the_waiting_path_is_legal_and_leads_somewhere():
    assert can_transition(
        IncidentStatus.POLICY_EVALUATED, IncidentStatus.WAITING_FOR_APPROVAL
    )
    assert can_transition(IncidentStatus.WAITING_FOR_APPROVAL, IncidentStatus.APPROVED)
    assert can_transition(IncidentStatus.APPROVED, IncidentStatus.EXECUTING)
    # A refusal must also be able to leave.
    assert can_transition(IncidentStatus.WAITING_FOR_APPROVAL, IncidentStatus.ESCALATED)


def test_nothing_is_claimed_while_waiting():
    """No executor call, no execution identity, no mutation before a human acts."""
    source = inspect.getsource(main._run_remediation)
    start = source.index("if policy_decision.decision is Decision.APPROVAL_REQUIRED:")
    end = source.index("if policy_decision.decision is not Decision.AUTO_ALLOWED:")
    park = source[start:end]
    assert "_call(" not in park, "the executor must not be called while waiting"
    assert "EXECUTOR_URL" not in park
    assert "return outcome" in park


# --- F2/F5: an approval is permission for ONE pinned decision ----------------


def test_an_approval_is_bound_to_the_exact_decision():
    base = dict(
        incident_id="INC-1",
        action_type="SHIFT_TRAFFIC_TO_APPROVED_CANDIDATE",
        target_ref="dispatch-web",
        authorized_target_revision="rev-a",
        policy_version="1.2.0",
        evidence_snapshot_hash="hash-a",
    )
    original = derive_authorization_fingerprint(**base)
    # Every component is load-bearing: change any one and the approval no longer
    # applies to what is being attempted.
    for field, value in (
        ("authorized_target_revision", "rev-b"),
        ("target_ref", "site-directory"),
        ("action_type", "FLIP_TRAFFIC_TO_LAST_GOOD"),
        ("policy_version", "9.9.9"),
        ("evidence_snapshot_hash", "hash-b"),
        ("incident_id", "INC-2"),
    ):
        assert (
            derive_authorization_fingerprint(**{**base, field: value}) != original
        ), field


@pytest.mark.parametrize("state", ["PENDING", "REJECTED", "EXPIRED"])
def test_only_an_approved_approval_permits_anything(state):
    blockers = main._approval_blockers(
        {
            "state": state,
            "expires_at": "2999-01-01T00:00:00+00:00",
            "decision_id": "DEC-1",
        },
        {"decision_id": "DEC-1", "decision": "APPROVAL_REQUIRED"},
        {"status": IncidentStatus.WAITING_FOR_APPROVAL.value},
        now_iso="2026-01-01T00:00:00+00:00",
    )
    assert f"approval_state:{state}" in blockers


def test_an_expired_approval_permits_nothing():
    blockers = main._approval_blockers(
        {
            "state": "APPROVED",
            "expires_at": "2020-01-01T00:00:00+00:00",
            "decision_id": "DEC-1",
        },
        {"decision_id": "DEC-1", "decision": "APPROVAL_REQUIRED"},
        {"status": IncidentStatus.WAITING_FOR_APPROVAL.value},
        now_iso="2026-01-01T00:00:00+00:00",
    )
    assert "approval_expired" in blockers


def test_an_approval_for_another_decision_permits_nothing():
    blockers = main._approval_blockers(
        {
            "state": "APPROVED",
            "expires_at": "2999-01-01T00:00:00+00:00",
            "decision_id": "DEC-OTHER",
        },
        {"decision_id": "DEC-1", "decision": "APPROVAL_REQUIRED"},
        {"status": IncidentStatus.WAITING_FOR_APPROVAL.value},
        now_iso="2026-01-01T00:00:00+00:00",
    )
    assert "decision_id_mismatch" in blockers


def test_a_revoked_decision_cannot_be_resumed():
    blockers = main._approval_blockers(
        {
            "state": "APPROVED",
            "expires_at": "2999-01-01T00:00:00+00:00",
            "decision_id": "DEC-1",
        },
        {"decision_id": "DEC-1", "decision": "APPROVAL_REQUIRED", "revoked": True},
        {"status": IncidentStatus.WAITING_FOR_APPROVAL.value},
        now_iso="2026-01-01T00:00:00+00:00",
    )
    assert "decision_revoked" in blockers


def test_a_closed_incident_cannot_be_resumed():
    for status in (IncidentStatus.RESOLVED, IncidentStatus.ESCALATED):
        blockers = main._approval_blockers(
            {
                "state": "APPROVED",
                "expires_at": "2999-01-01T00:00:00+00:00",
                "decision_id": "DEC-1",
            },
            {"decision_id": "DEC-1", "decision": "APPROVAL_REQUIRED"},
            {"status": status.value},
            now_iso="2026-01-01T00:00:00+00:00",
        )
        assert f"incident_state:{status.value}" in blockers


def test_a_tampered_fingerprint_permits_nothing():
    """Approval is permission for the pinned decision, not for a later one."""
    blockers = main._approval_blockers(
        {
            "state": "APPROVED",
            "expires_at": "2999-01-01T00:00:00+00:00",
            "decision_id": "DEC-1",
            "decision_fingerprint": "fingerprint-of-something-else",
        },
        {
            "decision_id": "DEC-1",
            "incident_id": "INC-1",
            "decision": "APPROVAL_REQUIRED",
            "action_type": "SHIFT_TRAFFIC_TO_APPROVED_CANDIDATE",
            "target_ref": "dispatch-web",
            "policy_version": "1.2.0",
            "evidence_snapshot_hash": "hash-a",
            "parameters": {"authorized_target_revision": "rev-a"},
        },
        {"status": IncidentStatus.WAITING_FOR_APPROVAL.value},
        now_iso="2026-01-01T00:00:00+00:00",
    )
    assert "decision_fingerprint_mismatch" in blockers


# --- F4/F12: a caller cannot dictate what it authorizes, or who it is --------


def test_the_approval_request_contract_forbids_everything_that_matters():
    for field, value in (
        ("target_ref", "site-directory"),
        ("authorized_target_revision", "attacker-revision"),
        ("decision_id", "DEC-OTHER"),
        ("approver_email", "ceo@example.com"),
        ("state", "APPROVED"),
    ):
        with pytest.raises(ValidationError):
            main.ApprovalDecisionRequest.model_validate({field: value})
    # A note is the only thing a caller may attach.
    assert main.ApprovalDecisionRequest.model_validate({"note": "ok"}).note == "ok"


def test_a_spoofable_header_cannot_name_the_approver():
    """Without IAP in front, X-Goog-* is just a header anyone may set."""
    assert main.TRUST_PLATFORM_APPROVER_HEADERS is False, (
        "this deployment has no IAP, so the headers must not be trusted"
    )
    for email in (
        "accounts.google.com:attacker@evil.example",
        "ceo@retailco.example",
        None,
    ):
        assert main._approver_principal(None, email) == main.DEMO_APPROVER_PRINCIPAL
    # A bare assertion string proves nothing either.
    assert main._approver_principal("any-string", None) == main.DEMO_APPROVER_PRINCIPAL

    source = inspect.getsource(main._approver_principal)
    assert "X-User" not in source
    assert "approver_email" not in source
    assert "TRUST_PLATFORM_APPROVER_HEADERS" in source


def test_approval_ids_are_server_minted():
    first, second = new_approval_id(), new_approval_id()
    assert first != second
    assert first.startswith("APR-")


# --- F12-G: reaching the executor is not authorization -----------------------


def test_the_executor_verifies_the_approval_itself():
    source = inspect.getsource(executor._approval_blocks_execution)
    assert "approval_fingerprint_mismatch" in source
    assert "approval_expired" in source
    assert 'approval.get("state") != "APPROVED"' in source
    # It reads the approval by id. It cannot enumerate the authoritative plane,
    # and that boundary is not something to route around.
    assert "find_approval_for_decision" not in source
    assert 'decision.get("approval_id")' in source

    assert "_approval_blocks_execution" in inspect.getsource(executor._validate)


def test_an_approval_required_decision_is_not_executable_by_default():
    assert Decision.APPROVAL_REQUIRED.value not in executor.EXECUTABLE


# --- F9: resume reads durable state, it does not re-run the workflow ---------


def test_resume_takes_identifiers_only_and_reads_the_rest():
    source = inspect.getsource(main.resume_incident)
    for loaded in ("repo.get", "repo.latest_decision", "repo.get_approval"):
        assert loaded in source, f"resume must load {loaded} from the store"
    assert "route_incident" not in source, "resume must not re-run routing"
    assert "/evidence" not in source, "resume must not re-investigate"
    assert "create_approval" not in source, "resume must not mint a second approval"


def test_the_resumed_path_records_the_action_it_took():
    """A mutation a person authorized must appear in the audit trail."""
    source = inspect.getsource(main._execute_approved_decision)
    assert "action_executed" in source
    assert "repo.record_action" in source
    assert "resumed_after_approval" in source


# --- Gate F internal hostile review ------------------------------------------


def test_a_resume_interrupted_after_approval_can_be_retried():
    """The APPROVED write and the executor call are not one atomic act."""
    assert IncidentStatus.APPROVED.value in main.RESUMABLE_STATES
    assert IncidentStatus.WAITING_FOR_APPROVAL.value in main.RESUMABLE_STATES

    for status in (IncidentStatus.WAITING_FOR_APPROVAL, IncidentStatus.APPROVED):
        blockers = main._approval_blockers(
            {
                "state": "APPROVED",
                "expires_at": "2999-01-01T00:00:00+00:00",
                "decision_id": "DEC-1",
            },
            {"decision_id": "DEC-1", "decision": "APPROVAL_REQUIRED"},
            {"status": status.value},
            now_iso="2026-01-01T00:00:00+00:00",
        )
        assert not [b for b in blockers if b.startswith("incident_state")], status

    # And the transition is skipped when it has already happened.
    source = inspect.getsource(main.resume_incident)
    assert 'if incident.get("status") == IncidentStatus.WAITING_FOR_APPROVAL.value:' in source


def test_a_refusal_and_a_lapse_both_reach_a_terminal_state():
    """"ESCALATE INSTEAD" must actually escalate."""
    from scf.domain.failures import FailureCategory, handling
    from scf.domain.state_machine import can_transition

    for category in (FailureCategory.APPROVAL_REJECTED, FailureCategory.APPROVAL_EXPIRED):
        rule = handling(category)
        assert rule.resting_status is IncidentStatus.ESCALATED, category
        assert rule.reconcilable is False, category
        assert "nothing was changed" in rule.manager_summary.lower(), category

    assert can_transition(
        IncidentStatus.WAITING_FOR_APPROVAL, IncidentStatus.APPROVAL_DENIED
    )
    assert can_transition(
        IncidentStatus.WAITING_FOR_APPROVAL, IncidentStatus.APPROVAL_EXPIRED
    )
    assert can_transition(IncidentStatus.APPROVAL_DENIED, IncidentStatus.ESCALATED)
    assert can_transition(IncidentStatus.APPROVAL_EXPIRED, IncidentStatus.ESCALATED)

    source = inspect.getsource(main._record_approval_decision)
    assert "_close_unapproved_incident" in source


def test_withdrawing_the_known_good_tag_still_blocks_a_rollback():
    """For a rollback, the tag IS the authorization."""
    source = inspect.getsource(executor.execute)
    assert "accept_untagged_candidate=human_approved" in source
    assert (
        "ActionType.SHIFT_TRAFFIC_TO_APPROVED_CANDIDATE.value" in source
    ), "the fallback is for the human-approved action only"

    observe = inspect.getsource(executor._observe)
    assert "accept_untagged_candidate" in observe
    # The fallback branch is gated, not merely ordered after the blessed tag.
    fallback = observe[observe.index("accept_untagged_candidate"):]
    assert "and authorized_revision" in fallback
