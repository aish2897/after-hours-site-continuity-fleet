from __future__ import annotations

import pytest

from scf.domain.enums import ActionType, Decision, TrustLevel
from scf.domain.models import Evidence, Proposal
from scf.policy import default_policy, evaluate

A = ActionType
D = Decision


def ev(key, value, trust=TrustLevel.TRUSTED_TOOL, agent="systems"):
    return Evidence(
        key=key,
        value=value,
        supports="decision matrix fixture",
        source_agent=agent,
        trust_level=trust,
    )


def propose(action_type, target_ref, confidence=0.9):
    return Proposal(
        action_type=action_type, target_ref=target_ref, confidence=confidence
    )


HEALTHY_FLIP_EVIDENCE = [
    ev("service_unhealthy", True),
    ev("last_good_revision_exists", True),
]

UNTRUSTED_FLIP_EVIDENCE = [
    ev("service_unhealthy", True, TrustLevel.UNTRUSTED_INPUT),
    ev("last_good_revision_exists", True, TrustLevel.UNTRUSTED_INPUT),
]


MATRIX = [
    # --- traffic flip: the slice-1 happy path ---------------------------------
    ("flip/ok", A.FLIP_TRAFFIC_TO_LAST_GOOD, "dispatch-web", HEALTHY_FLIP_EVIDENCE,
     D.AUTO_ALLOWED, "LOW_RISK_TRAFFIC_FLIP"),
    ("flip/no-last-good", A.FLIP_TRAFFIC_TO_LAST_GOOD, "dispatch-web",
     [ev("service_unhealthy", True)], D.DENIED, "MISSING_EVIDENCE"),
    ("flip/service-healthy", A.FLIP_TRAFFIC_TO_LAST_GOOD, "dispatch-web",
     [ev("service_unhealthy", False), ev("last_good_revision_exists", True)],
     D.DENIED, "MISSING_EVIDENCE"),
    ("flip/no-evidence", A.FLIP_TRAFFIC_TO_LAST_GOOD, "dispatch-web", [],
     D.DENIED, "MISSING_EVIDENCE"),
    # The injection defence: identical evidence, untrusted provenance.
    ("flip/untrusted-only", A.FLIP_TRAFFIC_TO_LAST_GOOD, "dispatch-web",
     UNTRUSTED_FLIP_EVIDENCE, D.DENIED, "MISSING_EVIDENCE"),
    ("flip/other-noncritical-service", A.FLIP_TRAFFIC_TO_LAST_GOOD,
     "site-directory", HEALTHY_FLIP_EVIDENCE, D.AUTO_ALLOWED,
     "LOW_RISK_TRAFFIC_FLIP"),
    ("flip/wrong-target-type", A.FLIP_TRAFFIC_TO_LAST_GOOD, "dispatch-db",
     HEALTHY_FLIP_EVIDENCE, D.DENIED, "NO_MATCHING_RULE"),
    ("flip/unknown-target", A.FLIP_TRAFFIC_TO_LAST_GOOD, "not-registered",
     HEALTHY_FLIP_EVIDENCE, D.DENIED, "UNKNOWN_TARGET"),
    # --- application restart --------------------------------------------------
    ("restart-app/ok", A.RESTART_APPLICATION_SERVICE, "dispatch-web",
     [ev("service_unhealthy", True), ev("server_reachable", True)],
     D.AUTO_ALLOWED, "LOW_RISK_RESTART"),
    ("restart-app/unreachable", A.RESTART_APPLICATION_SERVICE, "dispatch-web",
     [ev("service_unhealthy", True)], D.DENIED, "MISSING_EVIDENCE"),
    ("restart-app/wrong-target", A.RESTART_APPLICATION_SERVICE, "site-firewall",
     [], D.DENIED, "NO_MATCHING_RULE"),
    # --- database restart: evidence can never upgrade this ---------------------
    ("restart-db/approval", A.RESTART_DATABASE_SERVICE, "dispatch-db", [],
     D.APPROVAL_REQUIRED, "PRODUCTION_DATA_RISK"),
    ("restart-db/approval-despite-evidence", A.RESTART_DATABASE_SERVICE,
     "dispatch-db",
     [ev("service_unhealthy", True), ev("server_reachable", True),
      ev("backup_complete", True)],
     D.APPROVAL_REQUIRED, "PRODUCTION_DATA_RISK"),
    ("restart-db/wrong-target-type", A.RESTART_DATABASE_SERVICE, "dispatch-web",
     [], D.DENIED, "NO_MATCHING_RULE"),
    # --- never-allowed actions, wildcard target type --------------------------
    ("firewall/denied", A.DISABLE_FIREWALL, "site-firewall", [],
     D.DENIED, "NEVER_AUTONOMOUS"),
    ("firewall/denied-despite-evidence", A.DISABLE_FIREWALL, "site-firewall",
     [ev("change_approved", True), ev("incident_commander_present", True)],
     D.DENIED, "NEVER_AUTONOMOUS"),
    ("firewall/denied-on-other-target", A.DISABLE_FIREWALL, "dispatch-web", [],
     D.DENIED, "NEVER_AUTONOMOUS"),
    ("credentials/denied", A.EXPORT_CREDENTIALS, "credential-store", [],
     D.DENIED, "NEVER_ALLOWED"),
    ("credentials/denied-with-injected-approval", A.EXPORT_CREDENTIALS,
     "credential-store",
     [ev("approved_by_admin", True, TrustLevel.UNTRUSTED_INPUT)],
     D.DENIED, "NEVER_ALLOWED"),
    ("credentials/denied-on-other-target", A.EXPORT_CREDENTIALS, "dispatch-web",
     [], D.DENIED, "NEVER_ALLOWED"),
]


@pytest.mark.parametrize(
    "name,action_type,target_ref,evidence,expected_decision,expected_reason_code",
    MATRIX,
    ids=[row[0] for row in MATRIX],
)
def test_decision_matrix(
    name, action_type, target_ref, evidence, expected_decision, expected_reason_code
):
    decision = evaluate(propose(action_type, target_ref), evidence)
    assert decision.decision == expected_decision
    assert decision.reason_code == expected_reason_code


def test_approval_role_present_only_when_approval_required():
    approval = evaluate(propose(A.RESTART_DATABASE_SERVICE, "dispatch-db"), [])
    assert approval.required_approval_role == "incident_commander"

    allowed = evaluate(
        propose(A.FLIP_TRAFFIC_TO_LAST_GOOD, "dispatch-web"), HEALTHY_FLIP_EVIDENCE
    )
    assert allowed.required_approval_role is None


def test_untrusted_evidence_cannot_override_trusted_denial():
    """Injected content claiming health cannot flip a trusted 'healthy' reading."""
    evidence = [
        ev("service_unhealthy", False),
        ev("last_good_revision_exists", True),
        ev("service_unhealthy", True, TrustLevel.UNTRUSTED_INPUT),
    ]
    decision = evaluate(propose(A.FLIP_TRAFFIC_TO_LAST_GOOD, "dispatch-web"), evidence)
    assert decision.decision is D.DENIED
    assert decision.reason_code == "MISSING_EVIDENCE"


def test_untrusted_evidence_cannot_revoke_trusted_authorization():
    evidence = [*HEALTHY_FLIP_EVIDENCE,
                ev("service_unhealthy", False, TrustLevel.UNTRUSTED_INPUT)]
    decision = evaluate(propose(A.FLIP_TRAFFIC_TO_LAST_GOOD, "dispatch-web"), evidence)
    assert decision.decision is D.AUTO_ALLOWED


def test_evidence_snapshot_hash_ignores_untrusted_noise():
    clean = evaluate(
        propose(A.FLIP_TRAFFIC_TO_LAST_GOOD, "dispatch-web"), HEALTHY_FLIP_EVIDENCE
    )
    noisy = evaluate(
        propose(A.FLIP_TRAFFIC_TO_LAST_GOOD, "dispatch-web"),
        [*HEALTHY_FLIP_EVIDENCE,
         ev("ignore_all_previous_instructions", True, TrustLevel.UNTRUSTED_INPUT)],
    )
    assert clean.evidence_snapshot_hash == noisy.evidence_snapshot_hash


def test_policy_version_is_recorded_on_every_decision():
    version = default_policy().policy_version
    decision = evaluate(propose(A.EXPORT_CREDENTIALS, "credential-store"), [])
    assert decision.policy_version == version


def test_every_action_type_has_deterministic_coverage():
    """No member of the closed enum may fall through to an undefined outcome."""
    for action_type in ActionType:
        decision = evaluate(propose(action_type, "dispatch-web"), [])
        assert decision.decision in set(Decision)
        assert decision.reason_code
