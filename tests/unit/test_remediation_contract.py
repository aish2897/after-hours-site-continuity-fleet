from __future__ import annotations

import re
from pathlib import Path

import pytest

from scf import config
from scf.domain.enums import ActionType, Decision, TrustLevel
from scf.domain.models import Evidence
from scf.policy import default_registry, evaluate
from scf.tools.cloud_run_evidence import propose_remediation

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src"


def ev(key, value):
    return Evidence(
        key=key,
        value=value,
        supports="gate c fixture",
        source_agent="systems",
        trust_level=TrustLevel.TRUSTED_TOOL,
    )


BROKEN = [
    ev("service_unhealthy", True),
    ev("last_good_revision_exists", True),
    ev("last_good_revision", "dispatch-web-00003-x87"),
    ev("active_revision", "dispatch-web-00004-jqm"),
    ev("http_status", 503),
]

HEALTHY = [
    ev("service_unhealthy", False),
    ev("last_good_revision_exists", True),
    ev("http_status", 200),
]


def test_investigator_proposes_only_when_evidence_warrants_it():
    assert propose_remediation(HEALTHY) is None
    proposal = propose_remediation(BROKEN)
    assert proposal is not None
    assert proposal.action_type is ActionType.FLIP_TRAFFIC_TO_LAST_GOOD


def test_investigator_will_not_propose_without_a_rollback_target():
    evidence = [ev("service_unhealthy", True), ev("last_good_revision_exists", False)]
    assert propose_remediation(evidence) is None


def test_proposal_is_constrained_to_the_closed_enum():
    proposal = propose_remediation(BROKEN)
    assert proposal.action_type in set(ActionType)
    assert proposal.proposed_by == "agent:systems"


def test_gathered_evidence_is_always_trusted_tool():
    """Tool output is trusted; it is the user's words that are not."""
    for item in BROKEN:
        assert item.trust_level is TrustLevel.TRUSTED_TOOL


def test_policy_authorizes_the_flip_only_on_trusted_evidence():
    proposal = propose_remediation(BROKEN)
    allowed = evaluate(proposal, BROKEN)
    assert allowed.decision is Decision.AUTO_ALLOWED
    assert allowed.reason_code == "LOW_RISK_TRAFFIC_FLIP"

    untrusted = [
        Evidence(
            key=item.key,
            value=item.value,
            supports=item.supports,
            source_agent="intake",
            trust_level=TrustLevel.UNTRUSTED_INPUT,
        )
        for item in BROKEN
    ]
    assert evaluate(proposal, untrusted).decision is Decision.DENIED


def test_evidence_never_carries_an_authorization_decision():
    """Evidence describes the world; only PolicyDecision authorizes."""
    forbidden = {"decision", "authorized", "allowed", "approved", "permit"}
    for item in BROKEN:
        assert item.key.lower() not in forbidden


def test_investigator_holds_no_mutating_capability():
    registry = default_registry()
    systems = registry.agents["systems"]
    assert systems.may_write_firestore is False
    assert "flip_traffic_to_last_good" not in systems.allowed_tools
    assert registry.allows_tool("systems", "flip_traffic_to_last_good") is False


def test_only_executor_holds_the_mutating_tool():
    registry = default_registry()
    holders = {
        name
        for name, entry in registry.agents.items()
        if "flip_traffic_to_last_good" in entry.allowed_tools
    }
    assert holders == {"executor"}


def test_executor_target_scope_is_a_single_named_service():
    assert config.DISPATCH_WEB_SERVICE == "dispatch-web"
    assert config.UNRELATED_SERVICE == "site-directory"
    assert config.DISPATCH_WEB_SERVICE != config.UNRELATED_SERVICE


def test_no_application_level_fabricated_permission_denial():
    """Denials must come from Google IAM, never from our own raise statements.

    The prototype faked this with an unconditional raise. Guard against its
    return: no shipped module may construct a PERMISSION_DENIED or 403.
    """
    pattern = re.compile(r"(raise|return).{0,80}(PERMISSION_DENIED|403)", re.S)
    offenders = []
    for path in SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if pattern.search(text):
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert not offenders, f"fabricated permission denial found in: {offenders}"
