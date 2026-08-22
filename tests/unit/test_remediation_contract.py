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
    ev("candidate_revision_approved", True),
    ev("candidate_probe_healthy", True),
    ev("candidate_probe_http_status", 200),
    ev("candidate_revision", "dispatch-web-00003-x87"),
    ev("active_revision", "dispatch-web-00004-jqm"),
    ev("http_status", 503),
]

HEALTHY = [
    ev("service_unhealthy", False),
    ev("candidate_revision_approved", True),
    ev("candidate_probe_healthy", True),
    ev("http_status", 200),
]

#: D2.12 case F — the approved candidate exists but fails its own probe.
CANDIDATE_UNHEALTHY = [
    ev("service_unhealthy", True),
    ev("candidate_revision_approved", True),
    ev("candidate_probe_healthy", False),
    ev("candidate_probe_http_status", 503),
]


def test_investigator_proposes_only_when_evidence_warrants_it():
    assert propose_remediation(HEALTHY) is None
    proposal = propose_remediation(BROKEN)
    assert proposal is not None
    assert proposal.action_type is ActionType.FLIP_TRAFFIC_TO_LAST_GOOD


def test_investigator_will_not_propose_without_an_approved_candidate():
    evidence = [ev("service_unhealthy", True), ev("candidate_revision_approved", False)]
    assert propose_remediation(evidence) is None


def test_investigator_will_not_propose_an_unproven_candidate():
    """Case F: approved but failing its own probe is not a rollback target."""
    assert propose_remediation(CANDIDATE_UNHEALTHY) is None


def test_policy_denies_an_unproven_candidate():
    from scf.domain.models import Proposal

    proposal = Proposal(
        action_type=ActionType.FLIP_TRAFFIC_TO_LAST_GOOD,
        target_ref="dispatch-web",
        confidence=0.9,
    )
    decision = evaluate(proposal, CANDIDATE_UNHEALTHY)
    assert decision.decision is Decision.DENIED
    assert decision.reason_code == "MISSING_EVIDENCE"


def test_goodness_is_never_inferred_from_being_inactive():
    """A revision is not a rollback target merely because it is not serving."""
    import inspect

    from scf.tools import cloud_run_evidence

    source = inspect.getsource(cloud_run_evidence.propose_remediation)
    assert "candidate_revision_approved" in source
    assert "candidate_probe_healthy" in source


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
    # The one 403 this application is entitled to construct: refusing an
    # approval it is not satisfied with. That is an authorization decision this
    # system genuinely makes and owns — it claims nothing about what Google
    # decided, and it is named so it cannot be confused with an infrastructure
    # denial. Every INFRASTRUCTURE denial must still come from Google.
    OWN_AUTHORIZATION_DECISION = "approver_not_authorized"
    offenders = []
    for path in SRC.rglob("*.py"):
        # Code only. The modules that must NOT fabricate a denial are exactly
        # the ones whose docstrings explain that they do not — the Director
        # console says it "returns the 403 that Cloud Run produced, unmodified",
        # and matching that sentence flags the module for describing the
        # correct behaviour. Prose has tripped this suite before.
        text = _stripped(path)
        for match in pattern.finditer(text):
            # A window PAST the match: the pattern ends at "403", so the detail
            # that names the decision sits just beyond it.
            window = text[match.start():match.end() + 120]
            if OWN_AUTHORIZATION_DECISION in window:
                continue
            offenders.append(str(path.relative_to(REPO_ROOT)))
            break
    assert not offenders, f"fabricated permission denial found in: {offenders}"


def _stripped(path) -> str:
    """Source with docstrings removed, so guards match code rather than prose."""
    import ast

    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ) and ast.get_docstring(node):
            node.body = node.body[1:]
    return ast.unparse(tree)


def test_the_only_self_issued_403_is_the_approval_refusal():
    """Pin it, so a second one cannot be added without a decision."""
    forbidden = re.compile(r"status_code=403")
    sites = []
    for path in SRC.rglob("*.py"):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if forbidden.search(line):
                sites.append(f"{path.name}:{n}")
    # One: `approval.authorize()`. Approve and reject share it, so the refusal
    # is a single decision at a single place rather than two copies that could
    # drift apart. It must name itself.
    assert len(sites) == 1, f"unexpected self-issued 403s: {sites}"
    assert sites[0].startswith("approval.py"), sites
    for path in SRC.rglob("*.py"):
        for line in path.read_text(encoding="utf-8").splitlines():
            if "status_code=403" in line:
                assert "approver_not_authorized" in line, line.strip()
