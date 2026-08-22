"""Cheap guards against documentation drifting away from the running system.

Every claim here was actually wrong at some point. The Gate H evidence table
said the Network and Security investigators were LLM-backed when neither has
ever called a model; the README said their runtimes were not integrated after
they had been deployed and proven; STATUS.md listed human approval as not
started two gates after it shipped.

Prose is the part of this project a judge reads first and the part no test was
watching. These are deliberately cheap — substring and registry checks, no cloud
— so they can run on every doc change.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from scf.policy import default_registry

ROOT = Path(__file__).resolve().parents[2]
DOCS = [ROOT / name for name in ("README.md", "STATUS.md", "PROJECT_CONTROL.md")]
DOCS += sorted((ROOT / "docs/evidence").glob("*.md"))
DOCS += [ROOT / "infra/iam-matrix.md"]


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# --- the model boundary ------------------------------------------------------


def test_only_the_orchestrator_modules_call_a_model():
    """The claim every doc rests on. If this changes, the docs are wrong.

    Two modules, both owned by the orchestrator: `routing` decides which
    specialists to consult, and `vision` transcribes an attached screenshot so
    the text can be screened before routing reads it. No specialist service
    calls a model, which is the property the documents actually assert.
    """
    callers = set()
    for path in (ROOT / "src/scf").rglob("*.py"):
        source = _text(path)
        if any(
            marker in source
            for marker in ("LlmAgent(", "generate_content(", "InMemoryRunner(")
        ):
            callers.add(path.relative_to(ROOT).as_posix())
    assert callers == {
        "src/scf/agents/routing.py",
        "src/scf/agents/vision.py",
    }, callers
    # Both live under agents/, which the orchestrator alone runs.
    for caller in callers:
        assert caller.startswith("src/scf/agents/"), caller


def test_no_specialist_is_registered_as_llm_backed():
    registry = default_registry()
    assert registry.agents["orchestrator"].llm_backed is True
    for name in ("systems", "network", "security", "continuity",
                 "executor", "verifier"):
        assert registry.agents[name].llm_backed is False, name


@pytest.mark.parametrize("agent", ["Network", "Security", "Continuity"])
def test_no_document_calls_a_deterministic_specialist_llm_backed(agent):
    """Guard the specific sentence shape that was wrong in the Gate H table."""
    bad = re.compile(
        rf"{agent}[^|\n]*\|[^|\n]*\|[^|\n]*\|\s*(yes|LLM|llm)", re.IGNORECASE
    )
    for path in DOCS:
        if not path.exists():
            continue
        for line in _text(path).splitlines():
            assert not bad.search(line), f"{path.name}: {line.strip()}"


# --- integration honesty -----------------------------------------------------


def test_no_document_still_says_the_new_runtimes_are_missing():
    """They are deployed, proven, and carry live IAM denials."""
    stale = (
        "systems only so far",
        "only Systems deployed",
        "only Systems is deployed",
        "Network Investigator runtime\n",
        "Security & Identity Investigator runtime\n",
        "Continuity Coordinator runtime\n",
    )
    for path in DOCS:
        if not path.exists():
            continue
        source = _text(path)
        # A "NOT STARTED"-style list is the only place these bare runtime lines
        # were wrong; evidence files legitimately name the runtimes in prose.
        if "NOT STARTED" not in source:
            continue
        section = source[source.index("NOT STARTED"):]
        for phrase in stale:
            assert phrase not in section, f"{path.name}: stale '{phrase.strip()}'"


def test_human_approval_is_not_listed_as_unstarted():
    status = _text(ROOT / "STATUS.md")
    section = status[status.index("NOT STARTED"):]
    for phrase in ("Human approval and resume", "Crash-resumable workflow"):
        assert phrase not in section, phrase


# --- the registry is ours, not Google's --------------------------------------


def test_no_document_claims_the_google_agent_registry_is_integrated():
    """It is discovery-only. `POST .../agents` returns 404 and always has."""
    forbidden = re.compile(
        r"(Google (Cloud )?Agent Registry|agent-registry)[^.\n]{0,60}"
        r"(is integrated|integration (is )?(complete|verified)|registered our)",
        re.IGNORECASE,
    )
    for path in DOCS:
        if not path.exists():
            continue
        match = forbidden.search(_text(path))
        assert match is None, f"{path.name}: {match.group(0) if match else ''}"


def test_the_lifecycle_proof_is_still_documented():
    """Removing the overclaim must not remove the real result underneath it."""
    gate_h = _text(ROOT / "docs/evidence/gate-h-fleet-registry.md")
    assert "enabled: false" in gate_h
    assert "withheld ['network']" in gate_h
    assert "ESCALATED" in gate_h
    registry = default_registry()
    assert registry.is_selectable("network") is True
    assert hasattr(registry, "is_selectable")


# --- the IAM matrix describes what exists ------------------------------------


def test_the_iam_matrix_names_every_provisioned_identity():
    matrix = _text(ROOT / "infra/iam-matrix.md")
    for account in ("sa-orchestrator", "sa-agent-systems", "sa-agent-network",
                    "sa-agent-security", "sa-agent-continuity", "sa-executor",
                    "sa-verifier", "sa-approval"):
        assert account in matrix, account
    assert "scf-approval" in matrix
    assert "scfRemediator" in matrix


def test_the_iam_matrix_does_not_describe_identities_that_do_not_exist():
    """`sa-approval-api` was planned and never created."""
    matrix = _text(ROOT / "infra/iam-matrix.md")
    index = matrix.find("sa-approval-api")
    if index != -1:
        # Naming it is allowed only while saying it does not exist.
        assert "No `sa-approval-api`" in matrix or "does not exist" in matrix[index - 200:index + 200]
