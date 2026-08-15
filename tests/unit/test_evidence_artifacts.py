"""Evidence artifacts must exist and must match what the README claims.

A capability marked VERIFIED without a matching artifact is exactly the kind
of drift this project refuses to ship.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = REPO_ROOT / "docs" / "evidence"
README = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

REQUIRED_ARTIFACTS = [
    "gate-a-vertex-gemini.md",
    "gate-a-adk-routing.md",
    "gate-b-cloud-run-firestore.md",
    "gate-c-iam-boundary.md",
]


@pytest.mark.parametrize("filename", REQUIRED_ARTIFACTS)
def test_evidence_artifact_exists_and_is_substantive(filename):
    path = EVIDENCE / filename
    assert path.exists(), f"missing evidence artifact: {filename}"
    assert len(path.read_text(encoding="utf-8")) > 800


def test_gate_c_records_all_three_iam_proofs():
    text = (EVIDENCE / "gate-c-iam-boundary.md").read_text(encoding="utf-8")
    for marker in ("IAM PROOF A", "IAM PROOF B", "IAM PROOF C"):
        assert marker in text, f"{marker} missing from Gate C evidence"


@pytest.mark.parametrize(
    "denial",
    [
        "Permission 'run.services.update' denied on resource",
        "Permission 'run.services.get' denied on resource",
    ],
)
def test_gate_c_records_real_google_denial_text(denial):
    """The proofs must quote Google's own error, not a paraphrase."""
    text = (EVIDENCE / "gate-c-iam-boundary.md").read_text(encoding="utf-8")
    assert denial in text


def test_gate_c_records_the_real_recovery():
    text = (EVIDENCE / "gate-c-iam-boundary.md").read_text(encoding="utf-8")
    assert "503 Service Unavailable" in text
    assert "200 OK" in text
    assert "dispatch service healthy" in text
    assert "dispatch service unavailable" in text


def test_gate_c_discloses_the_actas_requirement():
    """actAs was required; hiding that would misrepresent the boundary."""
    text = (EVIDENCE / "gate-c-iam-boundary.md").read_text(encoding="utf-8")
    assert "iam.serviceAccounts.actAs" in text
    assert "roles/editor" in text.lower() or "roles/editor" in text


def test_readme_does_not_claim_unproven_capabilities():
    forbidden_verified = [
        "full autonomous remediation",
        "crash-resume",
        "Model Armor | **`VERIFIED`**",
        "Cloud Trace end-to-end spans | **`VERIFIED`**",
        "Resumable human approval | **`VERIFIED`**",
    ]
    for claim in forbidden_verified:
        assert claim not in README, f"README over-claims: {claim}"


def test_every_readme_evidence_link_resolves():
    import re

    for target in re.findall(r"\(docs/evidence/([a-z0-9\-.]+)\)", README):
        assert (EVIDENCE / target).exists(), f"README links missing artifact: {target}"
