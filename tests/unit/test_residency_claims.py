"""Guards against stale regional and residency claims re-entering the repo.

Scans published surfaces (markdown and shipped source). The tests directory is
deliberately excluded: guard tests legitimately name the phrases they forbid.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CANONICAL_DOCS = ["README.md", "ARCHITECTURE.md", "SECURITY.md"]

# Phrases that are wrong under the current architecture no matter the context.
FORBIDDEN = [
    "single-region sydney",
    "entirely australian",
    "fully australian",
    "wholly australian",
    "all-australian",
    "firestore, vertex ai, artifact registry",
    "allow_global_endpoint_fallback",
    "global endpoint fallback",
    "global fallback",
]

RESIDENCY_CLAIM = re.compile(r"complete australian[a-z\- ]*residency", re.IGNORECASE)


def published_files() -> list[Path]:
    files: list[Path] = []
    for pattern in ("*.md", "docs/**/*.md", "infra/**/*.md", "deployment/**/*.md"):
        files.extend(REPO_ROOT.glob(pattern))
    files.extend((REPO_ROOT / "src").rglob("*.py"))
    return [f for f in files if ".venv" not in f.parts and "tests" not in f.parts]


@pytest.mark.parametrize("phrase", FORBIDDEN)
def test_forbidden_regional_phrasing_is_absent(phrase):
    offenders = [
        str(path.relative_to(REPO_ROOT))
        for path in published_files()
        if phrase in path.read_text(encoding="utf-8").lower()
    ]
    assert not offenders, f"stale phrasing {phrase!r} found in: {offenders}"


def test_residency_is_only_ever_mentioned_to_disclaim_it():
    """'Complete Australian residency' may appear only alongside 'not claimed'."""
    for path in published_files():
        text = path.read_text(encoding="utf-8")
        for match in RESIDENCY_CLAIM.finditer(text):
            window = text[max(0, match.start() - 50) : match.end() + 70].lower()
            assert "not claimed" in window, (
                f"{path.relative_to(REPO_ROOT)} claims residency at "
                f"offset {match.start()} without disclaiming it"
            )


@pytest.mark.parametrize("doc", CANONICAL_DOCS)
def test_canonical_docs_state_the_split_honestly(doc):
    text = (REPO_ROOT / doc).read_text(encoding="utf-8").lower()
    assert "australia-southeast1" in text, f"{doc} omits the infrastructure region"
    assert "global" in text, f"{doc} omits the global inference location"
    assert "not claimed" in text, f"{doc} does not disclaim residency"


@pytest.mark.parametrize("doc", CANONICAL_DOCS)
def test_canonical_docs_do_not_pin_inference_to_australia(doc):
    text = (REPO_ROOT / doc).read_text(encoding="utf-8").lower()
    assert "australia-southeast1-aiplatform" not in text, (
        f"{doc} references the Sydney Vertex host, which returns 404 for this model"
    )


def test_no_absolute_developer_paths_in_published_files():
    """A public repo should not carry one machine's directory layout."""
    pattern = re.compile(r"[A-Za-z]:[\\/](Users|Agentic)[\\/]", re.IGNORECASE)
    offenders = [
        str(path.relative_to(REPO_ROOT))
        for path in published_files()
        if pattern.search(path.read_text(encoding="utf-8"))
    ]
    assert not offenders, f"absolute developer paths found in: {offenders}"
