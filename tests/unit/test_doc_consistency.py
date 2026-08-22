"""One accurate statement about Model Armor, in every document.

Codex found README and ARCHITECTURE contradicting the Gate G evidence. A guard
is cheaper than remembering.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PUBLISHED = ["README.md", "ARCHITECTURE.md", "SECURITY.md", "STATUS.md",
             "PROJECT_CONTROL.md"]


@pytest.mark.parametrize("name", PUBLISHED)
def test_no_document_still_says_model_armor_is_absent(name):
    text = " ".join((ROOT / name).read_text(encoding="utf-8").lower().split())
    for stale in (
        "model armor is not integrated",
        "model armor is **planned and not integrated**",
        "model armor is planned and not integrated",
        "no such boundary exists today",
        "without any inspection step",
    ):
        assert stale not in text, f"{name} contradicts the Gate G evidence: {stale}"


@pytest.mark.parametrize("name", PUBLISHED)
def test_no_document_makes_model_armor_the_boundary(name):
    """The opposite error: screening is a layer, not the authorization system."""
    text = " ".join((ROOT / name).read_text(encoding="utf-8").lower().split())
    for overclaim in (
        "prompt injection is impossible",
        "model armor guarantees",
        "guarantees safe actions",
        "prevents all prompt injection",
    ):
        assert overclaim not in text, f"{name} overclaims: {overclaim}"
