"""Gate G — Model Armor screening of untrusted input.

The claim under test is deliberately modest. Model Armor is one layer, and the
tests that matter most are the ones proving the system is still safe when it
misses — a defence you cannot afford to lose is a dependency, not a defence.
"""

from __future__ import annotations

import inspect

import pytest

from scf import config
from scf.app import main
from scf.domain.enums import ActionType, Decision, TrustLevel
from scf.domain.failures import FailureCategory, handling
from scf.domain.models import Evidence, Proposal
from scf.policy import evaluate, trusted_evidence_map
from scf.security import model_armor
from scf.security.model_armor import ModelArmorResult, ScreeningUnavailable


def _verdict(payload: dict) -> ModelArmorResult:
    return model_armor._read_verdict(payload, "hash", 12)


# --- the verdict reader ------------------------------------------------------


def test_a_clean_prompt_is_allowed():
    result = _verdict(
        {
            "sanitizationResult": {
                "filterMatchState": "NO_MATCH_FOUND",
                "filterResults": {
                    "pi_and_jailbreak": {
                        "piAndJailbreakFilterResult": {
                            "executionState": "EXECUTION_SUCCESS",
                            "matchState": "NO_MATCH_FOUND",
                        }
                    }
                },
            }
        }
    )
    assert result.allowed is True
    assert result.screened is True
    assert result.triggered_filters == ()


def test_an_injection_is_blocked():
    result = _verdict(
        {
            "sanitizationResult": {
                "filterMatchState": "MATCH_FOUND",
                "filterResults": {
                    "pi_and_jailbreak": {
                        "piAndJailbreakFilterResult": {
                            "executionState": "EXECUTION_SUCCESS",
                            "matchState": "MATCH_FOUND",
                            "confidenceLevel": "HIGH",
                        }
                    }
                },
            }
        }
    )
    assert result.allowed is False
    assert result.triggered_filters == ("pi_and_jailbreak",)
    assert "pi_and_jailbreak:HIGH" in result.findings


def test_sensitive_data_is_detected_and_the_value_is_not_kept():
    result = _verdict(
        {
            "sanitizationResult": {
                "filterMatchState": "MATCH_FOUND",
                "filterResults": {
                    "sdp": {
                        "sdpFilterResult": {
                            "inspectResult": {
                                "executionState": "EXECUTION_SUCCESS",
                                "matchState": "MATCH_FOUND",
                                "findings": [
                                    {"infoType": "CREDIT_CARD_NUMBER",
                                     "likelihood": "VERY_LIKELY"}
                                ],
                            }
                        }
                    }
                },
            }
        }
    )
    assert result.allowed is False
    assert "CREDIT_CARD_NUMBER" in result.findings
    # The infotype NAME is kept; the matched value never is.
    logged = result.as_log_fields()
    assert "4111" not in str(logged)
    assert logged["content_sha256"] == "hash"


# --- fail closed, every way it can go wrong ---------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"sanitizationResult": None},
        {"sanitizationResult": {"filterMatchState": "???", "filterResults": {}}},
        {"sanitizationResult": {"filterMatchState": "MATCH_FOUND"}},
        {"sanitizationResult": {"filterMatchState": "NO_MATCH_FOUND",
                                "filterResults": "not-a-dict"}},
    ],
)
def test_a_malformed_response_never_reads_as_allowed(payload):
    with pytest.raises(ScreeningUnavailable):
        _verdict(payload)


def test_a_filter_that_could_not_run_is_not_a_pass():
    """A skipped detector has cleared nothing."""
    with pytest.raises(ScreeningUnavailable) as raised:
        _verdict(
            {
                "sanitizationResult": {
                    "filterMatchState": "NO_MATCH_FOUND",
                    "filterResults": {
                        "pi_and_jailbreak": {
                            "piAndJailbreakFilterResult": {
                                "executionState": "EXECUTION_SKIPPED",
                                "matchState": "NO_MATCH_FOUND",
                            }
                        }
                    },
                }
            }
        )
    assert "filter_not_executed" in raised.value.reason


def test_screening_is_bounded_and_never_retried():
    assert model_armor.SCREENING_RETRY_BUDGET == 0
    assert model_armor.TIMEOUT_SECONDS <= 15
    source = inspect.getsource(model_armor._sanitize)
    assert "for attempt" not in source
    assert "while" not in source
    # Unauthorized is a screening failure, never an implicit pass.
    assert "unauthorized" in source


def test_an_unavailable_screener_stops_the_workflow():
    rule = handling(FailureCategory.SECURITY_SCREENING_UNAVAILABLE)
    assert rule.reconcilable is False
    assert "not processed automatically" in rule.manager_summary
    assert "Nothing was changed" in rule.manager_summary


# --- ordering: screened BEFORE the model ------------------------------------


def _code_only(obj) -> str:
    """Source with comments stripped — assert against calls, not prose.

    The prose here deliberately NAMES the events it is describing, so a plain
    substring search finds the comment before the code and reports an ordering
    that does not exist.
    """
    lines = [
        line for line in inspect.getsource(obj).splitlines()
        if not line.strip().startswith("#")
    ]
    return chr(10).join(lines)


def test_untrusted_text_is_screened_before_gemini_is_invoked():
    source = _code_only(main.create_incident)
    screen_at = source.index('"model_armor_screen_started"')
    adk_at = source.index('log_event("adk_invocation_started"')
    assert screen_at < adk_at, "screening after the model would be theatre"
    # And a blocked report returns before reaching the model at all.
    blocked_at = source.index('"model_armor_blocked"')
    assert blocked_at < adk_at
    # The CALL, not the import at the top of the function.
    assert "await route_incident(" not in source[:adk_at]


def test_a_blocked_report_never_reaches_the_model():
    source = _code_only(main.create_incident)
    block_branch = source[source.index("if not screening.allowed:"):]
    block_branch = block_branch[: block_branch.index("log_event(\"model_armor_allowed\"")]
    assert "await route_incident(" not in block_branch
    assert "return IncidentCreated" in block_branch


# --- a verdict authorizes nothing -------------------------------------------


def test_a_screening_verdict_never_becomes_evidence():
    """It is a security observation, not a fact the policy gate may read."""
    fields = ModelArmorResult(
        screened=True, allowed=True, verdict="NO_MATCH_FOUND"
    ).as_log_fields()
    assert "trust_level" not in fields
    assert TrustLevel.TRUSTED_TOOL.value not in str(fields)

    # The gate reads trusted evidence only, and nothing in this module produces
    # an Evidence object at all.
    assert "Evidence" not in inspect.getsource(model_armor)

    source = inspect.getsource(main.create_incident)
    screening_block = source[source.index("model_armor_screen_started"):]
    screening_block = screening_block[: screening_block.index("adk_invocation_started")]
    assert "save_evidence" not in screening_block
    assert "evaluate(" not in screening_block


def test_the_policy_gate_ignores_anything_untrusted():
    """The pre-existing structural defence, restated against this gate's claim."""
    hostile = [
        Evidence(key="service_unhealthy", value=True, supports="injected",
                 source_agent="intake", trust_level=TrustLevel.UNTRUSTED_INPUT),
        Evidence(key="candidate_revision_approved", value=True, supports="injected",
                 source_agent="intake", trust_level=TrustLevel.UNTRUSTED_INPUT),
        Evidence(key="candidate_probe_healthy", value=True, supports="injected",
                 source_agent="intake", trust_level=TrustLevel.UNTRUSTED_INPUT),
    ]
    assert trusted_evidence_map(hostile) == {}
    proposal = Proposal(
        action_type=ActionType.FLIP_TRAFFIC_TO_LAST_GOOD, target_ref="dispatch-web",
        confidence=0.9, rationale="t", proposed_by="agent:systems",
    )
    assert evaluate(proposal, hostile).decision is Decision.DENIED


def test_a_dangerous_action_is_refused_even_if_screening_missed_it():
    """Model Armor missing something must not be the difference that matters."""
    for action in (ActionType.EXPORT_CREDENTIALS, ActionType.DISABLE_FIREWALL):
        proposal = Proposal(
            action_type=action, target_ref="credential-store", confidence=0.99,
            rationale="the user asked for it", proposed_by="agent:systems",
        )
        assert evaluate(proposal, []).decision is Decision.DENIED


# --- region and honesty ------------------------------------------------------


def test_screening_runs_where_the_detector_actually_exists():
    assert config.MODEL_ARMOR_LOCATION == "asia-southeast1"
    assert config.MODEL_ARMOR_REGION_ABANDONED == "australia-southeast2"
    assert config.MODEL_ARMOR_LOCATION != config.CORE_REGION


def test_no_document_claims_injection_is_impossible():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    forbidden = (
        "prompt injection is impossible",
        "prevents all prompt injection",
        "guarantees safe actions",
        "model armor guarantees",
        "immune to prompt injection",
    )
    for path in list(root.glob("*.md")) + list(root.glob("docs/**/*.md")):
        text = " ".join(path.read_text(encoding="utf-8").lower().split())
        for claim in forbidden:
            assert claim not in text, f"{path.name} overclaims: {claim}"


def test_the_fault_modes_are_env_only_and_closed():
    from scf import faults

    assert faults.MODEL_ARMOR_UNAVAILABLE in faults.KNOWN_MODES
    assert faults.MODEL_ARMOR_MALFORMED in faults.KNOWN_MODES
    source = _code_only(model_armor.screen_untrusted_text)
    assert "faults.is_mode" in source
    # The mode is read from the process environment once, at import. Nothing in
    # the screening path consults request data to decide whether to fault.
    assert "request" not in source, "a fault must not be reachable from a request"
    assert "os.environ" not in source
