"""Gate E — failure engineering contracts.

The decisive proofs are live: a real Cloud Run worker that hangs, a real 503, a
real Google 409, a real verifier outage. See
docs/evidence/gate-e-failure-engineering.md. These tests lock the contracts
those proofs depend on, and carry the whole of the taxonomy and escalation
logic, which is where a failure would quietly become a false success.
"""

from __future__ import annotations

import importlib
import inspect
import json

import pytest
from pydantic import ValidationError

from scf import faults
from scf.agents.routing import MODEL_PARSE_RETRIES, ModelContractError, _parse
from scf.domain.enums import ActionType, IncidentStatus, TrustLevel
from scf.domain.failures import (
    HANDLING,
    NEXT_ACTION,
    FailureCategory,
    build_escalation_package,
    handling,
)
from scf.domain.models import Evidence, Proposal
from scf.domain.state_machine import LEGAL_TRANSITIONS, TERMINAL_STATES, can_transition

# --- E1 fault injection is not a production capability -----------------------


def test_fault_injection_is_disabled_by_default():
    assert faults.active() == faults.NONE
    assert not faults.enabled()
    assert faults.banner() == {"fault_mode": None}


def _fault_code() -> str:
    """Executable code only — docstrings and comments stripped.

    The module *describes* these rules in prose, so a naive substring search
    would match its own documentation. This asserts against what actually runs.
    """
    import ast

    tree = ast.parse(inspect.getsource(faults))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)) and ast.get_docstring(node):
            node.body = node.body[1:]
    return ast.unparse(tree)


def test_fault_mode_is_never_derived_from_a_request():
    """Structurally impossible to reach a fault from user input.

    Asserted against the parsed module rather than its text: the fault module
    imports nothing that can carry a request, reads exactly one external input
    (the process environment, once), and exposes no function that accepts
    caller-supplied data beyond a mode name compared against the closed set.
    """
    import ast

    tree = ast.parse(inspect.getsource(faults))

    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    for web in ("fastapi", "starlette", "httpx", "flask", "requests", "scf"):
        assert web not in imported, f"faults imports {web!r}"
    assert imported <= {"os", "time", "typing", "__future__"}

    environ_reads = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "environ"
    ]
    assert len(environ_reads) == 1, "the mode has exactly one source"

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = [a.arg for a in node.args.args + node.args.kwonlyargs]
            assert args in ([], ["mode"]), f"{node.name} accepts {args}"


def test_an_unknown_fault_mode_refuses_to_start():
    """A fault revision that silently ran healthy would invalidate its own test."""
    source = inspect.getsource(faults._read_mode)
    assert "raise RuntimeError" in source
    assert "KNOWN_MODES" in source


def test_every_fault_mode_is_in_the_closed_set():
    declared = {
        value
        for name, value in vars(faults).items()
        if name.isupper() and isinstance(value, str) and "_" in value and value.islower()
    }
    assert declared <= faults.KNOWN_MODES


def test_faults_never_produce_evidence():
    """A fault can break a worker; it can never satisfy the policy gate."""
    source = _fault_code()
    assert "Evidence" not in source
    assert "TRUSTED_TOOL" not in source


def test_a_deployed_fault_revision_is_labelled(monkeypatch):
    monkeypatch.setenv(faults.ENV_VAR, faults.INVESTIGATOR_5XX)
    reloaded = importlib.reload(faults)
    try:
        assert reloaded.enabled()
        banner = reloaded.banner()
        assert banner["fault_mode"] == reloaded.INVESTIGATOR_5XX
        assert reloaded.LABEL in banner["warning"]
    finally:
        monkeypatch.delenv(faults.ENV_VAR, raising=False)
        importlib.reload(faults)


# --- E2 Case A: malformed model output ---------------------------------------


def test_model_output_is_never_retried():
    assert MODEL_PARSE_RETRIES == 0
    from scf.agents import routing

    source = inspect.getsource(routing)
    for loop in ("for attempt", "while True", "range(retries", "retry_count"):
        assert loop not in source


@pytest.mark.parametrize(
    "payload,why",
    [
        ('{"routes": [{"specialist": "systems",', "invalid JSON"),
        ('{"routes": "everything is fine"}', "schema-invalid"),
        ('{"summary": "no routes at all"}', "missing required field"),
        ('{"routes": [], "summary": "empty"}', "violates min_length"),
        (
            '{"routes": [{"specialist": "database_wizard", "required": true, '
            '"why": "x"}], "summary": "s"}',
            "specialist outside the closed enum",
        ),
        (
            '{"routes": [{"specialist": "systems", "required": true, "why": "x"}], '
            '"summary": "s", "execute_now": true}',
            "extra field",
        ),
        ("not json at all", "not JSON"),
    ],
)
def test_malformed_model_output_is_rejected_at_the_parser(payload, why):
    with pytest.raises(ModelContractError):
        _parse(payload)


def test_a_valid_routing_payload_still_parses():
    decision = _parse(
        json.dumps(
            {
                "routes": [
                    {"specialist": "systems", "required": True, "why": "service health"},
                    {"specialist": "network", "required": False, "why": "wifi is fine"},
                ],
                "summary": "The dispatch screen is not loading.",
            }
        )
    )
    assert [s.value for s in decision.required_specialists()] == ["systems"]


def test_invalid_model_output_escalates_and_never_executes():
    rule = handling(FailureCategory.MODEL_OUTPUT_INVALID)
    assert rule.resting_status is IncidentStatus.ESCALATED
    assert not rule.reconcilable and not rule.retry_eligible
    from scf.app import main

    source = inspect.getsource(main.create_incident)
    # The failure is categorised before any specialist or executor is reached.
    assert source.index("MODEL_OUTPUT_INVALID") < source.index("_autonomous_remediation")


def test_a_failed_routing_does_not_strand_the_incident():
    """The incident is already persisted; a 502 would abandon it at INTAKE."""
    from scf.app import main

    source = inspect.getsource(main.create_incident)
    assert "raise HTTPException(status_code=502" not in source
    assert can_transition(IncidentStatus.INTAKE, IncidentStatus.ESCALATED)


# --- E2 Case B: hallucinated dangerous action --------------------------------


def test_dangerous_actions_stay_proposable_so_the_gate_refuses_them():
    from scf.app.main import DANGEROUS_ACTIONS

    assert ActionType.EXPORT_CREDENTIALS in DANGEROUS_ACTIONS
    assert ActionType.DISABLE_FIREWALL in DANGEROUS_ACTIONS
    # Proposable by construction — the enum is not the guard, the gate is.
    assert Proposal(
        action_type=ActionType.EXPORT_CREDENTIALS,
        target_ref="dispatch-web",
        confidence=0.9,
        rationale="x",
        proposed_by="agent:systems",
    ).action_type is ActionType.EXPORT_CREDENTIALS


def test_the_gate_denies_a_dangerous_proposal_whatever_the_evidence():
    from scf.policy import evaluate

    trusted = [
        Evidence(key=key, value=value, supports="t", source_agent="systems",
                 trust_level=TrustLevel.TRUSTED_TOOL)
        for key, value in [
            ("service_unhealthy", True),
            ("candidate_revision_approved", True),
            ("candidate_probe_healthy", True),
        ]
    ]
    for action in (ActionType.EXPORT_CREDENTIALS, ActionType.DISABLE_FIREWALL):
        decision = evaluate(
            Proposal(action_type=action, target_ref="dispatch-web", confidence=1.0,
                     rationale="hallucinated", proposed_by="agent:systems"),
            trusted,
        )
        assert decision.decision.value == "DENIED", action


def test_an_action_outside_the_closed_enum_never_becomes_a_proposal():
    with pytest.raises(ValidationError):
        Proposal.model_validate(
            {
                "action_type": "DELETE_DATABASE",
                "target_ref": "dispatch-web",
                "confidence": 0.9,
                "rationale": "hallucinated",
                "proposed_by": "agent:systems",
            }
        )


def test_a_denied_dangerous_action_is_categorised_as_refused():
    rule = handling(FailureCategory.DANGEROUS_ACTION_REFUSED)
    assert rule.resting_status is IncidentStatus.ESCALATED
    assert "unsafe action" in rule.manager_summary.lower()
    from scf.app import main

    source = inspect.getsource(main._run_remediation)
    assert "DANGEROUS_ACTIONS" in source
    assert source.index("Decision.DENIED") < source.index("IncidentStatus.EXECUTING")


# --- E3 bounded downstream calls ---------------------------------------------


def test_every_downstream_call_is_bounded():
    from scf.app.main import CALL_TIMEOUTS

    assert set(CALL_TIMEOUTS) == {"investigator", "executor", "verifier"}
    for service, seconds in CALL_TIMEOUTS.items():
        assert 0 < seconds <= 300, service


def test_a_timeout_is_categorised_and_never_retried():
    from scf.app import main

    for kind in main.TIMEOUT_KINDS:
        failure = main.DownstreamFailure("investigator", kind, "slow")
        assert main._categorise(failure) is FailureCategory.WORKER_TIMEOUT
    rule = handling(FailureCategory.WORKER_TIMEOUT)
    assert not rule.retry_eligible
    assert rule.resting_status is IncidentStatus.ESCALATED


def test_a_worker_5xx_is_categorised_as_unavailable():
    from scf.app import main

    assert main._categorise(
        main.DownstreamFailure("investigator", "http_503", "down")
    ) is FailureCategory.WORKER_UNAVAILABLE


# --- E4 worker budget --------------------------------------------------------


def test_the_investigator_has_a_step_and_time_budget():
    from scf.app.investigator import MAX_TOOL_CALLS, WORK_DEADLINE_SECONDS, WorkBudget

    assert 0 < MAX_TOOL_CALLS <= 50
    assert 0 < WORK_DEADLINE_SECONDS <= 120
    budget = WorkBudget(max_calls=2, deadline_seconds=60)
    budget.spend("one")
    budget.spend("two")
    with pytest.raises(Exception) as raised:
        budget.spend("three")
    assert raised.value.limit == "tool_calls"


def test_the_budget_also_bounds_wall_clock():
    from scf.app.investigator import BudgetExhausted, WorkBudget

    budget = WorkBudget(max_calls=1000, deadline_seconds=-1)
    with pytest.raises(BudgetExhausted) as raised:
        budget.spend("anything")
    assert raised.value.limit == "deadline_seconds"


def test_a_runaway_worker_is_stopped_by_the_budget_not_by_luck():
    from scf.app import investigator

    source = inspect.getsource(investigator._investigate)
    # The runaway loop has no exit of its own; `spend` is the only way out.
    assert "while True:" in source
    assert "budget.spend" in source


def test_budget_exhaustion_returns_a_truthful_contract_not_partial_evidence():
    from scf.app import investigator

    source = inspect.getsource(investigator.collect_evidence)
    assert '"evidence": []' in source
    assert '"proposal": None' in source
    assert '"budget_exceeded": True' in source


def test_the_orchestrator_treats_budget_exhaustion_as_a_failure():
    from scf.app import main

    source = inspect.getsource(main._run_remediation)
    assert 'body.get("budget_exceeded")' in source
    assert source.index("budget_exceeded") < source.index("Evidence.model_validate")
    rule = handling(FailureCategory.WORKER_BUDGET_EXCEEDED)
    assert not rule.retry_eligible


# --- E5 the system must be capable of doing nothing --------------------------


def test_no_proposal_is_a_legitimate_outcome_not_an_error():
    rule = handling(FailureCategory.INSUFFICIENT_EVIDENCE)
    assert rule.resting_status is IncidentStatus.ESCALATED
    assert "no change" in rule.manager_summary.lower()
    from scf.app import main

    source = inspect.getsource(main._run_remediation)
    assert "INSUFFICIENT_EVIDENCE" in source
    assert source.index("INSUFFICIENT_EVIDENCE") < source.index("IncidentStatus.EXECUTING")


def test_a_healthy_service_produces_no_proposal():
    from scf.tools.cloud_run_evidence import propose_remediation

    healthy = [
        Evidence(key=key, value=value, supports="t", source_agent="systems",
                 trust_level=TrustLevel.TRUSTED_TOOL)
        for key, value in [
            ("service_unhealthy", False),
            ("candidate_revision_approved", True),
            ("candidate_probe_healthy", True),
        ]
    ]
    assert propose_remediation(healthy, "dispatch-web") is None


# --- E11 authenticated but malformed worker responses ------------------------


def test_an_unknown_trust_level_cannot_be_coerced():
    """Authentication says who spoke; the contract says whether it is usable."""
    with pytest.raises(ValidationError):
        Evidence.model_validate(
            {
                "key": "service_unhealthy",
                "value": True,
                "supports": "x",
                "source_agent": "systems",
                "trust_level": "TOTALLY_TRUSTED",
            }
        )


def test_malformed_worker_evidence_is_a_categorised_failure():
    from scf.app import main

    source = inspect.getsource(main._run_remediation)
    assert "WORKER_CONTRACT_INVALID" in source
    assert "Evidence.model_validate" in source
    rule = handling(FailureCategory.WORKER_CONTRACT_INVALID)
    assert rule.resting_status is IncidentStatus.ESCALATED


def test_a_verifier_verdict_outside_the_contract_is_not_recovery():
    """Superseded by the typed contract: see test_a_verdict_string_alone_is_not_recovery."""
    from scf.app.main import VerifierVerdict

    assert not VerifierVerdict(
        verdict="PROBABLY_FINE", http_healthy=True,
        revision_matches_authorized=True, traffic_allocation_exclusive=True,
    ).recovered()


# --- E12 no blind retry ------------------------------------------------------


def test_every_retry_budget_is_zero():
    from scf.agents.routing import MODEL_PARSE_RETRIES
    from scf.app.main import (
        DOWNSTREAM_RETRY_BUDGET,
        MODEL_PARSE_RETRY_BUDGET,
        MUTATION_RETRY_BUDGET,
    )

    assert DOWNSTREAM_RETRY_BUDGET == 0
    assert MODEL_PARSE_RETRY_BUDGET == 0
    assert MUTATION_RETRY_BUDGET == 0
    assert MODEL_PARSE_RETRIES == 0


def test_no_loop_surrounds_a_downstream_call_or_a_mutation():
    from scf.app import executor, main

    for module, symbol in ((main, "_call"), (executor, "flip_traffic_to_revision")):
        source = inspect.getsource(module)
        for line_no, line in enumerate(source.splitlines()):
            if symbol in line and "def " not in line:
                # Walk back for an enclosing loop within the same function.
                window = source.splitlines()[max(0, line_no - 25):line_no]
                assert not any(
                    stripped.startswith(("while ", "for "))
                    for stripped in (w.strip() for w in window)
                ), f"{symbol} may sit inside a loop near line {line_no}"


def test_only_conflict_and_unavailability_are_retry_eligible():
    retryable = {c for c, rule in HANDLING.items() if rule.retry_eligible}
    assert retryable == {
        FailureCategory.EXECUTION_CONFLICT,
        FailureCategory.EXECUTOR_UNAVAILABLE,
    }


def test_reconciliation_is_distinguishable_from_retry_in_logs():
    from scf.app import main

    source = inspect.getsource(main.reconcile_incident)
    assert "reconciliation_execution" in source


# --- E13 escalation package --------------------------------------------------


def _package(category=FailureCategory.WORKER_TIMEOUT, **overrides):
    kwargs = dict(
        incident_id="INC-1",
        category=category,
        correlation_id="trace-abc",
        specialists_attempted=["systems"],
        evidence_keys=["service_unhealthy", "active_revision"],
        mutated=False,
        current_service_state="the dispatch service is still not responding normally",
        operations_restored=False,
    )
    kwargs.update(overrides)
    return build_escalation_package(**kwargs)


def test_the_escalation_package_is_complete():
    package = _package()
    for field in (
        "incident_id", "correlation_id", "failure_category", "impact",
        "specialists_attempted", "evidence_summary", "automation_changed_anything",
        "what_automation_did", "current_service_state", "operations_restored",
        "recommended_next_action",
    ):
        assert getattr(package, field) is not None, field


def test_the_escalation_package_leaks_nothing():
    """No model text, no credentials, no API names, no stack traces."""
    blob = _package().model_dump_json().lower()
    for leak in ("bearer", "token", "authorization", "private_key", "traceback",
                 "rationale", "replaceservice", "409", "abort", "sha256",
                 "resourceversion", "iam.gserviceaccount"):
        assert leak not in blob, f"escalation package leaks {leak!r}"


def test_the_manager_summary_is_plain_language():
    for category in FailureCategory:
        summary = handling(category).manager_summary
        assert summary[0].isupper() and summary.endswith(".")
        for jargon in ("HTTP", "409", "503", "API", "revision", "Firestore",
                       "Cloud Run", "resourceVersion", "null", "exception"):
            assert jargon not in summary, f"{category} summary contains {jargon!r}"


def test_evidence_summary_carries_keys_not_values():
    """Values can contain untrusted report text; keys name what was checked."""
    package = _package(evidence_keys=["duty_manager_report", "service_unhealthy"])
    assert package.evidence_summary == ["duty_manager_report", "service_unhealthy"]


def test_the_package_states_whether_anything_was_changed():
    assert "No change was made" in _package(mutated=False).what_automation_did
    assert "applied" in _package(mutated=True).what_automation_did
    assert _package(mutated=True).automation_changed_anything is True


# --- E14 taxonomy ------------------------------------------------------------


def test_every_category_is_handled():
    assert set(HANDLING) == set(FailureCategory)
    assert set(NEXT_ACTION) == set(FailureCategory)


def test_every_resting_status_is_reachable_and_consistent():
    for category, rule in HANDLING.items():
        if rule.reconcilable:
            assert rule.resting_status not in TERMINAL_STATES, category
            assert rule.resting_status in LEGAL_TRANSITIONS, category
        else:
            assert rule.resting_status is IncidentStatus.ESCALATED, category


def test_a_reconcilable_failure_can_always_reach_a_terminal_state():
    from scf.app.main import RECONCILABLE_STATES

    for category, rule in HANDLING.items():
        if rule.reconcilable:
            assert rule.resting_status in RECONCILABLE_STATES, category


def test_audit_events_are_unique_and_derived():
    events = [rule.audit_event for rule in HANDLING.values()]
    assert len(events) == len(set(events))
    for category, rule in HANDLING.items():
        assert rule.audit_event == f"failure_{category.value.lower()}"


def test_failures_flow_through_one_place():
    from scf.app import main

    source = inspect.getsource(main)
    # Every categorised failure resolves through _fail, which is the only
    # writer of escalation packages.
    assert source.count("repo.save_escalation") == 1
    assert "def _fail(" in source


def test_the_handover_reports_only_what_an_authorized_identity_observed():
    """The orchestrator holds no read on the target and must not acquire one."""
    from scf.app import main

    source = inspect.getsource(main._observe_service_state)
    assert "describe_service" not in source, "the orchestrator must not probe directly"
    assert "could not be checked automatically" in source

    # Nothing observed -> say so, rather than guess.
    assert main._observe_service_state({}) == {
        "state": "could not be checked automatically",
        "restored": False,
    }
    # The verifier's verdict is authoritative when there is one.
    assert main._observe_service_state(
        {"verification": {"verdict": "RECOVERED"}}
    )["restored"] is True
    assert main._observe_service_state(
        {"verification": {"verdict": "STILL_FAILING"}}
    )["restored"] is False
    # Otherwise the investigator's trusted observation.
    assert main._observe_service_state({"service_http_status": 200})["restored"] is True
    assert main._observe_service_state({"service_http_status": 503})["restored"] is False


def test_the_orchestrator_never_reads_the_target_service():
    """Widening its IAM to populate a status line would be a bad trade."""
    from scf.app import main

    source = inspect.getsource(main)
    assert "describe_service" not in source
    assert "probe_health" not in source


# --- E10: an unknown outcome must never be closed ----------------------------


def test_reaching_the_executor_or_verifier_is_never_a_terminal_timeout():
    """The sharpest false negative: fix the outage, then report failure.

    An executor timeout may mean the mutation completed and simply outlived our
    patience. Categorising that as a terminal WORKER_TIMEOUT escalated the
    incident while the fix was landing, and left no way back — found live.
    """
    from scf.app import main

    for kind in list(main.TIMEOUT_KINDS) + ["http_503", "ConnectError", "not_configured"]:
        assert main._categorise(
            main.DownstreamFailure("executor", kind, "x")
        ) is FailureCategory.EXECUTOR_UNAVAILABLE, kind
        assert main._categorise(
            main.DownstreamFailure("verifier", kind, "x")
        ) is FailureCategory.VERIFIER_UNAVAILABLE, kind

    for category in (FailureCategory.EXECUTOR_UNAVAILABLE,
                     FailureCategory.VERIFIER_UNAVAILABLE):
        assert handling(category).reconcilable, category


def test_a_read_only_worker_may_still_be_escalated_on_timeout():
    """The investigator changes nothing, so an unknown outcome is not possible."""
    from scf.app import main

    assert main._categorise(
        main.DownstreamFailure("investigator", "ReadTimeout", "x")
    ) is FailureCategory.WORKER_TIMEOUT
    assert not handling(FailureCategory.WORKER_TIMEOUT).reconcilable


def test_service_identity_dominates_failure_kind():
    from scf.app import main

    source = inspect.getsource(main._categorise)
    assert source.index('failure.service == "executor"') < source.index("TIMEOUT_KINDS")


def test_a_duplicate_outcome_is_not_a_failed_remediation():
    """A worker that outlived its caller still did the work."""
    from scf.app import main

    for state in ("MUTATED", "VERIFIED", "MUTATION_REQUESTED"):
        assert main._execution_already_landed(
            {"duplicate": True, "state": state}
        ), state
    # Nothing has landed in these.
    for state in ("CLAIMED", "PRECONDITION_CHECKED", "FAILED", "STALE", None):
        assert not main._execution_already_landed({"duplicate": True, "state": state})
    # And a non-duplicate receipt says nothing about another worker.
    assert not main._execution_already_landed({"state": "MUTATED"})


def test_reconciliation_does_not_escalate_work_another_worker_completed():
    from scf.app import main

    source = inspect.getsource(main.reconcile_incident)
    assert "_execution_already_landed(receipt)" in source
    landed_at = source.index("_execution_already_landed(receipt)")
    escalate_at = source.index("IncidentStatus.ESCALATED", landed_at)
    assert landed_at < escalate_at


# --- Codex Gate E audit ------------------------------------------------------


def test_a_non_object_downstream_response_is_a_typed_failure():
    """200 + JSON `[]` from an authenticated worker must not strand an incident."""
    from scf.app import main

    source = inspect.getsource(main._call)
    assert "isinstance(body, dict)" in source
    assert "malformed_response" in source


def test_nothing_can_strand_an_incident_mid_flight():
    from scf.app import main

    source = inspect.getsource(main._autonomous_remediation)
    assert "except Exception" in source
    assert "workflow_unexpected_error" in source
    # The catch-all still goes through the taxonomy, not around it.
    tail = source[source.index("except Exception"):]
    assert "_fail(" in tail
    assert "REMEDIATION_FAILED" in tail


def test_a_truthy_flag_alone_cannot_resolve_an_incident():
    """`{"verified": true}` is not terminalization."""
    from scf.app.main import TerminalizationReceipt

    assert not TerminalizationReceipt(verified=True).terminal()
    assert not TerminalizationReceipt(verified=True, state="MUTATED").terminal()
    assert not TerminalizationReceipt(
        verified=True, state="VERIFIED", serves_authorized_exclusively=False
    ).terminal()
    assert TerminalizationReceipt(
        verified=True, state="VERIFIED", serves_authorized_exclusively=True
    ).terminal()
    assert not TerminalizationReceipt(
        verified=False, state="VERIFIED", serves_authorized_exclusively=True
    ).terminal()


def test_a_verdict_string_alone_is_not_recovery():
    from scf.app.main import VerifierVerdict

    good = dict(verdict="RECOVERED", http_healthy=True,
                revision_matches_authorized=True, traffic_allocation_exclusive=True)
    assert VerifierVerdict(**good).recovered()
    for field in ("http_healthy", "revision_matches_authorized",
                  "traffic_allocation_exclusive"):
        assert not VerifierVerdict(**{**good, field: False}).recovered(), field
    assert not VerifierVerdict(**{**good, "verdict": "PROBABLY_FINE"}).recovered()


def test_a_missing_verdict_field_is_a_contract_failure():
    from scf.app.main import TerminalizationReceipt, VerifierVerdict

    with pytest.raises(ValidationError):
        VerifierVerdict.model_validate({"verdict": "RECOVERED"})
    with pytest.raises(ValidationError):
        TerminalizationReceipt.model_validate({})


def test_the_close_path_uses_the_typed_contracts():
    from scf.app import main

    source = inspect.getsource(main._verify_and_close)
    assert "checked.recovered()" in source
    assert "closed.terminal()" in source
    assert 'terminal.get("verified")' not in source
    assert 'verdict.get("verdict") != "RECOVERED"' not in source


# --- health signal -----------------------------------------------------------


@pytest.mark.parametrize(
    "body,healthy",
    [
        ("dispatch service healthy", True),
        ("healthy", True),
        ("OK", True),
        ("ready", True),
        ("unhealthy", False),
        ("dispatch service unhealthy", False),
        ("not healthy", False),
        ("dispatch service unavailable", False),
        ("degraded but healthy", False),
        ("internal error: healthy check failed", False),
        # Not failure reports: rejecting these would break a healthy service.
        ('{"status":"healthy","errorCount":0}', True),
        ("no errors detected; all systems healthy", True),
        ("", False),
        ("   ", False),
    ],
)
def test_a_service_calling_itself_unhealthy_is_never_read_as_healthy(body, healthy):
    """The naive check was satisfied by the word UNhealthy — the exact inversion."""
    from scf.tools.cloud_run_evidence import body_is_healthy

    assert body_is_healthy(body) is healthy


def test_no_substring_health_check_survives_anywhere():
    """Executable code only — the fix's own docstring quotes the old bug."""
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2] / "src"
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)) and ast.get_docstring(node):
                node.body = node.body[1:]
        code = ast.unparse(tree)
        assert "'healthy' in body" not in code, path
        assert "'healthy' in candidate_body" not in code, path


def test_every_health_decision_goes_through_one_predicate():
    from scf.app import executor, verifier
    from scf.tools import cloud_run_evidence

    for module in (executor, verifier, cloud_run_evidence):
        source = inspect.getsource(module)
        if "body_is_healthy" in source or module is cloud_run_evidence:
            continue
        raise AssertionError(f"{module.__name__} decides health without the predicate")


# --- worker budget bounds the step, not just the gap -------------------------


def test_the_budget_is_rechecked_after_each_step():
    from scf.app import investigator

    source = inspect.getsource(investigator._investigate)
    assert source.count("budget.check(") >= 2
    assert "budget.spend(" in source
    loop = source[source.index("while True:"):]
    assert "budget.check(" in loop


# --- Codex Gate E audit, round 2 ---------------------------------------------


def test_a_string_cannot_satisfy_a_boolean_safety_condition():
    """`"yes"`, `"true"` and `1` are not booleans. Ordinary bool coercion says otherwise."""
    from scf.app.main import ExecutionReceipt, TerminalizationReceipt, VerifierVerdict

    good = dict(verdict="RECOVERED", http_healthy=True,
                revision_matches_authorized=True, traffic_allocation_exclusive=True)
    for bad in ("yes", "true", 1, "1", "false"):
        with pytest.raises(ValidationError):
            VerifierVerdict.model_validate({**good, "http_healthy": bad})
        with pytest.raises(ValidationError):
            TerminalizationReceipt.model_validate(
                {"verified": bad, "state": "VERIFIED",
                 "serves_authorized_exclusively": True}
            )
        with pytest.raises(ValidationError):
            ExecutionReceipt.model_validate({"mutated": bad})


def test_a_string_false_is_not_a_successful_mutation():
    """"false" is a non-empty string and therefore truthy under `.get()`."""
    from scf.app.main import ExecutionReceipt

    with pytest.raises(ValidationError):
        ExecutionReceipt.model_validate({"mutated": "false", "reconciled": False})
    assert not ExecutionReceipt(mutated=False, reconciled=False).progressed()
    assert ExecutionReceipt(mutated=True).progressed()
    assert ExecutionReceipt(reconciled=True).progressed()


def test_the_execution_branch_uses_the_typed_receipt():
    from scf.app import main

    source = inspect.getsource(main._run_remediation)
    assert "ExecutionReceipt.model_validate(receipt)" in source
    assert "reported.progressed()" in source
    # No safety decision reads the raw dict; only inert audit metadata does.
    assert 'receipt.get("mutated")' not in source
    assert 'receipt.get("duplicate")' not in source
    assert 'receipt.get("reconciled")' not in source


def test_an_unhealthy_body_warrants_remediation_even_on_http_200():
    """A service answering 200 while saying it is unhealthy is unhealthy."""
    from scf.tools import cloud_run_evidence

    source = inspect.getsource(cloud_run_evidence.gather_evidence)
    assert "live_healthy = status_code == 200 and body_is_healthy(body)" in source
    assert '_ev("service_unhealthy", not live_healthy' in source
    assert '_ev("service_unhealthy", status_code != 200' not in source


def test_the_budget_charges_every_network_call():
    """Three calls hiding inside one charged step is not a bounded step."""
    from scf.app import investigator
    from scf.tools import cloud_run_evidence

    assert "charge" in inspect.signature(cloud_run_evidence.gather_evidence).parameters
    gather = inspect.getsource(cloud_run_evidence.gather_evidence)
    for call in ("describe_service", "probe_live_service", "probe_candidate_revision"):
        assert f'spend("{call}")' in gather

    source = inspect.getsource(investigator._investigate)
    assert "charge=budget.spend" in source


def test_every_probe_is_bounded_well_under_the_deadline():
    from scf.app.investigator import WORK_DEADLINE_SECONDS
    from scf.tools import cloud_run_evidence

    source = inspect.getsource(cloud_run_evidence)
    assert "timeout=30.0" not in source
    assert "timeout=20.0" not in source
    # Worst case is the deadline plus at most one call, and one call is small.
    assert WORK_DEADLINE_SECONDS >= 30


# --- self-audit, round 3 ------------------------------------------------------


def test_every_receipt_read_that_decides_anything_is_typed():
    from scf.app import main

    source = inspect.getsource(main._execution_already_landed)
    assert "ExecutionReceipt.model_validate" in source
    assert 'receipt.get("duplicate")' not in source
    # An unreadable receipt proves nothing landed.
    assert main._execution_already_landed({"duplicate": "yes", "state": "MUTATED"}) is False


def test_a_single_probe_blip_does_not_warrant_changing_infrastructure():
    """The cost of being wrong is rolling back a service that was fine."""
    from scf.tools import cloud_run_evidence

    source = inspect.getsource(cloud_run_evidence.gather_evidence)
    assert "confirm_live_service" in source
    assert "CONFIRM_UNHEALTHY_AFTER_SECONDS" in source
    # The confirmation only runs when the first look failed, and it is a read.
    assert source.index("live_healthy = status_code == 200") < source.index(
        "if not live_healthy:"
    )
    assert cloud_run_evidence.CONFIRM_UNHEALTHY_AFTER_SECONDS > 0


def test_the_confirmation_is_a_read_not_a_retry_of_an_action():
    from scf.tools import cloud_run_evidence

    source = inspect.getsource(cloud_run_evidence.gather_evidence)
    confirm = source[source.index("if not live_healthy:"):]
    assert "probe_health" in confirm
    for mutating in ("flip_traffic", "replaceService", "httpx.put", "httpx.patch"):
        assert mutating not in confirm
