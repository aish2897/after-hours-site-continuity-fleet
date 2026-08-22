"""Gate H — a real fleet, and routing that is actually selective.

The claim being tested is not "there are five agents". It is that different
incidents produce different specialist sets, that a withdrawn agent cannot be
selected whatever the model asks for, and that none of the new agents can change
anything.
"""

from __future__ import annotations

import inspect

import pytest

from scf.app import continuity, main, specialists
from scf.domain.enums import SpecialistName, TrustLevel
from scf.policy import default_registry
from scf.policy.loader import load_registry
from scf.tools import network_evidence, security_evidence


# --- H2: five roles, real contracts ------------------------------------------


def test_the_fleet_has_five_agent_roles_and_three_non_agent_components():
    registry = default_registry()
    agents = set(registry.agents)
    assert {"orchestrator", "systems", "network", "security", "continuity"} <= agents
    # The deterministic components are NOT agents pretending to be agents.
    for component in ("executor", "verifier"):
        assert registry.agents[component].llm_backed is False
        assert registry.agents[component].may_propose_actions is False


def test_every_specialist_is_deployed_and_declares_its_own_identity():
    registry = default_registry()
    accounts = set()
    for name in ("systems", "network", "security", "continuity"):
        entry = registry.agents[name]
        assert entry.deployed is True, name
        assert entry.enabled is True, name
        assert entry.version, name
        accounts.add(entry.service_account)
    # Distinct identities. Sharing one would mean sharing authority, which is
    # the opposite of what this fleet argues.
    assert len(accounts) == 4


def test_no_investigator_may_propose_or_write():
    registry = default_registry()
    for name in ("network", "security", "continuity"):
        entry = registry.agents[name]
        assert entry.may_propose_actions is False, name
        assert entry.may_write_firestore is False, name


# --- H5: governance gates discovery, and only discovery ----------------------


def test_a_withdrawn_agent_cannot_be_selected(tmp_path):
    """`enabled: false` withdraws an agent without a redeploy."""
    import json
    from pathlib import Path

    source = Path("src/scf/policies/agent_registry.json").read_text(encoding="utf-8")
    catalog = json.loads(source)
    catalog["agents"]["network"]["enabled"] = False
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(catalog), encoding="utf-8")

    withdrawn = load_registry(path)
    assert withdrawn.is_selectable("network") is False
    assert "network" not in withdrawn.selectable_specialists()
    # Everything else is unaffected.
    assert withdrawn.is_selectable("systems") is True


def test_an_undeployed_agent_cannot_be_selected(tmp_path):
    import json
    from pathlib import Path

    catalog = json.loads(
        Path("src/scf/policies/agent_registry.json").read_text(encoding="utf-8")
    )
    catalog["agents"]["security"]["deployed"] = False
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(catalog), encoding="utf-8")
    assert load_registry(path).is_selectable("security") is False


def test_the_orchestrator_filters_routing_through_the_catalog():
    source = inspect.getsource(main.create_incident)
    assert "registry.is_selectable(name)" in source
    assert "specialists_withheld_by_registry" in source
    # And the withholding is recorded rather than silently applied.
    assert "withheld=withheld" in source


def test_registry_governance_can_never_authorize_a_mutation():
    """It controls who is asked, never what may be done."""
    from scf.policy.loader import AgentRegistry

    source = inspect.getsource(AgentRegistry.is_selectable)
    assert "DISCOVERY only" in source
    # The policy gate does not consult the registry at all.
    from scf.policy import engine

    assert "registry" not in inspect.getsource(engine.evaluate)
    assert "is_selectable" not in inspect.getsource(engine)


# --- H3: selective routing, not fan-out --------------------------------------


def test_routing_consults_only_what_was_asked_for():
    source = inspect.getsource(main._run_fleet)
    assert "for specialist in [s for s in required if s in EVIDENCE_SPECIALISTS]" in source
    # No branch consults everything regardless.
    assert "EVIDENCE_SPECIALISTS.keys()" not in source
    assert "for specialist in EVIDENCE_SPECIALISTS" not in source


def test_systems_is_not_an_evidence_only_specialist():
    """It is the only one that may propose, so it runs the full pipeline."""
    assert "systems" not in main.EVIDENCE_SPECIALISTS
    assert set(main.EVIDENCE_SPECIALISTS) == {"network", "security"}


@pytest.mark.parametrize(
    "specialist", [SpecialistName.NETWORK, SpecialistName.SECURITY,
                   SpecialistName.SYSTEMS, SpecialistName.CONTINUITY]
)
def test_every_specialist_in_the_closed_enum_is_in_the_catalog(specialist):
    assert specialist.value in default_registry().agents


# --- H4: secondary delegation is evidence-driven -----------------------------


def test_delegation_follows_trusted_evidence_not_the_report():
    source = inspect.getsource(main._run_fleet)
    assert 'facts.get("network_reachable") is True' in source
    assert "secondary_delegation" in source
    # It reads the trusted evidence map, never the manager's words.
    assert "trusted_evidence_map(fleet_evidence)" in source
    assert "description" not in source
    # And a withdrawn Systems agent still cannot be delegated to.
    assert 'default_registry().is_selectable("systems")' in source


# --- H6/H7: the new agents cannot change anything ----------------------------


def _code_only(module) -> str:
    """Source with comments and docstrings stripped.

    These modules DESCRIBE the capabilities they do not have, so a plain
    substring search finds the prose rather than a call.
    """
    import ast

    tree = ast.parse(inspect.getsource(module))
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ) and ast.get_docstring(node):
            node.body = node.body[1:]
    return ast.unparse(tree)


def test_the_new_specialists_hold_no_mutation_capability():
    for module in (network_evidence, security_evidence, continuity):
        source = _code_only(module)
        for forbidden in ("replaceService", "setIamPolicy", "httpx.post",
                          "httpx.patch", "httpx.put", "httpx.delete"):
            assert forbidden not in source, f"{module.__name__} contains {forbidden}"


def test_the_specialists_never_write_firestore():
    source = _code_only(specialists)
    assert "IncidentRepository" not in source
    assert "firestore" not in source.lower()
    assert "google.cloud" not in source


def test_the_continuity_coordinator_calls_no_model():
    source = inspect.getsource(continuity)
    for forbidden in ("route_incident", "generate_content", "LlmAgent", "genai"):
        assert forbidden not in source, forbidden
    assert default_registry().agents["continuity"].llm_backed is False


def test_the_continuity_coordinator_refuses_to_invent_a_diagnosis():
    request = continuity.ContinuityRequest(incident_id="INC-1")
    found = continuity._what_we_found(request)
    assert len(found) == 1
    assert "could not establish" in found[0].lower()


def test_the_manager_message_is_plain_and_carries_no_internals():
    request = continuity.ContinuityRequest(
        incident_id="INC-1",
        network_reachable=True,
        service_responding=False,
        specialists_consulted=["network", "systems"],
        remediation_state="ESCALATED",
        changed_anything=False,
    )
    found = continuity._what_we_found(request)
    text = " ".join(found) + " " + continuity._what_happens_next(request)
    # Scoped to what the probe actually did — see the Director Test 2
    # finding below. This assertion previously pinned the overclaim.
    assert "reachable from our network check" in text.lower()
    assert "not responding correctly" in text.lower()
    # No revisions, no traffic percentages, no model reasoning.
    for internal in ("revision", "resourceVersion", "AUTO_ALLOWED", "dispatch-web-00"):
        assert internal not in text


def test_specialist_evidence_is_trusted_tool_and_says_who_gathered_it():
    for module, agent in ((network_evidence, "network"), (security_evidence, "security")):
        source = inspect.getsource(module)
        assert 'trust_level=TrustLevel.TRUSTED_TOOL' in source
        assert f'AGENT = "{agent}"' in source
    assert TrustLevel.TRUSTED_TOOL.value == "TRUSTED_TOOL"


# --- H8: Model Armor still precedes everything -------------------------------


def test_the_fleet_runs_after_screening_not_before():
    source = inspect.getsource(main.create_incident)
    assert source.index("model_armor_screen_started") < source.index("_run_fleet")
    assert source.index('"model_armor_blocked"') < source.index("_run_fleet")


def test_a_specialist_never_receives_raw_manager_text():
    """Untrusted words do not travel to the agents; identifiers do."""
    source = inspect.getsource(main._consult)
    assert "description" not in source
    assert "incident_id" in source
    assert "target_url" in source
    # The probe target comes from configuration, never from the report.
    assert "config.dispatch_web_url()" in source


# --- the Coordinator must not describe work that never happened --------------


def test_an_unattempted_run_is_reported_as_nothing_changed():
    """"Not attempted" is a known outcome, not an unknown one.

    Found live: a security-only incident that reached ESCALATED without any
    remediation told the duty manager "a repair was sent but we could not
    confirm whether it took effect". Nothing had been sent. The escalate branch
    of `_run_fleet` sets no `mutated_infrastructure`, and `None` is the
    Coordinator's sentinel for an unconfirmed mutation.
    """
    source = inspect.getsource(main._compose_manager_status)
    # Presence, not `.get()`. An absent key is "nothing changed"; only an
    # explicitly stored None is the genuine unknown.
    assert '"mutated_infrastructure" in outcome' in source
    assert 'outcome.get("mutated_infrastructure")' not in source

    unattempted = continuity.ContinuityRequest(
        incident_id="INC-1",
        identity_posture_sound=False,
        specialists_consulted=["security"],
        remediation_state="ESCALATED",
        changed_anything=False,
    )
    next_step = continuity._what_happens_next(unattempted)
    assert "repair was sent" not in next_step
    assert "nothing on your site has been changed" in next_step.lower()


def test_a_genuinely_unknown_outcome_still_says_so():
    """The fix must not flatten the real unknown case into a false negative."""
    unknown = continuity.ContinuityRequest(
        incident_id="INC-2",
        remediation_state="EXECUTED",
        changed_anything=None,
    )
    assert "could not confirm" in continuity._what_happens_next(unknown)


def test_the_unknown_sentinel_survives_only_when_it_was_actually_stored():
    """Absent key vs stored None are different facts and must stay different."""
    import asyncio
    from unittest.mock import patch

    async def _compose(outcome):
        captured = {}

        async def _fake_call(_url, _path, payload, **_kw):
            captured.update(payload)
            return {}

        with patch.object(main, "CONTINUITY_URL", "https://continuity.invalid"),              patch.object(main, "_call", _fake_call):
            await main._compose_manager_status("INC-1", [], {}, outcome, None, None)
        return captured

    # Nothing was ever executed: the key is absent.
    assert asyncio.run(_compose({"attempted": False}))["changed_anything"] is False
    # Systems ran, policy refused: still no executor call, still absent.
    assert asyncio.run(_compose(
        {"attempted": True, "final_status": "ESCALATED"}
    ))["changed_anything"] is False
    # A receipt reported an indeterminate effect: stored None, and it survives.
    assert asyncio.run(_compose(
        {"attempted": True, "mutated_infrastructure": None}
    ))["changed_anything"] is None
    # A mutation landed.
    assert asyncio.run(_compose(
        {"attempted": True, "mutated_infrastructure": True}
    ))["changed_anything"] is True


# --- an agent may only assert what it is competent to observe ----------------


def test_an_investigator_cannot_assert_another_agents_findings():
    """The exact evidence that authorizes an automatic traffic flip.

    A Network investigator resolves DNS and opens sockets. It has no way to
    observe whether a revision was blessed by an operator, so a claim that it
    was is dropped before the policy gate sees it — otherwise a single bad
    specialist could manufacture `AUTO_ALLOWED`.
    """
    from scf.domain.models import Evidence
    from scf.domain.enums import TrustLevel

    forged = [
        Evidence(source_agent="network", key=key, value=value,
                 supports="fabricated", trust_level=TrustLevel.TRUSTED_TOOL)
        for key, value in (
            ("network_reachable", True),
            ("service_unhealthy", True),
            ("candidate_revision_approved", True),
            ("candidate_probe_healthy", True),
        )
    ]
    kept = main._within_competence(
        "network", forged, incident_id="INC-1", trace_id=None
    )
    assert [item.key for item in kept] == ["network_reachable"]

    from scf.policy.engine import trusted_evidence_map

    facts = trusted_evidence_map(kept)
    for authorizing in ("service_unhealthy", "candidate_revision_approved",
                        "candidate_probe_healthy"):
        assert authorizing not in facts


def test_every_deployed_specialist_declares_its_competence():
    """An empty set is unconstrained, so a deployed agent must not have one."""
    registry = default_registry()
    for name in ("systems", "network", "security"):
        assert registry.agents[name].establishes, name


def test_the_declared_keys_match_what_the_tools_actually_emit():
    """A stale declaration silently drops real evidence."""
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    sources = {
        "network": root / "src/scf/tools/network_evidence.py",
        "security": root / "src/scf/tools/security_evidence.py",
        "systems": root / "src/scf/tools/cloud_run_evidence.py",
    }
    registry = default_registry()
    for agent, path in sources.items():
        emitted = set(re.findall(r'_ev\(\s*"([a-z_]+)"', path.read_text(encoding="utf-8")))
        declared = set(registry.agents[agent].establishes)
        assert emitted <= declared, (
            f"{agent} emits {sorted(emitted - declared)} which the registry "
            f"would drop"
        )


def test_competence_scoping_cannot_authorize_anything():
    """Same rule as is_selectable: discovery only, never authority."""
    from scf.policy import engine
    from scf.policy.loader import AgentRegistry

    assert "never authorize a mutation" in inspect.getsource(
        AgentRegistry.may_establish
    )
    assert "may_establish" not in inspect.getsource(engine)


# --- the network check must not be described as more than it is --------------


def test_reachability_is_never_reported_as_healthy_wifi():
    """Director acceptance, Test 2.

    The old sentence — "the site network is reachable, the connection to the
    dispatch service is fine" — reads as "your Wi-Fi is fine" to a manager whose
    scanners are dropping out. The check is a DNS lookup plus TCP and TLS from
    an agent in Google Cloud, at one instant. It observes no site equipment at
    all, and no Wi-Fi telemetry exists anywhere in this system.
    """
    reachable = continuity.ContinuityRequest(
        incident_id="INC-1", network_reachable=True
    )
    line = continuity._what_we_found(reachable)[0].lower()

    assert "reachable from our network check" in line
    assert "do not yet have direct evidence" in line
    assert "wi-fi" in line

    # None of the claims the evidence cannot support.
    for overclaim in ("network is fine", "connection to the dispatch service is fine",
                      "wi-fi is fine", "wi-fi is healthy", "your network is healthy"):
        assert overclaim not in line, overclaim


def test_an_unreachable_result_is_also_scoped_to_the_check():
    unreachable = continuity.ContinuityRequest(
        incident_id="INC-1", network_reachable=False
    )
    line = continuity._what_we_found(unreachable)[0].lower()
    assert "our network check" in line
    # It must not assert the site itself is offline; the probe cannot know that.
    assert "the site could not be reached" not in line


def test_no_component_claims_wifi_telemetry_it_does_not_have():
    """There is no Wi-Fi signal anywhere in the evidence surface."""
    from scf.tools import network_evidence

    emitted = _code_only(network_evidence)
    for absent in ("wifi", "wi_fi", "access_point", "ssid", "rssi", "wlan"):
        assert absent not in emitted.lower(), absent


def test_the_network_observations_name_what_was_not_observed():
    source = inspect.getsource(main._run_fleet)
    assert "network_observations" in source
    assert "not_observed" in source
    assert "vantage_point" in source
    # The observations are only attached when Network actually ran.
    assert 'if "network" in consulted:' in source
    for named in ("Wi-Fi access points", "handheld scanners",
                  "outside the instant of this probe"):
        assert named in source, named


def test_the_observations_are_the_trusted_facts_not_a_narrative():
    """They come from the evidence map, so they cannot drift from the probe."""
    source = inspect.getsource(main._run_fleet)
    block = source[source.index("network_observations"):]
    for key in ("dns_resolves", "tcp_connect_ok", "tls_handshake_ok"):
        assert f'facts.get("{key}")' in block, key
