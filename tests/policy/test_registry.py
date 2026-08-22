from __future__ import annotations

from scf.policy import default_registry


def test_registry_loads_and_is_versioned():
    registry = default_registry()
    assert registry.registry_version
    assert registry.agents


def test_security_agent_cannot_propose_actions():
    """The prototype let the security agent author an EXPORT_CREDENTIALS request.

    That is now a contract violation rather than a demo prop.
    """
    assert default_registry().may_propose("security") is False


def test_only_the_systems_investigator_may_propose():
    """Exactly one agent may propose a remediation.

    Network carried `may_propose_actions: true` from the Day-1 catalog, which
    described an intent rather than the runtime. It gathers reachability facts
    and proposes nothing; corrected when its runtime was actually built.
    """
    registry = default_registry()
    proposers = {
        name for name, entry in registry.agents.items() if entry.may_propose_actions
    }
    assert proposers == {"systems"}


def test_investigators_cannot_write_firestore():
    """Read-only investigators are what make datastore.viewer a real boundary."""
    registry = default_registry()
    for name in ("systems", "network", "security", "continuity"):
        assert registry.agents[name].may_write_firestore is False


def test_only_orchestrator_and_executor_write_state():
    registry = default_registry()
    writers = {
        name for name, entry in registry.agents.items() if entry.may_write_firestore
    }
    assert writers == {"orchestrator", "executor"}


def test_executor_is_the_only_holder_of_the_mutating_tool():
    registry = default_registry()
    holders = {
        name
        for name, entry in registry.agents.items()
        if "flip_traffic_to_last_good" in entry.allowed_tools
    }
    assert holders == {"executor"}


def test_executor_is_not_llm_backed():
    registry = default_registry()
    assert registry.agents["executor"].llm_backed is False
    assert registry.agents["verifier"].llm_backed is False


def test_every_agent_has_a_distinct_service_account():
    accounts = [entry.service_account for entry in default_registry().agents.values()]
    assert len(set(accounts)) == len(accounts)


def test_tool_allowlist_is_enforced_per_agent():
    registry = default_registry()
    assert registry.allows_tool("systems", "read_service_health") is True
    assert registry.allows_tool("systems", "flip_traffic_to_last_good") is False
    assert registry.allows_tool("network", "read_service_health") is False
