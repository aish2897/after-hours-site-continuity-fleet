from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from scf.domain.enums import ActionType, Decision

# Shipped as package data (see pyproject [tool.setuptools.package-data]) so the
# policy travels with the code. Resolving relative to a repo root works in a
# source checkout and fails inside site-packages on Cloud Run.
POLICY_DIR = Path(__file__).resolve().parents[1] / "policies"
POLICY_PATH = POLICY_DIR / "action_policy.json"
REGISTRY_PATH = POLICY_DIR / "agent_registry.json"

WILDCARD = "*"


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class PolicyTarget(Frozen):
    target_type: str
    region: str | None = None


class PolicyRule(Frozen):
    action_type: ActionType
    target_type: str
    decision: Decision
    reason_code: str
    reason: str
    required_evidence: dict[str, Any] = Field(default_factory=dict)
    required_approval_role: str | None = None


class PolicyDefault(Frozen):
    decision: Decision
    reason_code: str
    reason: str


class ActionPolicy(Frozen):
    policy_version: str
    targets: dict[str, PolicyTarget]
    rules: list[PolicyRule]
    default: PolicyDefault
    description: str = ""

    def target_type_of(self, target_ref: str) -> str | None:
        target = self.targets.get(target_ref)
        return target.target_type if target else None

    def match(self, action_type: ActionType, target_type: str) -> PolicyRule | None:
        for rule in self.rules:
            if rule.action_type != action_type:
                continue
            if rule.target_type in (target_type, WILDCARD):
                return rule
        return None


class AgentEntry(Frozen):
    version: str
    llm_backed: bool
    service_account: str
    may_propose_actions: bool
    may_write_firestore: bool
    allowed_tools: list[str]
    #: Whether a runtime for this agent is actually deployed. Three specialists
    #: are contracts only — no service, no service account — and `llm_backed`
    #: alone could not say so: "false" reads as "deterministic" rather than
    #: "does not exist". The registry claims to describe the runtime, so it has
    #: to be able to say when there isn't one.
    deployed: bool = False
    #: Lifecycle switch. A deployed agent can still be withdrawn from service —
    #: deprecated, under investigation, or simply not approved for use — and the
    #: orchestrator must respect that without any change to code. The catalog
    #: ships inside the image, so applying it does take a redeploy; what it does
    #: not take is editing the orchestrator.
    enabled: bool = True
    #: Evidence keys this agent is competent to assert. Empty means unconstrained
    #: — which is why every deployed specialist declares one. An agent returning
    #: a key outside its own set is not making a finding, it is asserting
    #: something it has no way to know, and the orchestrator drops it before the
    #: policy gate can read it.
    establishes: list[str] = []


class AgentRegistry(Frozen):
    registry_version: str
    agents: dict[str, AgentEntry]
    description: str = ""

    def is_selectable(self, agent_name: str) -> bool:
        """May the orchestrator route work to this agent right now?

        Governance, not authorization. A specialist that is disabled, or has no
        deployed runtime, must not be selected — and the answer comes from the
        governed catalog rather than from whatever the model proposed. This
        controls DISCOVERY only: it can never permit an infrastructure change,
        which still requires trusted evidence, the deterministic gate, an exact
        pinned authorization and a scoped identity.
        """
        entry = self.agents.get(agent_name)
        return bool(entry and entry.deployed and entry.enabled)

    def selectable_specialists(self) -> list[str]:
        return sorted(name for name in self.agents if self.is_selectable(name))

    def may_establish(self, agent_name: str, key: str) -> bool:
        """May this agent assert this evidence key?

        DISCOVERY and evidence scoping only. Like `is_selectable`, this can
        never authorize a mutation — it only narrows what an agent is allowed to
        claim to have observed. Widening it grants no new capability to anyone.
        """
        entry = self.agents.get(agent_name)
        if entry is None:
            return False
        return not entry.establishes or key in entry.establishes

    def may_propose(self, agent_name: str) -> bool:
        entry = self.agents.get(agent_name)
        return bool(entry and entry.may_propose_actions)

    def allows_tool(self, agent_name: str, tool_name: str) -> bool:
        entry = self.agents.get(agent_name)
        return bool(entry and tool_name in entry.allowed_tools)


def load_policy(path: Path | None = None) -> ActionPolicy:
    raw = json.loads((path or POLICY_PATH).read_text(encoding="utf-8"))
    return ActionPolicy.model_validate(raw)


def load_registry(path: Path | None = None) -> AgentRegistry:
    raw = json.loads((path or REGISTRY_PATH).read_text(encoding="utf-8"))
    return AgentRegistry.model_validate(raw)


@lru_cache(maxsize=1)
def default_policy() -> ActionPolicy:
    return load_policy()


@lru_cache(maxsize=1)
def default_registry() -> AgentRegistry:
    return load_registry()
