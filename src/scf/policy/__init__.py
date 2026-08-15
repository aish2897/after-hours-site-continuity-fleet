"""Deterministic policy gate. Pure, table-driven, TRUSTED_TOOL evidence only."""

from scf.policy.engine import evaluate, trusted_evidence_map
from scf.policy.loader import (
    POLICY_PATH,
    REGISTRY_PATH,
    ActionPolicy,
    AgentRegistry,
    default_policy,
    default_registry,
    load_policy,
    load_registry,
)

__all__ = [
    "POLICY_PATH",
    "REGISTRY_PATH",
    "ActionPolicy",
    "AgentRegistry",
    "default_policy",
    "default_registry",
    "evaluate",
    "load_policy",
    "load_registry",
    "trusted_evidence_map",
]
