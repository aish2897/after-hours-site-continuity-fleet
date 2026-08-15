from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from scf.domain.enums import Decision, TrustLevel
from scf.domain.ids import canonical_hash
from scf.domain.models import Evidence, PolicyDecision, Proposal
from scf.policy.loader import ActionPolicy, default_policy


def trusted_evidence_map(evidence: Iterable[Evidence]) -> dict[str, Any]:
    """Collapse evidence to a key/value map, discarding untrusted input.

    This is the structural prompt-injection defence: content that originated
    from a user report, attachment, or vendor message never reaches the
    authorization path, so it cannot satisfy a required-evidence condition.
    """
    return {
        item.key: item.value
        for item in evidence
        if item.trust_level is TrustLevel.TRUSTED_TOOL
    }


def evaluate(
    proposal: Proposal,
    evidence: Iterable[Evidence],
    policy: ActionPolicy | None = None,
) -> PolicyDecision:
    """Deterministic authorization. Pure function, no I/O, no model text."""
    policy = policy or default_policy()
    snapshot = trusted_evidence_map(evidence)
    snapshot_hash = canonical_hash(snapshot)

    def decide(
        decision: Decision,
        reason_code: str,
        reason: str,
        required_approval_role: str | None = None,
    ) -> PolicyDecision:
        return PolicyDecision(
            decision=decision,
            reason_code=reason_code,
            reason=reason,
            policy_version=policy.policy_version,
            evidence_snapshot_hash=snapshot_hash,
            required_approval_role=required_approval_role,
        )

    target_type = policy.target_type_of(proposal.target_ref)
    if target_type is None:
        return decide(
            Decision.DENIED,
            "UNKNOWN_TARGET",
            f"Target {proposal.target_ref!r} is not registered in policy.",
        )

    rule = policy.match(proposal.action_type, target_type)
    if rule is None:
        return decide(
            policy.default.decision,
            policy.default.reason_code,
            policy.default.reason,
        )

    missing = sorted(
        key
        for key, expected in rule.required_evidence.items()
        if snapshot.get(key) != expected
    )
    if missing:
        return decide(
            Decision.DENIED,
            "MISSING_EVIDENCE",
            f"Required trusted evidence not satisfied: {missing}",
        )

    return decide(
        rule.decision,
        rule.reason_code,
        rule.reason,
        rule.required_approval_role,
    )
