from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from scf.domain.enums import Decision, TrustLevel
from scf.domain.ids import canonical_hash
from scf.domain.models import Evidence, PolicyDecision, Proposal
from scf.policy.loader import ActionPolicy, default_policy


def trusted_evidence_map(evidence: Iterable[Evidence]) -> dict[str, Any]:
    """Collapse evidence to a key/value map, discarding untrusted input.

    This is the structural separation that keeps injected content out of the
    *authorization* path: content originating from a user report, attachment or
    vendor message cannot satisfy a required-evidence condition. It is
    deliberately not called prompt-injection resistance — the report text still
    reaches the model uninspected, and no such resistance is claimed anywhere.
    """
    return {
        item.key: item.value
        for item in evidence
        if item.trust_level is TrustLevel.TRUSTED_TOOL
    }


def trusted_evidence_conflicts(evidence: Iterable[Evidence]) -> set[str]:
    """Trusted keys asserted more than once with different values.

    Collapsing evidence to a map is last-write-wins, and last-write-wins is not
    a reading of a contradiction — it is a coin toss with the safety property.
    Two trusted facts saying `service_unhealthy` is both False and True do not
    average out to an authorization; they mean the evidence cannot be relied on
    at all, and the gate must say so.
    """
    seen: dict[str, Any] = {}
    conflicts: set[str] = set()
    for item in evidence:
        if item.trust_level is not TrustLevel.TRUSTED_TOOL:
            continue
        if item.key in seen and not _same_value(seen[item.key], item.value):
            conflicts.add(item.key)
        seen[item.key] = item.value
    return conflicts


def _same_value(left: Any, right: Any) -> bool:
    """Whether two trusted facts are genuinely the same assertion.

    Type-aware, because `bool` is a subclass of `int`: plain equality says `1`
    and `True` agree, so a contradiction check written with `!=` silently
    passed the exact case it existed to catch — evidence of `1` followed by
    evidence of `True`, where last-write-wins then leaves the boolean in the
    snapshot and the gate authorizes.
    """
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    return left == right


def _satisfies(actual: Any, expected: Any) -> bool:
    """Whether one trusted fact satisfies one required-evidence condition.

    Type-exact on purpose. Python says `1 == True` and `0 == False`, so a
    worker returning `1` where the policy requires the boolean `true` would
    have satisfied a safety condition with a number — and three such numbers
    are the whole distance between an outage report and an authorized
    infrastructure mutation. A required boolean is satisfied only by that
    boolean.
    """
    if isinstance(expected, bool) or isinstance(actual, bool):
        return actual is expected
    return actual == expected


def evaluate(
    proposal: Proposal,
    evidence: Iterable[Evidence],
    policy: ActionPolicy | None = None,
) -> PolicyDecision:
    """Deterministic authorization. Pure function, no I/O, no model text."""
    policy = policy or default_policy()
    # Materialised once: the gate reads the evidence twice, and a generator
    # read twice is empty the second time — which would silently disable the
    # contradiction check rather than fail it.
    evidence = list(evidence)
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

    contradicted = sorted(
        trusted_evidence_conflicts(evidence) & set(rule.required_evidence)
    )
    if contradicted:
        return decide(
            Decision.DENIED,
            "CONTRADICTORY_EVIDENCE",
            f"Trusted evidence contradicts itself: {contradicted}",
        )

    missing = sorted(
        key
        for key, expected in rule.required_evidence.items()
        if not _satisfies(snapshot.get(key), expected)
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
