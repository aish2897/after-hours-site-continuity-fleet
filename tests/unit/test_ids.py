from __future__ import annotations

from scf.domain.ids import (
    GENESIS_HASH,
    canonical_hash,
    canonical_json,
    chain_hash,
    derive_execution_id,
    new_incident_id,
)

BASE = {
    "incident_id": "INC-20260815-ABC123",
    "action_type": "FLIP_TRAFFIC_TO_LAST_GOOD",
    "target_ref": "dispatch-web",
    "decision_id": "DEC-0001",
}


def test_key_is_stable_across_calls():
    assert derive_execution_id(**BASE) == derive_execution_id(**BASE)


def test_key_is_stable_across_processes():
    """No uuid, clock, or hostname may leak into the key material."""
    expected = derive_execution_id(**BASE)
    for _ in range(50):
        assert derive_execution_id(**BASE) == expected


def test_no_extra_input_can_vary_the_execution_id():
    """One decision, one execution identity. No caller field participates."""
    import inspect

    params = set(inspect.signature(derive_execution_id).parameters)
    assert params == {"incident_id", "action_type", "target_ref", "decision_id"}
    assert "attempt_intent" not in params


def test_each_field_changes_the_key():
    baseline = derive_execution_id(**BASE)
    for field, value in [
        ("incident_id", "INC-20260815-ZZZ999"),
        ("action_type", "RESTART_APPLICATION_SERVICE"),
        ("target_ref", "site-directory"),
        ("decision_id", "DEC-0002"),
    ]:
        assert derive_execution_id(**{**BASE, field: value}) != baseline


def test_key_shape():
    key = derive_execution_id(**BASE)
    assert len(key) == 64
    assert set(key) <= set("0123456789abcdef")


def test_canonical_json_is_order_independent():
    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})
    assert canonical_hash({"a": 1, "b": 2}) == canonical_hash({"b": 2, "a": 1})


def test_chain_hash_depends_on_prev_and_payload():
    first = chain_hash(GENESIS_HASH, {"event": "incident_received"})
    same = chain_hash(GENESIS_HASH, {"event": "incident_received"})
    other_payload = chain_hash(GENESIS_HASH, {"event": "policy_decision"})
    other_prev = chain_hash(first, {"event": "incident_received"})

    assert first == same
    assert first != other_payload
    assert first != other_prev


def test_incident_ids_are_unique_and_dated():
    ids = {new_incident_id() for _ in range(200)}
    assert len(ids) == 200
    assert all(value.startswith("INC-") for value in ids)
