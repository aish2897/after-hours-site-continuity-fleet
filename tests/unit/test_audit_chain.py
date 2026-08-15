from __future__ import annotations

from scf.audit import append, verify_chain
from scf.domain.ids import GENESIS_HASH


def build_incident_trail():
    records = []
    for actor, event, payload in [
        ("orchestrator", "incident_received", {"site_id": "MEL-WAREHOUSE-01"}),
        ("orchestrator", "routing_decision", {"required": ["systems"]}),
        ("systems", "evidence_collected", {"service_unhealthy": True}),
        ("systems", "action_proposed", {"action": "FLIP_TRAFFIC_TO_LAST_GOOD"}),
        ("policy", "policy_decision", {"decision": "AUTO_ALLOWED"}),
        ("executor", "action_executed", {"changed": True}),
        ("verifier", "recovery_verified", {"http_status": 200}),
    ]:
        records.append(append(records, actor=actor, event=event, payload=payload))
    return records


def test_intact_chain_verifies():
    records = build_incident_trail()
    result = verify_chain(records)
    assert result.ok
    assert result.checked == 7


def test_chain_starts_at_genesis_and_is_contiguous():
    records = build_incident_trail()
    assert records[0].prev_hash == GENESIS_HASH
    assert [r.seq for r in records] == list(range(7))
    for prev, current in zip(records, records[1:]):
        assert current.prev_hash == prev.hash


def test_empty_chain_is_valid():
    assert verify_chain([]).ok


def test_editing_a_payload_breaks_the_chain():
    records = build_incident_trail()
    records[4] = records[4].model_copy(update={"payload": {"decision": "DENIED"}})
    result = verify_chain(records)
    assert not result.ok
    assert result.broken_at == 4
    assert "hash" in result.reason


def test_editing_the_actor_breaks_the_chain():
    records = build_incident_trail()
    records[5] = records[5].model_copy(update={"actor": "systems"})
    result = verify_chain(records)
    assert not result.ok
    assert result.broken_at == 5


def test_deleting_a_record_breaks_the_chain():
    records = build_incident_trail()
    del records[3]
    result = verify_chain(records)
    assert not result.ok
    assert "sequence gap" in result.reason


def test_reordering_records_breaks_the_chain():
    records = build_incident_trail()
    records[2], records[3] = records[3], records[2]
    assert not verify_chain(records).ok


def test_truncating_the_tail_is_detected_by_length():
    """Truncation leaves a valid prefix, so callers must check expected length."""
    records = build_incident_trail()
    truncated = records[:-2]
    result = verify_chain(truncated)
    assert result.ok
    assert result.checked == 5 < len(records)


def test_appending_a_forged_record_breaks_the_chain():
    records = build_incident_trail()
    forged = records[-1].model_copy(
        update={
            "seq": 7,
            "prev_hash": records[-1].hash,
            "event": "action_executed",
            "payload": {"changed": True, "target": "credential-store"},
        }
    )
    records.append(forged)
    result = verify_chain(records)
    assert not result.ok
    assert result.broken_at == 7
