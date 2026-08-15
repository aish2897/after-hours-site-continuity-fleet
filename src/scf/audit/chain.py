from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict

from scf.domain.ids import GENESIS_HASH, chain_hash
from scf.domain.models import AuditRecord


class ChainVerification(BaseModel):
    model_config = ConfigDict(frozen=True)

    ok: bool
    checked: int
    broken_at: int | None = None
    reason: str | None = None


def hashable_view(record: AuditRecord) -> dict[str, Any]:
    """The fields a record's own hash commits to. Excludes `hash` itself."""
    return {
        "seq": record.seq,
        "actor": record.actor,
        "actor_identity": record.actor_identity,
        "event": record.event,
        "payload": record.payload,
        "trace_id": record.trace_id,
        "span_id": record.span_id,
        "timestamp": record.timestamp.isoformat(),
    }


def seal(record: AuditRecord) -> AuditRecord:
    """Return the record with its chain hash computed."""
    return record.model_copy(
        update={"hash": chain_hash(record.prev_hash, hashable_view(record))}
    )


def append(
    records: Sequence[AuditRecord],
    *,
    actor: str,
    event: str,
    payload: dict[str, Any] | None = None,
    actor_identity: str | None = None,
    trace_id: str | None = None,
    span_id: str | None = None,
) -> AuditRecord:
    """Build the next sealed record for an existing chain."""
    prev = records[-1] if records else None
    return seal(
        AuditRecord(
            seq=(prev.seq + 1) if prev else 0,
            prev_hash=prev.hash if prev else GENESIS_HASH,
            actor=actor,
            actor_identity=actor_identity,
            event=event,
            payload=payload or {},
            trace_id=trace_id,
            span_id=span_id,
        )
    )


def verify_chain(records: Iterable[AuditRecord]) -> ChainVerification:
    """Detect any edit, reorder, insertion, or deletion in an audit trail."""
    ordered = list(records)
    if not ordered:
        return ChainVerification(ok=True, checked=0)

    expected_prev = GENESIS_HASH
    for index, record in enumerate(ordered):
        if record.seq != index:
            return ChainVerification(
                ok=False,
                checked=index,
                broken_at=index,
                reason=f"sequence gap: expected seq {index}, found {record.seq}",
            )
        if record.prev_hash != expected_prev:
            return ChainVerification(
                ok=False,
                checked=index,
                broken_at=record.seq,
                reason="prev_hash does not match the preceding record",
            )
        recomputed = chain_hash(record.prev_hash, hashable_view(record))
        if record.hash != recomputed:
            return ChainVerification(
                ok=False,
                checked=index,
                broken_at=record.seq,
                reason="record contents do not match its hash",
            )
        expected_prev = record.hash

    return ChainVerification(ok=True, checked=len(ordered))
