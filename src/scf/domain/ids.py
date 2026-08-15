from __future__ import annotations

import json
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any
from uuid import uuid4

SCHEMA_VERSION = "1.0.0"


def canonical_json(payload: Any) -> str:
    """Stable serialization so hashes are reproducible across processes."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def canonical_hash(payload: Any) -> str:
    return sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_incident_id(now: datetime | None = None) -> str:
    stamp = (now or utc_now()).strftime("%Y%m%d")
    return f"INC-{stamp}-{uuid4().hex[:6].upper()}"


def new_decision_id() -> str:
    return f"DEC-{uuid4().hex[:10].upper()}"


def new_action_id() -> str:
    return f"ACT-{uuid4().hex[:10].upper()}"


def derive_idempotency_key(
    *,
    incident_id: str,
    action_type: str,
    target_ref: str,
    decision_id: str,
    attempt_intent: int = 1,
) -> str:
    """Deterministic execution key.

    Derived from the authorizing decision, so re-delivery of the same approved
    decision collapses to one execution. A deliberate retry supplies a new
    attempt_intent and is therefore treated as a distinct, authorized attempt.
    """
    material = "|".join(
        [incident_id, action_type, target_ref, decision_id, str(attempt_intent)]
    )
    return sha256(material.encode("utf-8")).hexdigest()


def chain_hash(prev_hash: str, payload: Any) -> str:
    """Hash-chain link for the append-only audit log."""
    return sha256((prev_hash + canonical_json(payload)).encode("utf-8")).hexdigest()


GENESIS_HASH = "0" * 64
