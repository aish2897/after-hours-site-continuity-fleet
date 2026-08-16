"""Execution plane: execution lifecycle, ownership leases, receipts.

Holds no authorization truth. The executor reads authority from the
authoritative database and can only append execution facts here.

Firestore and the Cloud Run Admin API cannot be committed together, so this
does not pretend to distributed exactly-once execution. It provides
duplicate-safe, recoverable, effect-idempotent execution with reconciliation:
ownership is datastore-atomic, and a crashed execution is resolved by
inspecting real infrastructure rather than by guessing.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from google.api_core.exceptions import AlreadyExists
from google.cloud import firestore

from scf import config
from scf.domain.enums import ExecutionState
from scf.domain.ids import utc_now

EXECUTIONS = "executions"
RECEIPTS = "receipts"

LEASE_SECONDS = 120

#: An execution that reached one of these is finished; never re-run it.
TERMINAL_STATES = frozenset(
    {ExecutionState.VERIFIED, ExecutionState.FAILED, ExecutionState.STALE}
)

#: Outcomes of an ownership attempt.
ACQUIRED = "ACQUIRED"
RECOVERED = "RECOVERED"
HELD_BY_OTHER = "HELD_BY_OTHER"
ALREADY_FINISHED = "ALREADY_FINISHED"


class ExecutionStore:
    def __init__(self, client: firestore.Client | None = None) -> None:
        config.validate_database_config()
        self._db = client or firestore.Client(
            project=config.PROJECT_ID, database=config.EXECUTION_DATABASE
        )

    @property
    def database(self) -> str:
        return config.EXECUTION_DATABASE

    def _ref(self, execution_id: str):
        return self._db.collection(EXECUTIONS).document(execution_id)

    def get(self, execution_id: str) -> dict[str, Any] | None:
        snapshot = self._ref(execution_id).get()
        return snapshot.to_dict() if snapshot.exists else None

    def acquire(
        self,
        execution_id: str,
        *,
        owner: str,
        incident_id: str,
        decision_id: str,
        action_type: str,
        target_ref: str,
        authorized_target_revision: str,
        expected_source_revision: str | None = None,
        expected_etag: str | None = None,
        lease_seconds: int = LEASE_SECONDS,
    ) -> tuple[str, dict[str, Any] | None]:
        """Atomically take ownership of this execution.

        Exactly one worker can hold a live lease. A duplicate delivery while
        the lease is held is refused; a delivery after a crash (expired lease,
        non-terminal state) recovers the SAME execution rather than creating a
        new identity. The document is never deleted, so a claim cannot be
        retracted to manufacture a retry.
        """
        ref = self._ref(execution_id)
        transaction = self._db.transaction()

        @firestore.transactional
        def _acquire(tx: firestore.Transaction) -> tuple[str, dict[str, Any] | None]:
            snapshot = ref.get(transaction=tx)
            now = utc_now()
            lease_until = now + timedelta(seconds=lease_seconds)

            if not snapshot.exists:
                tx.create(
                    ref,
                    {
                        "execution_id": execution_id,
                        "incident_id": incident_id,
                        "decision_id": decision_id,
                        "action_type": action_type,
                        "target_ref": target_ref,
                        "authorized_target_revision": authorized_target_revision,
                        "expected_source_revision": expected_source_revision,
                        "expected_etag": expected_etag,
                        "state": ExecutionState.CLAIMED.value,
                        "lease_owner": owner,
                        "lease_expires_at": lease_until,
                        "recovery_count": 0,
                        "created_at": now,
                        "updated_at": now,
                    },
                )
                return ACQUIRED, None

            current = snapshot.to_dict()
            if current.get("state") in {s.value for s in TERMINAL_STATES}:
                return ALREADY_FINISHED, current

            expires = current.get("lease_expires_at")
            if expires is not None and expires > now:
                return HELD_BY_OTHER, current

            tx.update(
                ref,
                {
                    "lease_owner": owner,
                    "lease_expires_at": lease_until,
                    "recovery_count": (current.get("recovery_count") or 0) + 1,
                    "updated_at": now,
                },
            )
            return RECOVERED, current

        return _acquire(transaction)

    def advance(
        self, execution_id: str, state: ExecutionState, **fields: Any
    ) -> None:
        """Record lifecycle progress. Never deletes, never rewinds identity."""
        payload: dict[str, Any] = {
            "state": state.value,
            "updated_at": utc_now(),
            **fields,
        }
        if state in TERMINAL_STATES:
            payload["lease_expires_at"] = None
            payload["lease_owner"] = None
        self._ref(execution_id).update(payload)

    def record_receipt(self, action_id: str, receipt: dict[str, Any]) -> None:
        self._db.collection(RECEIPTS).document(action_id).set(receipt)

    def receipts_for(self, incident_id: str) -> list[dict[str, Any]]:
        return [
            doc.to_dict()
            for doc in self._db.collection(RECEIPTS)
            .where(filter=firestore.FieldFilter("incident_id", "==", incident_id))
            .stream()
        ]

    def executions_for(self, incident_id: str) -> list[dict[str, Any]]:
        return [
            doc.to_dict()
            for doc in self._db.collection(EXECUTIONS)
            .where(filter=firestore.FieldFilter("incident_id", "==", incident_id))
            .stream()
        ]

    def claim_once(self, key: str, payload: dict[str, Any]) -> bool:
        """Bare create-or-fail primitive, kept for simple one-shot claims."""
        try:
            self._db.collection(EXECUTIONS).document(key).create(payload)
            return True
        except AlreadyExists:
            return False
