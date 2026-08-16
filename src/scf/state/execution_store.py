"""Execution plane. Idempotency claims and executor receipts only.

This database deliberately holds no authorization truth. The executor reads
its authority from the authoritative database and can only ever append
execution facts here. Per-database IAM conditions enforce that split; nothing
in this file is load-bearing for the boundary.
"""

from __future__ import annotations

from typing import Any

from google.api_core.exceptions import AlreadyExists
from google.cloud import firestore

from scf import config

IDEMPOTENCY = "idempotency"
RECEIPTS = "receipts"


class ExecutionStore:
    def __init__(self, client: firestore.Client | None = None) -> None:
        config.validate_database_config()
        self._db = client or firestore.Client(
            project=config.PROJECT_ID, database=config.EXECUTION_DATABASE
        )

    @property
    def database(self) -> str:
        return config.EXECUTION_DATABASE

    def claim_idempotency(
        self,
        key: str,
        *,
        incident_id: str,
        decision_id: str,
        action_id: str,
    ) -> bool:
        """Atomically claim the right to execute exactly once.

        Firestore `create` fails if the document exists. That failure IS the
        duplicate signal: no read-then-write race, no in-memory set, no lock.
        The executor holds no delete permission here, so a claim cannot be
        retracted to permit a replay.
        """
        try:
            self._db.collection(IDEMPOTENCY).document(key).create(
                {
                    "incident_id": incident_id,
                    "decision_id": decision_id,
                    "action_id": action_id,
                    "claimed_at": firestore.SERVER_TIMESTAMP,
                }
            )
            return True
        except AlreadyExists:
            return False

    def record_receipt(self, action_id: str, receipt: dict[str, Any]) -> None:
        self._db.collection(RECEIPTS).document(action_id).set(receipt)

    def get_claim(self, key: str) -> dict[str, Any] | None:
        snapshot = self._db.collection(IDEMPOTENCY).document(key).get()
        return snapshot.to_dict() if snapshot.exists else None

    def receipts_for(self, incident_id: str) -> list[dict[str, Any]]:
        return [
            doc.to_dict()
            for doc in self._db.collection(RECEIPTS)
            .where("incident_id", "==", incident_id)
            .stream()
        ]
