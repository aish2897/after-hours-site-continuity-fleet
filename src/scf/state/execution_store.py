"""Execution plane: execution lifecycle, ownership leases, receipts.

Holds no authorization truth. The executor reads authority from the
authoritative database and can only append execution facts here.

Firestore and the Cloud Run Admin API cannot be committed together, so this
does not pretend to distributed exactly-once execution. It provides
duplicate-safe, recoverable, effect-idempotent execution with reconciliation:
ownership is datastore-atomic, and a crashed execution is resolved by
inspecting real infrastructure rather than by guessing.

Ownership is fenced by a `lease_epoch`. The epoch is generated here, never
supplied by a caller, is immutable for one ownership period, and increments on
every expired-lease takeover. Once epoch N+1 has been issued, the holder of
epoch N can no longer advance authoritative execution state — every worker
transition is a transactional compare-and-set on (owner, epoch, state, lease
validity, non-terminality).
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
AUTHORIZATIONS = "authorizations"

LEASE_SECONDS = 120

#: An execution that reached one of these is finished; never re-run it.
TERMINAL_STATES = frozenset(
    {ExecutionState.VERIFIED, ExecutionState.FAILED, ExecutionState.STALE}
)
_TERMINAL_VALUES = frozenset(s.value for s in TERMINAL_STATES)

#: Outcomes of an ownership attempt.
ACQUIRED = "ACQUIRED"
RECOVERED = "RECOVERED"
HELD_BY_OTHER = "HELD_BY_OTHER"
ALREADY_FINISHED = "ALREADY_FINISHED"

#: Outcomes of an ownership-bound state advance.
ADVANCED = "ADVANCED"
FENCED_OUT = "FENCED_OUT"
LEASE_LOST = "LEASE_LOST"
ALREADY_TERMINAL = "ALREADY_TERMINAL"
STATE_MISMATCH = "STATE_MISMATCH"
NOT_FOUND = "NOT_FOUND"

#: Outcomes of binding an authorization fingerprint to an execution identity.
BOUND = "BOUND"
SAME = "SAME"
CONFLICT = "CONFLICT"


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

    # --- authorization identity ---------------------------------------------

    def bind_authorization(
        self,
        fingerprint: str,
        *,
        execution_id: str,
        incident_id: str,
        decision_id: str,
    ) -> tuple[str, dict[str, Any] | None]:
        """Bind one authorization fingerprint to one execution identity.

        First writer wins, permanently — the executor holds no delete right on
        this database, so a binding cannot be retracted to permit a second
        effect. A re-issued but materially identical decision therefore cannot
        mint a second execution: it is refused as CONFLICT before any
        infrastructure is touched.
        """
        ref = self._db.collection(AUTHORIZATIONS).document(fingerprint)
        transaction = self._db.transaction()

        @firestore.transactional
        def _bind(tx: firestore.Transaction) -> tuple[str, dict[str, Any] | None]:
            snapshot = ref.get(transaction=tx)
            if not snapshot.exists:
                tx.create(
                    ref,
                    {
                        "authorization_fingerprint": fingerprint,
                        "execution_id": execution_id,
                        "incident_id": incident_id,
                        "decision_id": decision_id,
                        "bound_at": utc_now(),
                    },
                )
                return BOUND, None
            current = snapshot.to_dict()
            if current.get("execution_id") == execution_id:
                return SAME, current
            return CONFLICT, current

        return _bind(transaction)

    # --- ownership ------------------------------------------------------------

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
        """Atomically take ownership of this execution and issue a lease epoch.

        Exactly one worker can hold a live lease. A duplicate delivery while
        the lease is held is refused; a delivery after a crash (expired lease,
        non-terminal state) recovers the SAME execution rather than creating a
        new identity, and is issued the NEXT epoch so the previous holder is
        fenced out. The document is never deleted, so a claim cannot be
        retracted to manufacture a retry.

        Terminality is checked before lease expiry, so an expired lease on a
        terminal execution never reopens it.
        """
        ref = self._ref(execution_id)
        transaction = self._db.transaction()

        @firestore.transactional
        def _acquire(tx: firestore.Transaction) -> tuple[str, dict[str, Any] | None]:
            snapshot = ref.get(transaction=tx)
            now = utc_now()
            lease_until = now + timedelta(seconds=lease_seconds)

            if not snapshot.exists:
                record = {
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
                    "lease_epoch": 1,
                    "lease_expires_at": lease_until,
                    "recovery_count": 0,
                    "created_at": now,
                    "updated_at": now,
                }
                tx.create(ref, record)
                return ACQUIRED, record

            current = snapshot.to_dict()
            # Terminal first: a finished execution is never takeover eligible,
            # however long ago its lease lapsed.
            if current.get("state") in _TERMINAL_VALUES:
                return ALREADY_FINISHED, current

            expires = current.get("lease_expires_at")
            if expires is not None and expires > now:
                return HELD_BY_OTHER, current

            epoch = int(current.get("lease_epoch") or 0) + 1
            updates = {
                "lease_owner": owner,
                "lease_epoch": epoch,
                "lease_expires_at": lease_until,
                "recovery_count": (current.get("recovery_count") or 0) + 1,
                "updated_at": now,
            }
            tx.update(ref, updates)
            return RECOVERED, {**current, **updates}

        return _acquire(transaction)

    def renew(
        self,
        execution_id: str,
        *,
        owner: str,
        lease_epoch: int,
        lease_seconds: int = LEASE_SECONDS,
    ) -> tuple[str, dict[str, Any] | None]:
        """Extend a lease the caller still owns. Fenced like any other write.

        A worker whose epoch has been superseded cannot renew its way back into
        ownership — the epoch it presents no longer matches the document.
        """
        ref = self._ref(execution_id)
        transaction = self._db.transaction()

        @firestore.transactional
        def _renew(tx: firestore.Transaction) -> tuple[str, dict[str, Any] | None]:
            snapshot = ref.get(transaction=tx)
            if not snapshot.exists:
                return NOT_FOUND, None
            current = snapshot.to_dict()
            if current.get("state") in _TERMINAL_VALUES:
                return ALREADY_TERMINAL, current
            if current.get("lease_owner") != owner or int(
                current.get("lease_epoch") or 0
            ) != int(lease_epoch):
                return FENCED_OUT, current
            now = utc_now()
            updates = {
                "lease_expires_at": now + timedelta(seconds=lease_seconds),
                "updated_at": now,
            }
            tx.update(ref, updates)
            return ADVANCED, {**current, **updates}

        return _renew(transaction)

    def release(
        self, execution_id: str, *, owner: str, lease_epoch: int
    ) -> tuple[str, dict[str, Any] | None]:
        """Give up a lease the caller holds, without terminalizing.

        Used when a worker refuses *before* issuing any mutation — nothing was
        done, so squatting on the lease until it expires only delays a
        legitimate retry. Ownership-bound like every other write, so it cannot
        be used to evict a newer owner, and the epoch is left intact so the
        next acquirer still increments past this one.
        """
        ref = self._ref(execution_id)
        transaction = self._db.transaction()

        @firestore.transactional
        def _release(tx: firestore.Transaction) -> tuple[str, dict[str, Any] | None]:
            snapshot = ref.get(transaction=tx)
            if not snapshot.exists:
                return NOT_FOUND, None
            current = snapshot.to_dict()
            if current.get("state") in _TERMINAL_VALUES:
                return ALREADY_TERMINAL, current
            if current.get("lease_owner") != owner or int(
                current.get("lease_epoch") or 0
            ) != int(lease_epoch):
                return FENCED_OUT, current
            now = utc_now()
            updates = {"lease_expires_at": now, "updated_at": now}
            tx.update(ref, updates)
            return ADVANCED, {**current, **updates}

        return _release(transaction)

    # --- state -----------------------------------------------------------------

    def advance(
        self,
        execution_id: str,
        state: ExecutionState,
        *,
        owner: str,
        lease_epoch: int,
        expect_states: tuple[ExecutionState, ...] | None = None,
        **fields: Any,
    ) -> tuple[str, dict[str, Any] | None]:
        """Ownership-bound lifecycle progress. Never deletes.

        Not strictly forward-only: the executor deliberately winds a record back
        from `MUTATION_REQUESTED` to `PRECONDITION_CHECKED` when Google refuses
        the write with 409 ABORTED, because that response is proof no mutation
        was applied and the record should not claim one was attempted. Every
        such move is still subject to the full compare-and-set below.

        Atomically requires, in one transaction: the document exists, it is not
        terminal, `lease_owner` matches, `lease_epoch` matches, the lease has
        not expired, and the current state is one of `expect_states`. A worker
        that fails any of these writes nothing and is told so deterministically
        — it cannot overwrite the state a newer owner has established.
        """
        ref = self._ref(execution_id)
        transaction = self._db.transaction()

        @firestore.transactional
        def _advance(tx: firestore.Transaction) -> tuple[str, dict[str, Any] | None]:
            snapshot = ref.get(transaction=tx)
            if not snapshot.exists:
                return NOT_FOUND, None
            current = snapshot.to_dict()

            if current.get("state") in _TERMINAL_VALUES:
                return ALREADY_TERMINAL, current
            if current.get("lease_owner") != owner or int(
                current.get("lease_epoch") or 0
            ) != int(lease_epoch):
                return FENCED_OUT, current

            now = utc_now()
            expires = current.get("lease_expires_at")
            if expires is None or expires <= now:
                return LEASE_LOST, current
            if expect_states is not None and current.get("state") not in {
                s.value for s in expect_states
            }:
                return STATE_MISMATCH, current

            payload: dict[str, Any] = {
                "state": state.value,
                "updated_at": now,
                **fields,
            }
            if state in TERMINAL_STATES:
                payload["lease_expires_at"] = None
                payload["lease_owner"] = None
            tx.update(ref, payload)
            return ADVANCED, {**current, **payload}

        return _advance(transaction)

    def terminalize(
        self,
        execution_id: str,
        state: ExecutionState = ExecutionState.VERIFIED,
        *,
        expect_states: tuple[ExecutionState, ...] = (ExecutionState.MUTATED,),
        **fields: Any,
    ) -> tuple[str, dict[str, Any] | None]:
        """Close an execution permanently, gated on state rather than ownership.

        This transition performs no infrastructure mutation, so a lease is the
        wrong gate for it — the mutating worker's lease may still be live, or
        long gone, and neither fact bears on whether the authorized effect is
        now proven. What gates it instead is stronger: an independent verifier
        verdict plus the executor's own re-observation of the live service, and
        a transactional compare-and-set on the expected current state.

        Idempotent under concurrency: the first caller wins, later callers are
        told ALREADY_TERMINAL and change nothing.
        """
        ref = self._ref(execution_id)
        transaction = self._db.transaction()

        @firestore.transactional
        def _close(tx: firestore.Transaction) -> tuple[str, dict[str, Any] | None]:
            snapshot = ref.get(transaction=tx)
            if not snapshot.exists:
                return NOT_FOUND, None
            current = snapshot.to_dict()
            if current.get("state") in _TERMINAL_VALUES:
                return ALREADY_TERMINAL, current
            if current.get("state") not in {s.value for s in expect_states}:
                return STATE_MISMATCH, current

            payload: dict[str, Any] = {
                "state": state.value,
                "updated_at": utc_now(),
                "lease_expires_at": None,
                "lease_owner": None,
                **fields,
            }
            tx.update(ref, payload)
            return ADVANCED, {**current, **payload}

        return _close(transaction)

    # --- receipts ---------------------------------------------------------------

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
