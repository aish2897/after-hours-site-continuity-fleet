from __future__ import annotations

from typing import Any

from google.cloud import firestore

from scf import config
from scf.audit.chain import append as append_audit_record
from scf.domain.enums import IncidentStatus
from scf.domain.models import AuditRecord, IncidentDoc, RoutingDecision
from scf.domain.state_machine import assert_transition

INCIDENTS = "incidents"
AUDIT = "audit"


class IncidentNotFound(KeyError):
    pass


class IncidentRepository:
    """Firestore-backed incident store. Firestore is authoritative, not memory."""

    def __init__(self, client: firestore.Client | None = None) -> None:
        self._db = client or firestore.Client(project=config.PROJECT_ID)

    # --- reads ---------------------------------------------------------------

    def _doc_ref(self, incident_id: str):
        return self._db.collection(INCIDENTS).document(incident_id)

    def get(self, incident_id: str) -> dict[str, Any]:
        snapshot = self._doc_ref(incident_id).get()
        if not snapshot.exists:
            raise IncidentNotFound(incident_id)
        return snapshot.to_dict()

    def audit_trail(self, incident_id: str) -> list[AuditRecord]:
        docs = (
            self._doc_ref(incident_id)
            .collection(AUDIT)
            .order_by("seq")
            .stream()
        )
        return [AuditRecord.model_validate(doc.to_dict()) for doc in docs]

    # --- writes --------------------------------------------------------------

    def create(self, incident: IncidentDoc) -> str:
        payload = incident.model_dump(mode="json")
        self._doc_ref(incident.incident_id).create(payload)
        self.append_audit(
            incident.incident_id,
            actor="orchestrator",
            event="incident_received",
            payload={"site_id": incident.report.site_id, "status": incident.status},
            trace_id=incident.trace_id,
        )
        return incident.incident_id

    def append_audit(
        self,
        incident_id: str,
        *,
        actor: str,
        event: str,
        payload: dict[str, Any] | None = None,
        actor_identity: str | None = None,
        trace_id: str | None = None,
    ) -> AuditRecord:
        existing = self.audit_trail(incident_id)
        record = append_audit_record(
            existing,
            actor=actor,
            event=event,
            payload=payload or {},
            actor_identity=actor_identity,
            trace_id=trace_id,
        )
        (
            self._doc_ref(incident_id)
            .collection(AUDIT)
            .document(f"{record.seq:06d}")
            .create(record.model_dump(mode="json"))
        )
        return record

    def transition(
        self, incident_id: str, target: IncidentStatus, *, trace_id: str | None = None
    ) -> IncidentStatus:
        """Compare-and-set transition inside a Firestore transaction."""
        doc_ref = self._doc_ref(incident_id)

        @firestore.transactional
        def _apply(transaction: firestore.Transaction) -> IncidentStatus:
            snapshot = doc_ref.get(transaction=transaction)
            if not snapshot.exists:
                raise IncidentNotFound(incident_id)
            current = IncidentStatus(snapshot.to_dict()["status"])
            assert_transition(current, target)
            transaction.update(
                doc_ref,
                {
                    "status": target.value,
                    "updated_at": firestore.SERVER_TIMESTAMP,
                },
            )
            return current

        previous = _apply(self._db.transaction())
        self.append_audit(
            incident_id,
            actor="orchestrator",
            event="state_transition",
            payload={"from": previous.value, "to": target.value},
            trace_id=trace_id,
        )
        return previous

    def save_routing(
        self,
        incident_id: str,
        decision: RoutingDecision,
        *,
        trace_id: str | None = None,
    ) -> None:
        """Persist the routing decision and its model provenance.

        Stored as evidence and display material. The policy gate never reads it.
        """
        self._doc_ref(incident_id).update(
            {
                "routing": decision.model_dump(mode="json"),
                "updated_at": firestore.SERVER_TIMESTAMP,
            }
        )
        self.append_audit(
            incident_id,
            actor="orchestrator",
            event="routing_decision",
            payload={
                "required": [s.value for s in decision.required_specialists()],
                "model_id": decision.model_id,
            },
            trace_id=trace_id,
        )
