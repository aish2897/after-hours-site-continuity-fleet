from __future__ import annotations

from typing import Any


from google.cloud import firestore

from scf import config
from scf.audit.chain import append as append_audit_record
from scf.domain.enums import IncidentStatus, TrustLevel
from scf.domain.models import (
    ActionRecord,
    AuditRecord,
    Evidence,
    IncidentDoc,
    PolicyDecision,
    Proposal,
    RoutingDecision,
)
from scf.domain.state_machine import assert_transition

INCIDENTS = "incidents"
AUDIT = "audit"
DECISIONS = "decisions"
ACTIONS = "actions"
EVIDENCE = "evidence"



class IncidentNotFound(KeyError):
    pass


class DecisionNotFound(KeyError):
    pass


class IncidentRepository:
    """Authoritative control plane: incidents, evidence, decisions, audit.

    Only authoritative writers (the orchestrator) bind with write access here.
    The executor's identity is granted read-only on this database through a
    per-database IAM condition, so it can obtain authorization but cannot
    manufacture or alter it.
    """

    def __init__(
        self,
        client: firestore.Client | None = None,
        database: str | None = None,
    ) -> None:
        config.validate_database_config()
        self.database = database or config.AUTHORITATIVE_DATABASE
        self._db = client or firestore.Client(
            project=config.PROJECT_ID, database=self.database
        )

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

    def save_evidence(
        self,
        incident_id: str,
        evidence: list[Evidence],
        *,
        trace_id: str | None = None,
    ) -> int:
        collection = self._doc_ref(incident_id).collection(EVIDENCE)
        for item in evidence:
            payload = item.model_dump(mode="json")
            payload["content_hash"] = item.content_hash()
            collection.document(f"{item.source_agent}-{item.key}").set(payload)
        self.append_audit(
            incident_id,
            actor="orchestrator",
            event="evidence_collected",
            payload={
                "count": len(evidence),
                "trusted": sum(
                    1 for e in evidence if e.trust_level is TrustLevel.TRUSTED_TOOL
                ),
            },
            trace_id=trace_id,
        )
        return len(evidence)

    # --- decisions, idempotency, actions (Gate D) --------------------------

    def save_decision(
        self,
        incident_id: str,
        proposal: Proposal,
        decision: PolicyDecision,
        *,
        parameters: dict[str, Any] | None = None,
        trace_id: str | None = None,
    ) -> str:
        """Persist the authoritative authorization record.

        The executor re-reads this document rather than trusting its caller.
        The model's rationale is stored for display only and is not part of
        the authorization inputs.
        """
        payload = {
            "decision_id": decision.decision_id,
            "incident_id": incident_id,
            "action_type": proposal.action_type.value,
            "target_ref": proposal.target_ref,
            "decision": decision.decision.value,
            "reason_code": decision.reason_code,
            "reason": decision.reason,
            "evidence_snapshot_hash": decision.evidence_snapshot_hash,
            "policy_version": decision.policy_version,
            "required_approval_role": decision.required_approval_role,
            "evaluated_at": decision.evaluated_at.isoformat(),
            "proposed_by": proposal.proposed_by,
            "model_rationale_display_only": proposal.rationale,
            # Authorized mutation parameters, derived from TRUSTED_TOOL
            # evidence at decision time. The executor reads these rather than
            # accepting them from its caller.
            "parameters": parameters or {},
            "revoked": False,
        }
        (
            self._doc_ref(incident_id)
            .collection(DECISIONS)
            .document(decision.decision_id)
            .create(payload)
        )
        self.append_audit(
            incident_id,
            actor="policy",
            event="policy_decision",
            payload={
                "decision_id": decision.decision_id,
                "decision": decision.decision.value,
                "reason_code": decision.reason_code,
                "policy_version": decision.policy_version,
            },
            trace_id=trace_id,
        )
        return decision.decision_id

    def get_decision(self, incident_id: str, decision_id: str) -> dict[str, Any]:
        snapshot = (
            self._doc_ref(incident_id)
            .collection(DECISIONS)
            .document(decision_id)
            .get()
        )
        if not snapshot.exists:
            raise DecisionNotFound(f"{incident_id}/{decision_id}")
        return snapshot.to_dict()

    def record_action(self, incident_id: str, action: ActionRecord) -> None:
        (
            self._doc_ref(incident_id)
            .collection(ACTIONS)
            .document(action.action_id)
            .set(action.model_dump(mode="json"))
        )

    def actions(self, incident_id: str) -> list[dict[str, Any]]:
        return [
            doc.to_dict()
            for doc in self._doc_ref(incident_id).collection(ACTIONS).stream()
        ]

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
