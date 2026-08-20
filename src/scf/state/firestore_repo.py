from __future__ import annotations

from typing import Any


from google.cloud import firestore

from scf import config
from scf.audit.chain import seal
from scf.domain.ids import GENESIS_HASH
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
APPROVALS = "approvals"
AUDIT = "audit"
DECISIONS = "decisions"
ACTIONS = "actions"
EVIDENCE = "evidence"



class IncidentNotFound(KeyError):
    pass


class DecisionNotFound(KeyError):
    pass


class ApprovalNotFound(KeyError):
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
        payload["audit_seq"] = -1
        payload["audit_tail_hash"] = GENESIS_HASH
        self._doc_ref(incident.incident_id).create(payload)
        self.append_audit(
            incident.incident_id,
            actor="orchestrator",
            event="incident_received",
            payload={"site_id": incident.report.site_id, "status": incident.status},
            trace_id=incident.trace_id,
        )
        return incident.incident_id

    def _commit_audit(
        self,
        transaction: firestore.Transaction,
        incident_id: str,
        snapshot_data: dict[str, Any],
        *,
        actor: str,
        event: str,
        payload: dict[str, Any],
        actor_identity: str | None,
        trace_id: str | None,
        extra_updates: dict[str, Any] | None = None,
    ) -> AuditRecord:
        """Allocate the next audit slot and write it inside a transaction.

        The incident document carries `audit_seq` and `audit_tail_hash`, so the
        sequence is allocated from the same document the transaction already
        guards. Two concurrent appends contend on that document and Firestore
        retries the loser, so they cannot be handed the same sequence number.
        """
        doc_ref = self._doc_ref(incident_id)
        seq = int(snapshot_data.get("audit_seq", -1)) + 1
        prev_hash = snapshot_data.get("audit_tail_hash") or GENESIS_HASH

        record = seal(
            AuditRecord(
                seq=seq,
                prev_hash=prev_hash,
                actor=actor,
                actor_identity=actor_identity,
                event=event,
                payload=payload,
                trace_id=trace_id,
            )
        )

        updates: dict[str, Any] = {
            "audit_seq": seq,
            "audit_tail_hash": record.hash,
            "updated_at": firestore.SERVER_TIMESTAMP,
        }
        if extra_updates:
            updates.update(extra_updates)

        transaction.update(doc_ref, updates)
        transaction.create(
            doc_ref.collection(AUDIT).document(f"{seq:06d}"),
            record.model_dump(mode="json"),
        )
        return record

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
        doc_ref = self._doc_ref(incident_id)

        @firestore.transactional
        def _apply(transaction: firestore.Transaction) -> AuditRecord:
            snapshot = doc_ref.get(transaction=transaction)
            if not snapshot.exists:
                raise IncidentNotFound(incident_id)
            return self._commit_audit(
                transaction,
                incident_id,
                snapshot.to_dict(),
                actor=actor,
                event=event,
                payload=payload or {},
                actor_identity=actor_identity,
                trace_id=trace_id,
            )

        return _apply(self._db.transaction())

    def transition(
        self, incident_id: str, target: IncidentStatus, *, trace_id: str | None = None
    ) -> IncidentStatus:
        """Legal transition and its audit record, committed all-or-none.

        Previously the transition committed first and the audit record was
        appended afterwards, so a crash between them left authoritative state
        that the trail did not account for.
        """
        doc_ref = self._doc_ref(incident_id)

        @firestore.transactional
        def _apply(transaction: firestore.Transaction) -> IncidentStatus:
            snapshot = doc_ref.get(transaction=transaction)
            if not snapshot.exists:
                raise IncidentNotFound(incident_id)
            data = snapshot.to_dict()
            current = IncidentStatus(data["status"])
            assert_transition(current, target)
            self._commit_audit(
                transaction,
                incident_id,
                data,
                actor="orchestrator",
                event="state_transition",
                payload={"from": current.value, "to": target.value},
                actor_identity=None,
                trace_id=trace_id,
                extra_updates={"status": target.value},
            )
            return current

        return _apply(self._db.transaction())

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

    # --- human approval ------------------------------------------------------
    #
    # Approvals live in the AUTHORITATIVE database, alongside the decisions they
    # authorize and out of the executor's write reach. An approval is permission
    # for one exact persisted decision — bound by its authorization fingerprint,
    # which covers the incident, action, target, exact revision, policy version
    # and evidence snapshot. Change any of those and the fingerprint changes, so
    # the approval no longer applies to what is being attempted.

    def create_approval(
        self,
        *,
        approval_id: str,
        incident_id: str,
        decision_id: str,
        decision_fingerprint: str,
        action_type: str,
        target_ref: str,
        authorized_target_revision: str,
        required_approval_role: str | None,
        requested_at: str,
        expires_at: str,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        """Record a pending request for a human to authorize one decision."""
        payload = {
            "approval_id": approval_id,
            "incident_id": incident_id,
            "decision_id": decision_id,
            "decision_fingerprint": decision_fingerprint,
            "action_type": action_type,
            "target_ref": target_ref,
            "authorized_target_revision": authorized_target_revision,
            "required_approval_role": required_approval_role,
            "state": "PENDING",
            "requested_at": requested_at,
            "expires_at": expires_at,
            "decided_at": None,
            "approver_principal": None,
            "approval_version": 1,
            "trace_id": trace_id,
        }
        # `create`, not `set`: a colliding approval id must fail rather than
        # overwrite a decision somebody may already have acted on.
        self._db.collection(APPROVALS).document(approval_id).create(payload)
        self.append_audit(
            incident_id,
            actor="orchestrator",
            event="approval_requested",
            payload={
                "approval_id": approval_id,
                "decision_id": decision_id,
                "action_type": action_type,
                "required_approval_role": required_approval_role,
                "expires_at": expires_at,
            },
            trace_id=trace_id,
        )
        return payload

    def get_approval(self, approval_id: str) -> dict[str, Any]:
        snapshot = self._db.collection(APPROVALS).document(approval_id).get()
        if not snapshot.exists:
            raise ApprovalNotFound(approval_id)
        return snapshot.to_dict() or {}

    def decide_approval(
        self,
        approval_id: str,
        *,
        state: str,
        approver_principal: str,
        decided_at: str,
        now: str,
        trace_id: str | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """Transactionally record a human decision. Idempotent by construction.

        Returns (outcome, record) where outcome is one of DECIDED,
        ALREADY_DECIDED, EXPIRED or NOT_FOUND. A second delivery of the same
        approval is ALREADY_DECIDED and changes nothing — the human pressed the
        button once, and a retried request must not become a second permission.
        """
        ref = self._db.collection(APPROVALS).document(approval_id)
        transaction = self._db.transaction()

        @firestore.transactional
        def _apply(tx: firestore.Transaction) -> tuple[str, dict[str, Any]]:
            snapshot = ref.get(transaction=tx)
            if not snapshot.exists:
                return "NOT_FOUND", {}
            current = snapshot.to_dict() or {}
            if current.get("state") != "PENDING":
                return "ALREADY_DECIDED", current
            if str(current.get("expires_at") or "") <= now:
                expired = {"state": "EXPIRED", "decided_at": now}
                tx.update(ref, expired)
                return "EXPIRED", {**current, **expired}
            decided = {
                "state": state,
                "decided_at": decided_at,
                "approver_principal": approver_principal,
            }
            tx.update(ref, decided)
            return "DECIDED", {**current, **decided}

        return _apply(transaction)

    def record_screening(
        self, incident_id: str, screening: dict[str, Any], *, trace_id: str | None = None
    ) -> None:
        """Persist the screening verdict and audit it.

        Metadata only — verdict, filter names, region, template, version, a hash
        of what was screened. Never the raw text and never a matched value: the
        report is untrusted content that may itself carry sensitive data, and an
        evidence artifact that quotes it back has leaked it.

        This is recorded as a security observation, NOT as `Evidence`. It never
        reaches the policy gate, because a screening verdict authorizes nothing.
        """
        self._doc_ref(incident_id).update({"security_screening": screening})
        self.append_audit(
            incident_id,
            actor="model_armor",
            event="untrusted_content_screened",
            payload={
                "verdict": screening.get("verdict"),
                "allowed": screening.get("allowed"),
                "triggered_filters": screening.get("triggered_filters"),
                "findings": screening.get("findings"),
                "location": screening.get("model_armor_location"),
                "template": screening.get("model_armor_template"),
                "filter_version": screening.get("filter_version"),
                "content_sha256": screening.get("content_sha256"),
            },
            trace_id=trace_id,
        )

    def attach_approval_to_decision(
        self, incident_id: str, decision_id: str, approval_id: str
    ) -> None:
        """Record which approval was raised for this decision, on the decision.

        The executor holds `datastore.entities.get` and NOT `datastore.entities
        .list` — it can fetch a document by id and cannot run a query. That is
        the two-plane isolation working exactly as designed, and it is not
        something to widen for convenience: an identity that can enumerate the
        authoritative plane is a materially different identity.

        So the reference is written here, by the authoritative writer, into the
        document the executor already reads. The executor still verifies the
        approval's state and fingerprint for itself; it is being told where to
        look, not what to conclude.
        """
        (
            self._doc_ref(incident_id)
            .collection(DECISIONS)
            .document(decision_id)
            .update({"approval_id": approval_id})
        )

    def find_approval_for_decision(self, incident_id: str, decision_id: str) -> str:
        """The approval raised for one decision, or "" if there is none.

        A query rather than a stored pointer on the incident: the incident
        document is written by the workflow, and an approval must be findable
        from authoritative facts even if a process died before it could record
        a convenience reference anywhere.
        """
        matches = (
            self._db.collection(APPROVALS)
            .where(filter=firestore.FieldFilter("incident_id", "==", incident_id))
            .where(filter=firestore.FieldFilter("decision_id", "==", decision_id))
            .limit(2)
            .get()
        )
        found = [doc.to_dict() or {} for doc in matches]
        if not found:
            return ""
        return str(found[0].get("approval_id") or "")

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

    def save_escalation(
        self,
        incident_id: str,
        package: dict[str, Any],
        *,
        trace_id: str | None = None,
    ) -> None:
        """Persist the human handover alongside the incident.

        Written by an authoritative writer, never by the executor. It contains
        no model text, no credentials and no API detail — see
        `scf.domain.failures.EscalationPackage`.
        """
        self._doc_ref(incident_id).update(
            {"escalation": package, "updated_at": firestore.SERVER_TIMESTAMP}
        )
        self.append_audit(
            incident_id,
            actor="orchestrator",
            event="escalation_package",
            payload={
                "failure_category": package.get("failure_category"),
                "automation_changed_anything": package.get(
                    "automation_changed_anything"
                ),
                "operations_restored": package.get("operations_restored"),
            },
            trace_id=trace_id,
        )

    def latest_decision(self, incident_id: str) -> dict[str, Any] | None:
        """Most recently evaluated decision for an incident.

        Used only by reconciliation, so a recovery call names an incident and
        the orchestrator resolves the authorization itself. A caller still
        cannot nominate which decision gets executed.
        """
        decisions = [
            doc.to_dict()
            for doc in self._doc_ref(incident_id).collection(DECISIONS).stream()
        ]
        if not decisions:
            return None
        return max(decisions, key=lambda d: str(d.get("evaluated_at") or ""))

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
