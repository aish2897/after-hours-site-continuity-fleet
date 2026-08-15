from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4


class Decision(StrEnum):
    AUTO_ALLOWED = "AUTO_ALLOWED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    DENIED = "DENIED"


class IncidentStatus(StrEnum):
    OPEN = "OPEN"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    RESOLVED = "RESOLVED"
    ESCALATED = "ESCALATED"
    DENIED = "DENIED"


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class IncidentReport:
    site_id: str
    description: str
    reported_by: str = "site-supervisor"
    attachment_kind: str | None = None
    incident_id: str = field(default_factory=lambda: f"INC-{uuid4().hex[:8].upper()}")


@dataclass(frozen=True)
class Evidence:
    source_agent: str
    key: str
    value: Any
    supports: str


@dataclass(frozen=True)
class ActionRequest:
    action: str
    target: str
    target_type: str
    requested_by: str
    evidence_keys: tuple[str, ...]
    action_id: str = field(default_factory=lambda: f"ACT-{uuid4().hex[:8].upper()}")
    idempotency_key: str = field(default_factory=lambda: uuid4().hex)


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    reason: str
    required_approval_role: str | None = None


@dataclass
class AuditEvent:
    actor: str
    event: str
    details: dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class IncidentState:
    report: IncidentReport
    severity: Severity = Severity.HIGH
    status: IncidentStatus = IncidentStatus.OPEN
    evidence: list[Evidence] = field(default_factory=list)
    requested_action: ActionRequest | None = None
    policy_decision: PolicyDecision | None = None
    audit: list[AuditEvent] = field(default_factory=list)

    def add_evidence(self, evidence: Evidence) -> None:
        self.evidence.append(evidence)

    def add_audit(self, actor: str, event: str, **details: Any) -> None:
        self.audit.append(AuditEvent(actor=actor, event=event, details=details))

    def evidence_map(self) -> dict[str, Any]:
        return {item.key: item.value for item in self.evidence}

