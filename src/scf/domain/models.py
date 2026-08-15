from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from scf.domain.enums import (
    ActionState,
    ActionType,
    ApprovalState,
    Decision,
    IncidentStatus,
    Severity,
    SpecialistName,
    TrustLevel,
)
from scf.domain.ids import (
    GENESIS_HASH,
    SCHEMA_VERSION,
    canonical_hash,
    new_action_id,
    new_decision_id,
    new_incident_id,
    utc_now,
)


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Mutable(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IncidentReport(Frozen):
    site_id: str
    description: str
    reported_by: str = "site-supervisor"
    attachment_kind: str | None = None
    received_at: datetime = Field(default_factory=utc_now)


class Evidence(Frozen):
    """A single observation. trust_level decides whether policy may read it."""

    key: str
    value: Any
    supports: str
    source_agent: str
    trust_level: TrustLevel
    tool_call_id: str | None = None
    collected_at: datetime = Field(default_factory=utc_now)

    def content_hash(self) -> str:
        return canonical_hash(
            {
                "key": self.key,
                "value": self.value,
                "source_agent": self.source_agent,
                "trust_level": str(self.trust_level),
            }
        )


class Proposal(Frozen):
    """Constrained LLM output. The only model-authored artifact in the system.

    rationale is display-only and is never read by the Policy Gate.
    """

    action_type: ActionType
    target_ref: str
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""
    proposed_by: str = "agent:systems"
    model_id: str | None = None
    prompt_hash: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class SpecialistRoute(Frozen):
    specialist: SpecialistName
    required: bool
    why: str = Field(min_length=1)


class RoutingDecision(Frozen):
    """Constrained orchestrator output for evidence-dependent delegation.

    Every specialist must be explicitly reasoned about, so declining to invoke
    one is a recorded decision rather than an omission. Fan-out to all
    specialists is possible but never automatic.
    """

    routes: list[SpecialistRoute] = Field(min_length=1)
    summary: str = ""
    model_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("routes")
    @classmethod
    def _no_duplicate_specialists(
        cls, routes: list[SpecialistRoute]
    ) -> list[SpecialistRoute]:
        seen = [route.specialist for route in routes]
        if len(set(seen)) != len(seen):
            raise ValueError("duplicate specialist in routing decision")
        return routes

    def required_specialists(self) -> list[SpecialistName]:
        return [route.specialist for route in self.routes if route.required]


class PolicyDecision(Frozen):
    decision: Decision
    reason_code: str
    reason: str
    policy_version: str
    evidence_snapshot_hash: str
    required_approval_role: str | None = None
    decision_id: str = Field(default_factory=new_decision_id)
    evaluated_at: datetime = Field(default_factory=utc_now)


class ActionRecord(Mutable):
    decision_id: str
    action_type: ActionType
    target_ref: str
    idempotency_key: str
    action_id: str = Field(default_factory=new_action_id)
    state: ActionState = ActionState.PENDING
    attempt_intent: int = 1
    executor_identity: str | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class ApprovalRecord(Mutable):
    approval_id: str
    incident_id: str
    decision_id: str
    required_role: str
    token_hash: str
    expires_at: datetime
    state: ApprovalState = ApprovalState.PENDING
    approver_identity: str | None = None
    decided_at: datetime | None = None


class AuditRecord(Frozen):
    seq: int
    actor: str
    event: str
    payload: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = GENESIS_HASH
    hash: str = ""
    actor_identity: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    timestamp: datetime = Field(default_factory=utc_now)


class Lease(Frozen):
    owner: str
    expires_at: datetime


class IncidentDoc(Mutable):
    report: IncidentReport
    incident_id: str = Field(default_factory=new_incident_id)
    schema_version: str = SCHEMA_VERSION
    status: IncidentStatus = IncidentStatus.INTAKE
    severity: Severity = Severity.HIGH
    trace_id: str | None = None
    current_step: str = "intake"
    step_budget_remaining: int = 12
    deadline_at: datetime | None = None
    lease: Lease | None = None
    untrusted_content_flags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
