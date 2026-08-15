"""Domain layer: enums, schemas, identifiers, and the incident state machine.

Pure and dependency-free apart from pydantic. No cloud, no I/O, no LLM.
"""

from scf.domain.enums import (
    ActionState,
    ActionType,
    ApprovalState,
    Decision,
    IncidentStatus,
    Severity,
    TrustLevel,
)
from scf.domain.ids import (
    GENESIS_HASH,
    SCHEMA_VERSION,
    canonical_hash,
    canonical_json,
    chain_hash,
    derive_idempotency_key,
    new_action_id,
    new_decision_id,
    new_incident_id,
    utc_now,
)
from scf.domain.models import (
    ActionRecord,
    ApprovalRecord,
    AuditRecord,
    Evidence,
    IncidentDoc,
    IncidentReport,
    Lease,
    PolicyDecision,
    Proposal,
)
from scf.domain.state_machine import (
    LEGAL_TRANSITIONS,
    TERMINAL_STATES,
    IllegalTransition,
    assert_transition,
    can_transition,
    is_terminal,
)

__all__ = [
    "GENESIS_HASH",
    "LEGAL_TRANSITIONS",
    "SCHEMA_VERSION",
    "TERMINAL_STATES",
    "ActionRecord",
    "ActionState",
    "ActionType",
    "ApprovalRecord",
    "ApprovalState",
    "AuditRecord",
    "Decision",
    "Evidence",
    "IllegalTransition",
    "IncidentDoc",
    "IncidentReport",
    "IncidentStatus",
    "Lease",
    "PolicyDecision",
    "Proposal",
    "Severity",
    "TrustLevel",
    "assert_transition",
    "can_transition",
    "canonical_hash",
    "canonical_json",
    "chain_hash",
    "derive_idempotency_key",
    "is_terminal",
    "new_action_id",
    "new_decision_id",
    "new_incident_id",
    "utc_now",
]
