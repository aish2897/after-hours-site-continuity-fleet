from __future__ import annotations

from enum import StrEnum


class Decision(StrEnum):
    AUTO_ALLOWED = "AUTO_ALLOWED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    DENIED = "DENIED"


class IncidentStatus(StrEnum):
    INTAKE = "INTAKE"
    INVESTIGATING = "INVESTIGATING"
    PROPOSED = "PROPOSED"
    POLICY_EVALUATED = "POLICY_EVALUATED"
    AUTO_ALLOWED = "AUTO_ALLOWED"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    APPROVED = "APPROVED"
    APPROVAL_DENIED = "APPROVAL_DENIED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    DENIED = "DENIED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    VERIFYING = "VERIFYING"
    REMEDIATION_FAILED = "REMEDIATION_FAILED"
    RESOLVED = "RESOLVED"
    ESCALATED = "ESCALATED"


class TrustLevel(StrEnum):
    """Evidence provenance. The Policy Gate may only read TRUSTED_TOOL."""

    TRUSTED_TOOL = "TRUSTED_TOOL"
    UNTRUSTED_INPUT = "UNTRUSTED_INPUT"


class ActionType(StrEnum):
    """Closed set of actions an LLM may propose.

    Dangerous members are deliberately proposable so that the deterministic
    Policy Gate is what refuses them, on the record, rather than the enum.
    """

    FLIP_TRAFFIC_TO_LAST_GOOD = "FLIP_TRAFFIC_TO_LAST_GOOD"
    #: The same Cloud Run traffic mutation, aimed somewhere nobody has blessed.
    #:
    #: Rolling back to a revision an operator tagged `known-good` is a low-risk,
    #: reversible move to a state that was deliberately approved in advance.
    #: Moving production traffic to a revision that merely *probes healthy* is a
    #: judgement call: nothing says it is the right version, only that it
    #: answers. Same primitive, same revision pinning, same OCC, same scoped
    #: identity — different authorization regime, and that difference comes from
    #: trusted evidence about the target, never from anything a caller says.
    SHIFT_TRAFFIC_TO_APPROVED_CANDIDATE = "SHIFT_TRAFFIC_TO_APPROVED_CANDIDATE"
    RESTART_APPLICATION_SERVICE = "RESTART_APPLICATION_SERVICE"
    RESTART_DATABASE_SERVICE = "RESTART_DATABASE_SERVICE"
    DISABLE_FIREWALL = "DISABLE_FIREWALL"
    EXPORT_CREDENTIALS = "EXPORT_CREDENTIALS"


class SpecialistName(StrEnum):
    """Specialists the orchestrator may route to. Closed set."""

    NETWORK = "network"
    SYSTEMS = "systems"
    SECURITY = "security"
    CONTINUITY = "continuity"


class ExecutionState(StrEnum):
    """Execution lifecycle in the execution plane.

    Firestore and the Cloud Run Admin API cannot be committed atomically, so
    this records where an execution reached. Recovery reconciles against real
    infrastructure rather than assuming a crashed execution did or did not act.

    `PRECONDITION_CHECKED` is written immediately before the Cloud Run snapshot
    is read. Because that write is ownership-bound, reaching it proves the
    worker still held the lease at that instant — a worker that has been fenced
    out cannot get past it and therefore never fetches a resourceVersion.
    """

    CLAIMED = "CLAIMED"
    PRECONDITION_CHECKED = "PRECONDITION_CHECKED"
    MUTATION_REQUESTED = "MUTATION_REQUESTED"
    MUTATED = "MUTATED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    STALE = "STALE"


class ActionState(StrEnum):
    PENDING = "PENDING"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    #: Issued, and the platform answered with something that is proof neither
    #: way. Distinct from FAILED on purpose: recording a failure nobody
    #: observed is the same overclaim at the action level that terminal FAILED
    #: was at the execution level.
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    DUPLICATE_SUPPRESSED = "DUPLICATE_SUPPRESSED"


class ApprovalState(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
