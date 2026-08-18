"""Systems Investigator runtime. Read-only.

Runs as sa-agent-systems, which holds run.viewer on dispatch-web and nothing
else. It cannot write Firestore, cannot authorize, and cannot execute. It
gathers evidence and may propose from the closed enum; the proposal is inert
until the deterministic policy gate authorizes it.

Work here is bounded. An investigator that loops — retrying a tool call,
chasing an ambiguous signal, or simply never converging — must not be able to
hold an outage open indefinitely. It gets a fixed number of tool calls and a
wall-clock deadline, and when it exhausts either it returns a truthful
budget-exhausted contract rather than partial evidence dressed up as complete.
"""

from __future__ import annotations

import os
import time
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from scf import config, faults
from scf.domain.enums import ActionType
from scf.domain.models import Evidence, Proposal
from scf.obs import log_event, trace_id_from_header
from scf.tools.cloud_run_evidence import (  # noqa: F401
    GATHER_EVIDENCE_WORST_CASE_SECONDS,
)
from scf.tools.cloud_run_evidence import gather_evidence, propose_remediation

app = FastAPI(title="SCF Systems Investigator", version="0.5.0")

#: Bounded work. Both limits are deliberately small: this investigator makes
#: four real Cloud Run/HTTP calls on the healthy path, so anything approaching
#: these numbers is a loop, not thoroughness.
#:
#: The deadline is a real ceiling rather than a between-steps check: every
#: network call charges the budget, and each carries a 10s client timeout, so
#: the worst case is the deadline plus at most one call.
MAX_TOOL_CALLS = int(os.environ.get("SCF_INVESTIGATOR_MAX_TOOL_CALLS", "12"))
#: Derived from what the work actually costs, plus headroom. A fixed 30s sat
#: BELOW the 43s worst case of the calls it charged for, and only the unhealthy
#: branch paid the extra — so the budget was tightest at exactly the moment the
#: service was down, and a remediable outage was escalated as
#: WORKER_BUDGET_EXCEEDED, which is terminal. One second slower than a clean
#: rollback meant no rollback at all.
WORK_DEADLINE_SECONDS = float(
    os.environ.get(
        "SCF_INVESTIGATOR_DEADLINE_SECONDS",
        str(GATHER_EVIDENCE_WORST_CASE_SECONDS + 5.0),
    )
)

BUDGET_EXCEEDED = "WORKER_BUDGET_EXCEEDED"


class EvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=3)
    service: str = config.DISPATCH_WEB_SERVICE


class WorkBudget:
    """A step and time budget the worker must ask permission from.

    Deterministic termination, not best-effort: `spend()` raises the moment
    either limit is passed, so no code path can quietly continue past it.
    """

    def __init__(
        self,
        max_calls: int = MAX_TOOL_CALLS,
        deadline_seconds: float = WORK_DEADLINE_SECONDS,
    ) -> None:
        self.max_calls = max_calls
        self.deadline_seconds = deadline_seconds
        self.calls = 0
        self._started = time.monotonic()

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._started

    def spend(self, what: str) -> None:
        """Charge a step. Raises if either limit is already passed."""
        self.calls += 1
        if self.calls > self.max_calls:
            raise BudgetExhausted("tool_calls", self.calls, self.max_calls, what)
        self.check(what)

    def check(self, what: str) -> None:
        """Re-check the clock. Called AFTER each step as well as before it.

        Checking only on the way in bounds the work between steps, not the step
        itself: a single call could then run long and the budget would not
        notice until the next one. Each underlying HTTP call carries its own
        timeout, so the real bound is the deadline plus at most one step.
        """
        if self.elapsed > self.deadline_seconds:
            raise BudgetExhausted(
                "deadline_seconds", round(self.elapsed, 1), self.deadline_seconds, what
            )


class BudgetExhausted(RuntimeError):
    def __init__(self, limit: str, used: float, allowed: float, during: str) -> None:
        super().__init__(f"{limit} exhausted: {used} > {allowed} during {during}")
        self.limit = limit
        self.used = used
        self.allowed = allowed
        self.during = during


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "scf-agent-systems",
        "role": "investigator",
        "read_only": True,
        "revision": os.environ.get("K_REVISION"),
        "max_tool_calls": MAX_TOOL_CALLS,
        "work_deadline_seconds": WORK_DEADLINE_SECONDS,
        **faults.banner(),
    }


def _investigate(service: str, budget: WorkBudget) -> tuple[list[Evidence], Proposal | None]:
    """The real work, every step of it charged to the budget."""
    if faults.is_mode(faults.INVESTIGATOR_LOOP):
        # A worker that will not converge. It is the budget that stops it, not
        # the loop noticing anything — which is the point of the test.
        while True:
            budget.spend("runaway_evidence_pass")
            gather_evidence(service, charge=budget.spend)
            budget.check("runaway_evidence_pass")

    # Each network call inside gather_evidence charges the budget itself, so
    # the deadline bounds the work rather than the gaps between steps.
    evidence = gather_evidence(service, charge=budget.spend)
    budget.check("gather_evidence")
    budget.spend("propose_remediation")
    proposal = propose_remediation(evidence, service)
    budget.check("propose_remediation")
    return evidence, proposal


def _inject_proposal(evidence: list[Evidence]) -> dict[str, Any] | None:
    """TEST ONLY. Model-equivalent proposals the gate must refuse."""
    if faults.is_mode(faults.INVESTIGATOR_DANGEROUS_PROPOSAL):
        # In the closed enum, so it parses — and is then refused on the record
        # by the deterministic gate, which is exactly the design.
        return Proposal(
            action_type=ActionType.EXPORT_CREDENTIALS,
            target_ref=config.DISPATCH_WEB_SERVICE,
            confidence=0.99,
            rationale="FAULT INJECTION: hallucinated privileged action.",
            proposed_by="agent:systems",
        ).model_dump(mode="json")
    if faults.is_mode(faults.INVESTIGATOR_UNKNOWN_ACTION):
        # NOT in the closed enum. The typed contract must reject it outright.
        return {
            "action_type": "DELETE_DATABASE",
            "target_ref": config.DISPATCH_WEB_SERVICE,
            "confidence": 0.99,
            "rationale": "FAULT INJECTION: action outside the closed enum.",
            "proposed_by": "agent:systems",
        }
    return None


@app.post("/evidence")
async def collect_evidence(
    request: EvidenceRequest,
    x_cloud_trace_context: str | None = Header(default=None),
) -> dict[str, Any]:
    trace_id = trace_id_from_header(x_cloud_trace_context)
    log_event(
        "investigator_invoked",
        trace_id=trace_id,
        incident_id=request.incident_id,
        service=request.service,
        agent="systems",
        fault_mode=faults.active() or None,
    )

    if faults.is_mode(faults.INVESTIGATOR_HANG):
        log_event("fault_injection", severity="WARNING", trace_id=trace_id,
                  incident_id=request.incident_id, label=faults.LABEL,
                  fault_mode=faults.active())
        await run_in_threadpool(faults.hang)
    if faults.is_mode(faults.INVESTIGATOR_5XX):
        log_event("fault_injection", severity="WARNING", trace_id=trace_id,
                  incident_id=request.incident_id, label=faults.LABEL,
                  fault_mode=faults.active())
        raise HTTPException(status_code=503, detail="FAULT INJECTION: investigator down")

    budget = WorkBudget()
    try:
        evidence, proposal = await run_in_threadpool(_investigate, request.service, budget)
    except BudgetExhausted as exhausted:
        log_event(
            "investigator_budget_exceeded",
            severity="ERROR",
            trace_id=trace_id,
            incident_id=request.incident_id,
            limit=exhausted.limit,
            used=exhausted.used,
            allowed=exhausted.allowed,
            during=exhausted.during,
            tool_calls=budget.calls,
        )
        # A truthful terminal contract, not partial evidence dressed as whole.
        return {
            "incident_id": request.incident_id,
            "agent": "systems",
            "evidence": [],
            "proposal": None,
            "budget_exceeded": True,
            "failure_category": BUDGET_EXCEEDED,
            "limit": exhausted.limit,
            "tool_calls": budget.calls,
            "trace_id": trace_id,
            "served_by_revision": os.environ.get("K_REVISION"),
        }

    payload: dict[str, Any] = {
        "incident_id": request.incident_id,
        "agent": "systems",
        "evidence": [item.model_dump(mode="json") for item in evidence],
        "proposal": proposal.model_dump(mode="json") if proposal else None,
        "tool_calls": budget.calls,
        "trace_id": trace_id,
        "served_by_revision": os.environ.get("K_REVISION"),
    }

    injected = _inject_proposal(evidence)
    if injected is not None:
        log_event("fault_injection", severity="WARNING", trace_id=trace_id,
                  incident_id=request.incident_id, label=faults.LABEL,
                  fault_mode=faults.active())
        payload["proposal"] = injected
    if faults.is_mode(faults.INVESTIGATOR_MALFORMED):
        log_event("fault_injection", severity="WARNING", trace_id=trace_id,
                  incident_id=request.incident_id, label=faults.LABEL,
                  fault_mode=faults.active())
        # Authenticated, 200 OK, structurally plausible, semantically invalid:
        # an unknown trust level, which must never be coerced to TRUSTED_TOOL.
        payload["evidence"] = [
            {
                "key": "service_unhealthy",
                "value": True,
                "supports": "FAULT INJECTION",
                "source_agent": "systems",
                "trust_level": "TOTALLY_TRUSTED",
            }
        ]

    if faults.is_mode(faults.INVESTIGATOR_TRUTHY_BUDGET_STRING):
        log_event("fault_injection", severity="WARNING", trace_id=trace_id,
                  incident_id=request.incident_id, label=faults.LABEL,
                  fault_mode=faults.active())
        # A complete, usable investigation carrying a *string* where a boolean
        # was declared. `"false"` is non-empty and therefore truthy: read with
        # `.get()` the caller would have thrown this whole investigation away
        # as budget exhaustion and escalated an incident it could have fixed.
        payload["budget_exceeded"] = "false"
    if faults.is_mode(faults.INVESTIGATOR_EMPTY_PROPOSAL):
        log_event("fault_injection", severity="WARNING", trace_id=trace_id,
                  incident_id=request.incident_id, label=faults.LABEL,
                  fault_mode=faults.active())
        # `{}` is falsy but it is not the same statement as `null`. Absent means
        # "no remediation is warranted"; empty means the worker broke its own
        # contract, and the manager must be told which of the two happened.
        payload["proposal"] = {}

    log_event(
        "investigator_evidence_collected",
        trace_id=trace_id,
        incident_id=request.incident_id,
        evidence_count=len(payload["evidence"]),
        proposed=(payload["proposal"] or {}).get("action_type"),
        tool_calls=budget.calls,
        fault_mode=faults.active() or None,
    )
    return payload
