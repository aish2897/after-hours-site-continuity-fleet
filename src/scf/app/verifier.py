"""Independent verification runtime. Read-only.

Runs as sa-verifier, a different identity from the executor, so the component
that acts is never the component that grades its own work. It returns a
verdict; it does not transition state and holds no mutation rights.
"""

from __future__ import annotations

import os
import time
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from scf import config, faults
from scf.obs import log_event, trace_id_from_header
from scf.tools.cloud_run_evidence import (
    describe_service,
    probe_health,
    serves_exclusively,
    traffic_allocation,
)

app = FastAPI(title="SCF Verifier", version="0.4.0")

RECOVERED = "RECOVERED"
STILL_FAILING = "STILL_FAILING"
SETTLE_SECONDS = int(os.environ.get("SCF_VERIFY_SETTLE_SECONDS", "75"))


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=3)
    service: str = config.DISPATCH_WEB_SERVICE
    expected_revision: str | None = Field(
        default=None,
        description="The exact revision the decision authorized. HTTP 200 from "
        "the wrong revision must not resolve an incident.",
    )


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "scf-verifier",
        "role": "verifier",
        "read_only": True,
        "revision": os.environ.get("K_REVISION"),
        **faults.banner(),
    }


def _observe(service: str, expected_revision: str | None = None) -> dict[str, Any]:
    """Three independent conditions, all required.

    The authorized action is a 100% traffic flip, so the expected allocation is
    exactly 100% to the authorized revision and nothing to anything else. A
    healthy response is not recovery on its own — 200 from an unauthorized
    revision is simply a different service state that happens to answer — and
    neither is the right revision merely appearing in the traffic list. A 90/10
    or 50/50 split, or the correct revision with unexpected secondary traffic,
    is not the authorized outcome and must not resolve an incident.
    """
    described = describe_service(service)
    url = described.get("uri", "")
    allocation = traffic_allocation(described)
    active = next((rev for rev, pct in allocation.items() if pct == 100), "")

    status_code, body = probe_health(url)
    responding = status_code == 200 and "healthy" in body.lower()
    revision_matches = expected_revision is None or active == expected_revision
    allocation_exclusive = (
        serves_exclusively(described, expected_revision)
        if expected_revision
        else allocation in ({}, {active: 100})
    )
    return {
        "healthy": responding and revision_matches and allocation_exclusive,
        "http_healthy": responding,
        "revision_matches_authorized": revision_matches,
        "traffic_allocation_exclusive": allocation_exclusive,
        "traffic_allocation": allocation,
        "expected_revision": expected_revision,
        "http_status": status_code,
        "body": body[:120],
        "active_revision": active,
        "service_url": url,
    }


def _verify(
    service: str,
    expected_revision: str | None = None,
    settle_seconds: int = SETTLE_SECONDS,
    interval: float = 3.0,
) -> dict[str, Any]:
    """Observe the live service until it recovers or the window expires.

    A Cloud Run traffic migration is asynchronous: the Admin API accepts the
    change before the frontend has finished shifting requests. Declaring
    STILL_FAILING on the first probe would report a race, not an outcome. The
    verifier therefore polls read-only for a bounded window. It never mutates
    and never retries the remediation.
    """
    deadline = time.monotonic() + settle_seconds
    attempts = 0
    observation = _observe(service, expected_revision)
    while not observation["healthy"] and time.monotonic() < deadline:
        time.sleep(interval)
        attempts += 1
        observation = _observe(service, expected_revision)

    observation["verdict"] = RECOVERED if observation.pop("healthy") else STILL_FAILING
    observation["probe_attempts"] = attempts + 1
    observation["settle_window_seconds"] = settle_seconds
    return observation


@app.post("/verify")
async def verify(
    request: VerifyRequest,
    x_cloud_trace_context: str | None = Header(default=None),
) -> dict[str, Any]:
    trace_id = trace_id_from_header(x_cloud_trace_context)

    if faults.is_mode(faults.VERIFIER_5XX):
        log_event("fault_injection", severity="WARNING", trace_id=trace_id,
                  incident_id=request.incident_id, label=faults.LABEL,
                  fault_mode=faults.active())
        raise HTTPException(status_code=503, detail="FAULT INJECTION: verifier down")

    result = await run_in_threadpool(
        _verify, request.service, request.expected_revision
    )

    if faults.is_mode(faults.VERIFIER_MALFORMED):
        # Authenticated, 200 OK, and semantically useless: the verdict is not a
        # member of the contract. The caller must not read it as recovery.
        log_event("fault_injection", severity="WARNING", trace_id=trace_id,
                  incident_id=request.incident_id, label=faults.LABEL,
                  fault_mode=faults.active())
        result["verdict"] = "PROBABLY_FINE"
    log_event(
        "verification_completed",
        trace_id=trace_id,
        incident_id=request.incident_id,
        verdict=result["verdict"],
        http_status=result["http_status"],
        active_revision=result["active_revision"],
        expected_revision=request.expected_revision,
        revision_matches_authorized=result["revision_matches_authorized"],
        traffic_allocation_exclusive=result["traffic_allocation_exclusive"],
    )
    result["incident_id"] = request.incident_id
    result["verified_by_revision"] = os.environ.get("K_REVISION")
    result["trace_id"] = trace_id
    return result
