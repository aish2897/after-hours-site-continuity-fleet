"""Independent verification runtime. Read-only.

Runs as sa-verifier, a different identity from the executor, so the component
that acts is never the component that grades its own work. It returns a
verdict; it does not transition state and holds no mutation rights.
"""

from __future__ import annotations

import os
import time
from typing import Any

from fastapi import FastAPI, Header
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from scf import config
from scf.obs import log_event, trace_id_from_header
from scf.tools.cloud_run_evidence import describe_service, probe_health

app = FastAPI(title="SCF Verifier", version="0.4.0")

RECOVERED = "RECOVERED"
STILL_FAILING = "STILL_FAILING"
SETTLE_SECONDS = int(os.environ.get("SCF_VERIFY_SETTLE_SECONDS", "75"))


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=3)
    service: str = config.DISPATCH_WEB_SERVICE


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "scf-verifier",
        "role": "verifier",
        "read_only": True,
        "revision": os.environ.get("K_REVISION"),
    }


def _observe(service: str) -> dict[str, Any]:
    described = describe_service(service)
    url = described.get("uri", "")
    active = ""
    for entry in described.get("trafficStatuses") or []:
        if entry.get("percent") == 100:
            active = (entry.get("revision") or "").rsplit("/", 1)[-1]
            break

    status_code, body = probe_health(url)
    return {
        "healthy": status_code == 200 and "healthy" in body.lower(),
        "http_status": status_code,
        "body": body[:120],
        "active_revision": active,
        "service_url": url,
    }


def _verify(
    service: str, settle_seconds: int = SETTLE_SECONDS, interval: float = 3.0
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
    observation = _observe(service)
    while not observation["healthy"] and time.monotonic() < deadline:
        time.sleep(interval)
        attempts += 1
        observation = _observe(service)

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
    result = await run_in_threadpool(_verify, request.service)
    log_event(
        "verification_completed",
        trace_id=trace_id,
        incident_id=request.incident_id,
        verdict=result["verdict"],
        http_status=result["http_status"],
        active_revision=result["active_revision"],
    )
    result["incident_id"] = request.incident_id
    result["verified_by_revision"] = os.environ.get("K_REVISION")
    result["trace_id"] = trace_id
    return result
