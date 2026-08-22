"""Continuity Coordinator — what the duty manager is actually told.

Deterministic. Every sentence below is assembled from incident state and trusted
evidence by ordinary code; no model output reaches this service, and it does not
call one. That is deliberate and it is the point: the person reading this is
making a decision about their site, and the text they read should be derivable
from the record rather than generated fresh each time.

It holds no mutation capability, no policy authority and no Firestore write. It
reads what happened and says it in plain words.

What it will not do:

* invent a diagnosis. If the evidence does not say which layer failed, the
  message says that, rather than picking the likeliest-sounding one.
* expose reasoning. No chain-of-thought, no model rationale, no internal
  identifiers in the default view.
* speak in infrastructure. "The dispatch application is not responding" is
  something a warehouse manager can act on; "revision dispatch-web-00004-jqm is
  serving 503" is not.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, Header
from pydantic import BaseModel, ConfigDict, Field

from scf import faults
from scf.obs import log_event, trace_id_from_header

app = FastAPI(title="SCF Continuity Coordinator", version="0.1.0")


class ContinuityRequest(BaseModel):
    """Structured incident state. Never raw manager text, never model output."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=3)
    status: str = ""
    specialists_consulted: list[str] = Field(default_factory=list)
    #: Trusted findings only, already filtered by the orchestrator.
    network_reachable: bool | None = None
    service_responding: bool | None = None
    identity_posture_sound: bool | None = None
    remediation_state: str = ""
    awaiting_human: bool = False
    changed_anything: bool | None = None


def _what_we_found(request: ContinuityRequest) -> list[str]:
    """One plain sentence per thing actually established. No inference."""
    found: list[str] = []
    if request.network_reachable is True:
        # Say what was actually observed, and from where.
        #
        # The earlier wording — "the site network is reachable, the connection
        # to the dispatch service is fine" — was accepted in Director testing as
        # misleading, and it was. The check is a DNS lookup plus a TCP and TLS
        # connection made by an agent running in Google Cloud, at one instant.
        # It says the dispatch service answered that agent. It says nothing
        # about the warehouse's own Wi-Fi, nothing about the link between the
        # site and the internet, and nothing about five minutes ago.
        #
        # For a manager reporting scanners dropping out in the loading bay, the
        # old sentence read as "your Wi-Fi is fine" — advice the system has no
        # evidence for and cannot get without Wi-Fi telemetry it does not have.
        found.append(
            "The dispatch service is reachable from our network check. We do "
            "not yet have direct evidence of the Wi-Fi or network equipment at "
            "your site."
        )
    elif request.network_reachable is False:
        found.append(
            "Our network check could not reach the dispatch service at all."
        )

    if request.service_responding is False:
        found.append("The dispatch application itself is not responding correctly.")
    elif request.service_responding is True:
        found.append("The dispatch application is responding normally.")

    if request.identity_posture_sound is False:
        found.append("The sign-in settings for the dispatch service need a person to look at them.")
    elif request.identity_posture_sound is True:
        found.append("Sign-in and access settings for the dispatch service look correct.")

    if not found:
        # The honest answer when nothing was established. Naming a likely cause
        # here would be inventing a diagnosis, which is the one thing this
        # service must never do.
        found.append(
            "We could not establish what has failed. No checks returned a "
            "trustworthy answer."
        )
    return found


def _what_happens_next(request: ContinuityRequest) -> str:
    if request.awaiting_human:
        return (
            "A recovery has been prepared and needs your approval before "
            "anything changes."
        )
    state = (request.remediation_state or "").upper()
    if state == "RESOLVED":
        return "The service has been restored and independently confirmed."
    if request.changed_anything is None:
        return (
            "A repair was sent but we could not confirm whether it took effect. "
            "It is being re-checked before anything is reported as done."
        )
    if request.changed_anything is False:
        return (
            "Nothing on your site has been changed. The details have been "
            "prepared for a technical responder."
        )
    return "A change was made and is being confirmed."


@app.get("/health")
def health() -> dict[str, Any]:
    body = {
        "ok": True,
        "service": "scf-agent-continuity",
        "role": "continuity_coordinator",
        "read_only": True,
        "may_propose_actions": False,
        "llm_backed": False,
        "revision": os.environ.get("K_REVISION"),
        "fault_mode": faults.active() or None,
    }
    return faults.banner(body) if faults.enabled() else body


@app.post("/status")
async def status(
    request: ContinuityRequest,
    x_cloud_trace_context: str | None = Header(default=None),
) -> dict[str, Any]:
    """The manager-facing account of one incident."""
    trace_id = trace_id_from_header(x_cloud_trace_context)
    found = _what_we_found(request)
    message = {
        "incident_id": request.incident_id,
        "headline": (
            "Your dispatch service has been restored."
            if (request.remediation_state or "").upper() == "RESOLVED"
            else "We are working on your dispatch service."
        ),
        "what_we_found": found,
        "what_happens_next": _what_happens_next(request),
        "who_checked": [
            {"systems": "the dispatch application",
             "network": "the site's network and connection",
             "security": "sign-in and access settings"}.get(name, name)
            for name in request.specialists_consulted
        ],
        # Kept out of the default view. A duty manager should never need it, and
        # a technical responder should never have to go hunting for it.
        "reference": request.incident_id,
    }
    log_event(
        "continuity_status_composed",
        trace_id=trace_id,
        incident_id=request.incident_id,
        specialists=request.specialists_consulted,
        findings=len(found),
        served_by_revision=os.environ.get("K_REVISION"),
    )
    return message
