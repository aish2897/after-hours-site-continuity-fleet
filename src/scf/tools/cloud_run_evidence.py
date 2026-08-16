"""Systems Investigator evidence tools.

Read-only. Every value returned is TRUSTED_TOOL evidence gathered through a
declared tool call under a scoped identity. Nothing here authorizes anything:
these functions describe the world, and the deterministic policy gate decides
what may be done about it.
"""

from __future__ import annotations

from typing import Any

import google.auth
import google.auth.transport.requests
import httpx

from scf import config
from scf.domain.enums import ActionType, TrustLevel
from scf.domain.models import Evidence, Proposal

RUN_API = "https://run.googleapis.com/v2"
AGENT = "systems"


def _access_token() -> str:
    credentials, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    credentials.refresh(google.auth.transport.requests.Request())
    return credentials.token


def _service_path(service: str) -> str:
    return (
        f"projects/{config.PROJECT_ID}"
        f"/locations/{config.CLOUD_RUN_REGION}/services/{service}"
    )


def describe_service(service: str) -> dict[str, Any]:
    response = httpx.get(
        f"{RUN_API}/{_service_path(service)}",
        headers={"Authorization": f"Bearer {_access_token()}"},
        timeout=30.0,
    )
    response.raise_for_status()
    return response.json()


def list_revisions(service: str) -> list[dict[str, Any]]:
    response = httpx.get(
        f"{RUN_API}/{_service_path(service)}/revisions",
        headers={"Authorization": f"Bearer {_access_token()}"},
        timeout=30.0,
    )
    response.raise_for_status()
    return response.json().get("revisions", [])


def probe_health(url: str) -> tuple[int, str]:
    try:
        response = httpx.get(url, timeout=20.0, follow_redirects=True)
        return response.status_code, response.text.strip()
    except httpx.HTTPError as exc:
        return 0, f"unreachable: {type(exc).__name__}"


def _ev(key: str, value: Any, supports: str) -> Evidence:
    return Evidence(
        key=key,
        value=value,
        supports=supports,
        source_agent=AGENT,
        trust_level=TrustLevel.TRUSTED_TOOL,
    )


KNOWN_GOOD_TAG = "known-good"


def gather_evidence(service: str = config.DISPATCH_WEB_SERVICE) -> list[Evidence]:
    """Collect real Cloud Run state as trusted evidence.

    The rollback candidate is NOT inferred from "some revision that is not
    currently active". It is the revision an operator has explicitly approved
    by attaching the `known-good` Cloud Run traffic tag, and the investigator
    independently probes that tag's own URL to prove it actually serves a
    healthy response before anything may be proposed.
    """
    described = describe_service(service)
    url = described.get("uri", "")
    etag = described.get("etag", "")
    traffic = described.get("trafficStatuses") or []

    active_revision = ""
    candidate_revision = ""
    candidate_url = ""
    for entry in traffic:
        revision = (entry.get("revision") or "").rsplit("/", 1)[-1]
        if entry.get("percent") == 100:
            active_revision = revision
        if entry.get("tag") == KNOWN_GOOD_TAG:
            candidate_revision = revision
            candidate_url = entry.get("uri") or ""

    status_code, body = probe_health(url)
    approved = bool(candidate_revision) and candidate_revision != active_revision

    candidate_status, candidate_body = (
        probe_health(candidate_url) if candidate_url else (0, "no known-good tag")
    )
    candidate_healthy = candidate_status == 200 and "healthy" in candidate_body.lower()

    return [
        _ev("service_exists", True, "target is a real Cloud Run service"),
        _ev("service_url", url, "where live health was probed"),
        _ev("service_etag", etag, "precondition token for safe mutation"),
        _ev("active_revision", active_revision, "revision currently serving traffic"),
        _ev("http_status", status_code, "observed health of the live service"),
        _ev("http_body", body[:200], "observed response body"),
        _ev("service_unhealthy", status_code != 200, "whether remediation is warranted"),
        _ev("candidate_revision", candidate_revision or None,
            "operator-approved rollback target, from the known-good tag"),
        _ev("candidate_revision_approved", approved,
            "tag present and distinct from the failing revision"),
        _ev("candidate_probe_url", candidate_url or None,
            "tag URL probed independently of live traffic"),
        _ev("candidate_probe_http_status", candidate_status,
            "candidate revision probed directly"),
        _ev("candidate_probe_healthy", candidate_healthy,
            "candidate proven healthy before being proposed"),
    ]


def propose_remediation(
    evidence: list[Evidence], service: str = config.DISPATCH_WEB_SERVICE
) -> Proposal | None:
    """Propose, never authorize.

    Returns a closed-enum proposal when the trusted evidence warrants it. The
    investigator holds no mutating permission, so this proposal is inert until
    the policy gate authorizes it and the scoped executor performs it.
    """
    facts = {item.key: item.value for item in evidence}
    if not facts.get("service_unhealthy"):
        return None
    # A rollback target must be approved AND independently proven healthy.
    # "Not currently active" is not evidence of anything.
    if not facts.get("candidate_revision_approved"):
        return None
    if not facts.get("candidate_probe_healthy"):
        return None

    return Proposal(
        action_type=ActionType.FLIP_TRAFFIC_TO_LAST_GOOD,
        target_ref=service,
        confidence=0.9,
        rationale=(
            f"{service} returned HTTP {facts.get('http_status')} on revision "
            f"{facts.get('active_revision')}. The approved known-good revision "
            f"{facts.get('candidate_revision')} was probed directly and returned "
            f"HTTP {facts.get('candidate_probe_http_status')}."
        ),
        proposed_by=f"agent:{AGENT}",
    )
