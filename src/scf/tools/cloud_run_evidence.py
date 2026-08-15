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


def gather_evidence(service: str = config.DISPATCH_WEB_SERVICE) -> list[Evidence]:
    """Collect real Cloud Run state as trusted evidence."""
    described = describe_service(service)
    url = described.get("uri", "")
    traffic = described.get("trafficStatuses") or described.get("traffic") or []
    active_revision = ""
    for entry in traffic:
        if entry.get("percent") == 100:
            active_revision = (entry.get("revision") or "").rsplit("/", 1)[-1]
            break

    revisions = [r["name"].rsplit("/", 1)[-1] for r in list_revisions(service)]
    known_good = [r for r in revisions if r != active_revision]

    status_code, body = probe_health(url)
    unhealthy = status_code != 200

    return [
        _ev("service_exists", True, "target is a real Cloud Run service"),
        _ev("service_url", url, "where health was probed"),
        _ev("active_revision", active_revision, "revision currently serving traffic"),
        _ev("available_revisions", revisions, "revisions that could receive traffic"),
        _ev("http_status", status_code, "observed health of the live service"),
        _ev("http_body", body[:200], "observed response body"),
        _ev("service_unhealthy", unhealthy, "whether remediation is warranted"),
        _ev(
            "last_good_revision_exists",
            bool(known_good),
            "whether a rollback target is available",
        ),
        _ev("last_good_revision", known_good[0] if known_good else None,
            "candidate rollback target"),
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
    if not facts.get("last_good_revision_exists"):
        return None

    return Proposal(
        action_type=ActionType.FLIP_TRAFFIC_TO_LAST_GOOD,
        target_ref=service,
        confidence=0.9,
        rationale=(
            f"{service} returned HTTP {facts.get('http_status')} on revision "
            f"{facts.get('active_revision')}; revision "
            f"{facts.get('last_good_revision')} is available to receive traffic."
        ),
        proposed_by=f"agent:{AGENT}",
    )
