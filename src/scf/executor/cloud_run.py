"""The only code in this project that mutates infrastructure.

Runs exclusively under sa-executor, whose scfRemediator role is bound to the
dispatch-web service resource alone. Any other target is refused by Google
IAM, not by a check in this file.
"""

from __future__ import annotations


from typing import Any

import google.auth
import google.auth.transport.requests
import httpx

from scf import config

RUN_API = "https://run.googleapis.com/v2"


def _token() -> str:
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


def flip_traffic_to_revision(service: str, revision: str) -> dict[str, Any]:
    """Migrate 100% of traffic to a named revision. Real Cloud Run Admin API."""
    headers = {"Authorization": f"Bearer {_token()}"}
    # The v2 API expects a bare revision name here, not a full resource path.
    # A path is rejected with INVALID_ARGUMENT "Expected a revision prefixed
    # with '<service>-'".
    body = {
        "traffic": [
            {
                "type": "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",
                "revision": revision.rsplit("/", 1)[-1],
                "percent": 100,
            }
        ]
    }
    response = httpx.patch(
        f"{RUN_API}/{_service_path(service)}",
        params={"updateMask": "traffic"},
        headers=headers,
        json=body,
        timeout=60.0,
    )
    if response.status_code >= 400:
        return {
            "accepted": False,
            "http_status": response.status_code,
            "error": response.text[:400],
            "service": service,
            "revision": revision,
        }

    # The executor deliberately does NOT poll the operation to declare victory.
    # Two reasons, one architectural and one practical:
    #   1. The component that acts must not grade its own work. Recovery is
    #      established by the independent verifier observing the live service
    #      under a different, read-only identity.
    #   2. A Cloud Run operation is a distinct resource from the service, so a
    #      service-scoped role cannot read it. Polling would have required a
    #      broader project-level grant to learn something the verifier already
    #      establishes more convincingly.
    return {
        "accepted": True,
        "http_status": response.status_code,
        "operation": response.json().get("name", ""),
        "service": service,
        "revision": revision,
    }
