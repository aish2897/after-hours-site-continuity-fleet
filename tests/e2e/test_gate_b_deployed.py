"""Gate B proof against the deployed Cloud Run service.

Skipped unless SCF_DEPLOYED_URL is set. Requires an identity token:

    $env:SCF_DEPLOYED_URL="https://scf-orchestrator-booyfgej7a-ts.a.run.app"
    $env:SCF_ID_TOKEN=(gcloud auth print-identity-token)
    .\\.venv\\Scripts\\python.exe -m pytest tests/e2e/test_gate_b_deployed.py

Costs real tokens and writes to real Firestore.
"""

from __future__ import annotations

import os

import pytest

URL = os.environ.get("SCF_DEPLOYED_URL")
TOKEN = os.environ.get("SCF_ID_TOKEN")

pytestmark = pytest.mark.skipif(
    not URL or not TOKEN,
    reason="set SCF_DEPLOYED_URL and SCF_ID_TOKEN to run deployed Gate B tests",
)

APPLICATION_SYMPTOM = (
    "The dispatch screens are showing an error page. Phones and Wi-Fi seem fine."
)
NETWORK_SYMPTOM = (
    "Nothing at the site can reach our internal services, and staff say Wi-Fi "
    "devices have also lost connectivity."
)

ALL_SPECIALISTS = {"network", "systems", "security", "continuity"}


def _client():
    import httpx

    return httpx.Client(
        base_url=URL, headers={"Authorization": f"Bearer {TOKEN}"}, timeout=120.0
    )


def _create(client, description: str) -> dict:
    response = client.post("/incidents", json={"description": description})
    assert response.status_code == 201, response.text
    return response.json()


def test_health_reports_deployed_configuration():
    with _client() as client:
        body = client.get("/health").json()
    assert body["ok"] is True
    assert body["core_region"] == "australia-southeast1"
    assert body["model_location"] == "global"
    assert body["revision"], "K_REVISION missing: not running on Cloud Run"


def test_routing_is_evidence_dependent_not_fixed_fan_out():
    with _client() as client:
        application = _create(client, APPLICATION_SYMPTOM)
        network = _create(client, NETWORK_SYMPTOM)

    app_required = set(application["required_specialists"])
    net_required = set(network["required_specialists"])

    # The whole point: different evidence produces different delegation.
    assert app_required != net_required, "routing did not vary with evidence"
    assert app_required != ALL_SPECIALISTS, "fixed fan-out on application symptom"
    assert net_required != ALL_SPECIALISTS, "fixed fan-out on network symptom"
    assert "systems" in app_required
    assert "network" in net_required

    # Declining is a recorded decision, not an omission.
    for incident in (application, network):
        assert {r["specialist"] for r in incident["routes"]} == ALL_SPECIALISTS
        assert all(r["why"].strip() for r in incident["routes"])


def test_state_is_read_back_from_firestore():
    with _client() as client:
        created = _create(client, APPLICATION_SYMPTOM)
        fetched = client.get(f"/incidents/{created['incident_id']}").json()

    assert fetched["incident_id"] == created["incident_id"]
    assert fetched["status"] == "INVESTIGATING"
    assert fetched["trace_id"]
    assert fetched["routing"]["model_id"] == "gemini-3.7-flash"
    assert fetched["untrusted_content_flags"] == ["UNTRUSTED_INPUT"]
    assert fetched["audit_record_count"] >= 3


def test_unknown_incident_returns_404():
    with _client() as client:
        assert client.get("/incidents/INC-19990101-NOPE00").status_code == 404


@pytest.mark.parametrize(
    "payload",
    [
        {"description": "short"},
        {"description": ""},
        {"description": APPLICATION_SYMPTOM, "specialist": "systems"},
        {"description": APPLICATION_SYMPTOM, "remediation": "restart"},
    ],
)
def test_malformed_intake_is_rejected(payload):
    with _client() as client:
        assert client.post("/incidents", json=payload).status_code == 422


def test_service_requires_authentication():
    import httpx

    with httpx.Client(base_url=URL, timeout=60.0) as anonymous:
        assert anonymous.get("/health").status_code in (401, 403)
