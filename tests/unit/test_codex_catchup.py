"""Codex accumulated audit of 74766ce — the two High findings, executed.

These run the real handlers rather than inspecting their source, because both
findings were cases where the code *read* correct and behaved otherwise.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from scf.app import main
from scf.domain.enums import IncidentStatus


class _Repo:
    """Enough authoritative plane to drive create_incident."""

    def __init__(self, screening_error: Exception | None = None):
        self.docs: dict[str, dict] = {}
        self.audits: list[tuple] = []
        self.screening_error = screening_error
        self.escalations: list[dict] = []

    def create(self, incident):
        self.docs[incident.incident_id] = {
            "incident_id": incident.incident_id,
            "status": IncidentStatus.INTAKE.value,
        }
        return incident.incident_id

    def get(self, incident_id):
        return self.docs[incident_id]

    def transition(self, incident_id, target, **_):
        self.docs[incident_id]["status"] = target.value
        return target

    def append_audit(self, incident_id, **kwargs):
        self.audits.append((incident_id, kwargs.get("event")))

    def record_screening(self, *_args, **_kwargs):
        if self.screening_error:
            raise self.screening_error

    def save_escalation(self, incident_id, package, **_):
        self.escalations.append(package)


@pytest.fixture
def client(monkeypatch):
    def _make(*, screen_error=None, record_error=None):
        repo = _Repo(screening_error=record_error)
        monkeypatch.setattr(main, "repository", lambda: repo)
        if screen_error is not None:
            def _boom(_text):
                raise screen_error
            monkeypatch.setattr(main, "screen_untrusted_text", _boom)

        called: dict[str, int] = {"gemini": 0, "executor": 0}

        async def _no_gemini(*_a, **_k):
            called["gemini"] += 1
            raise AssertionError("Gemini must not be invoked")

        async def _no_executor(*_a, **_k):
            called["executor"] += 1
            raise AssertionError("the executor must not be invoked")

        monkeypatch.setattr(main, "_run_fleet", _no_executor)
        import scf.agents.routing as routing

        monkeypatch.setattr(routing, "route_incident", _no_gemini)
        return TestClient(main.app, raise_server_exceptions=False), repo, called

    return _make


# --- HIGH 1: any screening failure fails closed, without a 500 ---------------


@pytest.mark.parametrize(
    "boom",
    [
        RuntimeError("metadata server said no"),
        ValueError("unexpected client error"),
        OSError("credential refresh failed"),
    ],
)
def test_a_generic_screening_failure_escalates_rather_than_500ing(client, boom):
    """The fail-closed path must not itself raise while reporting a failure."""
    api, repo, called = client(screen_error=boom)
    response = api.post(
        "/incidents",
        json={"description": "The dispatch screens are down at the warehouse."},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == IncidentStatus.ESCALATED.value
    assert body["remediation"]["failure_category"] == "SECURITY_SCREENING_UNAVAILABLE"
    assert called["gemini"] == 0
    assert called["executor"] == 0
    assert repo.escalations, "a handover must still be produced"


def test_a_failed_screening_record_also_fails_closed(client):
    """The metadata write is inside the guard, not after it."""
    api, repo, called = client(record_error=RuntimeError("firestore unavailable"))
    response = api.post(
        "/incidents",
        json={"description": "The dispatch screens are down at the warehouse."},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == IncidentStatus.ESCALATED.value
    assert body["remediation"]["failure_category"] == "SECURITY_SCREENING_UNAVAILABLE"
    assert called["gemini"] == 0
    assert called["executor"] == 0


# --- HIGH 2: authentication is not authorization ----------------------------


def test_an_unverifiable_caller_is_recorded_honestly_not_named(monkeypatch):
    """Cloud Run IAM is the gate; the app records what it actually knows.

    The app cannot verify a forwarded caller token — see `_authorize_approver`.
    It must therefore never write a specific person into the audit chain, and
    must never claim the identity was checked when it was not.
    """
    monkeypatch.setattr(main, "APPROVER_ROLE_BINDINGS",
                        {"incident_commander": frozenset({"boss@example.test"})})
    for header in (None, "Bearer forged", "Basic abc", ""):
        recorded = main._authorize_approver(header, "incident_commander")
        assert "not verifiable" in recorded
        assert "boss@example.test" not in recorded
        assert "@" not in recorded.split("(")[0]


def test_a_verified_but_unbound_principal_is_refused(monkeypatch):
    monkeypatch.setattr(main, "APPROVER_ROLE_BINDINGS",
                        {"incident_commander": frozenset({"boss@example.test"})})
    monkeypatch.setattr(main, "_verified_caller", lambda _h: "intruder@example.test")
    with pytest.raises(main.ApprovalForbidden):
        main._authorize_approver("Bearer real", "incident_commander")


def test_every_fleet_identity_is_refused_when_verifiable(monkeypatch):
    """No agent may approve its own work. Cloud Run IAM refuses them first."""
    monkeypatch.setattr(main, "APPROVER_ROLE_BINDINGS",
                        {"incident_commander": frozenset({"boss@example.test"})})
    for identity in (
        "sa-orchestrator@site-continuity-fleet.iam.gserviceaccount.com",
        "sa-agent-systems@site-continuity-fleet.iam.gserviceaccount.com",
        "sa-executor@site-continuity-fleet.iam.gserviceaccount.com",
        "sa-verifier@site-continuity-fleet.iam.gserviceaccount.com",
    ):
        monkeypatch.setattr(main, "_verified_caller", lambda _h, i=identity: i)
        with pytest.raises(main.ApprovalForbidden):
            main._authorize_approver("Bearer real", "incident_commander")


def test_the_configured_approver_is_accepted_and_is_the_recorded_principal(monkeypatch):
    monkeypatch.setattr(main, "APPROVER_ROLE_BINDINGS",
                        {"incident_commander": frozenset({"boss@example.test"})})
    monkeypatch.setattr(main, "_verified_caller", lambda _h: "boss@example.test")
    assert main._authorize_approver("Bearer real", "incident_commander") == (
        "boss@example.test"
    )


def test_a_role_with_no_bindings_grants_nobody(monkeypatch):
    """An unconfigured role is closed, not open."""
    monkeypatch.setattr(main, "APPROVER_ROLE_BINDINGS", {})
    monkeypatch.setattr(main, "_verified_caller", lambda _h: "boss@example.test")
    with pytest.raises(main.ApprovalForbidden):
        main._authorize_approver("Bearer real", "incident_commander")


def test_the_orchestrator_no_longer_hosts_an_approval_door():
    """Approval decisions live on a service no agent can invoke."""
    import inspect

    source = inspect.getsource(main)
    assert '/approvals/{approval_id}/approve"' not in source
    assert '/approvals/{approval_id}/reject"' not in source
    # Reading one stays: reading authorizes nothing.
    assert '@app.get("/approvals/{approval_id}")' in source


def test_the_approval_surface_never_trusts_a_plain_header():
    """Only a signed IAP assertion may name a person."""
    import inspect

    from scf.app import approval

    source = inspect.getsource(approval.verified_iap_principal)
    assert "verify_token" in source
    assert "certs_url" in source
    assert "cloud.google.com/iap" in source
    # The unsigned convenience header is never READ anywhere in the service.
    # Checked against code, not prose: the module docstring names the header in
    # order to say it is not trusted.
    import ast

    tree = ast.parse(inspect.getsource(approval))
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ) and ast.get_docstring(node):
            node.body = node.body[1:]
    code = ast.unparse(tree)
    assert "x_goog_authenticated_user_email" not in code
    assert "X-Goog-Authenticated-User-Email" not in code


def test_without_iap_the_record_names_the_authority_not_a_person(monkeypatch):
    from scf.app import approval

    monkeypatch.setattr(approval, "APPROVER_ROLE_BINDINGS",
                        {"incident_commander": frozenset({"boss@example.test"})})
    principal, authority = approval.authorize(None, "incident_commander")
    assert authority == "PLATFORM_IAM"
    assert "PLATFORM_IAM" in principal
    assert "@" not in principal.split("(")[0]
    assert "boss@example.test" not in principal


def test_a_verified_iap_principal_must_still_be_bound_to_the_role(monkeypatch):
    from fastapi import HTTPException

    from scf.app import approval

    monkeypatch.setattr(approval, "APPROVER_ROLE_BINDINGS",
                        {"incident_commander": frozenset({"boss@example.test"})})
    monkeypatch.setattr(approval, "verified_iap_principal", lambda _a: "boss@example.test")
    assert approval.authorize("signed", "incident_commander") == (
        "boss@example.test", "IAP_VERIFIED_IDENTITY"
    )
    monkeypatch.setattr(approval, "verified_iap_principal", lambda _a: "intruder@example.test")
    with pytest.raises(HTTPException) as refused:
        approval.authorize("signed", "incident_commander")
    assert refused.value.status_code == 403


def test_bindings_parse_exactly_and_never_wildcard(monkeypatch):
    monkeypatch.setenv(
        "SCF_APPROVER_BINDINGS",
        "incident_commander:Boss@Example.test, second@example.test;ops:o@example.test",
    )
    bindings = main._load_approver_bindings()
    assert bindings["incident_commander"] == frozenset(
        {"boss@example.test", "second@example.test"}
    )
    assert bindings["ops"] == frozenset({"o@example.test"})
    assert "*" not in str(bindings)
