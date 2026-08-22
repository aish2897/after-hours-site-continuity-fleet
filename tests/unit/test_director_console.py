"""The Director console: it must hold no authority and leak no files.

Two properties are load-bearing here, and both were wrong at some point.

The console forwards the *caller's* identity token and never falls back to its
own. If that ever changed, `sa-director` would need `run.invoker` on
`scf-approval`, and the Codex High 2 property — that no autonomous identity can
approve an autonomous decision — would quietly become false, defeated by the
convenience layer rather than by an attacker.

And the single-page-app catch-all served arbitrary files for one deployed
revision. `..%2fdirector.py` reached the container as `../director.py` and
returned this module's own source to an unauthenticated caller.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from scf.app import director


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A console with a real static root, so traversal is actually testable."""
    root = tmp_path / "console"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text("<!doctype html><title>console</title>", encoding="utf-8")
    (root / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
    (root / "manifest.json").write_text('{"name":"console"}', encoding="utf-8")
    (tmp_path / "secret.py").write_text("SECRET = 'must never be served'", encoding="utf-8")

    # The catch-all reads the module global on every call, so patching it is
    # enough. The `/assets` StaticFiles mount binds its directory at import
    # time and cannot be redirected this way — which is why the asset test
    # below requests a file the catch-all serves rather than one the mount does.
    monkeypatch.setattr(director, "STATIC_ROOT", root)
    return TestClient(director.app, raise_server_exceptions=False), root


# --- the console holds no authority of its own -------------------------------


def _code_only(module) -> str:
    tree = ast.parse(inspect.getsource(module))
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ) and ast.get_docstring(node):
            node.body = node.body[1:]
    return ast.unparse(tree)


def test_the_console_never_mints_or_falls_back_to_its_own_credential():
    source = _code_only(director)
    for forbidden in (
        "google.auth",
        "id_token",
        "fetch_id_token",
        "default(",
        "impersonated_credentials",
    ):
        assert forbidden not in source, forbidden


def test_a_missing_token_is_refused_rather_than_substituted():
    for header in (None, "", "Basic abc", "Token xyz"):
        with pytest.raises(Exception) as refused:
            director._bearer(header)
        assert getattr(refused.value, "status_code", None) == 401


def test_the_caller_token_is_what_goes_upstream():
    source = _code_only(director._forward)
    assert "'Authorization': authorization" in source or (
        '"Authorization": authorization' in source
    )


def test_approval_actions_go_to_the_approval_service_not_the_orchestrator():
    source = _code_only(director.decide_approval)
    assert "APPROVAL_URL" in source
    assert "ORCHESTRATOR_URL" not in source
    # And only the two real verbs exist.
    assert "('approve', 'reject')" in source


def test_reading_an_approval_stays_on_the_orchestrator():
    """Reading authorizes nothing, so it does not belong on the approval door."""
    source = _code_only(director.read_approval)
    assert "ORCHESTRATOR_URL" in source
    assert "APPROVAL_URL" not in source


def test_upstream_status_codes_are_relayed_not_flattened():
    """A 403 from Google is the most informative thing the flow can return."""
    source = _code_only(director._forward)
    assert "status_code=response.status_code" in source


def test_the_console_never_logs_the_token():
    source = _code_only(director)
    for line in source.splitlines():
        if "log_event" in line or "authorization" in line.lower():
            assert "log_event" not in line or "authorization" not in line.lower()
    # And the report text itself is never logged, only its length.
    assert "description_chars" in source
    assert 'description=body' not in source


# --- the static handler may not leave its directory --------------------------


@pytest.mark.parametrize(
    "attack",
    [
        "../director.py",
        "../../secret.py",
        "../../../../etc/passwd",
        "..%2fdirector.py",
        "assets/../../secret.py",
        "./../secret.py",
    ],
)
def test_the_console_never_serves_a_file_outside_its_own_directory(client, attack):
    api, root = client
    response = api.get(f"/{attack}")
    body = response.text
    assert "must never be served" not in body
    assert "SECRET" not in body
    # Falling through to the app is fine; leaking is not.
    assert response.status_code in (200, 404)
    if response.status_code == 200:
        assert "<!doctype html>" in body.lower()


def test_a_real_file_inside_the_console_is_still_served(client):
    """Containment must not break ordinary delivery."""
    api, _ = client
    response = api.get("/manifest.json")
    assert response.status_code == 200
    assert "console" in response.text


def test_an_unknown_route_renders_the_console(client):
    api, _ = client
    response = api.get("/incidents/anything")
    assert response.status_code == 200
    assert "<!doctype html>" in response.text.lower()


def test_the_containment_check_is_present_in_the_shipped_code():
    """Pin the fix: a refactor must not drop the boundary check."""
    source = inspect.getsource(director)
    assert "is_relative_to" in source


# --- the health endpoint tells the truth about what it holds -----------------


def test_health_declares_that_it_holds_no_authority():
    body = director.health()
    assert body["holds_own_authority"] is False
    assert body["service"] == "scf-director"


def test_the_built_console_is_declared_as_package_data():
    """Otherwise the buildpack installs the .py files and serves a 404 page."""
    root = Path(__file__).resolve().parents[2]
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    assert "app/console/*" in pyproject
    assert "app/console/assets/*" in pyproject
