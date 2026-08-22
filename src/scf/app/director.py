"""The Director console — the duty manager's window onto the fleet.

This service deliberately holds **no authority of its own.**

That is the whole design. It serves a static page and forwards requests to the
orchestrator and to `scf-approval`, carrying the *caller's* Google identity
token rather than its own. Its service account has no `run.invoker` on anything.
If nobody is signed in, this service can do nothing at all — not create an
incident, not read one, and certainly not approve one.

The alternative was tempting and wrong. A console that called the backend under
its own identity would need `run.invoker` on `scf-approval`, and the property
Codex High 2 established — that no autonomous identity can approve an autonomous
decision — would have quietly become false, defeated by the convenience layer
rather than by an attacker.

So the console is a pipe. The cost is that the Director signs in by pasting an
identity token once per session; the benefit is that every boundary proven in
Gates D through H still holds with a browser in front of them.

The token is never logged, never persisted, and never stored server-side.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from scf import config
from scf.obs import log_event, trace_id_from_header

app = FastAPI(title="SCF Director Console", version="0.1.0")

ORCHESTRATOR_URL = os.environ.get("SCF_ORCHESTRATOR_URL", "").rstrip("/")
APPROVAL_URL = os.environ.get("SCF_APPROVAL_URL", "").rstrip("/")

#: Where the built console lives inside the image.
#:
#: Inside the Python package on purpose. `web/dist` is ignored by git, and an
#: ignored directory is exactly the kind of thing that silently fails to reach a
#: build context — which it did, once, producing a service that answered its API
#: and served a 404 for the page. `infra/build-console.sh` copies the Vite output
#: here, and this path is ordinary package data that nothing ignores.
STATIC_ROOT = Path(__file__).resolve().parent / "console"

#: An incident can take a while: screening, routing, up to three specialists,
#: execution and verification all happen inside the one call.
UPSTREAM_TIMEOUT = httpx.Timeout(300.0, connect=15.0)


def _bearer(authorization: str | None) -> str:
    """The caller's own credential, or a refusal.

    Never falls back to this service's identity. A missing token is a missing
    person, and a console with nobody at it may not act.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail="director_not_signed_in",
        )
    return authorization


async def _forward(
    base: str,
    path: str,
    *,
    authorization: str,
    method: str = "POST",
    json_body: dict[str, Any] | None = None,
    trace_header: str | None = None,
) -> JSONResponse:
    """Pass the request upstream under the caller's identity, verbatim.

    Upstream status codes are preserved rather than flattened. A 403 from Cloud
    Run IAM is the most informative thing the approval flow can return, and
    turning it into a friendly 200 would hide exactly the boundary this project
    is built to demonstrate.
    """
    if not base:
        raise HTTPException(status_code=503, detail="upstream_not_configured")

    headers = {"Authorization": authorization, "Content-Type": "application/json"}
    if trace_header:
        headers["X-Cloud-Trace-Context"] = trace_header

    try:
        async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
            response = await client.request(
                method, f"{base}{path}", headers=headers, json=json_body
            )
    except httpx.HTTPError as exc:
        log_event(
            "director_upstream_unreachable",
            severity="ERROR",
            upstream=base.rsplit("/", 1)[-1],
            path=path,
            error_type=type(exc).__name__,
        )
        raise HTTPException(status_code=504, detail="upstream_unreachable") from exc

    try:
        payload = response.json()
    except ValueError:
        # Cloud Run's own 401/403 pages are HTML, not JSON. Say what happened
        # rather than crashing on the parse.
        payload = {
            "detail": "upstream_refused" if response.status_code in (401, 403)
            else "upstream_returned_non_json",
            "status": response.status_code,
        }
    return JSONResponse(status_code=response.status_code, content=payload)


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "scf-director",
        "role": "director_console",
        "holds_own_authority": False,
        "orchestrator_configured": bool(ORCHESTRATOR_URL),
        "approval_configured": bool(APPROVAL_URL),
        "static_built": STATIC_ROOT.is_dir(),
        "revision": os.environ.get("K_REVISION"),
    }


@app.get("/api/session")
async def session(authorization: str | None = Header(default=None)) -> JSONResponse:
    """Does this token actually open the doors? Ask the doors, don't guess."""
    token = _bearer(authorization)
    reachable = {}
    async with httpx.AsyncClient(timeout=httpx.Timeout(20.0)) as client:
        for name, base in (("orchestrator", ORCHESTRATOR_URL),
                           ("approval", APPROVAL_URL)):
            if not base:
                reachable[name] = "not_configured"
                continue
            try:
                probe = await client.get(
                    f"{base}/health", headers={"Authorization": token}
                )
                reachable[name] = "ok" if probe.status_code == 200 else str(
                    probe.status_code
                )
            except httpx.HTTPError:
                reachable[name] = "unreachable"
    return JSONResponse(
        content={
            "signed_in": reachable.get("orchestrator") == "ok",
            "reachable": reachable,
            "core_region": config.CORE_REGION,
        }
    )


@app.post("/api/incidents")
async def create_incident(
    request: Request,
    authorization: str | None = Header(default=None),
    x_cloud_trace_context: str | None = Header(default=None),
) -> JSONResponse:
    token = _bearer(authorization)
    body = await request.json()
    trace_id = trace_id_from_header(x_cloud_trace_context)
    # Log the shape, never the content. The report is untrusted text and the
    # screenshot is untrusted bytes; neither belongs in an application log.
    log_event(
        "director_incident_submitted",
        trace_id=trace_id,
        description_chars=len(str(body.get("description") or "")),
        image_attached=bool(body.get("image_base64")),
    )
    return await _forward(
        ORCHESTRATOR_URL,
        "/incidents",
        authorization=token,
        json_body=body,
        trace_header=x_cloud_trace_context,
    )


@app.get("/api/incidents/{incident_id}")
async def read_incident(
    incident_id: str,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    return await _forward(
        ORCHESTRATOR_URL,
        f"/incidents/{incident_id}",
        authorization=_bearer(authorization),
        method="GET",
    )


@app.post("/api/incidents/{incident_id}/resume")
async def resume_incident(
    incident_id: str,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    return await _forward(
        ORCHESTRATOR_URL,
        f"/incidents/{incident_id}/resume",
        authorization=_bearer(authorization),
        json_body={},
    )


@app.get("/api/approvals/{approval_id}")
async def read_approval(
    approval_id: str,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    """Reading an approval stays on the orchestrator: reading authorizes nothing."""
    return await _forward(
        ORCHESTRATOR_URL,
        f"/approvals/{approval_id}",
        authorization=_bearer(authorization),
        method="GET",
    )


@app.post("/api/approvals/{approval_id}/{verb}")
async def decide_approval(
    approval_id: str,
    verb: str,
    request: Request,
    authorization: str | None = Header(default=None),
    x_cloud_trace_context: str | None = Header(default=None),
) -> JSONResponse:
    """The only privileged action this console can carry — and it carries the
    caller's credential, not its own.

    `sa-director` holds no `run.invoker` on `scf-approval`. If the person at the
    browser is not the principal Google lets in, this returns the 403 that Cloud
    Run produced, unmodified.
    """
    if verb not in ("approve", "reject"):
        raise HTTPException(status_code=404, detail="unknown_approval_action")
    token = _bearer(authorization)
    try:
        body = await request.json()
    except ValueError:
        body = {}
    log_event(
        "director_approval_attempted",
        trace_id=trace_id_from_header(x_cloud_trace_context),
        approval_id=approval_id,
        action=verb,
    )
    return await _forward(
        APPROVAL_URL,
        f"/approvals/{approval_id}/{verb}",
        authorization=token,
        json_body={"note": str(body.get("note") or "")[:500]} if body else {},
        trace_header=x_cloud_trace_context,
    )


# --- the page itself ---------------------------------------------------------

if STATIC_ROOT.is_dir():
    app.mount(
        "/assets",
        StaticFiles(directory=STATIC_ROOT / "assets"),
        name="assets",
    )

    @app.get("/{full_path:path}")
    def spa(full_path: str) -> FileResponse:
        """Single page app: every non-API path renders the console.

        The containment check is the whole point of this function.

        `STATIC_ROOT / full_path` will happily walk out of the console
        directory: Starlette hands the path segment over percent-decoded, so
        `..%2fdirector.py` arrives as `../director.py` and resolves to real
        source. That was live for one revision and served this file's own
        contents to an unauthenticated caller.

        So the resolved path must still be inside the console directory, and
        anything else falls through to index.html rather than erroring — a
        probe learns nothing from the response either way.
        """
        root = STATIC_ROOT.resolve()
        index = root / "index.html"
        if not full_path:
            return FileResponse(index)
        try:
            candidate = (root / full_path).resolve()
        except (OSError, ValueError):
            return FileResponse(index)
        if candidate.is_file() and candidate.is_relative_to(root):
            return FileResponse(candidate)
        return FileResponse(index)
