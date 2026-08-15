from __future__ import annotations

from typing import Any

import google.auth.transport.requests
import httpx
from google.oauth2 import id_token


def _identity_token(audience: str) -> str:
    """Mint an ID token for authenticated Cloud Run service-to-service calls.

    On Cloud Run this uses the attached service account via the metadata
    server. Invoker permission is required in addition to a valid token.
    """
    return id_token.fetch_id_token(
        google.auth.transport.requests.Request(), audience
    )


def call_service(
    base_url: str,
    path: str,
    payload: dict[str, Any],
    *,
    trace_header: str | None = None,
    timeout: float = 120.0,
) -> httpx.Response:
    headers = {"Authorization": f"Bearer {_identity_token(base_url)}"}
    if trace_header:
        headers["X-Cloud-Trace-Context"] = trace_header
    return httpx.post(
        f"{base_url.rstrip('/')}{path}", json=payload, headers=headers, timeout=timeout
    )
