from __future__ import annotations

import json
import sys
from typing import Any

from scf import config

REDACTED_KEYS = {
    "authorization",
    "x-goog-api-key",
    "access_token",
    "id_token",
    "refresh_token",
    "private_key",
    "client_secret",
    "token",
}


def _scrub(payload: dict[str, Any]) -> dict[str, Any]:
    """Defence in depth: credentials must never reach Cloud Logging."""
    return {
        key: ("[REDACTED]" if key.lower() in REDACTED_KEYS else value)
        for key, value in payload.items()
    }


def log_event(
    event: str,
    *,
    severity: str = "INFO",
    trace_id: str | None = None,
    incident_id: str | None = None,
    **fields: Any,
) -> None:
    """Emit one structured Cloud Logging entry on stdout.

    The `logging.googleapis.com/trace` field is what lets Cloud Logging group
    every entry for a single incident into one correlated request.
    """
    entry: dict[str, Any] = {
        "severity": severity,
        "message": event,
        "event": event,
        **_scrub(fields),
    }
    if incident_id:
        entry["incident_id"] = incident_id
    if trace_id:
        entry["logging.googleapis.com/trace"] = (
            f"projects/{config.PROJECT_ID}/traces/{trace_id}"
        )
        entry["trace_id"] = trace_id

    print(json.dumps(entry, default=str), file=sys.stdout, flush=True)


def trace_id_from_header(header: str | None) -> str | None:
    """Parse Cloud Run's X-Cloud-Trace-Context: TRACE_ID/SPAN_ID;o=1."""
    if not header:
        return None
    return header.split("/", 1)[0].strip() or None
