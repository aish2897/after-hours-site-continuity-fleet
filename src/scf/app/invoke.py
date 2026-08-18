from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import google.auth.transport.requests
import httpx
from google.oauth2 import id_token

#: The largest worker answer this fleet will read. Every legitimate response is
#: a small JSON envelope — twelve evidence items, a proposal, a receipt, a
#: verdict. A worker is authenticated, not trusted: an authenticated service
#: that has itself failed can answer 200 with an unbounded evidence array, or
#: 503 with a body far larger than the error it describes. Buffering that
#: before the failure can even be classified is how a caller dies of the
#: failure it was built to survive.
MAX_WORKER_RESPONSE_BYTES = 1024 * 1024
#: Read size. Bounds how much arrives before the total is next checked.
READ_CHUNK_BYTES = 64 * 1024


class WorkerResponseTooLarge(Exception):
    """A worker answered with more than the fleet agreed to read."""

    def __init__(self, limit: int) -> None:
        super().__init__(
            f"worker response exceeded {limit} bytes and was refused unread"
        )
        self.limit = limit


class DuplicateJSONKey(ValueError):
    """A worker answered with the same key twice."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse any JSON object that names a key more than once.

    RFC 8259 says a receiver's behaviour is unpredictable when a name repeats,
    and Python's decoder resolves it by keeping the last one. That is
    last-write-wins on a safety flag: a worker answering both
    `"budget_exceeded": true` and `"budget_exceeded": false` had its refusal
    silently discarded and the workflow carried on to authorization. A
    well-formed worker never repeats a key, so repeating one is a contract
    violation and is treated as such — no attempt is made to guess which value
    was meant.
    """
    seen: set[str] = set()
    for key, _value in pairs:
        if key in seen:
            raise DuplicateJSONKey(f"duplicate JSON key {key!r} in worker response")
        seen.add(key)
    return dict(pairs)


@dataclass(frozen=True)
class WorkerResponse:
    """A bounded worker answer.

    Deliberately not an `httpx.Response`: holding one invites `.text` and
    `.json()`, both of which read whatever arrived. What is here has already
    been bounded, so nothing downstream can unbound it.
    """

    status_code: int
    text: str

    def json(self) -> Any:
        """Parse the bounded body.

        Raises `ValueError` for malformed JSON and `RecursionError` for a body
        nested deeply enough to exhaust the parser. Callers must handle BOTH:
        they are different exception hierarchies, and treating only the first
        as "malformed" let a hostile-but-authenticated payload escape typed
        failure handling entirely.
        """
        import json

        return json.loads(self.text, object_pairs_hook=_reject_duplicate_keys)


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
) -> WorkerResponse:
    """One bounded, authenticated call to a fleet worker.

    The response is streamed and refused outright once it passes the bound,
    rather than buffered and measured afterwards. Refusing is deliberate: a
    truncated worker answer is not a smaller worker answer, it is a different
    one, and reading half a receipt is worse than not reading it.
    """
    headers = {"Authorization": f"Bearer {_identity_token(base_url)}"}
    if trace_header:
        headers["X-Cloud-Trace-Context"] = trace_header

    with httpx.stream(
        "POST",
        f"{base_url.rstrip('/')}{path}",
        json=payload,
        headers=headers,
        timeout=timeout,
    ) as response:
        chunks: list[bytes] = []
        read = 0
        for chunk in response.iter_bytes(chunk_size=READ_CHUNK_BYTES):
            read += len(chunk)
            if read > MAX_WORKER_RESPONSE_BYTES:
                raise WorkerResponseTooLarge(MAX_WORKER_RESPONSE_BYTES)
            chunks.append(chunk)
        return WorkerResponse(
            status_code=response.status_code,
            text=b"".join(chunks).decode("utf-8", "replace"),
        )
