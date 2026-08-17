"""Systems Investigator evidence tools.

Read-only. Every value returned is TRUSTED_TOOL evidence gathered through a
declared tool call under a scoped identity. Nothing here authorizes anything:
these functions describe the world, and the deterministic policy gate decides
what may be done about it.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
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
        timeout=10.0,
    )
    response.raise_for_status()
    return response.json()


def list_revisions(service: str) -> list[dict[str, Any]]:
    response = httpx.get(
        f"{RUN_API}/{_service_path(service)}/revisions",
        headers={"Authorization": f"Bearer {_access_token()}"},
        timeout=10.0,
    )
    response.raise_for_status()
    return response.json().get("revisions", [])


def traffic_allocation(described: dict[str, Any]) -> dict[str, int]:
    """Revision -> percent, for every revision actually receiving traffic.

    Tag-only entries carry no percent and are excluded: a tag is an addressable
    URL, not a share of live traffic. Reading the whole allocation rather than
    hunting for a single 100% entry is what lets a caller reject a 90/10 or
    50/50 split, or a correct revision with unexpected secondary traffic.
    """
    allocation: dict[str, int] = {}
    for entry in described.get("trafficStatuses") or []:
        percent = int(entry.get("percent") or 0)
        if percent <= 0:
            continue
        revision = (entry.get("revision") or "").rsplit("/", 1)[-1]
        allocation[revision] = allocation.get(revision, 0) + percent
    return allocation


def serves_exclusively(described: dict[str, Any], revision: str) -> bool:
    """True only when the named revision takes 100% and nothing else takes any."""
    return bool(revision) and traffic_allocation(described) == {revision: 100}


#: Bodies that assert health. Matched as whole words against a bounded read.
_HEALTHY_MARKERS = frozenset({"healthy", "ok", "ready", "serving"})
#: Whole words that disqualify a body outright. Matched as words, not raw
#: substrings: `errorCount` and `no errors detected` are not failure reports,
#: and rejecting them would make a healthy service look broken.
_UNHEALTHY_WORDS = frozenset(
    {"unhealthy", "unavailable", "degraded", "failing", "failed", "failure",
     "down", "false"}
)
#: Phrases that negate a positive marker and cannot be caught word-by-word.
_UNHEALTHY_PHRASES = ("not healthy", "not ok", "not ready", "not serving")


#: Keys a JSON health body might answer with. Checked in order.
_HEALTH_KEYS = ("healthy", "ok", "ready", "serving", "status", "state")


def _text_is_negative(text: str) -> bool:
    """Does the raw body contain an explicit failure marker anywhere?"""
    if any(phrase in text for phrase in _UNHEALTHY_PHRASES):
        return True
    return bool(set(re.findall(r"[a-z]+", text)) & _UNHEALTHY_WORDS)


def _collect_health_verdicts(payload: Any) -> list[bool]:
    """Every recognised health key in the structure, at any depth.

    A health endpoint that reports per-dependency detail keeps its verdicts in
    nested objects. Looking only at the top level means a body can announce
    `ok: true` while a nested check says it has failed.
    """
    verdicts: list[bool] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in _HEALTH_KEYS:
                if isinstance(value, bool):
                    verdicts.append(value)
                elif isinstance(value, str):
                    verdicts.append(_text_is_healthy(value.strip().lower()))
                elif not isinstance(value, (dict, list)):
                    # A non-boolean, non-string health value asserts nothing,
                    # and guessing at it would be exactly the wrong instinct.
                    verdicts.append(False)
            verdicts.extend(_collect_health_verdicts(value))
    elif isinstance(payload, list):
        for item in payload:
            verdicts.extend(_collect_health_verdicts(item))
    return verdicts


def _text_is_healthy(text: str) -> bool:
    """Word-level reading of a plain-text health body."""
    if not text:
        return False
    if any(phrase in text for phrase in _UNHEALTHY_PHRASES):
        return False
    words = set(re.findall(r"[a-z]+", text))
    if words & _UNHEALTHY_WORDS:
        return False
    return bool(words & _HEALTHY_MARKERS)


def body_is_healthy(body: str) -> bool:
    """Whether a probe body asserts health, without being fooled by negation.

    Two traps, both of which have bitten this predicate:

    1. `"healthy" in body.lower()` is satisfied by the word **un**healthy, so a
       service reporting its own failure was read as healthy — the exact
       inversion of the signal.
    2. Word matching alone is satisfied by `{"healthy": false}`, because the
       word *healthy* is present. A JSON body is therefore parsed and read
       structurally: the value of the health key decides, not its name.

    Anything that does not parse as a JSON object falls back to word matching,
    where negatives are whole words and negating phrases are matched literally.
    """
    text = body.strip().lower()
    if not text:
        return False

    try:
        payload = json.loads(text)
    except ValueError:
        payload = None

    verdicts = _collect_health_verdicts(payload)
    if verdicts:
        # EVERY recognised health key must agree, at any depth. Reading only the
        # first one called `{"ok": true, "state": "failed"}` healthy; reading
        # only the top level called `{"ok": true, "checks": {"db": {"state":
        # "failed"}}}` healthy. A body that contradicts itself anywhere gets
        # the pessimistic reading.
        #
        # The raw text is also scanned as a veto. That catches what structure
        # alone cannot — duplicate keys, where JSON parsing silently keeps the
        # last one and the contradiction disappears before we ever see it.
        return all(verdicts) and not _text_is_negative(text)

    return _text_is_healthy(text)


def probe(url: str) -> tuple[int, bool, str]:
    """(status, healthy, body) for a read-only probe. One place, one rule."""
    status_code, body = probe_health(url)
    return status_code, status_code == 200 and body_is_healthy(body), body


def probe_health(url: str) -> tuple[int, str]:
    try:
        response = httpx.get(url, timeout=10.0, follow_redirects=True)
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


#: A failing probe is confirmed once before it counts as evidence.
CONFIRM_UNHEALTHY_AFTER_SECONDS = 3.0

KNOWN_GOOD_TAG = "known-good"


def gather_evidence(
    service: str = config.DISPATCH_WEB_SERVICE,
    charge: Callable[[str], None] | None = None,
) -> list[Evidence]:
    """Collect real Cloud Run state as trusted evidence.

    `charge` lets a caller's work budget account for each network call rather
    than for the function as a whole. Without it, three calls with their own
    timeouts hide inside one charged step, and a deadline measured only between
    steps does not bound what a step can cost.

    The rollback candidate is NOT inferred from "some revision that is not
    currently active". It is the revision an operator has explicitly approved
    by attaching the `known-good` Cloud Run traffic tag, and the investigator
    independently probes that tag's own URL to prove it actually serves a
    healthy response before anything may be proposed.
    """
    spend = charge or (lambda _what: None)

    spend("describe_service")
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

    spend("probe_live_service")
    status_code, body = probe_health(url)
    # Not status alone. A service answering 200 with a body that says it is
    # unhealthy is unhealthy; reading only the status code would let it report
    # its own failure and be ignored.
    live_healthy = status_code == 200 and body_is_healthy(body)

    if not live_healthy:
        # Confirm before concluding. A single dropped connection or cold-start
        # blip would otherwise be enough evidence to warrant changing
        # infrastructure, and the cost of being wrong here is an unnecessary
        # rollback of a service that was fine. This is a read-only second
        # look, not a retry of any action.
        time.sleep(CONFIRM_UNHEALTHY_AFTER_SECONDS)
        spend("confirm_live_service")
        status_code, body = probe_health(url)
        live_healthy = status_code == 200 and body_is_healthy(body)
    approved = bool(candidate_revision) and candidate_revision != active_revision

    spend("probe_candidate_revision")
    candidate_status, candidate_body = (
        probe_health(candidate_url) if candidate_url else (0, "no known-good tag")
    )
    candidate_healthy = candidate_status == 200 and body_is_healthy(candidate_body)

    return [
        _ev("service_exists", True, "target is a real Cloud Run service"),
        _ev("service_url", url, "where live health was probed"),
        _ev("service_etag", etag, "precondition token for safe mutation"),
        _ev("active_revision", active_revision, "revision currently serving traffic"),
        _ev("http_status", status_code, "observed health of the live service"),
        _ev("http_body", body[:200], "observed response body"),
        _ev("service_unhealthy", not live_healthy,
            "whether remediation is warranted: status AND what the body says"),
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
