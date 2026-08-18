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

#: Client timeout for one Cloud Run Admin read and one health probe. Exported
#: so a caller's work budget can be derived from what the work actually costs
#: rather than guessed — a deadline smaller than its own worst case aborts the
#: investigation on exactly the slow outage it exists to diagnose.
ADMIN_CALL_TIMEOUT = 10.0
PROBE_TIMEOUT = 8.0


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
        timeout=ADMIN_CALL_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def list_revisions(service: str) -> list[dict[str, Any]]:
    response = httpx.get(
        f"{RUN_API}/{_service_path(service)}/revisions",
        headers={"Authorization": f"Bearer {_access_token()}"},
        timeout=ADMIN_CALL_TIMEOUT,
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
#: `up` and `pass` are the vocabularies real health endpoints actually use —
#: Spring Boot Actuator answers `{"status":"UP"}` and the IETF health-check
#: draft answers `{"status":"pass"}`. Omitting them did not fail closed in a
#: useful direction: it made a recovered service unverifiable, which blocks the
#: recovery from ever being confirmed.
_HEALTHY_MARKERS = frozenset(
    {"healthy", "ok", "ready", "serving", "up", "pass", "passing", "available"}
)
#: Whole words that disqualify a body outright. Matched as words, not raw
#: substrings: `errorCount` and `no errors detected` are not failure reports,
#: and rejecting them would make a healthy service look broken. `fail` is the
#: counterpart of `pass`; without it `{"status":"pass","db":"fail"}` would have
#: read as healthy on the strength of one word.
_UNHEALTHY_WORDS = frozenset(
    {"unhealthy", "unavailable", "degraded", "failing", "failed", "failure",
     "fail", "down", "false",
     # Lifecycle words. `{"status": "starting up"}` is a container answering 200
     # before it can serve; reading it as healthy off `up` is how a revision
     # that is not ready yet gets graded RECOVERED.
     "starting", "stopping", "terminating", "draining", "initializing",
     "warming", "pending"}
)
#: Phrases that negate a positive marker and cannot be caught word-by-word.
#: Derived from the markers themselves rather than listed by hand: the list was
#: written when there were four markers, four more were added later, and
#: `{"status": "not up"}` then read as healthy off the word `up` — a service
#: reporting its own failure, taken as a report that it was fine.
_UNHEALTHY_PHRASES = tuple(f"not {marker}" for marker in sorted(_HEALTHY_MARKERS))
#: ...and matched as WORDS. Plain substring containment made `cannot upload` and
#: `cannot upgrade` contain "not up", so an ordinary sentence in a healthy
#: body — "cannot upload logs" — reported the service as unhealthy. That is the
#: one direction this predicate must never fail in: a healthy production
#: revision reading as broken is what triggers an unwarranted rollback of a
#: service nobody asked us to touch.
#:
#: Up to two words may sit between the negator and the marker. Requiring them
#: adjacent meant `not yet ready`, `not currently available` and `not fully up`
#: all read as HEALTHY off the marker word alone — ordinary readiness bodies
#: from a container that is answering 200 while it is still starting.
_NEGATED_MARKER = re.compile(
    "(?<![a-z])(?:not|never) +(?:[a-z]+ +){0,2}?(?:"
    + "|".join(sorted(_HEALTHY_MARKERS, key=len, reverse=True))
    + ")(?![a-z])"
)

#: A negated failure word is not a failure report. `"message": "no failure
#: detected"` is a service saying it is fine, and reading it as a failure
#: blocks candidate freshness, recovery verification and terminalization for a
#: service that is genuinely healthy — a false negative in the one place where
#: failing closed does real damage. Negators are matched only against failure
#: words, so `not healthy` above is untouched.
#:
#: Deliberately narrow. The separator is a plain space and there is no numeric
#: negator, because `{"checks": ["0: failed"]}` is an *indexed* failure report,
#: not a claim that zero things failed — and reading it as a negation turned a
#: genuine failure into a healthy verdict, which is the worst direction this
#: predicate can be wrong in. `"0 failures"` is therefore read pessimistically;
#: a service that means it is fine can say `no failures` or `zero failures`.
#:
#: A literal `0` is allowed back as a negator, but ONLY with a plain space after
#: it, which is what separates the count phrase `0 failed checks` from the
#: indexed report `0: failed`. No other digit negates: `3 failed checks` is a
#: failure report and must stay one.
_NEGATED_FAILURE = re.compile(
    "(?<![a-z0-9])(?:no|not|zero|never|without|0) +"
    "(?:" + "|".join(sorted(_UNHEALTHY_WORDS, key=len, reverse=True)) + ")s?(?![a-z])"
)


#: Guard strings some servers prepend to a JSON body to defeat script
#: inclusion. They are not part of the document and must not disguise it.
_JSON_PREFIXES = (")]}'" + chr(10), ")]}'," + chr(10), ")]}'", "while(1);", "for(;;);")

#: Bounded, because the loop consumes untrusted input: a body made entirely of
#: guard strings must terminate the reader, not occupy it.
_MAX_PREFIX_STRIPS = 8

#: Keys a JSON health body might answer with. Checked in order.
_HEALTH_KEYS = ("healthy", "ok", "ready", "serving", "status", "state")


#: Marker for a health key that appeared twice with different values. JSON
#: parsing silently keeps the last one, so the contradiction has to be recorded
#: while the pairs are still visible.
_CONFLICT_KEY = "__scf_conflicting_health_keys__"


def _same_value(left: Any, right: Any) -> bool:
    """Whether two JSON values are the same assertion, not merely equal.

    `bool` is a subclass of `int`, so `1 == True`. A duplicate-key check
    written with `!=` therefore missed `{"healthy": 1, "healthy": true}`
    entirely — the parser kept the boolean, and a body that could not decide
    what type its own health verdict was got read as healthy.
    """
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    return left == right


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a dict while remembering keys that disagreed with themselves."""
    result: dict[str, Any] = {}
    conflicts: list[str] = []
    for key, value in pairs:
        if key in result and not _same_value(result[key], value):
            conflicts.append(key)
        result[key] = value
    if conflicts:
        result[_CONFLICT_KEY] = conflicts
    return result


def _collect_health_verdicts(payload: Any, depth: int = 0) -> list[bool]:
    """Every recognised health key in the structure, at any depth.

    A health endpoint that reports per-dependency detail keeps its verdicts in
    nested objects. Looking only at the top level means a body can announce
    `ok: true` while a nested check says it has failed.
    """
    if depth > MAX_HEALTH_DEPTH:
        # Too deep to read is not an assertion of health.
        return [False]

    verdicts: list[bool] = []
    if isinstance(payload, str):
        # A failure reported under a key this reader does not recognise is
        # still a failure. `{"healthy": true, "checks": {"db": "failed"}}` says
        # a dependency is down; reading only recognised health keys called that
        # body healthy, because `db` is not one of them. Any *string value*
        # anywhere that reports failure vetoes the body. Only values are read,
        # never key names, so a healthy body carrying `"failure_count": 0` — a
        # number, under a name that merely contains the word — is unaffected.
        return [False] if _value_reports_failure(payload) else []
    if isinstance(payload, dict):
        # A health key that contradicted itself is a contradiction, whichever
        # value the parser happened to keep.
        declared_conflicts = payload.get(_CONFLICT_KEY, ())
        if not isinstance(declared_conflicts, (list, tuple)):
            # The body supplied our own sentinel key with a value we did not
            # write. Iterating it raised TypeError straight out of the reader —
            # a probed service crashing the investigator or verifier, which is
            # exactly what this function's bounds exist to prevent. A body
            # carrying this key is not a health answer.
            return [False]
        if any(key in _HEALTH_KEYS for key in declared_conflicts):
            verdicts.append(False)
        for key, value in payload.items():
            if key == _CONFLICT_KEY:
                continue
            nested = _collect_health_verdicts(value, depth + 1)
            if key in _HEALTH_KEYS:
                if isinstance(value, bool):
                    verdicts.append(value)
                elif isinstance(value, str):
                    verdicts.append(_text_is_healthy(value.strip().lower()))
                elif isinstance(value, (dict, list)):
                    # A health key whose container answers nothing — `{"ok": []}`,
                    # `{"healthy": {}}` — is not an assertion of health. Letting
                    # it contribute no verdict was worse than silent: with no
                    # verdicts at all the reader fell back to word matching, saw
                    # the *key name* `healthy`, and called the service healthy.
                    if not nested:
                        verdicts.append(False)
                else:
                    # A non-boolean, non-string health value asserts nothing,
                    # and guessing at it would be exactly the wrong instinct.
                    verdicts.append(False)
            verdicts.extend(nested)
    elif isinstance(payload, list):
        for item in payload:
            verdicts.extend(_collect_health_verdicts(item, depth + 1))
    return verdicts


#: Values that carry a failure word without reporting a failure. A hostname
#: like `web-down-under-01` and a stringified boolean like `"false"` are not
#: health statements, and vetoing on them blocked a genuinely recovered service
#: from ever being verified — which escalates healthy infrastructure
#: permanently, with no route back.
_IDENTIFIER_SHAPED = re.compile(r"[0-9]|[-_./]")
_BARE_LITERALS = frozenset({"true", "false", "null", "none", "0", "1"})


def _value_reports_failure(value: str) -> bool:
    """Whether a non-health-key string VALUE is reporting a failure.

    Only a WHOLE value that is a bare literal or a single identifier-shaped
    token is excused. Excusing any value that merely *contains* a digit was too
    broad by far: it let `{"checks": ["0: failed"]}` through as healthy, which
    is an indexed failure report and precisely the defect an earlier round
    closed. A failure word sitting in a sentence is still a failure word.
    """
    stripped = value.strip().lower()
    if stripped in _BARE_LITERALS:
        return False
    if not stripped.split()[1:] and _IDENTIFIER_SHAPED.search(stripped):
        # One token, shaped like a hostname, build tag or resource id.
        return False
    return _text_says_unhealthy(stripped)


def _text_says_unhealthy(text: str) -> bool:
    """Whether a plain string reports a failure, as whole words and phrases."""
    if _NEGATED_MARKER.search(text):
        return True
    return bool(set(re.findall(r"[a-z]+", _NEGATED_FAILURE.sub(" ", text))) & _UNHEALTHY_WORDS)


def _text_is_healthy(text: str) -> bool:
    """Word-level reading of a plain-text health body."""
    if not text:
        return False
    if _NEGATED_MARKER.search(text):
        return False
    words = set(re.findall(r"[a-z]+", _NEGATED_FAILURE.sub(" ", text)))
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
    if len(body) > MAX_HEALTH_BODY_BYTES:
        # A body this size is not a health answer. Refusing it fails closed,
        # and refusing it *first* means an oversized body is never normalised,
        # copied or parsed — the work is what made it a denial-of-service
        # surface, not the decision at the end of it.
        return False
    text = body.strip().lower()
    if not text:
        return False

    # A BOM is not whitespace, so `.strip()` leaves it in place and the body
    # stops "looking like JSON" on its first character alone. A failing service
    # behind a proxy that prepends anything — a BOM, an XSSI guard — therefore
    # skipped the truncated-JSON guard entirely and fell into word matching,
    # which is exactly the half-delivered-response case that guard exists for.
    # Until none remain, not once in tuple order. A single ordered pass left
    # residue for a BOM *behind* a guard string, for a guard repeated by two
    # layered proxies, and for guards arriving out of tuple order — and residue
    # means the body stops looking like JSON, which drops it into word matching:
    # the exact half-delivered-response case this guard exists to catch.
    for _ in range(_MAX_PREFIX_STRIPS):
        stripped = text.lstrip("﻿").lstrip()
        for prefix in _JSON_PREFIXES:
            if stripped.startswith(prefix):
                stripped = stripped[len(prefix):]
                break
        if stripped == text:
            break
        text = stripped
    looks_like_json = text[:1] in ("{", "[")
    try:
        payload = json.loads(text, object_pairs_hook=_object_pairs)
    except RecursionError:
        payload = None
    except ValueError:
        payload = None

    if payload is None and looks_like_json:
        # A truncated or invalid JSON body is not a plain-text health answer,
        # and must not be handed to word matching: `{"status":"UP"` with the
        # brace never closed would be read as healthy off the marker word
        # alone, which is exactly how a half-delivered response from a failing
        # service gets mistaken for a report that it is fine.
        return False

    verdicts = _collect_health_verdicts(payload)
    if verdicts:
        # EVERY recognised health key must agree, at any depth. Reading only the
        # first one called `{"ok": true, "state": "failed"}` healthy; reading
        # only the top level called `{"ok": true, "checks": {"db": {"state":
        # "failed"}}}` healthy. A body that contradicts itself anywhere gets
        # the pessimistic reading.
        #
        # Duplicate keys are caught precisely, while the pairs are still
        # visible, rather than by scanning the raw text for failure words. That
        # scan looked safer than it was: a healthy body carrying metadata like
        # `"failure_count": 0` would have been read as unhealthy, which fails
        # closed in the worst place — it would block a genuine recovery from
        # ever being verified.
        return all(verdicts)

    if payload is not None:
        # It parsed, and it answered nothing this reader recognises. Handing it
        # to word matching would scan the raw text including KEY NAMES, so a
        # body like `{"healthy_check_name": "x"}` would be read as healthy off
        # a name. A structured body that declines to state a verdict is not a
        # statement of health.
        return False

    return _text_is_healthy(text)


def probe(url: str) -> tuple[int, bool, str]:
    """(status, healthy, body) for a read-only probe. One place, one rule.

    Every caller that decides whether a service is up goes through this, so the
    rule "HTTP 200 **and** a body that says so" exists once. It was previously
    declared and then never called, while five sites open-coded the same
    conjunction — which meant a defect in the rule had to be fixed five times.
    """
    status_code, body = probe_health(url)
    return status_code, status_code == 200 and body_is_healthy(body), body


def probe_health(url: str) -> tuple[int, str]:
    """Read a health body under a hard byte bound.

    Streamed and stopped at the bound rather than buffered whole and measured
    afterwards. A probe target may be failing in exactly the way we are trying
    to detect, including by answering with an unbounded body; `response.text`
    would have materialised all of it into the investigator's memory before
    anything got the chance to reject it.

    A truncated read returns a fixed marker string rather than the fragment.
    The previous approach — keep one byte past the bound and let the length
    check notice — did not survive contact with reality: `.strip()` removed the
    sentinel byte whenever the body ended in whitespace, and a multi-byte body
    decoded to roughly half its byte count, so 128 KiB of two-byte characters
    arrived as 32 769 characters and sailed under a 65 536-character bound. The
    fragment was then word-matched, and a large error dump whose failure words
    happened to fall past the cut read as healthy. Signalling truncation
    explicitly cannot be undone by decoding.
    """
    try:
        with httpx.stream(
            "GET", url, timeout=PROBE_TIMEOUT, follow_redirects=True
        ) as response:
            chunks: list[bytes] = []
            read = 0
            for chunk in response.iter_bytes(chunk_size=READ_CHUNK_BYTES):
                chunks.append(chunk)
                read += len(chunk)
                if read > MAX_HEALTH_BODY_BYTES:
                    break
            if read > MAX_HEALTH_BODY_BYTES:
                return response.status_code, TRUNCATED_BODY
            return (
                response.status_code,
                b"".join(chunks).decode("utf-8", "replace").strip(),
            )
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


#: Bounds on reading a health body. A probe response is untrusted input from a
#: service that may be misbehaving in exactly the way we are trying to detect,
#: so it must not be able to exhaust the reader: an unbounded walk over deeply
#: nested JSON raises RecursionError, which would crash the investigator or the
#: verifier instead of returning "unhealthy".
MAX_HEALTH_BODY_BYTES = 64 * 1024
MAX_HEALTH_DEPTH = 20
#: Read size for the streamed probe. Without it httpx yields whatever the
#: transport hands over, so a single decoded chunk can be megabytes and the
#: bound is only discovered after that chunk is already in memory — the same
#: defect as buffering, arriving one chunk later.
READ_CHUNK_BYTES = 8 * 1024

#: What a probe returns instead of an oversized body. Deliberately contains no
#: health marker, so every reader of it fails closed without needing to know
#: that truncation is a special case.
TRUNCATED_BODY = "unreadable: health response exceeded the readable bound"

#: A failing probe is confirmed once before it counts as evidence.
CONFIRM_UNHEALTHY_AFTER_SECONDS = 3.0

#: Worst-case wall time for one `gather_evidence`: the service description, the
#: live probe, the confirming sleep, the second live probe, and the candidate
#: probe. Derived rather than written down, so it cannot drift away from the
#: timeouts above the way the investigator's 30s deadline drifted away from the
#: 43s of work it was supposed to bound.
GATHER_EVIDENCE_WORST_CASE_SECONDS = (
    ADMIN_CALL_TIMEOUT
    + PROBE_TIMEOUT
    + CONFIRM_UNHEALTHY_AFTER_SECONDS
    + PROBE_TIMEOUT
    + PROBE_TIMEOUT
)

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
