"""Model Armor screening for untrusted text, ahead of the model.

Where this sits, and why it sits there
--------------------------------------

A duty manager's report is `UNTRUSTED_INPUT`. It is screened by Google Model
Armor **before** it reaches Gemini, not after:

    report -> UNTRUSTED_INPUT -> Model Armor -> (only if acceptable) -> Gemini

Screening after the model would be theatre. The model has already read the
hostile text by then, and a verdict arriving afterwards can only describe what
already happened.

What this is NOT
----------------

Model Armor is a filter, never an authorization. Its verdict cannot approve a
remediation, cannot satisfy a required-evidence condition, and never becomes
`TRUSTED_TOOL` evidence. Nothing in this module returns anything the policy gate
reads. The Golden Rule is unchanged:

    LLM PROPOSES. DETERMINISTIC POLICY DECIDES. SCOPED IDENTITY EXECUTES.

That matters for the honest claim. This does not make prompt injection
impossible, and no such claim is made anywhere. It is one layer; privileged
action still requires trusted evidence gathered by a scoped identity, a
deterministic policy decision, an exact pinned authorization, and IAM that
bounds the blast radius. The system is designed to be safe when this layer
misses — proven separately, because a defence you cannot afford to lose is not
a defence, it is a dependency.

Region
------

`asia-southeast1` (Singapore). Melbourne `australia-southeast2` was the original
plan and cannot serve this purpose: template-based Model Armor there offers
Sensitive Data Protection only, without the prompt-injection detector this gate
exists to add. Screening therefore leaves Australia, and the residency claim in
the documentation says so rather than rounding it off.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

import google.auth
import google.auth.transport.requests
import httpx

from scf import config

#: Regional endpoint. Model Armor is addressed per-region and the global host
#: does not serve these calls — the `gcloud` CLI targets the wrong one and fails
#: with PERMISSION_DENIED even for a project Owner, which is worth knowing
#: before concluding a permission is missing.
API_HOST = "https://modelarmor.{location}.rep.googleapis.com/v1"

#: One bounded attempt. A screening call that hangs must not hold an incident
#: open: the caller fails closed instead, which is the safe direction, and a
#: retry loop here would turn a security control into an availability problem.
TIMEOUT_SECONDS = 10.0
SCREENING_RETRY_BUDGET = 0

#: The filter whose absence means this screening did not do its job. The whole
#: point of the region choice was to get this detector; a response without it
#: has not screened for the thing being screened for.
REQUIRED_FILTER = "pi_and_jailbreak"


class ScreeningUnavailable(Exception):
    """Screening could not be completed. Never means "the text was fine"."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ModelArmorResult:
    """A screening verdict. Deliberately not an authorization of anything."""

    screened: bool
    allowed: bool
    verdict: str
    triggered_filters: tuple[str, ...] = ()
    template: str = ""
    location: str = ""
    filter_version: str = ""
    #: The screened text, hashed. The raw text is untrusted content that may
    #: itself contain sensitive data, so evidence and logs carry a hash and the
    #: authoritative store carries the report — not both.
    content_sha256: str = ""
    latency_ms: int = 0
    failure_reason: str | None = None
    findings: tuple[str, ...] = field(default=())

    def as_log_fields(self) -> dict[str, Any]:
        """What may safely be logged. No raw prompt, no matched values."""
        return {
            "screened": self.screened,
            "allowed": self.allowed,
            "verdict": self.verdict,
            "triggered_filters": list(self.triggered_filters),
            "findings": list(self.findings),
            "model_armor_template": self.template,
            "model_armor_location": self.location,
            "filter_version": self.filter_version,
            "content_sha256": self.content_sha256,
            "latency_ms": self.latency_ms,
            "failure_reason": self.failure_reason,
        }


def _access_token() -> str:
    credentials, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    credentials.refresh(google.auth.transport.requests.Request())
    return credentials.token


def _template_path() -> str:
    return (
        f"projects/{config.PROJECT_ID}"
        f"/locations/{config.MODEL_ARMOR_LOCATION}"
        f"/templates/{config.MODEL_ARMOR_TEMPLATE}"
    )


def _read_verdict(payload: dict[str, Any], content_hash: str, latency_ms: int) -> ModelArmorResult:
    """Turn the API response into a verdict, failing closed on anything odd."""
    result = payload.get("sanitizationResult")
    if not isinstance(result, dict):
        raise ScreeningUnavailable("malformed_response:no_sanitization_result")

    match_state = result.get("filterMatchState")
    if match_state not in ("MATCH_FOUND", "NO_MATCH_FOUND"):
        # An unrecognised verdict is not permission to proceed.
        raise ScreeningUnavailable(f"malformed_response:match_state={match_state}")

    triggered: list[str] = []
    findings: list[str] = []
    filters = result.get("filterResults")
    if not isinstance(filters, dict):
        raise ScreeningUnavailable("malformed_response:no_filter_results")
    if not filters:
        # No filter ran at all. A response that screened nothing is not a
        # response that found nothing, and a silently mis-scoped template must
        # not read as clean.
        raise ScreeningUnavailable("no_filters_executed")
    if REQUIRED_FILTER not in filters:
        # The detector this gate exists for did not report. Same reasoning.
        raise ScreeningUnavailable(f"required_filter_absent:{REQUIRED_FILTER}")

    for name, wrapper in filters.items():
        if not isinstance(wrapper, dict):
            continue
        for inner in wrapper.values():
            if not isinstance(inner, dict):
                continue
            # A filter that could not run has not cleared the text. Treating a
            # skipped detector as a pass is precisely the fail-open this gate
            # exists to prevent.
            execution = inner.get("executionState")
            if execution and execution != "EXECUTION_SUCCESS":
                raise ScreeningUnavailable(f"filter_not_executed:{name}:{execution}")
            nested = inner.get("inspectResult")
            if isinstance(nested, dict):
                if nested.get("executionState") not in (None, "EXECUTION_SUCCESS"):
                    raise ScreeningUnavailable(f"filter_not_executed:{name}")
                if nested.get("matchState") == "MATCH_FOUND":
                    triggered.append(name)
                    findings.extend(
                        str(item.get("infoType"))
                        for item in nested.get("findings", [])
                        if isinstance(item, dict) and item.get("infoType")
                    )
            elif inner.get("matchState") == "MATCH_FOUND":
                triggered.append(name)
                level = inner.get("confidenceLevel")
                if level:
                    findings.append(f"{name}:{level}")

    metadata = result.get("sanitizationMetadata") or {}
    version = (metadata.get("filterVersionConfig") or {}).get("filterVersion", "")

    allowed = match_state == "NO_MATCH_FOUND"
    return ModelArmorResult(
        screened=True,
        allowed=allowed,
        verdict=match_state,
        triggered_filters=tuple(sorted(set(triggered))),
        template=config.MODEL_ARMOR_TEMPLATE,
        location=config.MODEL_ARMOR_LOCATION,
        filter_version=str(version),
        content_sha256=content_hash,
        latency_ms=latency_ms,
        findings=tuple(sorted(set(findings))),
    )


def _sanitize(endpoint: str, body: dict[str, Any], text: str) -> ModelArmorResult:
    content_hash = sha256(text.encode("utf-8")).hexdigest()
    url = (
        f"{API_HOST.format(location=config.MODEL_ARMOR_LOCATION)}"
        f"/{_template_path()}:{endpoint}"
    )
    started = time.perf_counter()
    try:
        response = httpx.post(
            url,
            json=body,
            headers={"Authorization": f"Bearer {_access_token()}"},
            timeout=TIMEOUT_SECONDS,
        )
    except httpx.HTTPError as exc:
        raise ScreeningUnavailable(f"transport:{type(exc).__name__}") from exc
    latency_ms = int((time.perf_counter() - started) * 1000)

    if response.status_code in (401, 403):
        # Never treated as "nothing to see". A screening call this identity is
        # not permitted to make has screened nothing.
        raise ScreeningUnavailable(f"unauthorized:{response.status_code}")
    if response.status_code >= 400:
        raise ScreeningUnavailable(f"http_{response.status_code}")
    try:
        payload = response.json()
    except ValueError as exc:
        raise ScreeningUnavailable("malformed_response:not_json") from exc
    if not isinstance(payload, dict):
        raise ScreeningUnavailable("malformed_response:not_an_object")

    return _read_verdict(payload, content_hash, latency_ms)


def screen_untrusted_text(text: str) -> ModelArmorResult:
    """Screen a duty manager's report BEFORE any of it reaches the model."""
    from scf import faults

    if faults.is_mode(faults.MODEL_ARMOR_UNAVAILABLE):
        # Test-only, env-selected, never reachable from request data.
        raise ScreeningUnavailable("FAULT INJECTION: screening unreachable")
    if faults.is_mode(faults.MODEL_ARMOR_MALFORMED):
        return _read_verdict({"sanitizationResult": {"filterMatchState": "???"}},
                             sha256(text.encode("utf-8")).hexdigest(), 0)
    return _sanitize("sanitizeUserPrompt", {"userPromptData": {"text": text}}, text)


def screen_model_response(text: str) -> ModelArmorResult:
    """Screen what the model produced, before the workflow acts on it.

    NOT WIRED INTO THE LIVE PATH. Implemented and tested, and deliberately not
    claimed as verified: today the routing output is a typed schema and the
    remediation proposal is produced deterministically, so the schema and the
    deterministic gate are what constrain the model's output. Wiring this in
    front of them is a real improvement and it has not been done yet.
    """
    return _sanitize(
        "sanitizeModelResponse", {"modelResponseData": {"text": text}}, text
    )
