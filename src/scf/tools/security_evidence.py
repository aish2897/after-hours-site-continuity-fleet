"""Security / Identity Investigator evidence. Read-only, and real.

Reads the target's actual Cloud Run IAM policy and ingress posture through the
Admin API under a scoped, read-only identity. No mutation surface exists here:
this module can call `getIamPolicy` and `get`, and there is no code path to
`setIamPolicy` or to any update.

What it is for: a duty manager reporting "staff keep getting sign-in errors"
cannot tell an identity problem from an application problem. The facts that
distinguish them are who may invoke the service, whether it is exposed publicly,
and whether it demands authentication — all of which are readable, and none of
which require guessing.

It may NOT propose actions. `agent_registry.json` records that
(`may_propose_actions: false`), and the deterministic gate would refuse anything
it produced regardless. Its job is to describe the identity posture, not to
decide what to do about it.
"""

from __future__ import annotations

from typing import Any

import google.auth
import google.auth.transport.requests
import httpx

from scf import config
from scf.domain.enums import TrustLevel
from scf.domain.models import Evidence

AGENT = "security"
RUN_API = "https://run.googleapis.com/v2"
TIMEOUT_SECONDS = 10.0

#: Members that mean "anyone at all". Their presence on an invoker binding is
#: the difference between a private service and one the whole internet can call.
PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})


def _ev(key: str, value: object, supports: str) -> Evidence:
    return Evidence(
        key=key,
        value=value,
        supports=supports,
        source_agent=AGENT,
        trust_level=TrustLevel.TRUSTED_TOOL,
    )


def _token() -> str:
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


def _get(url: str) -> tuple[int, dict[str, Any]]:
    try:
        response = httpx.get(
            url,
            headers={"Authorization": f"Bearer {_token()}"},
            timeout=TIMEOUT_SECONDS,
        )
    except httpx.HTTPError as exc:
        return 0, {"error": type(exc).__name__}
    try:
        body = response.json()
    except ValueError:
        body = {}
    return response.status_code, body if isinstance(body, dict) else {}


def gather_evidence(service: str = config.DISPATCH_WEB_SERVICE) -> list[Evidence]:
    """Identity posture of the target, as Google actually reports it."""
    described_status, described = _get(f"{RUN_API}/{_service_path(service)}")
    policy_status, policy = _get(f"{RUN_API}/{_service_path(service)}:getIamPolicy")

    bindings = policy.get("bindings") or []
    invoker_members: list[str] = []
    for binding in bindings:
        if binding.get("role") == "roles/run.invoker":
            invoker_members.extend(binding.get("members") or [])

    public = sorted(set(invoker_members) & PUBLIC_MEMBERS)
    named = sorted(m for m in invoker_members if m not in PUBLIC_MEMBERS)

    # A read that FAILED is not a clean bill of health, and must not read as one.
    readable = policy_status == 200 and described_status == 200

    return [
        _ev("security_target_service", service, "the service whose posture was read"),
        _ev("iam_policy_readable", readable,
            "whether the identity posture could actually be read"),
        _ev("invoker_binding_count", len(invoker_members),
            "how many principals may invoke the service"),
        _ev("public_invokers", public,
            "bindings that permit anyone — empty is the expected state"),
        _ev("named_invokers", named[:6],
            "the specific principals permitted to invoke"),
        _ev("publicly_invokable", bool(public),
            "whether the service is reachable without authentication"),
        _ev("ingress", described.get("ingress"),
            "Cloud Run ingress setting"),
        _ev("service_generation", described.get("generation"),
            "generation of the observed service configuration"),
        # The conclusion the orchestrator reads. Deliberately conservative: an
        # unreadable policy is reported as "not confirmed sound", never as sound.
        _ev(
            "identity_posture_sound",
            bool(readable and not public),
            "the service requires authentication and no binding opens it to "
            "everyone — confirmed by reading the live policy, not assumed",
        ),
    ]
