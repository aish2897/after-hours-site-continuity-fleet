"""The only code in this project that mutates infrastructure.

Runs exclusively under sa-executor, whose scfRemediator role is bound to the
dispatch-web service resource alone. Any other target is refused by Google
IAM, not by a check in this file.

## Why the Knative v1 API rather than v2

The Cloud Run **v2** `services.patch` call does not enforce `Service.etag` as
an update precondition for a traffic change. Tested live against the real
service, a stale etag in the body, a stale `If-Match:` header, and an entirely
bogus etag string were all accepted with HTTP 200 and the traffic actually
moved. No optimistic-concurrency claim can rest on it.

The **v1** `namespaces.services.replaceService` call does enforce
`metadata.resourceVersion`: a stale value is rejected by Google with HTTP 409
ABORTED and the service is left untouched. Both were proven against the same
live service; see `docs/evidence/gate-d3a-cloud-run-resourceversion-cas.md`.

The mutation therefore deliberately uses v1. This is a positive selection of
the operation that provides the concurrency property the architecture requires,
made under the permissions already held — it needed no additional IAM.
"""

from __future__ import annotations

import copy
from typing import Any

import google.auth
import google.auth.transport.requests
import httpx

from scf import config

#: Read-only descriptions elsewhere in the codebase use v2. Only the mutation
#: is pinned to v1, and only because v1 is where the precondition is enforced.
RUN_API_V2 = "https://run.googleapis.com/v2"

#: The Knative surface is regional-endpoint only; the global host will not
#: serve it for a regional service.
KNATIVE_API = (
    f"https://{config.CLOUD_RUN_REGION}-run.googleapis.com/apis/serving.knative.dev/v1"
)

#: Output-only metadata Google generates per write. Echoing these back is at
#: best noise and at worst a rejected request. `resourceVersion` is emphatically
#: NOT in this set: it is the compare-and-set precondition.
SERVER_ONLY_METADATA = ("selfLink", "uid", "creationTimestamp", "generation")

#: Operation bookkeeping the server stamps on the previous write.
SERVER_ONLY_ANNOTATIONS = ("run.googleapis.com/operation-id",)


class ServiceSnapshotError(RuntimeError):
    """The Service representation is not safe to build a replacement from."""


def _token() -> str:
    credentials, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    credentials.refresh(google.auth.transport.requests.Request())
    return credentials.token


def _knative_url(service: str) -> str:
    return f"{KNATIVE_API}/namespaces/{config.PROJECT_ID}/services/{service}"


def read_service_v1(service: str) -> dict[str, Any]:
    """Authorized read of the Service, and the only source of resourceVersion.

    The precondition token must come from a real read performed by the identity
    that is about to mutate. It is never accepted from a request body, never
    cached across a lost lease, and treated as opaque.
    """
    response = httpx.get(
        _knative_url(service),
        headers={"Authorization": f"Bearer {_token()}"},
        timeout=30.0,
    )
    response.raise_for_status()
    return response.json()


def resource_version_of(snapshot: dict[str, Any]) -> str:
    return str((snapshot.get("metadata") or {}).get("resourceVersion") or "")


def traffic_of(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    return list(((snapshot.get("spec") or {}).get("traffic")) or [])


def build_traffic_replacement(
    snapshot: dict[str, Any], revision: str
) -> dict[str, Any]:
    """Derive a replacement Service that changes traffic and nothing else.

    A replace call sends the whole object, so a naive `PUT` of the raw `GET`
    body is dangerous in two specific ways, both handled here:

    1. `spec.template.metadata.name` is absent from the read representation. Sent
       that way, Cloud Run treats the template as new and mints a fresh
       revision — a configuration change smuggled inside a traffic rollback.
       It is pinned to the revision the current template already produced, so
       the template resolves to something that exists and nothing is created.
    2. Traffic tags are part of `spec.traffic`. Rebuilding that list naively
       drops the `known-good` tag, which is the operator-applied marker the
       investigator's candidate probe depends on. Tag entries are carried
       across verbatim.

    Everything else — image, runtime service account, environment, ingress,
    scaling, labels — is copied from the authorized snapshot untouched.
    """
    replacement = copy.deepcopy(snapshot)
    # `status` is server-owned observation, not desired state.
    replacement.pop("status", None)

    metadata = replacement.get("metadata") or {}
    for field in SERVER_ONLY_METADATA:
        metadata.pop(field, None)
    annotations = metadata.get("annotations") or {}
    for field in SERVER_ONLY_ANNOTATIONS:
        annotations.pop(field, None)
    if not metadata.get("resourceVersion"):
        raise ServiceSnapshotError("snapshot carries no resourceVersion precondition")
    replacement["metadata"] = metadata

    spec = replacement.get("spec") or {}
    template = spec.get("template") or {}
    template_metadata = template.get("metadata") or {}
    pinned = template_metadata.get("name") or (
        (snapshot.get("status") or {}).get("latestCreatedRevisionName")
    )
    if not pinned:
        raise ServiceSnapshotError(
            "cannot pin spec.template.metadata.name; refusing to risk a new revision"
        )
    template_metadata["name"] = pinned
    template["metadata"] = template_metadata
    spec["template"] = template

    # 100% to the authorized revision, plus every tag entry unchanged. Tag-only
    # entries carry no percent and so receive no traffic.
    tags = [entry for entry in traffic_of(snapshot) if entry.get("tag")]
    spec["traffic"] = [{"revisionName": revision, "percent": 100}] + [
        {k: v for k, v in entry.items() if k != "percent"} for entry in tags
    ]
    replacement["spec"] = spec
    return replacement


def flip_traffic_to_revision(
    service: str, revision: str, snapshot: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Migrate 100% of traffic to a named revision, under resourceVersion CAS.

    `snapshot` is the authorized read taken after the caller's final ownership
    check. Passing it in is deliberate: the executor must not be able to paper
    over a lost lease by fetching a fresher precondition here.
    """
    snapshot = snapshot if snapshot is not None else read_service_v1(service)
    sent_version = resource_version_of(snapshot)
    body = build_traffic_replacement(snapshot, revision.rsplit("/", 1)[-1])

    response = httpx.put(
        _knative_url(service),
        headers={"Authorization": f"Bearer {_token()}"},
        json=body,
        timeout=60.0,
    )

    base = {
        "service": service,
        "revision": revision,
        "api": "serving.knative.dev/v1 replaceService",
        "resource_version_sent": sent_version,
        "http_status": response.status_code,
    }

    if response.status_code == 409:
        # Google refused the write because the Service moved on. Nothing was
        # overwritten. This is the platform enforcing the precondition, not an
        # application-level check.
        return {
            **base,
            "accepted": False,
            "conflict": True,
            "error": response.text[:400],
        }
    if response.status_code >= 400:
        return {**base, "accepted": False, "conflict": False, "error": response.text[:400]}

    # The executor deliberately does NOT poll to declare victory. The component
    # that acts must not grade its own work: recovery is established by the
    # independent verifier observing the live service under a different,
    # read-only identity.
    return {
        **base,
        "accepted": True,
        "conflict": False,
        "resource_version_after": resource_version_of(response.json()),
    }
