# Gate D.3A — Cloud Run v1 `resourceVersion` optimistic concurrency

**Status: PASSED — feasibility proven**

Sanitized. No credentials, no tokens. Feasibility test only; none of D3.1–D3.3
was implemented.

## Why this test exists

Gate D.3 stopped at D3.4 because Cloud Run **v2** does not enforce
`Service.etag` as an update precondition on the traffic PATCH.

Recap of that result (`docs/evidence/gate-d2-execution-correctness.md` and the
D.3 stop report):

| Attempt against v2 `services.patch` | Result |
|---|---|
| Stale `etag` in body | **HTTP 200 accepted**, traffic actually changed |
| Stale `etag` via `If-Match:` header | **HTTP 200 accepted** |
| Bogus `etag` `"THIS-IS-NOT-A-VALID-ETAG"` | **HTTP 200 accepted** |

The third case is conclusive: v2 does not validate the field at all on this
call. No CAS claim was made.

## What was tested here

Cloud Run Admin API **v1**, `namespaces.services.replaceService`:

```
PUT https://australia-southeast1-run.googleapis.com
    /apis/serving.knative.dev/v1/namespaces/site-continuity-fleet/services/dispatch-web
```

with `metadata.resourceVersion` carried from the last read.

## D3A.1 — v1 representation

```
apiVersion      : serving.knative.dev/v1
kind            : Service
resourceVersion : AAZZJpwmJn4          <- version A
generation      : 31
traffic         : 100% dispatch-web-00003-x87
                  tag known-good -> dispatch-web-00003-x87
runtime SA      : sa-dispatch-web@…
latestCreatedRevisionName : dispatch-web-00004-jqm
```

`resourceVersion` was treated as opaque and never manufactured or modified.

`spec.template.metadata.name` is null in the GET representation, so a naive
replace would have minted an unwanted revision. The payload therefore pins
`spec.template.metadata.name = dispatch-web-00004-jqm`, the existing latest
revision, keeping the change traffic-only.

## D3A.3 — stale `resourceVersion`: **REJECTED BY GOOGLE**

1. Captured version **A = `AAZZJpwmJn4`** while traffic was `00003-x87`.
2. Controlled second actor moved traffic to `dispatch-web-00004-jqm`.
3. Re-read: version **B = `AAZZJrWF8/E`**, `A != B` confirmed, live service
   returning `503` from `00004-jqm`.
4. As the real `sa-executor` identity, submitted `replaceService` using the
   **stale representation A**, attempting to move traffic to `00003-x87`.

```
HTTP 409
{
  "error": {
    "code": 409,
    "message": "Conflict for resource 'dispatch-web': version '1786872223639166'
                was specified but current version is '1786872645876013'.",
    "status": "ABORTED"
  }
}
```

**Infrastructure after the rejected request — unchanged:**

```
HTTP/1.1 503 Service Unavailable
x-revision: dispatch-web-00004-jqm
traffic: 100% dispatch-web-00004-jqm, tag known-good -> dispatch-web-00003-x87
```

The stale snapshot did **not** overwrite the newer Service version. This is
platform-enforced optimistic concurrency, not an application check.

## D3A.4 — current `resourceVersion`: succeeds cleanly

Re-read gave current version `AAZZJrWF8/E`; the authorized update was
submitted with that exact value as `sa-executor`.

```
HTTP 200
new resourceVersion : AAZZJrh/VzY
traffic spec        : 100% dispatch-web-00003-x87
                      tag known-good -> dispatch-web-00003-x87
```

Live service afterwards: `HTTP 200`, `x-revision: dispatch-web-00003-x87`.

### Configuration diff — only traffic changed

| Property | Result |
|---|---|
| runtime service account | UNCHANGED |
| container image | UNCHANGED |
| environment (`SERVICE_MODE`) | UNCHANGED |
| ingress | UNCHANGED |
| maxScale | UNCHANGED |
| labels | UNCHANGED |
| `latestCreatedRevisionName` | UNCHANGED |
| **traffic** | **CHANGED (intended)** |

**Revision count 4 → 4.** No revision was created. The `known-good` tag
survived the replace, which the investigator's candidate probe depends on.

## D3A.5 — IAM scope unchanged

**No IAM was changed for this gate.** The v1 operation succeeded under the
existing resource-scoped role:

```
scfRemediator = run.services.get, run.services.update
  bound on the dispatch-web service resource only
```

`sa-executor` project-level roles remain `scfDecisionReader`,
`scfExecutionWriter`, `roles/logging.logWriter` — no Cloud Run project role.

Blast radius re-tested against the unrelated service via **v1**:

```
GET  site-directory as sa-executor -> 403 PERMISSION_DENIED  run.services.get
PUT  site-directory as sa-executor -> 403 PERMISSION_DENIED  run.services.update
```

Changing API version did not widen authority.

## D3A.6 — recommendation

`resourceVersion` optimistic concurrency is genuinely enforced by Google on
v1 `replaceService`, under the permissions we already hold, without creating
revisions or drifting configuration.

Recommended as the executor's mutation primitive for the remainder of Gate D.3.
This is a deliberate selection of the Cloud Run operation that provides the
concurrency property the security architecture requires — not a fallback and
not a workaround:

- v2 `services.patch` empirically ignores `etag` on this call;
- v1 `replaceService` documents and empirically enforces `resourceVersion`;
- both were tested live against the same real service.

Read paths may continue to use v2 where convenient; the *mutation* moves to v1.

## D3A.7 — what is and is not claimed

Claimed once D.3 is implemented on this primitive:

- Firestore fencing prevents a stale worker from advancing execution state.
- Cloud Run `resourceVersion` OCC prevents a stale Service snapshot from
  overwriting a newer Service version.
- Reconciliation handles crash boundaries.
- Together these are **layered stale-worker protection**.

Still **not** claimed:

- distributed exactly-once execution;
- transactional coupling of Firestore and Cloud Run;
- protection against compromise of the authoritative control-plane writer.

## Residual note

OCC narrows, but does not by itself eliminate, the stale-worker window: a
worker that read version B, was fenced out, and then submitted using B could
still succeed if nothing else advanced the Service in between.

**Correction, recorded after Gate D.3 was implemented:** an earlier draft of
this note said Firestore fencing "closes that case". It does not. Fencing stops
a stale worker advancing execution state, renewing, or writing a receipt — it
does not stop it reaching the Cloud Run API, and it is not what gates
terminalization. Terminalization is gated on an independent verifier verdict,
the executor's own re-observation of the live service, and a compare-and-set on
the expected state. *(This sentence originally said "or terminalizing", which
was never true — `terminalize()` takes no owner and no `lease_epoch`. Corrected
after Gate E.)* The window is narrowed by both
layers and closed by neither alone. See the D3.5 section of
[`gate-d3-lease-fencing-cas.md`](gate-d3-lease-fencing-cas.md) for the property
that is actually defended.
