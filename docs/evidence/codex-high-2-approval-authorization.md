# Codex High 2 — approval authorization

**Finding.** The approval endpoints lived on the orchestrator — the service every
agent in the fleet can already reach — and the identity of the approver was taken
from the request rather than established. The audit chain recorded
`demo-approver@site-continuity-fleet.invalid`, a name the code invented.

Two separate defects sat under one heading: *authentication is not
authorization*, and *a name in a record is not a verified identity*.

Date: 2026-08-22. Project `site-continuity-fleet`, `australia-southeast1`.

---

## What was attempted first, and why it was abandoned

**Cloud Run does not forward a verifiable caller token to the container.** The
`Authorization` header the platform passes through is not one the application can
verify — both a user credential and an audience-scoped service-account token
produced the same result inside the container:

```
MalformedError: Could not verify token signature
```

So the orchestrator could never have known who was calling. The original code was
not merely trusting the wrong header; there was no header it could have trusted.

**Direct IAP on Cloud Run was attempted and blocked.** `gcloud run deploy --iap`
deployed, then served:

```
health -> HTTP 502
Empty Google Account OAuth client ID(s)/secret(s).
```

IAP requires an OAuth brand and client, and the `gcloud iap oauth-brands` /
`oauth-clients` commands that create them are deprecated. This was time-boxed and
dropped rather than pursued.

**No security boundary was weakened to get past either.** The fallback below is
stronger than the original design, not weaker.

---

## What was built instead

A separate Cloud Run service, `scf-approval`, exposing three routes and nothing
else: `/health`, `POST /approvals/{id}/approve`, `POST /approvals/{id}/reject`.
No intake, no routing, no executor call, no resume.

`roles/run.invoker` on that service is held by exactly one member:

```
roles/run.invoker -> ['user:arslanali.2897@gmail.com']
```

No fleet service account holds it. **"An autonomous identity cannot approve an
autonomous decision" is now a property of Google Cloud IAM rather than a property
of this repository's code.** A bug in the orchestrator cannot grant approval
authority the orchestrator was never given.

The two write endpoints were removed from the orchestrator. Reading an approval
stays there, because reading authorizes nothing:

```
orchestrator POST /approvals/{id}/approve -> 404
orchestrator POST /approvals/{id}/reject  -> 404
```

One door.

---

## The live attack matrix

| # | Caller | Result |
|---|---|---|
| 1 | configured human principal | **200** — approval recorded |
| 2 | authenticated principal not on the invoker list | **403** (six identities, below) |
| 3 | `sa-orchestrator` | **403** |
| 4 | `sa-agent-systems` | **403** |
| 5 | `sa-executor` | **403** |
| 6 | `sa-verifier` | **403** |
| 6a | `sa-agent-network` | **403** |
| 6b | `sa-agent-security` | **403** |
| 7 | unauthenticated | **403** |
| 8 | spoofed `X-Goog-Authenticated-User-Email` + forged `X-Goog-IAP-JWT-Assertion` + `X-User`, no bearer token | **403** |
| 9 | valid approval to resume to mutation | **RESOLVED**, generation 368 to 369 |
| 10 | duplicate approval | `ALREADY_DECIDED`, generation unchanged |

Items 3–6b were also re-run against the **real pending approval id** rather than a
synthetic one, with the same result. The refusal happens at the Cloud Run edge,
before any application code runs, so the approval id is not material — but the
run was done both ways rather than assumed.

**On item 2, honestly:** this project has one human Google account. The six
service accounts above *are* authenticated Google principals that are not on the
invoker list, and that is what item 2 tests. A second human account was not
created, so "a different person is refused" is demonstrated by identity type, not
by a second person.

### Harness note on items 3, 6, 6a, 6b

Minting an identity token for those four required
`roles/iam.serviceAccountTokenCreator` for the human principal on each service
account; two others already carried it from the Gate C denial work. The grant was
made, the proof run, and the grant revoked:

```
gcloud iam service-accounts add-iam-policy-binding SA \
  --member="user:$ME" --role="roles/iam.serviceAccountTokenCreator"
# ... run the probe ...
gcloud iam service-accounts remove-iam-policy-binding SA \
  --member="user:$ME" --role="roles/iam.serviceAccountTokenCreator"
```

This grants a **human** the ability to mint tokens; it grants the fleet nothing,
and it widens no agent's authority. The first attempt returned
`IAM_PERMISSION_DENIED` on bindings identical to a working one — propagation
delay, not a policy failure, confirmed by re-running the same command unchanged
about two minutes later. That is the same trap the Model Armor 403 turned out to
be in Gate G.

---

## The end-to-end run

```
setup     dispatch-web serving broken dispatch-web-00004-jqm
          candidate tag -> dispatch-web-00003-x87
          NO known-good tag              generation 368   target HTTP 503

incident  INC-20260822-64F3B0
routing   required_specialists ["systems"]; network NOT consulted
          ("the screens can load an error page")
proposal  SHIFT_TRAFFIC_TO_APPROVED_CANDIDATE
policy    APPROVAL_REQUIRED / UNBLESSED_CANDIDATE_RISK
decision  DEC-10908176B1
approval  APR-20260822-878B0DD9  PENDING
status    WAITING_FOR_APPROVAL           generation 368   (nothing claimed)

fleet identities against APR-20260822-878B0DD9   -> 403, 403
human   POST /approvals/APR-.../approve          -> 200 DECIDED / APPROVED
duplicate delivery                               -> 200 ALREADY_DECIDED
                                                 generation 368 (approval
                                                 alone mutates nothing)

resume    resumed_by_revision  scf-orchestrator-00166-gd9
          authorized revision  dispatch-web-00003-x87
          execution            replaceService  SUCCEEDED  duplicate false
          verification         healthy, revision matches, traffic exclusive
          terminalization      VERIFIED
          final_status         RESOLVED
                               generation 368 -> 369   target 503 -> 200

duplicate resume after RESOLVED -> resumed: false, generation 369
```

Exactly one mutation.

---

## What the audit chain records

```
approver_principal: "PLATFORM_IAM (role incident_commander, service scf-approval)"
```

Not an email. The service does not know which human pressed the button, so it
does not claim to. It records the authority that actually applied.

When an IAP assertion **is** present, `verified_iap_principal()` verifies the
signature against `https://www.gstatic.com/iap/verify/public_key`, checks
`iss == "https://cloud.google.com/iap"` and the audience, and only then reads the
email from the claims — and the resulting principal must additionally appear in
the configured role bindings, or the request is refused with 403. That path is
implemented and unit-tested. **It is not live in this deployment**, because IAP is
not in front of the service.

The plain `X-Goog-Authenticated-User-Email` header is never read anywhere in the
service. That is checked against the parsed AST rather than the text of the file,
because the module docstring names the header in order to say it is not trusted.

---

## What this does and does not establish

**Does:** no autonomous identity in this fleet can approve an autonomous
decision, and that is enforced by Google Cloud IAM at the service boundary rather
than by application logic. A forged header cannot authorize anything. A duplicate
approval is not a second permission. Approval alone changes no infrastructure.

**Does not:** this deployment does not separately verify *which human* approved.
Cloud Run IAM proves the caller is the one principal holding `run.invoker`; the
application does not independently establish an end-user identity on top of that,
and the record says so instead of inventing a name.

`required_approval_role` is carried on the decision and recorded on the approval.
It is enforced against configured bindings **only on the IAP path**. On the live
IAM-only path the role is recorded, and the actual gate is Cloud Run IAM on
`scf-approval`. It is not a second, independent check today.

---

## Suite

**Offline: 578 passed, 11 skipped** — no cloud credentials required.

The four new tests cover the separated surface: that the orchestrator no longer
hosts an approval door, that the service reads no unsigned identity header, that
the record names the authority rather than a person when IAP is absent, and that
a verified IAP principal must still be bound to the required role.
