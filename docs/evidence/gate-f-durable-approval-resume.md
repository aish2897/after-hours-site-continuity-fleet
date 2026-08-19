# Gate F — durable human approval, process restart, resume

**Status: VERIFIED — live end-to-end proof; external Codex catch-up audit pending
when quota restores**

Sanitized. No credentials, no bearer tokens, no model reasoning. Synthetic data
only. Every state below was read back from Firestore by a process that did not
create it.

## What is being demonstrated

A high-risk action that a person must authorize, where the authorization
survives the death of the process that asked for it.

The claim is not "there is an approve button". It is that the authority to
change infrastructure comes from a human, is bound to one exact decision, is
verified independently by the component that mutates, and is picked up from
durable state by a process that has never seen the incident before.

---

## F1 — where the approval requirement comes from

It is not a field a caller sets. Untrusted input does not choose its own
authorization regime, and the intake contract has no way to express one: a duty
manager supplies a site and a description, and `extra="forbid"` refuses
anything else.

It is also not a fake dangerous action invented so there is something to refuse.
The distinction is real, and it comes from trusted evidence about the target:

| Situation | Action | Regime |
|---|---|---|
| An operator tagged a revision `known-good`, and it probes healthy | `FLIP_TRAFFIC_TO_LAST_GOOD` | `AUTO_ALLOWED` |
| No such tag exists, but another revision answers a health probe | `SHIFT_TRAFFIC_TO_APPROVED_CANDIDATE` | **`APPROVAL_REQUIRED`** |

Rolling back to a revision an operator blessed in advance is reversible and
pre-approved. Moving production traffic to a revision that merely *answers* is a
judgement about which version the business should be running — the system has
checked that it responds, and that is not the same thing.

Both use the identical mutation primitive: Cloud Run v1 `replaceService`, exact
revision pinning, `resourceVersion` optimistic concurrency, the same
resource-scoped `sa-executor`, the same independent verifier. Nothing new was
added to the blast radius to create risk.

```
policy_version 1.2.0
SHIFT_TRAFFIC_TO_APPROVED_CANDIDATE | cloud_run_service_non_critical
  -> APPROVAL_REQUIRED  reason_code UNBLESSED_CANDIDATE_RISK
  required_approval_role incident_commander
  required_evidence  service_unhealthy: true
                     candidate_revision_approved: false
                     fallback_candidate_probe_healthy: true
```

---

## F6 — the incident parks, durably, having claimed nothing

Setup: `dispatch-web` serving a broken revision, **no `known-good` tag**, and one
healthy revision addressable through a `candidate` tag.

```
REVISION A                   scf-orchestrator-00148-j8n
live target                  HTTP 503        generation 348
incident                     INC-20260819-39A4B4
proposal                     SHIFT_TRAFFIC_TO_APPROVED_CANDIDATE
policy                       APPROVAL_REQUIRED / UNBLESSED_CANDIDATE_RISK
decision                     DEC-61D4C330F8
approval                     APR-20260819-D79093FC   PENDING
incident status              WAITING_FOR_APPROVAL
executor                     NOT CALLED
generation                   348  (unchanged)
```

Nothing was claimed: no executor invocation, no execution-state ownership, no
mutation, no automatic approval.

### What the duty manager is shown

Generated deterministically from the pinned decision — no model output reaches
it. The revision identifiers exist, and are kept out of the default view.

```
Automatic recovery found a higher-impact action that needs your approval.

What will happen        Traffic will move to a version of the dispatch service
                        that is currently answering normally.
Why you are being asked No version has been marked known good, so the system
                        cannot tell on its own which one the business should be
                        running. It has checked that this one responds
                        correctly, but choosing it is your call.
Scope                   The dispatch-web service only.
What will NOT happen    No other service at your site can be changed by this
                        action. No data is deleted, and the change can be
                        reversed.
Choices                 APPROVE RECOVERY | ESCALATE INSTEAD

technical_detail (collapsed by default)
  action_type   SHIFT_TRAFFIC_TO_APPROVED_CANDIDATE
  target_ref    dispatch-web
  revision      dispatch-web-00003-x87
```

---

## F7 — the process that asked is replaced

```
REVISION B deployed          scf-orchestrator-00149-zbh   serving 100%
```

Read back, by the new process:

```
incident   WAITING_FOR_APPROVAL    served_by scf-orchestrator-00149-zbh
approval   PENDING                 served_by scf-orchestrator-00149-zbh
target     HTTP 503                generation 348
```

The revision that created the waiting state is no longer serving. The state came
from Firestore, not from memory.

---

## F12-G — reaching the executor is not authorization

Called directly, with a valid Google identity token, while the incident waits:

```
POST /execute {incident_id: INC-20260819-39A4B4, decision_id: DEC-61D4C330F8}
-> {mutated: false, refused: true, reason: "approval_state:PENDING"}
   generation 348 (unchanged)
```

The executor verified the approval **itself**, against the authoritative plane.
The orchestrator checks too, and that is defence in depth rather than a
substitute: a compromised or simply buggy orchestrator must not be able to talk
this executor into mutating something no person agreed to.

---

## F8 / F11 — the human decision, and its idempotency

Performed on revision B, after the restart:

```
POST /approvals/APR-20260819-D79093FC/approve
-> outcome DECIDED   state APPROVED
   approver_principal demo-approver@site-continuity-fleet.invalid

delivery 2 -> outcome ALREADY_DECIDED  state APPROVED
delivery 3 -> outcome ALREADY_DECIDED  state APPROVED

generation 348 (approval alone mutates nothing)
```

A person pressed the button once. A retried request is not a second permission.

---

## F13 — a second restart, after approval

```
REVISION C deployed          scf-orchestrator-00150-tg2   serving 100%
```

So `WAITING_FOR_APPROVAL` survived one process replacement and `APPROVED`
survived another. The process that executes has seen neither the investigation
nor the human.

---

## F9 / F10 — resume from durable state, and the real recovery

```
POST /incidents/INC-20260819-39A4B4/resume        (identifiers only)

resumed_by_revision      scf-orchestrator-00150-tg2
decision_id              DEC-61D4C330F8            (the same decision)
authorized revision      dispatch-web-00003-x87    (the exact pinned revision)
approval                 APR-20260819-D79093FC  APPROVED
                         by demo-approver@site-continuity-fleet.invalid

mutation                 serving.knative.dev/v1 replaceService   HTTP 200
resourceVersion          AAZZZYs6Gh8 -> AAZZZeD5BV8   conflict false
verification             RECOVERED   healthy   traffic exclusive
terminalization          VERIFIED    serves authorized exclusively
incident                 RESOLVED

target                   HTTP 503 -> HTTP 200
generation               348 -> 349               exactly one mutation
```

No operator ran a `gcloud` command. No human diagnosed anything. The person was
asked one question and answered it.

---

## F12 — approval attack tests

Every one of these ran live against the deployed fleet.

| # | Attack | Result | Mutations |
|---|---|---|---|
| A | Fabricated `approval_id` | HTTP 404 | 0 |
| B | Approval naming a different decision | `decision_id_mismatch` blocker | 0 |
| C | Expired approval | `approval_expired` blocker | 0 |
| D | Rejected approval, then resume **and** direct executor call | `approval_state:REJECTED` on both | 0 |
| E | Resume an already-RESOLVED incident | `incident_state:RESOLVED` blocker | 0 |
| F | Caller supplies `target_ref` / `authorized_target_revision` / `approver_email` | HTTP 422 `extra_forbidden` | 0 |
| G | Direct executor call while `WAITING_FOR_APPROVAL` | `approval_state:PENDING` | 0 |

The rejection path in full:

```
incident   INC-20260819-2AF775 -> WAITING_FOR_APPROVAL
approval   APR-20260819-C9B887EE
human      REJECT  ->  state REJECTED
resume     -> {resumed: false, mutated: false, blockers: [approval_state:REJECTED]}
executor   -> {mutated: false, refused: true, reason: "approval_state:REJECTED"}
target     still HTTP 503        generation 350 (unchanged)
```

B and C are covered by contract tests rather than a live run: manufacturing a
cross-bound approval requires writing a forged document to the authoritative
plane, and an expiry requires waiting out the TTL. Both are stated here as
what they are rather than dressed up as live platform proofs.

---

## F5 — what is checked before an approval becomes a mutation

Checked at **resume** time against the authoritative plane, not at approval
time, because the world moves between the two:

- the approval exists, and its state is `APPROVED`
- it has not expired
- its `decision_id` matches the decision being resumed
- the incident is still `WAITING_FOR_APPROVAL`
- the decision is not revoked, and is still the `APPROVAL_REQUIRED` one
- the **authorization fingerprint** matches

That last one is the real check. The fingerprint covers incident, action,
target, exact revision, policy version and evidence snapshot together, so any
substitution between asking and acting changes it. An approval for something
else is not an approval for this.

Then the executor re-checks the approval independently, re-reads the decision,
claims its own execution identity, re-probes the target, and mutates under
`resourceVersion` OCC. Approval changes *who authorized the action* and nothing
else about how it is carried out.

---

## F14 — one correlation identifier, the whole story

`trace_id 560b9e85948d06edaabd39afdf65edfb`, audit chain for
`INC-20260819-39A4B4` (18 hash-chained records):

```
  0  orchestrator  incident_received
  1  orchestrator  routing_decision
  2  orchestrator  state_transition
  3  orchestrator  evidence_collected
  4  orchestrator  state_transition
  5  orchestrator  state_transition
  6  policy        policy_decision
  7  orchestrator  approval_requested
  8  orchestrator  state_transition        -> WAITING_FOR_APPROVAL
                   ---- revision A replaced by revision B ----
  9  human         approval_approved       <- a person, recorded as one
 10  orchestrator  state_transition        -> APPROVED
                   ---- revision B replaced by revision C ----
 11  orchestrator  state_transition        -> EXECUTING
 12  orchestrator  state_transition
 13  orchestrator  state_transition
 14  verifier      verification
 15  executor      execution_terminalized
 16  orchestrator  state_transition        -> RESOLVED
 17  orchestrator  resume_refused          <- the F12-E replay, refused
```

Structured Cloud Logging. **Cloud Trace is still not integrated and is not
claimed.**

---

## Two defects this gate found in itself

Recorded because they are the interesting part.

**The executor could not read the approval.** Its first implementation ran a
Firestore query, and Firestore refused it with a 500 out of the gRPC streaming
layer. The cause was the isolation boundary doing exactly its job:
`scfDecisionReader` grants `datastore.entities.get` and **not**
`datastore.entities.list`, so that identity can fetch a document by id and
cannot enumerate the authoritative plane. Widening the role would have been the
easy fix and the wrong one — an identity that can enumerate authorization
records is a materially different identity. The approval reference is now
written onto the decision document by the authoritative writer, and the executor
is told where to look rather than what to conclude.

**The freshness check looked for the wrong premise.** The executor refused the
first approved shift with `TARGET_NO_LONGER_HEALTHY`, because its pre-mutation
check hunted specifically for the `known-good` tag — which this scenario
deliberately does not have. For a rollback that check is exactly right: the tag
*is* the authorization, and an operator who withdraws it has withdrawn the
premise. For a human-approved shift the authorization is the person's decision
against one exact revision, so the check is whether that revision is still
addressable and still healthy. It never accepts a substitute.

---

## Internal hostile review

One focused review of the whole gate, by a reviewer with no editing role. It
confirmed the core properties hold — it could not produce a mutation without a
human approval, a duplicate infrastructure effect, or a false RESOLVED — and it
found five defects, all fixed before this artifact was finalised.

| Sev | Finding | Fix |
|---|---|---|
| High | An incident stranded permanently at `APPROVED` if the instance died between recording the human decision and calling the executor. No endpoint could move it. | resume accepts `APPROVED` and is idempotent |
| High | A human **rejection** left the incident waiting forever with no handover — "ESCALATE INSTEAD" escalated nothing. Same for a lapsed request. | refusal and expiry walk to `ESCALATED` through `APPROVAL_DENIED` / `APPROVAL_EXPIRED`, with a manager handover |
| Medium | The new freshness check let a rollback proceed after an operator **withdrew** the `known-good` tag — removing the only mid-flight way to revoke a standing auto-allowed authorization | the untagged fallback applies only to the human-approved action |
| Medium | `X-Goog-Authenticated-User-Email` was trusted without IAP in front, so any invoker could write an arbitrary named person into the audit chain as the approver | headers are read only where a deployment declares IAP; otherwise a named placeholder |
| Low | `"APPROVED"` sat in the executor's executable set as a bare string the `Decision` enum cannot produce — inert until this gate, then a value that skipped the approval check | removed; every member now comes from the closed enum |

The two High findings are the same shape and worth naming: both were incidents
that a person had engaged with, left in a state nothing could move. The gate is
about surviving process death, and its own failure mode was to strand precisely
the incidents a human had touched.

---

## Tests

**Offline: 507 passed, 11 skipped** — including 24 Gate F contract tests
covering the approval-required policy path, the durable waiting state, approval
binding and every integrity check, the caller-supplied-field refusals, approver
identity handling, executor-side verification, and that resume reads durable
state rather than re-running the workflow.

---

## Honest limitations after Gate F

1. **Approver identity is a named demo principal.** Google populates
   `X-Goog-Authenticated-User-Email` only for end-user credentials, and this
   fleet's calls carry service-to-service tokens, so no real human principal
   reaches the container today. The code reads a platform assertion when one is
   present and otherwise records
   `demo-approver@site-continuity-fleet.invalid` — a named placeholder, not a
   fabricated person. Binding a real signed-in manager identity belongs with the
   manager UI, and is **not claimed here**.
2. **The approval endpoint is authenticated, not authorized by role.** Any
   principal Google lets invoke the orchestrator may approve. `required_approval_role`
   is recorded on the approval and is not yet enforced against the caller.
   Because of that, and because no IAP is deployed, the approver is recorded as
   a named placeholder rather than from a request header: a header this fleet
   cannot verify must not be able to name a person in a hash-chained audit
   record. `SCF_TRUST_IAP_HEADERS=true` enables reading it on a deployment that
   genuinely has IAP in front.
3. **Expiry is enforced on read, not swept.** An approval past its TTL is
   refused when someone looks at it; nothing proactively marks it `EXPIRED`.
4. **Resume is operator-triggered**, like reconciliation. Nothing sweeps
   `WAITING_FOR_APPROVAL` incidents, and the manager-facing text says a person
   must act rather than implying an automatic process.
5. **Attack cases B and C are contract-tested, not live-proven** — see the F12
   table.
6. Everything in the Gate E limitations list still stands.
