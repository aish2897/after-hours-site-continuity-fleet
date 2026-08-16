# Gate D.2 — Execution correctness and crash-safety hardening

**Status: PASSED**

Sanitized. No credentials, no bearer tokens, no model reasoning.

## Hostile-review findings and disposition

All nine were **confirmed** against the code before any change was made.

| # | Finding | Verdict | Where |
|---|---|---|---|
| 1 | Caller-controlled `attempt_intent` can mint a new idempotency key for the same decision | **CONFIRMED** | `executor.py:52` field; used at `:107,:145,:185`; `ids.py:44,53` |
| 2 | Claim occurs before mutation and can strand an execution after a crash | **CONFIRMED** | claim at `executor.py:153`, mutation at `:196` |
| 3 | "Last good revision" selected merely because it is non-active | **CONFIRMED** | `cloud_run_evidence.py:90` — `[r for r in revisions if r != active_revision]` |
| 4 | Verifier checks HTTP health but not that the authorized revision is active | **CONFIRMED** | `verifier.py:58,85` — verdict from status + body only |
| 5 | Evidence can go stale between investigation and execution | **CONFIRMED** | no re-read or precondition anywhere in the executor |
| 6 | State transition and audit append are not atomic | **CONFIRMED** | `firestore_repo.py` — transaction committed, then `append_audit` called separately |
| 7 | Audit sequence advancement is not concurrency-safe | **CONFIRMED** | seq derived from a full read of the trail, then a separate `create` |
| 8 | Downstream call failures leave an incident mid-workflow | **CONFIRMED** | `main.py:206,273,341` — bare `raise_for_status()` |
| 9 | Documentation overclaims | **CONFIRMED (partial)** | `ARCHITECTURE.md:33` "immutable audit records"; `:170` Cloud Trace in present tense; `:109` Model Armor in present tense |

No finding was rejected. Nothing was changed that a finding did not justify.

## D2.1 — execution identity

```
execution_id = sha256(incident_id | action_type | target_ref | decision_id)
```

`attempt_intent` is gone from both the derivation and the request schema. The
executor derives the identity itself from the decision it read from
`(default)`. `ExecuteRequest` now has exactly two fields, `incident_id` and
`decision_id`, and forbids extras — so `attempt_intent`, `execution_id`,
`target_revision` and similar are rejected with `422`.

## D2.2 / D2.3 — lifecycle and datastore-atomic ownership

Execution documents in `execution-state` carry `execution_id`, `incident_id`,
`decision_id`, `action_type`, `target_ref`, `authorized_target_revision`,
`expected_source_revision`, `expected_etag`, `state`, `lease_owner`,
`lease_expires_at`, `recovery_count`, timestamps.

States: `CLAIMED → MUTATION_REQUESTED → MUTATED`, terminal `VERIFIED`,
`FAILED`, `STALE`. Mid-flight states are deliberately **not** terminal, so a
crashed execution stays recoverable instead of looking finished.

Ownership is a Firestore transaction that either creates the document or takes
over an expired lease. Documents are never deleted and the executor holds no
delete permission, so a claim cannot be retracted to manufacture a retry.

**Correctness does not depend on Cloud Run concurrency being 1** — the service
runs `--max-instances=4`.

### Concurrency proof — 10 simultaneous requests, same decision

```
generation BEFORE: 21

  9 "outcome":"HELD_BY_OTHER"    mutated=false
  1 "outcome":"RECOVERED"        mutated=true

generation AFTER:  22
dispatch-web: HTTP 200, x-revision: dispatch-web-00003-x87
```

**Exactly one execution took ownership and exactly one infrastructure mutation
occurred**, measured by Cloud Run's own generation counter across multiple
instances.

## D2.4 — reconciliation, not pretend exactly-once

Before mutating, the executor re-reads real infrastructure.

**CASE B — crash after mutation, before the success write.** Re-delivering the
same execution once the target is already active:

```
outcome                    RECOVERED
executed                   True
mutated                    False
reconciled                 True
state                      MUTATED
observed_active_revision   dispatch-web-00003-x87
authorized_target_revision dispatch-web-00003-x87

generation BEFORE: 22    generation AFTER: 22
```

The same execution identity is resumed and **no second mutation is issued**.

**CASE A — crash before mutation.** The lease expires, the same execution is
recovered (`RECOVERED`, not a new identity), infrastructure still shows the
authorized source state, and the execution resumes. This is the path exercised
by the winning request in the concurrency proof above.

**CASE C — infrastructure is neither pre-state nor target.** See D2.7.

### Terminology

This is **not** globally exactly-once distributed execution. Firestore and the
Cloud Run Admin API cannot be committed together. The honest property is
**duplicate-safe, recoverable, effect-idempotent execution with
reconciliation**, and repeated delivery produces exactly one mutation.

## D2.5 — "known good" now means proven

The rollback candidate is the revision carrying the operator-applied Cloud Run
traffic tag `known-good`, and the investigator probes that tag's own URL
directly before anything may be proposed.

Live evidence while the service was healthy (candidate == active, so not a
valid rollback target):

```
active_revision              dispatch-web-00003-x87
service_unhealthy            False
candidate_revision           dispatch-web-00003-x87
candidate_revision_approved  False
candidate_probe_http_status  200
candidate_probe_healthy      True
proposal                     None
```

Policy `1.1.0` now requires `service_unhealthy`,
`candidate_revision_approved` **and** `candidate_probe_healthy`. Goodness is
never inferred from "not currently active".

**Case F** — an approved candidate that fails its own probe produces no
proposal and, if proposed anyway, is `DENIED / MISSING_EVIDENCE`.

## D2.6 — exact target pinned

The decision persists `authorized_target_revision`. The executor may not
choose another revision, and the verifier must observe that exact one.

**CASE E — healthy 200 from the wrong revision must not resolve:**

```
verdict                      STILL_FAILING
http_status                  200
http_healthy                 True
active_revision              dispatch-web-00001-g5c
expected_revision            dispatch-web-00003-x87
revision_matches_authorized  False
```

## D2.7 — stale evidence / TOCTOU

The decision captures `expected_source_revision` and the Cloud Run `etag` from
the same trusted evidence snapshot. Before mutating, the executor re-reads.

**CASE G — infrastructure moved to an unexpected revision:**

```
refused        True
reason         STALE_EVIDENCE
precondition   expected_source_revision
expected       dispatch-web-00004-jqm
observed       dispatch-web-00002-x5g
mutated        False

generation BEFORE: 23    generation AFTER: 23
```

No mutation against changed infrastructure.

**Etag limitation, stated rather than implied:** the Cloud Run v2 traffic
update does not accept the service `etag` as an enforced update precondition in
the call we make. The `etag` is therefore captured and compared, and drift is
logged, but the load-bearing guard is the compare-before-update on
`expected_source_revision`. This is the strongest viable guard available, not a
claim of API-level optimistic concurrency.

## D2.8 — state and audit committed together

The incident document now carries `audit_seq` and `audit_tail_hash`. A single
Firestore transaction reads the incident, verifies the transition is legal,
allocates the next sequence, computes the chain hash, updates status + seq +
tail, and creates the audit record. All or none.

Because the sequence is allocated from the same document the transaction
guards, two concurrent appends contend on it and Firestore retries the loser,
so they cannot be handed the same sequence number.

Audit remains **tamper-evident, not immutable** — a compromised authoritative
writer could rewrite a record and the tail hash together.

## D2.9 — downstream failure handling

Service-to-service calls are bounded and typed. A transport error, non-2xx,
malformed body, or unconfigured URL raises `DownstreamFailure` carrying the
service and error kind. The orchestrator records a `downstream_failure` audit
event and drives the incident to a terminal state along a **legal** path —
`EXECUTING → EXECUTION_FAILED → ESCALATED`, `VERIFYING → REMEDIATION_FAILED →
ESCALATED`, and so on. No bare `raise_for_status()` remains.

## D2.10 — reconfirmed, unchanged

- Every deployed service uses a distinct explicit service account:
  `sa-orchestrator`, `sa-agent-systems`, `sa-executor`, `sa-verifier`,
  `sa-dispatch-web`.
- No agent or executor runtime uses the default compute service account.
- The executor cannot write `(default)` — Gate D.1 boundary intact.
- Executor mutation remains scoped to `dispatch-web` via `scfRemediator`.
- The verifier remains non-mutating.

## D2.13 — final autonomous run

Test setup, operator-controlled, before submission: traffic to
`dispatch-web-00004-jqm`, confirmed `HTTP 503`, generation 25.

**No operator or CLI action after submission.**

| Field | Value |
|---|---|
| Incident | `INC-20260816-9E03F3` |
| Trace | `2e64ec8adda0d39e1104ee333fd23897` |
| Evidence items | 12, all `TRUSTED_TOOL` |
| Decision | `AUTO_ALLOWED` / `LOW_RISK_TRAFFIC_FLIP`, `DEC-5F149367AA` |
| Authorized revision | `dispatch-web-00003-x87` |
| Execution id | `ff0cb300794b75e5…` |
| Mutated | `True` |
| Verifier | `RECOVERED`, http 200, `revision_matches_authorized: True`, 2 probes |
| **Final state** | **`RESOLVED`** |

## D2.13 — replay

```
replay 1: outcome=HELD_BY_OTHER mutated=False state=MUTATED
replay 2: outcome=HELD_BY_OTHER mutated=False state=MUTATED
replay 3: outcome=HELD_BY_OTHER mutated=False state=MUTATED

mutations during autonomous run: 1
mutations during 3 replays:      0
generation 25 → 26 → 26
```

## D2.11 — documentation drift purge

| Claim | Correction |
|---|---|
| "Write immutable audit records" | → "tamper-evident", with the compromise limitation stated |
| Cloud Trace "exported to Cloud Trace" | → explicit *Status: structured Cloud Logging correlation only. No span has been exported.* |
| Model Armor described in the present tense | → labelled **PLANNED, not integrated** in `ARCHITECTURE.md`, `README.md`, `SECURITY.md`; no prompt-injection resistance claimed |
| Idempotency section describing `attempt_intent` | → rewritten to the decision-bound identity and the reconciliation property |
| `idempotency/{key}` collection | → corrected to the two-plane layout |
| "Three IAM proofs are required before this section may claim to be verified" | → they are captured; pointer added |
| "Every Google Cloud row … reads NOT INTEGRATED" | → stale since Gate B; replaced |

Investigator claims were checked: `ARCHITECTURE.md` marks Network, Security and
Continuity as *(slice 2)* and does not claim they are deployed.

## Tests

**197 offline passed, 11 skipped**, including 20 new Gate D.2 contract tests
covering identity derivation, request surface, lifecycle terminality,
no-delete, transactional ownership, reconcile-before-mutate ordering,
fail-closed staleness, verifier revision matching, transaction atomicity, and
legal escalation paths.

Live decisive tests: 10-way concurrency, reconciliation, stale precondition,
wrong-revision verification, autonomous recovery, 3× replay.
