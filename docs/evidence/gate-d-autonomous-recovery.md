# Gate D — Full autonomous 503 → 200 slice

**Status: PASSED**

Sanitized. No bearer tokens, no credentials, no model chain-of-thought — only
structured routing and decision summaries.

## The claim

A plain-language report from a non-technical duty manager autonomously
recovered real infrastructure. **After the incident was submitted, no operator
or CLI command touched the recovery.**

## Runtime topology

| Service | Runtime identity | Role |
|---|---|---|
| `scf-orchestrator` | `sa-orchestrator` | intake, routing, policy, state |
| `scf-agent-systems` | `sa-agent-systems` | read-only evidence |
| `scf-executor` | `sa-executor` | the only mutating identity |
| `scf-verifier` | `sa-verifier` | independent read-only verification |
| `dispatch-web` | `sa-dispatch-web` | the real target |

All Sydney `australia-southeast1`, all authenticated, all invoked
service-to-service with ID tokens. The orchestrator holds `run.invoker` on the
three services and **none of their infrastructure privileges**.

## Test setup (operator-controlled, BEFORE submission)

```
$ gcloud run services update-traffic dispatch-web --to-revisions=dispatch-web-00004-jqm=100
  100% dispatch-web-00004-jqm

HTTP/1.1 503 Service Unavailable
x-service-mode: broken
x-revision: dispatch-web-00004-jqm
dispatch service unavailable
```

## The incident

Submitted 2026-08-15T16:29:12Z. The only input:

```json
{"description": "The dispatch screens are showing an error page. Phones and Wi-Fi seem fine.",
 "site_id": "MEL-WAREHOUSE-01", "reported_by": "duty-manager"}
```

No service name, no category, no specialist, no root cause, no remediation.

## Autonomous result

`HTTP 201` in 13 seconds. Incident `INC-20260815-20ABB8`,
trace `0858ee4bf780a73a679e7739fd1bb776`.

| Stage | Result |
|---|---|
| Routing | `['systems']` — 1 of 4 specialists |
| Evidence | 9 items, all `TRUSTED_TOOL`, from the real Cloud Run API |
| Proposal | `FLIP_TRAFFIC_TO_LAST_GOOD` (closed enum) |
| Policy | `AUTO_ALLOWED` / `LOW_RISK_TRAFFIC_FLIP`, `policy_version 1.0.0` |
| Decision | `DEC-C57E81CD0D` persisted to Firestore |
| Execution | `mutated=True`, `state=SUCCEEDED` |
| Idempotency key | `78c9651e9b9bc98cf09bb9d2d24408ac59d4b1e42996badb64dbb0902f6a2f20` |
| Verification | `RECOVERED`, HTTP 200, active `dispatch-web-00003-x87`, 2 probes |
| **Final state** | **`RESOLVED`** |

**Live service after, with no operator action:**

```
HTTP/1.1 200 OK
x-service-mode: healthy
x-revision: dispatch-web-00003-x87
dispatch service healthy
```

## Audit trail — 17 records, hash chain verified

```
 0 orchestrator incident_received      9 executor     action_executed
 1 orchestrator routing_decision      10 orchestrator state_transition
 2 orchestrator state_transition      11 orchestrator state_transition
 3 orchestrator evidence_collected    12 verifier     verification
 4 orchestrator state_transition      13 orchestrator state_transition
 5 orchestrator state_transition      14 executor     duplicate_suppressed
 6 policy       policy_decision       15 executor     duplicate_suppressed
 7 orchestrator state_transition      16 executor     duplicate_suppressed
 8 orchestrator state_transition
```

`verify_chain` → `True`. Action records: exactly one, `SUCCEEDED`.

State path, every transition compare-and-set against the declared machine:
`INTAKE → INVESTIGATING → PROPOSED → POLICY_EVALUATED → AUTO_ALLOWED →
EXECUTING → EXECUTED → VERIFYING → RESOLVED`

## Idempotency — live, Firestore-atomic

The key is derived, never generated:

```
sha256(incident_id | action_type | target_ref | decision_id | attempt_intent)
```

> **Superseded at Gate D.2.** `attempt_intent` was caller-supplied, so any
> client able to reach the executor could mint a fresh key and re-run a
> completed mutation. It was removed from both the derivation and the request
> schema. The current identity is
> `sha256(incident_id | action_type | target_ref | decision_id)` — see
> `src/scf/domain/ids.py` and
> [`gate-d2`](gate-d2-execution-correctness.md). This section is kept as the
> record of what was true at Gate D, not as a description of current behaviour.

It is claimed with a Firestore `create`, which fails if the document already
exists. That failure *is* the duplicate signal — no read-then-write race, no
in-memory set, no process-local lock, no UUID.

Replaying the identical executor request three times:

```
replay 1  {"duplicate":true,"state":"DUPLICATE_SUPPRESSED", ...}
replay 2  {"duplicate":true,"state":"DUPLICATE_SUPPRESSED", ...}
replay 3  {"duplicate":true,"state":"DUPLICATE_SUPPRESSED", ...}
```

**Cloud Run service generation before replays: 15. After: 15.**

Generation is Cloud Run's own mutation counter, so this is not a count of HTTP
responses — it is proof the infrastructure was not touched again.

**Total infrastructure mutations for decision `DEC-C57E81CD0D`: 1.**

## Direct executor attack tests

Invoker permission is not authorization. Six attempts, including decisions
planted directly into Firestore to simulate an attacker who already has write
access:

| Attack | Executor response |
|---|---|
| Fabricated `decision_id` | `refused: decision_not_found` |
| Mismatched `incident_id` | `refused: decision_not_found` |
| `DENIED` decision | `refused: decision_not_executable:DENIED` |
| Forged `AUTO_ALLOWED` for `EXPORT_CREDENTIALS` | `refused: unsupported_action_type:EXPORT_CREDENTIALS` |
| Revoked decision | `refused: decision_revoked` |
| Caller asserts `decision`/`target_ref`/`action_type` in the body | `422 extra_forbidden` |

**Cloud Run generation before attacks: 15. After: 15.** Zero mutations.

The last row is the structural point: the request schema physically cannot
carry an authorization claim. The executor loads the decision from Firestore
itself, so a caller cannot assert `AUTO_ALLOWED`, redirect the target to
`site-directory`, or change the action.

Planted adversarial decisions were deleted after the test.

## Logging correlation

One incident id and trace id across all four services:

```
16:30:10.454  scf-orchestrator   request_received
16:30:10.567  scf-orchestrator   incident_persisted
16:30:10.567  scf-orchestrator   adk_invocation_started
16:30:14.013  scf-orchestrator   routing_decision
16:30:14.469  scf-agent-systems  investigator_invoked
16:30:14.974  scf-agent-systems  investigator_evidence_collected
16:30:15.809  scf-executor       execution_requested
16:30:17.146  scf-executor       action_executed
16:30:22.248  scf-verifier       verification_completed
```

Structured Cloud Logging only. **Cloud Trace is not claimed** — no span has
been exported.

## Findings

1. **`.gcloudignore` `tools/` was unanchored.** It matched `src/scf/tools/` as
   well as the repo-root directory, shipping a package that failed at import on
   Cloud Run. Patterns are now anchored with a leading slash.
2. **Policy files were not packaged.** `loader.py` resolved them relative to a
   repo root, which does not exist inside site-packages. They now live in
   `src/scf/policies/` and ship as declared package data. This never surfaced
   in Gate B because that orchestrator never called the policy engine.
3. **Cloud Run v2 expects a bare revision name** in a traffic target, not a
   full resource path. A path returns `INVALID_ARGUMENT`.
4. **A service-scoped role cannot read Cloud Run operations.** Polling the
   operation returned 403 because an operation is a distinct resource from the
   service. Rather than broaden the grant, operation polling was removed
   entirely and `run.operations.get` was dropped from `scfRemediator`, which
   now holds only `run.services.get` and `run.services.update`. The executor
   does not certify its own success; the independent verifier does.
5. **Traffic migration is asynchronous.** The Admin API accepts the change
   before the frontend finishes shifting requests, so a single immediate probe
   reported `STILL_FAILING` for a mutation that had in fact landed. The
   verifier now polls read-only for a bounded settle window (75s default). It
   never mutates and never retries the remediation.

Findings 4 and 5 both produced *false failures*, not false successes. In each
case the system escalated rather than claiming a recovery it could not prove.
