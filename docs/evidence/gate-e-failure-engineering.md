# Gate E — failure engineering

**Status: PENDING FINAL INDEPENDENT REVIEW**

Implementation and live proof are complete and re-verified on the deployed
build. What is outstanding is *independent* review of the fixes made after
Codex round 11 — Codex hit a hard account usage limit before round 12 could
run. Until a reviewer that is not the author has passed on the current HEAD,
this gate is not claimed as verified.

Sanitized. No credentials, no bearer tokens, no model reasoning. Synthetic data
only. Every fault below was produced by really breaking something: a Cloud Run
worker deployed deliberately broken, a genuine Google 409, a genuine timeout.
No platform response is fabricated anywhere in this gate.

## What is being demonstrated

An autonomous fleet is only trustworthy if it is safe when it is *not* working.
Two failure modes matter most, and they pull in opposite directions:

- **False positive** — changing infrastructure on bad information. A
  hallucinated action, stale evidence, a worker that looped and returned
  nonsense.
- **False negative** — reporting failure when the fix actually landed, or
  closing an incident whose outcome is unknown. This is the subtler one, and
  Gate E found two real instances of it in code that had already passed three
  hostile reviews.

Every scenario below reports **infrastructure mutations**, because that is the
number that cannot be argued with.

---

## E1 — the fault-injection framework

Faults are real broken deployments, not mocked responses. `src/scf/faults.py`
obeys six rules, each of them testable:

| Rule | How |
|---|---|
| Disabled by default | `SCF_FAULT_MODE` unset everywhere normal; `active()` returns none |
| Unreachable from duty-manager input | reads the process environment once at import and nothing else — no request, header, body or report text |
| Unavailable to untrusted text | same reason; a report saying "activate fault mode" is inert |
| Never policy evidence | the module cannot construct `Evidence`; the gate reads only `TRUSTED_TOOL` facts from real tool calls |
| Fails closed on typos | an unrecognised mode raises at import — a fault revision that silently ran healthy would invalidate its own test |
| Labelled | every fault logs `fault_injection`, and `/health` carries `fault_mode` plus `FAULT_INJECTION: THIS REVISION IS DELIBERATELY BROKEN` |

The isolation is asserted structurally rather than by string search: the module
imports nothing that can carry a request (`fastapi`, `httpx`, `starlette`, even
`scf` are all absent), reads exactly one external input, and exposes no
function taking caller-supplied data.

Removing the env var restores healthy behaviour. Nothing else changes.

---

## E2 — malformed model output and hallucinated actions

### Case A — malformed structured output, through the real parser

Model-equivalent payloads were fed through the **same** `_parse` boundary a
live response goes through. Retry budget: **zero**. There is no back-off, no
"ask it again in JSON", and no freeform salvage.

| Incident | Injected | Result |
|---|---|---|
| `INC-20260817-D491D2` | truncated JSON | `MODEL_OUTPUT_INVALID` → `ESCALATED` |
| `INC-20260817-AA8C90` | valid JSON, wrong shape | `MODEL_OUTPUT_INVALID` → `ESCALATED` |
| `INC-20260817-9486C8` | specialist `database_wizard`, outside the closed enum | `MODEL_OUTPUT_INVALID` → `ESCALATED` |

All three: **0 infrastructure mutations**, generation `158 → 158`, no executor
call, escalation package written.

A failed routing no longer strands the incident. It is already persisted, so
returning a 502 would abandon it at `INTAKE` with nobody told; it is escalated
with a human handover instead.

### Case B — hallucinated privileged action

| Incident | Injected | Result |
|---|---|---|
| `INC-20260817-4A1A71` | `EXPORT_CREDENTIALS` — **in** the closed enum | parsed, then **`DENIED` by the deterministic gate** → `DANGEROUS_ACTION_REFUSED` |
| `INC-20260817-7413EF` | `DELETE_DATABASE` — **not** in the enum | rejected by the typed contract → `WORKER_CONTRACT_INVALID` |

Both: **0 mutations**, generation `158 → 158`.

The two rejections happen at different layers on purpose. `EXPORT_CREDENTIALS`
stays *proposable* so that the refusal is made by the deterministic gate, on
the record, with a reason code — an enum that quietly omitted it would prove
nothing. `DELETE_DATABASE` never becomes a domain object at all.

**No dangerous tool exists.** What is proven is that hallucinated intent cannot
become capability.

---

## E3 — real investigator timeout and unavailability

`scf-agent-systems` was redeployed as a labelled fault revision that genuinely
sleeps past every caller bound, then one that genuinely returns 503.

```
incident            INC-20260817-EF319C
fault revision      fault_mode: investigator_hang
                    warning: "FAULT_INJECTION: THIS REVISION IS DELIBERATELY BROKEN"
failure category    WORKER_TIMEOUT
failure detail      investigator/ReadTimeout        <- real httpx timeout
incident status     ESCALATED  (persisted)
mutations           0           generation 158 -> 158
manager sees        "A checking step took too long and was stopped. No fix was
                     attempted, and nothing was changed."
```

A real 503 from the same service (`INC-20260817-1D2804`) produced
`WORKER_UNAVAILABLE`, also escalated with zero mutations.

Bounded by construction: every downstream call carries a per-service timeout
(investigator 45 s, executor 120 s, verifier 150 s — the verifier's is larger
because it deliberately polls a settle window). No incident waits on a stuck
worker.

The healthy revision was restored and normal operation reconfirmed.

---

## E4 — worker loop / budget exhaustion

The investigator holds a genuine production budget, not a test-only guard:
**12 tool calls** and a **30 s** wall-clock deadline, both visible on
`/health`. A fault revision loops forever gathering evidence; the loop has no
exit of its own, so termination is the budget's doing.

```
incident            INC-20260817-134018
failure category    WORKER_BUDGET_EXCEEDED
incident status     ESCALATED
mutations           0           generation 158 -> 158
```

The worker returns a truthful terminal contract — `evidence: []`,
`proposal: null`, `budget_exceeded: true` — rather than partial evidence
dressed up as complete, and the orchestrator checks that **before** validating
evidence. No privileged action can be taken from incomplete work.

---

## E5 — the system must be capable of doing nothing

A healthy service and a vague report: *"Staff mentioned the dispatch screen
felt slow and unreliable earlier this evening. It seems to be working now."*

```
incident            INC-20260817-C604DE
evidence            gathered, all TRUSTED_TOOL
proposal            none — service_unhealthy is false
failure category    INSUFFICIENT_EVIDENCE
incident status     ESCALATED
mutations           0           generation 183 -> 183
manager sees        "The system could not confirm a fault it knows how to fix
                     safely, so it made no change and asked for a person to look."
```

**Autonomy is not an obligation to change infrastructure.** The model may
investigate; the deterministic gate still refuses to act without the evidence
its policy requires.

---

## E6 — real Cloud Run `resourceVersion` conflict

Reuses the Gate D.3 OCC primitive rather than inventing a second failure
mechanism. A labelled executor revision pauses *after* its authorized Cloud Run
read; a controlled second actor then moves the Service, so the executor's
precondition is genuinely stale and **Google** refuses the write.

```
incident            INC-20260817-4DD51D
http_status         409
conflict            true
google message      "Conflict for resource 'dispatch-web': version
                     '1786946577368306' was specified but current version is
                     '1786946626661729'."   status ABORTED
conflict_rewind     ADVANCED      (record wound back; nothing was applied)
retryable           true
mutated             false
failure category    EXECUTION_CONFLICT
incident status     EXECUTION_FAILED   <- non-terminal, reconcilable
manager sees        "Someone or something else changed the service at the same
                     moment, so the automatic fix was refused. Nothing was changed."
```

The generation counter moved `188 → 189` in this window — that is the **second
actor's** tag change, not a remediation. The executor's mutation was refused
and `mutated` is `false`. No blind retry followed.

---

## E7 — the authorized target stops being healthy

Deterministic, not raced: a real decision is created while the executor is
unavailable, the operator then moves the `known-good` marker onto the failing
revision, and the same decision is delivered to a healthy executor.

```
incident                      INC-20260817-908019
authorized_target_revision    dispatch-web-00003-x87
observed_candidate_revision   dispatch-web-00004-jqm
reason                        TARGET_NO_LONGER_HEALTHY
detail                        candidate_no_longer_approved
mutated                       false
generation                    191 -> 191
live                          HTTP 503, untouched
```

No substitute revision was chosen. The fleet does not act on yesterday's
evidence, and it does not improvise a target.

---

## E8 — verifier fails after a successful mutation

`scf-verifier` was redeployed as a labelled revision returning a real 503.

```
incident            INC-20260817-F88D93
mutation            landed — generation 186 -> 187, service HTTP 200
verification        real 503 from the verifier service
failure category    VERIFIER_UNAVAILABLE
incident status     REMEDIATION_FAILED   <- NOT resolved, NOT terminal
manager sees        "A fix was applied but could not be independently confirmed
                     yet, so this is not being reported as resolved until it is."
```

Verifier restored, then reconciliation:

```
executor re-delivery   no mutation
verifier               RECOVERED
terminalization        VERIFIED
incident               RESOLVED
generation             187 -> 187      no blind second mutation
```

**A fix that cannot be confirmed is not reported as done.**

---

## E9 — executor unavailable before any mutation

Labelled executor revision returning a real 503.

```
incident            INC-20260817-EF8ED3
failure category    EXECUTOR_UNAVAILABLE
incident status     EXECUTION_FAILED    <- reconcilable, not closed
mutations           0        generation 184 -> 184
```

Executor restored, then reconciliation → `RESOLVED`, generation `184 → 185`:
exactly one infrastructure change for the incident as a whole.

---

## E10 — the caller loses the executor mid-mutation

Two interruptions were attempted. Both results are recorded, because the first
is informative.

**Attempt 1 — redeploy during execution.** Cloud Run **drained** the in-flight
request rather than killing it: the paused execution completed normally, the
incident resolved correctly, and the generation moved exactly once. A real
observation about the platform, but not an interruption.

**Attempt 2 — force the caller to lose the call.** The executor was deployed
with a real pause after its authorized read, and the orchestrator's executor
timeout was lowered below that pause. The orchestrator therefore got a genuine
`ReadTimeout` and never learned the outcome, while the executor really did
complete the mutation. This is the interesting half of a crash: *the component
that acts survives, the component waiting on it does not.*

```
incident                INC-20260817-934DA6
orchestrator            real ReadTimeout on the executor call
failure category        EXECUTOR_UNAVAILABLE
incident status         EXECUTION_FAILED     <- not resolved on an unknown outcome
meanwhile               the surviving executor completed the mutation,
                        service HTTP 200

reconciliation:
  executor re-delivery  HELD_BY_OTHER, execution already carried forward
  mutated               false
  verifier              RECOVERED
  terminalization       VERIFIED
  incident              RESOLVED
  total generation      exactly one change
```

State survived in Firestore, not in process memory.

### Two real defects this scenario exposed

Both had survived three rounds of hostile review of Gate D.3, and both were
**false negatives** — the fleet fixing an outage and then reporting it had not.

1. **An executor timeout was terminal.** `_categorise` checked the failure
   *kind* before the *service*, so a timeout on the executor became
   `WORKER_TIMEOUT` and escalated — while the mutation was landing, with no
   route back. Service identity now dominates: for the executor and the
   verifier, any failure to reach them means the outcome is unknown and the
   incident stays reconcilable. The investigator is read-only, so escalating it
   remains safe.
2. **Reconciliation escalated on `HELD_BY_OTHER`.** A worker that outlived its
   caller still did the work. A duplicate outcome whose execution has reached
   `MUTATION_REQUESTED`, `MUTATED` or `VERIFIED` is no longer read as failure.

---

## E11 — authenticated but semantically invalid worker output

A worker returning HTTP 200 under a valid identity is not a reason to trust its
payload. Authentication says *who* is speaking; the contract says whether what
they said is usable.

```
incident            INC-20260817-663027
injected            evidence with trust_level "TOTALLY_TRUSTED"
result              rejected by the typed contract
failure category    WORKER_CONTRACT_INVALID
incident status     ESCALATED
mutations           0        generation 158 -> 158
```

An unknown trust level is never coerced to `TRUSTED_TOOL`. A verifier verdict
outside the contract is likewise not recovery — only the exact string
`RECOVERED` proceeds.

### The envelope itself, not only its contents

Two further faults were deployed to the real investigator, because a worker can
break its contract in the *shape* of its answer rather than in the evidence it
carries. Both ran against the live fleet with the real orchestrator calling a
real authenticated worker.

```
fault mode          investigator_truthy_budget_string
injected            "budget_exceeded": "false"   (a string, not a boolean)
incident            INC-20260818-5FB6F0
result              WORKER_CONTRACT_INVALID
                    "investigator envelope rejected: not the declared shape"
incident status     ESCALATED       mutations 0

fault mode          investigator_empty_proposal
injected            "proposal": {}   (empty, not absent)
incident            INC-20260818-82038F
evidence collected  12 real trusted facts
result              WORKER_CONTRACT_INVALID
manager summary     "A checking step returned information the system could not
                     trust, so it was discarded. Nothing was changed."
incident status     ESCALATED       mutations 0
```

Both were read with `.get()` before Gate E's review loop closed them. `"false"`
is a non-empty string and therefore truthy, so a complete and usable
investigation would have been discarded as budget exhaustion. `{}` is falsy, so
a worker breaking its own contract would have been reported to the duty manager
as a considered decision that no remediation was warranted. Neither is a
distinction the manager can be expected to make on our behalf, so the envelope
is settled by a typed contract before anything branches on it.

---

## E12 — no blind retry

Every retry budget is **zero**, declared as a constant so it can be audited
rather than inferred:

```
DOWNSTREAM_RETRY_BUDGET   = 0
MODEL_PARSE_RETRY_BUDGET  = 0
MUTATION_RETRY_BUDGET     = 0
MODEL_PARSE_RETRIES       = 0
```

`_call` makes one attempt with no back-off. A test walks the source and fails
if any downstream call or Cloud Run mutation sits inside a `while` or `for`.

Only two categories are retry-eligible at all — `EXECUTION_CONFLICT` and
`EXECUTOR_UNAVAILABLE` — and both mean "Google refused, or we never found out",
never "try the same thing again". What follows is *reconciliation*: observe
real infrastructure, act only if reality proves it is still needed. It is
logged as `reconciliation_execution`, distinctly from any execution attempt.

Across all sixteen fault scenarios, **no scenario produced more than one
infrastructure change**, and every scenario that changed nothing reported
generation unchanged.

---

## E13 — escalation package

Every failure produces a deterministic human handover, written by an
authoritative writer and persisted on the incident. Example, from the real
conflict:

```
impact                        "Someone or something else changed the service at
                               the same moment, so the automatic fix was refused.
                               Nothing was changed."
automation_changed_anything   false
what_automation_did           "No change was made to any service."
current_service_state         "the dispatch service is still not responding normally"
operations_restored           false
recommended_next_action       "Re-report the problem if it is still happening."
specialists_attempted         ["systems"]
evidence_summary              active_revision, candidate_probe_healthy,
                              candidate_probe_http_status, candidate_probe_url,
                              candidate_revision, candidate_revision_approved,
                              http_body, http_status, service_etag,
                              service_exists, service_unhealthy, service_url
correlation_id                <trace id>
```

What it deliberately does **not** contain: model rationale, credentials,
tokens, stack traces, API names, HTTP status codes, revision names.
A test asserts the serialized package contains none of them, and that no
manager-facing summary contains jargon.

Evidence is summarised by **key, not value** — values can carry untrusted
report text, and the handover names what was checked rather than repeating it.

`current_service_state` is derived from what an **authorized** identity
observed: the verifier's verdict, or the investigator's trusted evidence. The
orchestrator holds no read permission on the target service, and widening its
IAM to populate a status line would trade a real security boundary for a
cosmetic one. When nothing was observed — an early timeout, an unavailable
investigator — it says *"could not be checked automatically"* rather than
guessing.

---

## E14 — failure taxonomy

Sixteen categories, one table, no free-form failure semantics anywhere. Each
row fixes the resting state, reconcilability, retry eligibility, audit event
and manager summary together, so a new category cannot be added without
deciding what a human should do about it.

| Category | Rests at | Reconcilable | Retry eligible |
|---|---|---|---|
| `MODEL_OUTPUT_INVALID` | `ESCALATED` | no | no |
| `DANGEROUS_ACTION_REFUSED` | `ESCALATED` | no | no |
| `WORKER_TIMEOUT` | `ESCALATED` | no | no |
| `WORKER_UNAVAILABLE` | `ESCALATED` | no | no |
| `WORKER_BUDGET_EXCEEDED` | `ESCALATED` | no | no |
| `WORKER_CONTRACT_INVALID` | `ESCALATED` | no | no |
| `INSUFFICIENT_EVIDENCE` | `ESCALATED` | no | no |
| `STALE_EVIDENCE` | `ESCALATED` | no | no |
| `TARGET_NO_LONGER_HEALTHY` | `ESCALATED` | no | no |
| `EXECUTION_CONFLICT` | `EXECUTION_FAILED` | **yes** | **yes** |
| `EXECUTOR_UNAVAILABLE` | `EXECUTION_FAILED` | **yes** | **yes** |
| `EXECUTION_OUTCOME_UNKNOWN` | `EXECUTION_FAILED` | **yes** | no |
| `APPROVAL_REQUIRED_NO_APPROVER` | `ESCALATED` | no | no |
| `VERIFIER_UNAVAILABLE` | `REMEDIATION_FAILED` | **yes** | no |
| `VERIFICATION_FAILED` | `ESCALATED` | no | no |
| `REMEDIATION_FAILED` | `ESCALATED` | no | no |

The pattern is not arbitrary: **a category is reconcilable exactly when the
infrastructure outcome is unknown or unconfirmed.** Everything else is a state
we are sure about, and being sure is what makes it safe to close.

Tests assert every category is handled, every reconcilable resting state is
non-terminal and reachable by `/reconcile`, and audit events are unique.

---

## E15 — one correlation identifier through a fault path

Real Cloud Logging query on a single `trace_id`, across three services, for the
conflict scenario:

```
request_received                       scf-orchestrator
incident_persisted                     scf-orchestrator
adk_invocation_started                 scf-orchestrator
routing_decision                       scf-orchestrator
investigator_invoked                   scf-agent-systems
investigator_evidence_collected        scf-agent-systems
execution_requested                    scf-executor
fault_injection                        scf-executor      executor_delay_before_mutation
execution_resource_version_conflict    scf-executor
failure_execution_conflict             scf-orchestrator  EXECUTION_CONFLICT
```

Incident → agent call → fault → deterministic handling → no unauthorized
mutation → categorised failure, reconstructable from structured logs alone.

**No span has been exported to Cloud Trace.** This is structured Cloud Logging
correlation, and is not claimed as distributed tracing.

---

## E16 — healthy regression after all fault injection

Every fault revision was removed and normal operation reconfirmed end to end.

```
autonomous 503 -> 200        PASS
incident                     RESOLVED
execution                    VERIFIED
revisions                    4 -> 4      no revision minted
replays                      refused, zero mutations
```

Re-verified again on the final build, after all eleven review rounds:

```
build                        orchestrator-00136-ck2  agent-systems-00117-ffl
                             executor-00117-pjn      verifier-00039-jfm
all four services            healthy, fault_mode: null
autonomous 503 -> 200        INC-20260818-F9335B     RESOLVED
mutation                     serving.knative.dev/v1 replaceService, HTTP 200
                             conflict False, action SUCCEEDED
verification                 RECOVERED, healthy, traffic exclusive
terminalization              VERIFIED, serves authorized exclusively
generation                   332 -> 333              one mutation
replays x3                   refused incident_closed:RESOLVED
generation after replays     333                     no further mutation
audit chain                  15 records, audit_seq 14, tail hash recorded
```

Re-verified once more after the internal hostile review and its fixes:

```
build                        orchestrator-00137-gvj  agent-systems-00118-fb5
                             executor-00118-dmn      verifier-00040-k9f
all four services            healthy, fault_mode: null
autonomous 503 -> 200        INC-20260818-7F1C25     RESOLVED
mutation                     HTTP 200, conflict False, action SUCCEEDED
verification                 RECOVERED, healthy, traffic exclusive
terminalization              VERIFIED, serves authorized exclusively
generation                   334 -> 335              one mutation
replays x3                   refused incident_closed:RESOLVED
generation after replays     335                     no further mutation
executor project roles       scfDecisionReader, scfExecutionWriter,
                             roles/logging.logWriter          (unchanged)
scfRemediator                run.services.get, run.services.update  (unchanged)
executor write (default)     403       executor read (default)   200
executor -> site-directory   PERMISSION_DENIED
executor -> dispatch-web     200
```

Security boundaries re-checked after the whole gate:

```
sa-executor project roles    scfDecisionReader, scfExecutionWriter,
                             roles/logging.logWriter      (unchanged)
scfRemediator                run.services.get, run.services.update  (unchanged)
executor -> dispatch-web     200
executor -> site-directory   403 get, 403 put
executor read  (default)     200 (document)   403 (collection list)
executor write (default)     403
executor delete execution    403
all four services            healthy, fault_mode: null
```

**No IAM was created, widened or changed in this gate.**

---

## Live proof matrix

| Scenario | Real / controlled | Result | Mutations |
|---|---|---|---|
| malformed model output ×3 | controlled payload, **real parser** | rejected, escalated | 0 |
| dangerous hallucinated action | controlled proposal, **real gate** | deterministic `DENIED` | 0 |
| action outside the enum | controlled proposal, **real contract** | rejected | 0 |
| Systems timeout | **REAL** Cloud Run worker | escalated | 0 |
| Systems 503 | **REAL** Cloud Run worker | escalated | 0 |
| worker budget exceeded | controlled loop, **real budget** | bounded termination | 0 |
| insufficient evidence | **REAL** healthy system | no remediation | 0 |
| `resourceVersion` conflict | **REAL** Google 409 ABORTED | no blind retry, reconcilable | 0 |
| candidate no longer healthy | **REAL** probe | refused | 0 |
| verifier unavailable | **REAL** Cloud Run service failure | no false resolve, later reconciled | 1 total |
| executor unavailable | **REAL** Cloud Run service failure | safe state, later reconciled | 1 total |
| caller loses the executor | **REAL** timeout + surviving worker | reconciled from infrastructure | 1 total |
| malformed worker contract | controlled payload, **real caller** | rejected | 0 |
| truthy-string `budget_exceeded` | controlled payload, **real caller** | rejected, not read as exhaustion | 0 |
| empty `proposal: {}` | controlled payload, **real caller** | rejected as contract-invalid | 0 |
| final healthy path | **REAL** | autonomous 503 → 200 | 1 |

---

## Tests

**Offline: 471 passed, 11 skipped** — including 191 Gate E contract tests
covering fault-injection isolation, malformed model output at the parser,
dangerous and unknown actions, call bounds, budget exhaustion, doing nothing,
authenticated-but-invalid worker payloads, retry budgets, escalation-package
completeness and leakage, and taxonomy consistency.

**Live scenarios:** all sixteen rows of the matrix above ran end to end
against the deployed fleet. They are not all *live platform failures*, and the
matrix says which is which: the timeout, both 503s, the 409 conflict, the
candidate probe and the final recovery are failures produced by Google
infrastructure, while the malformed model output, the dangerous and unknown
actions, the runaway loop and the malformed worker payload are controlled
payloads driven through the real parser, the real gate and the real caller.
Both kinds are real runs; only the first kind is evidence about the platform.

---

## Hostile review status

Eleven rounds of adversarial review were run by Codex (GPT-5), read-only,
against the committed HEAD each time, over the sixteen attack axes. Every
Critical and High it raised was fixed and the fix re-reviewed in the following
round.

**Round 12 did not run.** Codex hit a hard account usage limit that does not
reset until 2026-08-21. The checks round 12 was asked to make against the newest
code — the `EXECUTION_OUTCOME_UNKNOWN` path — were instead written as contract
tests by the author and are marked as such in
`tests/unit/test_failure_engineering.py`. That is not equivalent: the value of
the loop is that the reviewer is not the author, and that property is missing
for the round-11 fixes. **The loop therefore has one unverified round
outstanding**, and this is stated rather than presented as convergence.

What the loop actually found is worth recording, because it is the argument for
having run it:

| Round | Raised | Notable |
|---|---|---|
| 1–7 | Critical 0 | Non-dict JSON stranding incidents; truthy-flag terminalization; `"healthy" in body` inversion |
| 8 | 2 High | `1 == True` satisfied three required booleans at the policy gate |
| 9 | 1 High | The round-8 fix was incomplete — the contradiction check next to it still used `!=` |
| 10 | 3 High | A repeated JSON key discarded a worker's own refusal; the round-9 negation fix read an indexed failure as healthy |
| 11 | 2 High | Only a 409 proves a mutation did not land; a stale owner "cannot terminalize" was never true |

Rounds 9, 10 and 11 each found a defect in the **previous round's fix**, not in
the original code. Three of the last four Highs were introduced by a fix for an
earlier High. That is the strongest available argument that a single review pass
would not have been enough, and it is also why the missing round 12 is reported
as a gap rather than rounded down.

---

## Honest limitations after Gate E

1. **Fault injection ships in the codebase.** It is disabled by default,
   structurally unreachable from user input, and refuses to start on an
   unrecognised mode — but the code is present. It can be removed before final
   submission if preferred; nothing in the healthy path depends on it.
2. **Cloud Run drains in-flight requests on redeploy**, so a redeploy is not a
   reliable way to kill a running execution. The interruption proof therefore
   comes from the caller losing the call, which is a genuine and arguably more
   realistic failure, but it is not a process kill mid-write.
3. **`/reconcile` is operator-triggered.** Nothing sweeps reconcilable
   incidents automatically yet, so an incident can sit at `EXECUTION_FAILED` or
   `REMEDIATION_FAILED` until someone calls it. Durability and automatic
   resumption belong to the next gate.
4. **One investigator.** Network, Security and Continuity remain contracts, not
   runtimes, so cross-specialist failure modes are untested.
5. **The escalation package is a persisted artifact, not a delivery
   mechanism.** No email, SMS or ticket is raised.
6. All Gate D limitations still stand: not globally exactly-once; the
   stale-worker window is narrowed, not eliminated; audit is tamper-evident,
   not immutable; Firestore isolation is database-level.
7. **Model Armor is not integrated** and no prompt-injection resistance is
   claimed — report text still reaches the model uninspected. **No Cloud Trace
   span exists.** Complete Australian data residency is **not claimed**.
