# Project control

The durable record of what this project is, why it is built this way, what is
actually proven, and what must not change. If every chat transcript is lost,
this file alone should be enough to pick the work back up without re-deriving
the strategy or repeating a settled decision.

Update §16 at the end of every gate.

---

## 1. Winning objective

The goal is not to submit. The goal is to maximise the realistic probability of
winning, across more than one lane:

- Grand Prize
- Fortified Enterprise Fleet (the entered track)
- Best Architecture
- Best Multimodal UX
- Individual / Hobbyist
- Honorable Mention competitiveness

One submission will ultimately receive at most one prize. Building to be
*awardable* in several lanes is deliberate: it is the cheapest available hedge
against a single judging panel's taste, and each lane's requirement — evidence,
architecture, UX, honesty — makes the submission better on its own terms.

---

## 2. Product north star

**This is not an AI SRE tool.** Every design argument resolves against this
sentence:

> A secure autonomous continuity fleet lets a **non-technical after-hours duty
> manager** restore a failing business site without having to work out whether
> the problem belongs to network, systems, identity, or somewhere else.

The Unlikely Hero comes first. The duty manager cannot name the service, the
category, the specialist, the root cause, or the remediation — and the intake
contract deliberately refuses to accept any of those from them. The system
infers routing itself.

If a feature makes the engineering more impressive but the duty manager's
experience worse, it is the wrong feature.

---

## 3. Golden rule (frozen)

```
LLM PROPOSES.
DETERMINISTIC POLICY DECIDES.
SCOPED IDENTITY EXECUTES.
```

Preserved alongside it:

- `TRUSTED_TOOL` vs `UNTRUSTED_INPUT` — the policy gate reads only trusted
  evidence, so injected text is *architecturally incapable* of satisfying an
  authorization condition, not merely filtered.
- LLM rationale is display-only and never becomes authorization.
- Investigators read and propose. They hold no mutation capability.
- The executor alone mutates, under a resource-scoped identity.
- The verifier verifies independently, under a different read-only identity.

Changing any of these is a STOP condition, not a refactor.

---

## 4. Frozen platform decisions

| Decision | Value |
|---|---|
| Project | `site-continuity-fleet` |
| Core infrastructure | Sydney `australia-southeast1` |
| Model Armor threat screening | Singapore `asia-southeast1` |
| Gemini 3.7 Flash inference | Vertex AI `global` |
| Cloud Run mutation | v1 `namespaces.services.replaceService` with `metadata.resourceVersion` |
| Authoritative plane | Firestore `(default)` |
| Execution plane | Firestore `execution-state` |
| Service-account JSON keys | **None. Never created, never downloaded.** |

Two findings behind these that must not be re-litigated:

- **Complete Australian model-processing residency is not claimed**, and must
  never be. Gemini 3.7 Flash is not served from an Australian regional inference
  endpoint — Sydney returned `404 NOT_FOUND` for the publisher model on a real
  call. Inference therefore leaves the country, and the docs say so.
- **Cloud Run v2 `etag` is not a concurrency control.** Tested live against the
  real service: a stale etag in the body, a stale `If-Match:` header, and a
  bogus etag string were *all accepted with HTTP 200* on the traffic PATCH. The
  executor therefore mutates through v1 `replaceService`, where
  `resourceVersion` is genuinely enforced and returns a real 409 ABORTED. No
  claim rests on v2.

---

## 5. Verified capabilities

Every row below has a live evidence artifact. `VERIFIED` means *exercised for
real against Google infrastructure, with the artifact saved*.

| Capability | Evidence |
|---|---|
| Gemini 3.7 Flash on real Vertex AI | `docs/evidence/gate-a-vertex-gemini.md` |
| Google ADK agent with typed output | `docs/evidence/gate-a-adk-routing.md` |
| Evidence-dependent selective routing | `docs/evidence/gate-b-cloud-run-firestore.md` |
| Cloud Run orchestrator (Sydney, authenticated) | `docs/evidence/gate-b-cloud-run-firestore.md` |
| Firestore durable incident state (Sydney) | `docs/evidence/gate-b-cloud-run-firestore.md` |
| Real `dispatch-web` healthy + broken revisions | `docs/evidence/gate-c-iam-boundary.md` |
| Real investigator IAM denial (403) | `docs/evidence/gate-c-iam-boundary.md` |
| Resource-scoped executor (`scfRemediator` on one service) | `docs/evidence/gate-c-iam-boundary.md` |
| Executor denied on unrelated `site-directory` | `docs/evidence/gate-c-iam-boundary.md` |
| Real 503 → 200 infrastructure recovery | `docs/evidence/gate-c-iam-boundary.md` |
| Full autonomous 503 → 200 slice | `docs/evidence/gate-d-autonomous-recovery.md` |
| Executor cannot write the authoritative plane | `docs/evidence/gate-d1-executor-firestore-isolation.md` |
| Two-plane Firestore isolation (IAM-conditioned) | `docs/evidence/gate-d1-executor-firestore-isolation.md` |
| Deterministic policy gate, exact revision pinned | `docs/evidence/gate-d2-execution-correctness.md` |
| Independently probed known-good candidate | `docs/evidence/gate-d2-execution-correctness.md` |
| Firestore-atomic idempotency / execution plane | `docs/evidence/gate-d2-execution-correctness.md` |
| Datastore-atomic ownership under concurrency | `docs/evidence/gate-d2-execution-correctness.md` · `gate-d3` |
| `lease_epoch` fencing of a stale owner | `docs/evidence/gate-d3-lease-fencing-cas.md` |
| Cloud Run `resourceVersion` OCC (real 409 ABORTED) | `docs/evidence/gate-d3a-cloud-run-resourceversion-cas.md` |
| Reconciliation after crash, no second mutation | `docs/evidence/gate-d3-lease-fencing-cas.md` |
| Independent verifier (separate identity) | `docs/evidence/gate-d-autonomous-recovery.md` |
| Terminal `VERIFIED` execution, replay cannot re-run | `docs/evidence/gate-d3-lease-fencing-cas.md` |
| Hash-chained audit + tamper/truncation detection | `docs/evidence/gate-d3-lease-fencing-cas.md` |
| Failure engineering (16 live fault scenarios) | `docs/evidence/gate-e-failure-engineering.md` |
| Durable human approval across two process restarts | `docs/evidence/gate-f-durable-approval-resume.md` |
| Real Model Armor screening of untrusted input (Singapore) | `docs/evidence/gate-g-model-armor-security.md` |
| Blocked input never reaches the model | `docs/evidence/gate-g-model-armor-security.md` |
| Screening fails closed; safe when it misses | `docs/evidence/gate-g-model-armor-security.md` |
| No fleet identity can approve its own work | `docs/evidence/gate-g-model-armor-security.md` |
| Approval bound to one decision by authorization fingerprint | `docs/evidence/gate-f-durable-approval-resume.md` |
| Executor independently verifies human approval | `docs/evidence/gate-f-durable-approval-resume.md` |

**Marked `IMPLEMENTED`, not verified:** ambiguous mutation-outcome handling.
Google has never returned a non-409 failure here, so there is no live proof to
point at. Offline contract tests only. Do not upgrade this row without a real
platform failure to cite.

---

## 6. Wall plan status

| Date | Gate | Status |
|---|---|---|
| Aug 16 | Cloud foundation | **VERIFIED** |
| Aug 17 | Real target | **VERIFIED** |
| Aug 18 | Zero-trust execution | **VERIFIED** |
| Aug 19 | Full autonomous slice | **VERIFIED** |
| Aug 20 | Idempotency | **VERIFIED** |
| Aug 21 | Failure engineering (Gate E) | **VERIFIED** |
| Aug 22 | Durability / HITL (Gate F) | **VERIFIED** |
| Aug 23 | Security / Model Armor (Gate G) | **VERIFIED** |
| Aug 24 | Fleet completion | NOT STARTED |
| Aug 25 | Agent registry / lifecycle | NOT STARTED |
| Aug 26 | Evaluation | NOT STARTED |
| Aug 27 | Reliability | NOT STARTED |
| Aug 28 | **FEATURE FREEZE** | — |
| Aug 29 | Product / submission | — |
| Aug 30 | **REAL INTERNAL DEADLINE** | — |
| Aug 31 | Emergency buffer only — no feature work | — |

---

## 7. Next gates

**Gate F — durability / HITL: DONE.** A high-risk action now requires a person.
The approval model:

- The requirement comes from **trusted evidence**, never caller input. A blessed
  `known-good` rollback stays AUTO_ALLOWED; moving traffic to an unblessed but
  healthy revision is `SHIFT_TRAFFIC_TO_APPROVED_CANDIDATE` and needs a human.
- Same mutation primitive, same revision pinning, same OCC, same scoped
  identity, same verifier. Nothing was added to the blast radius to create risk.
- The approval lives in `(default)` beside the decision, bound by the
  authorization fingerprint. Change the action, target, revision, policy version
  or evidence snapshot and the approval no longer applies.
- The **executor verifies the approval itself**. Cloud Run invoker permission is
  not authorization.
- Proven across two process replacements: WAITING survived one, APPROVED
  survived another, and a third revision executed.

Then, in order: Model Armor and security · full fleet · runtime registry and
lifecycle · manager UI · meaningful multimodal screenshot routing · Cloud Trace
and observability · a 30+ incident evaluation suite · reliability and torture
runs · submission, demo and bonus work.

---

## 8. Required final fleet

LLM-backed specialists:

- Orchestrator
- Systems Investigator *(only one with a deployed runtime today)*
- Network Investigator
- Security / Identity Investigator
- Continuity Coordinator

Deterministic, non-agent components:

- Policy Gate
- Remediation Executor
- Independent Verifier / Audit

**Different incidents must route differently. Never a fixed fan-out.** A fleet
that always calls everyone is not a fleet; it is a batch job with a personality.
Selective routing is the claim, and it has to keep being true as specialists are
added.

---

## 9. Manager UX target

The opening question is:

> **"What is happening at your site?"**

The user supplies plain language, and optionally a screenshot or photo. Nothing
else is asked of them.

The final UI is for a manager, not an SRE. Technical evidence lives behind a
**"View technical evidence"** disclosure and is never the default view.

The screenshot must **materially affect routing or reasoning** to count as
meaningful multimodality. Decorative image upload does not qualify.

| Screenshot | Should route to |
|---|---|
| 503 error page | Systems |
| DNS / connection error | Network |
| MFA or session-expiry prompt | Security / Identity |

---

## 10. Final demo target (4 minutes)

| Time | Beat |
|---|---|
| 0:00–0:20 | The human problem |
| 0:20–0:45 | Incident report |
| 0:45–1:15 | Selective delegation |
| 1:15–1:50 | Trust / IAM boundary |
| 1:50–2:15 | Real recovery |
| 2:15–2:35 | Idempotency |
| 2:35–2:55 | Security / injection |
| 2:55–3:20 | HITL durable resume |
| 3:20–3:40 | Production proof |
| 3:40–4:00 | Architecture, measured results, close |

Anything important must be visible and immediately legible on screen. A judge
should not have to squint at a terminal to find the point.

---

## 11. Evaluation target

At least 30 synthetic incidents, normal and adversarial, if time permits.
Measure real numbers:

- routing accuracy
- policy correctness
- unauthorized mutations (target: zero)
- duplicate effects (target: zero)
- injection-induced privileged actions (target: zero)
- malformed proposals executed (target: zero)
- escalation when evidence is weak
- safe remediation success rate
- median resolution time, if useful

**Never invent numbers.** A missing measurement is reported as missing.

---

## 12. Current known limitations

Stated plainly, in the repo as well as here:

1. Execution is **not globally exactly-once**. Firestore and the Cloud Run Admin
   API cannot be committed together. The claim is fenced, duplicate-safe,
   recoverable, effect-idempotent execution with reconciliation.
2. The **stale-worker window is narrowed, not mathematically eliminated**.
3. Audit is **tamper-evident, not immutable**. Detecting a compromised
   authoritative writer needs an external witness we do not have.
4. **Full control-plane compromise is not solved** by executor isolation. An
   authorization fingerprint stops an equivalent re-issued decision becoming a
   second effect; a materially different forged authorization remains open.
5. **Candidate health is point-in-time.** Nothing guarantees the rollback target
   stays healthy after it is probed.
6. **Firestore isolation is database-level**, not collection-level — Google IAM
   cannot scope below a database.
7. **Gemini inference is global.** Complete Australian residency is not claimed.
8. **Model Armor screens untrusted input in Singapore**, not Melbourne:
   template Model Armor in `australia-southeast2` offers Sensitive Data
   Protection without the prompt-injection detector. Complete prompt-injection
   resistance is NOT claimed — a live policy-bypass attempt passed screening and
   changed nothing, which is the point. Response screening is implemented but
   not on the live path.
9. **Cloud Trace is not integrated** — structured Cloud Logging correlation via
   `trace_id` only.
10. **Only the Systems specialist has a deployed runtime.** Network, Security
    and Continuity are contract-level until the fleet gate.
11. **Terminalization is evidence-gated, not lease-gated.** `terminalize()`
    takes no owner and no `lease_epoch` — it mutates nothing, so ownership is
    the wrong gate. It requires an independent verifier verdict, the executor's
    own re-observation, and a CAS on the expected state.
12. **Ambiguous mutation-outcome handling has no live platform proof.**
13. **The approver is a named demo principal.** Google populates
    `X-Goog-Authenticated-User-Email` only for end-user credentials, and this
    fleet uses service-to-service tokens, so no real human principal reaches the
    container yet. Binding a signed-in manager identity belongs with the UI.
14. **The approval endpoint is authenticated, not role-authorized.** Any
    principal Google lets invoke the orchestrator may approve;
    `required_approval_role` is recorded, not enforced against the caller.
15. **Approval expiry is enforced on read, not swept.**

---

## 13. Ways we lose

Kept explicit because each one is a plausible way to spend two weeks and lose:

- **AI SRE disguise** — the duty-manager framing collapses into a tool for
  engineers, and the entry stops being distinctive.
- **Fake multi-agent** — a fixed fan-out with agent-shaped labels.
- **Architecture without evidence** — impressive diagrams, no artifacts.
- **Too many Google products** — breadth mistaken for depth; each integration
  costs reliability.
- **Only the happy path** — no failure engineering, so the safety claim is
  decorative.
- **Brittle demo** — anything that needs luck on the day.
- **LLM directly controls infrastructure** — the one architectural sin this
  entire design exists to avoid.
- **Late submission.**
- **Speculative bonus features damaging stability** near the freeze.

---

## 14. Review workflow

**Claude Code is the sole editor and primary implementer.** No other tool edits
this repository.

While Codex is unavailable (quota):

- A Claude internal hostile reviewer, spawned fresh with **no editing
  responsibility**, closes gates.
- Its verdict is labelled honestly as an internal review. It is **not** to be
  described as an independent external review.

Once Codex is available again:

- Codex performs a **read-only** accumulated catch-up review from Gate E onward.
- Claude fixes real Critical/High findings. Codex never edits concurrently.

Standard closing rule: the latest HEAD must carry **zero unresolved Critical and
zero High** from the available reviewer. Do not spend rounds eliminating
speculative Low findings.

What the review loop actually bought, recorded because it is the argument for
keeping it: across eighteen rounds, a majority of the later Highs were found
inside the *previous round's fix* rather than in the original code. Twice, a
passing test was found to be pinning the defect in place rather than catching
it. The last three rounds found no safety violation at all and their findings
moved to the truthfulness of the manager-facing handover, which is the signal
that was used to stop.

**Cadence changed after Gate E.** Endless rounds cost more than they return
once severities are falling. From Gate F onward: implement, run ONE focused
internal hostile review, fix real Critical/High and re-review ONCE, then close.
Speculative Low findings are documented, not chased.

---

## 15. Competition clock

| Milestone | Date |
|---|---|
| Feature freeze | **Aug 28** |
| Internal real deadline | **Aug 30** |
| Devpost deadline | Aug 31, 17:00 PT (Sep 1, 10:00 Melbourne) |

Aug 31 is submission, link and access buffer **only**. No feature development.

---

## 16. Current repo state

*Updated at the end of every gate.*

| Field | Value |
|---|---|
| Latest commit | see the tail of `git log --oneline` |
| Offline tests | 537 collected (526 passed, 11 skipped) |
| Current gate | Gate G closed |
| Gate E status | **VERIFIED**; external Codex catch-up audit pending on quota |
| Gate F status | **VERIFIED**; same Codex catch-up audit pending |
| Next gate | Aug 24 — Fleet completion. **Not started.** |
| Public repo | https://github.com/aish2897/after-hours-site-continuity-fleet |

Deployed Cloud Run revisions (Sydney):

| Service | Revision |
|---|---|
| `scf-orchestrator` | `scf-orchestrator-00136-ck2` |
| `scf-agent-systems` | `scf-agent-systems-00117-ffl` |
| `scf-executor` | `scf-executor-00117-pjn` |
| `scf-verifier` | `scf-verifier-00039-jfm` |
| `dispatch-web` (target) | `dispatch-web-00004-jqm` |
| `site-directory` (blast-radius control) | `site-directory-00001-hzn` |

Custom IAM roles: `scfRemediator`, `scfDecisionReader`, `scfExecutionWriter`,
`scfArtifactReader`. Firestore databases: `(default)` and `execution-state`,
both `australia-southeast1`.
