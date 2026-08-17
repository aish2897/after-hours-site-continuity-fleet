# After-Hours Site Continuity Fleet

A secure autonomous multi-agent system that lets a non-technical duty manager
recover a distributed business site when an incident spans network, systems,
identity, and external vendors.

Built for the All Things Agentic Hackathon, Fortified Enterprise Fleet track.

## Golden rule

> **LLM proposes. Deterministic code decides. Scoped identity executes.**

Gemini interprets messy human reports and decides which specialists should
investigate, with a stated reason for every call and every decline. It never
authorizes anything.

**What the LLM does today, precisely.** Routing is the LLM's only load-bearing
output. The remediation proposal is currently produced *deterministically* by
the Systems Investigator from trusted evidence — the model does not choose the
action. The `Proposal` contract, the closed `ActionType` enum and the
`propose_remediation` boundary all exist so that an LLM-authored proposal can
be dropped in without widening anyone's authority, and the security properties
are written for that case: a hallucinated privileged action is refused by the
deterministic gate, on the record ([`gate-e`](docs/evidence/gate-e-failure-engineering.md)).
Until that lands, "LLM proposes" describes the architecture, not the runtime.

Authorization is a pure, table-driven function over trusted evidence. Execution
happens under a Google service account whose IAM role is scoped to a single
Cloud Run service.

## Integration status

This table is the project's honesty mechanism.

| State | Meaning |
|---|---|
| `NOT INTEGRATED` | Not built. |
| `IMPLEMENTED` | Code exists and local tests pass. No dedicated live evidence artifact — some of these do run in the live path, but nothing here is claimed on that basis. |
| `VERIFIED` | Exercised for real, with a saved evidence artifact in `docs/evidence/`. |

Nothing in this repo, the demo video, or the Devpost entry may claim a
capability beyond the state recorded here.

| Capability | Status | Evidence |
|---|---|---|
| Gemini 3.7 Flash via Vertex AI | **`VERIFIED`** | [`gate-b`](docs/evidence/gate-b-cloud-run-firestore.md) · [`gate-a`](docs/evidence/gate-a-vertex-gemini.md) |
| Google ADK agent, typed output | **`VERIFIED`** | [`gate-b`](docs/evidence/gate-b-cloud-run-firestore.md) · [`gate-a`](docs/evidence/gate-a-adk-routing.md) |
| Evidence-dependent specialist routing | **`VERIFIED`** | [`gate-b`](docs/evidence/gate-b-cloud-run-firestore.md) |
| Cloud Run service (Sydney, authenticated) | **`VERIFIED`** | [`gate-b`](docs/evidence/gate-b-cloud-run-firestore.md) |
| Firestore durable incident state (Sydney) | **`VERIFIED`** | [`gate-b`](docs/evidence/gate-b-cloud-run-firestore.md) |
| Structured Cloud Logging correlation | **`VERIFIED`** | [`gate-b`](docs/evidence/gate-b-cloud-run-firestore.md) |
| Real Cloud Run target, healthy + broken revisions | **`VERIFIED`** | [`gate-c`](docs/evidence/gate-c-iam-boundary.md) |
| Real IAM investigator denial (403) | **`VERIFIED`** | [`gate-c`](docs/evidence/gate-c-iam-boundary.md) |
| Scoped executor mutation (resource-bound) | **`VERIFIED`** | [`gate-c`](docs/evidence/gate-c-iam-boundary.md) |
| Executor blast-radius denial (403) | **`VERIFIED`** | [`gate-c`](docs/evidence/gate-c-iam-boundary.md) |
| Real 503 → 200 infrastructure recovery | **`VERIFIED`** | [`gate-c`](docs/evidence/gate-c-iam-boundary.md) |
| **Full autonomous 503 → 200 slice** | **`VERIFIED`** | [`gate-d`](docs/evidence/gate-d-autonomous-recovery.md) |
| Investigator as its own read-only runtime | **`VERIFIED`** | [`gate-d`](docs/evidence/gate-d-autonomous-recovery.md) |
| Persisted authorization decisions | **`VERIFIED`** | [`gate-d`](docs/evidence/gate-d-autonomous-recovery.md) |
| Live Firestore-atomic idempotency | **`VERIFIED`** | [`gate-d`](docs/evidence/gate-d-autonomous-recovery.md) |
| Independent verification (separate identity) | **`VERIFIED`** | [`gate-d`](docs/evidence/gate-d-autonomous-recovery.md) |
| Executor rejects forged authority | **`VERIFIED`** | [`gate-d`](docs/evidence/gate-d-autonomous-recovery.md) |
| Executor cannot write authorization state | **`VERIFIED`** | [`gate-d1`](docs/evidence/gate-d1-executor-firestore-isolation.md) |
| Two-plane Firestore isolation (IAM-conditioned) | **`VERIFIED`** | [`gate-d1`](docs/evidence/gate-d1-executor-firestore-isolation.md) |
| Decision-bound execution identity (no caller retry field) | **`VERIFIED`** | [`gate-d2`](docs/evidence/gate-d2-execution-correctness.md) |
| Datastore-atomic ownership under 10-way concurrency | **`VERIFIED`** | [`gate-d2`](docs/evidence/gate-d2-execution-correctness.md) |
| Reconciliation after crash (no second mutation) | **`VERIFIED`** | [`gate-d2`](docs/evidence/gate-d2-execution-correctness.md) |
| Proven known-good candidate (tag + direct probe) | **`VERIFIED`** | [`gate-d2`](docs/evidence/gate-d2-execution-correctness.md) |
| Exact authorized revision pinned and verified | **`VERIFIED`** | [`gate-d2`](docs/evidence/gate-d2-execution-correctness.md) |
| Stale-evidence precondition fails closed | **`VERIFIED`** | [`gate-d2`](docs/evidence/gate-d2-execution-correctness.md) |
| State + audit committed in one transaction | **`VERIFIED`** | [`gate-d2`](docs/evidence/gate-d2-execution-correctness.md) |
| Cloud Run v1 `resourceVersion` CAS (real 409 ABORTED) | **`VERIFIED`** | [`gate-d3a`](docs/evidence/gate-d3a-cloud-run-resourceversion-cas.md) · [`gate-d3`](docs/evidence/gate-d3-lease-fencing-cas.md) |
| Lease-epoch fencing of a stale owner | **`VERIFIED`** | [`gate-d3`](docs/evidence/gate-d3-lease-fencing-cas.md) |
| Ownership under 100-way same-decision concurrency | **`VERIFIED`** | [`gate-d3`](docs/evidence/gate-d3-lease-fencing-cas.md) |
| Terminal execution state (replay cannot re-run) | **`VERIFIED`** | [`gate-d3`](docs/evidence/gate-d3-lease-fencing-cas.md) |
| Verifier-crash recovery without blind re-mutation | **`VERIFIED`** | [`gate-d3`](docs/evidence/gate-d3-lease-fencing-cas.md) |
| Partial-traffic rejection (50/50, 90/10) | **`VERIFIED`** | [`gate-d3`](docs/evidence/gate-d3-lease-fencing-cas.md) |
| Traffic-only mutation, no revision or config drift | **`VERIFIED`** | [`gate-d3`](docs/evidence/gate-d3-lease-fencing-cas.md) |
| Candidate re-probed immediately before mutating | **`VERIFIED`** | [`gate-d3`](docs/evidence/gate-d3-lease-fencing-cas.md) |
| Audit truncation detected against incident tail metadata | **`VERIFIED`** | [`gate-d3`](docs/evidence/gate-d3-lease-fencing-cas.md) |
| One authorization fingerprint → one execution identity | **`VERIFIED`** | [`gate-d3`](docs/evidence/gate-d3-lease-fencing-cas.md) |
| Malformed model output rejected at the parser | **`VERIFIED`** | [`gate-e`](docs/evidence/gate-e-failure-engineering.md) |
| Hallucinated privileged action deterministically denied | **`VERIFIED`** | [`gate-e`](docs/evidence/gate-e-failure-engineering.md) |
| Real worker timeout and 503 → escalation, zero mutation | **`VERIFIED`** | [`gate-e`](docs/evidence/gate-e-failure-engineering.md) |
| Bounded worker budget (looping worker terminated) | **`VERIFIED`** | [`gate-e`](docs/evidence/gate-e-failure-engineering.md) |
| Doing nothing when evidence is insufficient | **`VERIFIED`** | [`gate-e`](docs/evidence/gate-e-failure-engineering.md) |
| Authenticated-but-malformed worker payload rejected | **`VERIFIED`** | [`gate-e`](docs/evidence/gate-e-failure-engineering.md) |
| Caller loses a surviving executor → reconciled, one effect | **`VERIFIED`** | [`gate-e`](docs/evidence/gate-e-failure-engineering.md) |
| Deterministic failure taxonomy + escalation package | **`VERIFIED`** | [`gate-e`](docs/evidence/gate-e-failure-engineering.md) |
| No blind retry (every retry budget is zero) | **`VERIFIED`** | [`gate-e`](docs/evidence/gate-e-failure-engineering.md) |
| Closed incident cannot be re-executed | **`VERIFIED`** | [`gate-d3`](docs/evidence/gate-d3-lease-fencing-cas.md) |
| Reconciliation after an unreachable executor | **`VERIFIED`** | [`gate-d3`](docs/evidence/gate-d3-lease-fencing-cas.md) |
| An attempted execution never mutates twice | **`VERIFIED`** | [`gate-d3`](docs/evidence/gate-d3-lease-fencing-cas.md) |
| Deterministic policy gate | **`VERIFIED`** | [`gate-d`](docs/evidence/gate-d-autonomous-recovery.md) · [`gate-d3`](docs/evidence/gate-d3-lease-fencing-cas.md) — authorized every live run |
| Agent capability registry | `IMPLEMENTED` | `tests/policy/test_registry.py` — 9 |
| Incident state machine | **`VERIFIED`** | [`gate-d3`](docs/evidence/gate-d3-lease-fencing-cas.md) — every live run walks it end to end; illegal-transition refusal is offline-tested |
| Deterministic idempotency keys | **`VERIFIED`** | [`gate-d2`](docs/evidence/gate-d2-execution-correctness.md) · [`gate-d3`](docs/evidence/gate-d3-lease-fencing-cas.md) — one identity across 200 requests |
| Hash-chained audit + tamper detection | **`VERIFIED`** | [`gate-d3`](docs/evidence/gate-d3-lease-fencing-cas.md) — chains verified against live incidents |
| Trusted/untrusted evidence separation | `IMPLEMENTED` | `tests/policy/test_decision_matrix.py` |
| Cloud Trace end-to-end spans | `NOT INTEGRATED` | logging correlation only |
| Model Armor | `NOT INTEGRATED` | Melbourne, next |
| Resumable / crash-resumable workflow | `NOT INTEGRATED` | durable persistence only |
| Resumable human approval | `NOT INTEGRATED` | — |
| Network / Security / Continuity runtimes | `NOT INTEGRATED` | systems only so far |
| Duty-manager UI | `NOT INTEGRATED` | — |

Boundaries of the claim, stated precisely:

- Execution is **fenced, duplicate-safe, recoverable and effect-idempotent with
  reconciliation** — *not* globally exactly-once distributed execution.
  Firestore and the Cloud Run Admin API cannot be committed together.
- The **stale-worker window is narrowed, not eliminated**. A fenced worker
  cannot advance execution state, and a stale Cloud Run snapshot is rejected by
  Google with 409 ABORTED — but a worker that lost its lease after its final
  ownership check can still reach the API if the service has not changed. It
  can only apply the same authorized effect, and it cannot advance the
  execution lifecycle state or write a receipt. See [`SECURITY.md`](SECURITY.md).
- **Cloud Run v2 `etag` is not a concurrency control** for the traffic update;
  proven live. The executor mutates through v1 `replaceService`, where
  `resourceVersion` is genuinely enforced.
- Audit is **tamper-evident, not immutable**.
- Durable persistence is proven; **crash-resumable workflow is not**.
- Cloud Logging entries share a trace id across all four services, but **no
  span has been exported to Cloud Trace**.
- **Model Armor is not integrated**, so no prompt-injection resistance is
  claimed — only that untrusted content cannot reach an authorization path.
- One investigator is deployed; the other three are contracts only.

See [`STATUS.md`](STATUS.md) for the current phase and next gate.

## What exists today

- `src/scf/domain/` — closed action enum, evidence provenance, deterministic
  idempotency derivation, 17-state incident machine, routing contract.
- `src/scf/policy/` — the gate. Loads `src/scf/policies/action_policy.json`, reads only
  `TRUSTED_TOOL` evidence, returns a versioned decision with a reason code.
- `src/scf/audit/` — append-only hash chain with tamper detection.
- `src/scf/config.py` — frozen region and model decisions.

## Regions and data handling

| Concern | Location |
|---|---|
| Cloud Run, Firestore, Artifact Registry | Sydney `australia-southeast1` |
| Model Armor inspection *(PLANNED, not integrated)* | Melbourne `australia-southeast2` |
| Gemini 3.7 Flash inference | `global` |

Authoritative incident state, audit records, and privileged execution remain on
Australian Google Cloud infrastructure.

Gemini 3.7 Flash publishes inference endpoints for `global`, `us`, and `eu`
only — Sydney returns `404 NOT_FOUND` for this publisher model, confirmed by a
real call ([evidence](docs/evidence/gate-a-vertex-gemini.md)). Gemini 3.5 Flash
has no Sydney endpoint either. Model inference is therefore performed through
Vertex AI's `global` endpoint as a deliberate, documented architecture choice.

**Complete Australian data residency is not claimed.** The competition
environment uses synthetic data only.

**There is no classification or inspection step today.** The duty manager's
report text is passed to the routing agent, and therefore to the `global`
endpoint, uninspected. A boundary that decides what may cross is the intended
design and is **PLANNED, NOT INTEGRATED** — see
[`ARCHITECTURE.md`](ARCHITECTURE.md). What does hold is narrower: untrusted
text is recorded as `UNTRUSTED_INPUT` and can never satisfy a policy
condition, which protects the *authorization* path and nothing more.

Pub/Sub is deliberately excluded. Replay and duplicate-delivery proof is done
by repeated delivery against Firestore-backed deterministic idempotency.

## Local run

Requires **Python 3.11+** (`StrEnum` means 3.10 will not work). Developed and
tested on 3.13; on some machines `python` on PATH is older than `py -3.13`.

```powershell
git clone https://github.com/aish2897/after-hours-site-continuity-fleet.git
cd after-hours-site-continuity-fleet
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,adk]"
.\.venv\Scripts\python.exe -m pytest
```

Live tests that call Vertex AI are skipped by default. They need Application
Default Credentials (`gcloud auth application-default login`) and cost tokens:

```powershell
$env:SCF_LIVE=1; .\.venv\Scripts\python.exe -m pytest tests/e2e
```

## Non-negotiables

- Synthetic company, sites, users, and logs only. No employer data, code,
  names, policies, addresses, configurations, or IP.
- An LLM may investigate and propose; it never authorizes. Deterministic code
  decides every mutation. (Today the LLM only routes — see the golden rule
  section above.)
- Untrusted text never reaches an authorization path.
- Every mutating action carries an incident id, action id, deterministic
  idempotency key, executor identity, evidence snapshot, and policy decision.
- No capability is claimed before its evidence artifact exists.
