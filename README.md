# After-Hours Site Continuity Fleet

A secure autonomous multi-agent system that lets a non-technical duty manager
recover a distributed business site when an incident spans network, systems,
identity, and external vendors.

Built for the All Things Agentic Hackathon, Fortified Enterprise Fleet track.

## Golden rule

> **LLM proposes. Deterministic code decides. Scoped identity executes.**

Gemini interprets messy human reports, routes to specialists, and proposes a
remediation from a closed enum. It never authorizes anything. Authorization is
a pure, table-driven function over trusted evidence. Execution happens under a
Google service account whose IAM role is scoped to a single Cloud Run service.

## Integration status

This table is the project's honesty mechanism.

| State | Meaning |
|---|---|
| `NOT INTEGRATED` | Not built. |
| `IMPLEMENTED` | Code exists and local tests pass. Not yet exercised against real infrastructure. |
| `VERIFIED` | Exercised for real, with a saved evidence artifact in `docs/evidence/`. |

Nothing in this repo, the demo video, or the Devpost entry may claim a
capability beyond the state recorded here.

| Capability | Status | Evidence |
|---|---|---|
| Gemini 3.7 Flash via Vertex AI | **`VERIFIED`** | [`gate-a-vertex-gemini.md`](docs/evidence/gate-a-vertex-gemini.md) |
| Deterministic policy gate | `IMPLEMENTED` | `tests/policy/test_decision_matrix.py` — 26 |
| Agent capability registry | `IMPLEMENTED` | `tests/policy/test_registry.py` — 9 |
| Incident state machine | `IMPLEMENTED` | `tests/unit/test_state_machine.py` — 15 |
| Deterministic idempotency keys | `IMPLEMENTED` | `tests/unit/test_ids.py` — 8 |
| Hash-chained audit + tamper detection | `IMPLEMENTED` | `tests/unit/test_audit_chain.py` — 9 |
| Evidence-dependent routing contract | `IMPLEMENTED` | `tests/unit/test_routing.py` — 7 |
| Trusted/untrusted evidence separation | `IMPLEMENTED` | `tests/policy/test_decision_matrix.py` |
| Google ADK | `NOT INTEGRATED` | in progress |
| Cloud Run services | `NOT INTEGRATED` | Gate B |
| Firestore durable state | `NOT INTEGRATED` | Gate B |
| Real IAM permission boundaries | `NOT INTEGRATED` | 3 proofs required |
| Real remediation on a live service | `NOT INTEGRATED` | `dispatch-web` |
| Cloud Logging / Trace correlation | `NOT INTEGRATED` | — |
| Model Armor | `NOT INTEGRATED` | after first remediation path |
| Resumable human approval | `NOT INTEGRATED` | out of slice 1 |
| Web UI | `NOT INTEGRATED` | out of slice 1 |

## What exists today

- `src/scf/domain/` — closed action enum, evidence provenance, deterministic
  idempotency derivation, 17-state incident machine, routing contract.
- `src/scf/policy/` — the gate. Loads `policies/action_policy.json`, reads only
  `TRUSTED_TOOL` evidence, returns a versioned decision with a reason code.
- `src/scf/audit/` — append-only hash chain with tamper detection.
- `src/scf/config.py` — frozen region and model decisions.

## Regions and data handling

| Concern | Location |
|---|---|
| Cloud Run, Firestore, Artifact Registry | Sydney `australia-southeast1` |
| Model Armor inspection | Melbourne `australia-southeast2` |
| Gemini 3.7 Flash inference | `global` |

Authoritative incident state, audit records, and privileged execution remain on
Australian Google Cloud infrastructure.

Gemini 3.7 Flash publishes inference endpoints for `global`, `us`, and `eu`
only — Sydney returns `404 NOT_FOUND` for this publisher model, confirmed by a
real call ([evidence](docs/evidence/gate-a-vertex-gemini.md)). Gemini 3.5 Flash
has no Sydney endpoint either. Model inference is therefore performed through
Vertex AI's `global` endpoint as a deliberate, documented architecture choice.

**Complete Australian data residency is not claimed.** The competition
environment uses synthetic data only. Sensitive or policy-restricted content
must never be silently sent to the global endpoint; an explicit classification
and security boundary governs what crosses it.

Pub/Sub is deliberately excluded. Replay and duplicate-delivery proof is done
by repeated delivery against Firestore-backed deterministic idempotency.

## Local run

Requires **Python 3.13+**. `StrEnum` means 3.10 will not work, and on some
machines `python` on PATH is older than `py -3.13`.

```powershell
cd D:\Agentic\site-continuity-fleet
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
```

## Non-negotiables

- Synthetic company, sites, users, and logs only. No employer data, code,
  names, policies, addresses, configurations, or IP.
- LLMs investigate and propose. Deterministic code decides every mutation.
- Untrusted text never reaches an authorization path.
- Every mutating action carries an incident id, action id, deterministic
  idempotency key, executor identity, evidence snapshot, and policy decision.
- No capability is claimed before its evidence artifact exists.
