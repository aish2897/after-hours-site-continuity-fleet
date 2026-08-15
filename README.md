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

This table is the project's honesty mechanism. A row becomes `VERIFIED` only
when a matching evidence artifact exists in `docs/evidence/`. Nothing in this
repo, the demo video, or the Devpost entry may claim a capability whose row is
not `VERIFIED`.

| Capability | Status | Evidence |
|---|---|---|
| Deterministic policy gate | **VERIFIED (local)** | `tests/policy/test_decision_matrix.py` — 26 |
| Agent capability registry | **VERIFIED (local)** | `tests/policy/test_registry.py` — 9 |
| Incident state machine | **VERIFIED (local)** | `tests/unit/test_state_machine.py` — 15 |
| Deterministic idempotency keys | **VERIFIED (local)** | `tests/unit/test_ids.py` — 8 |
| Hash-chained audit + tamper detection | **VERIFIED (local)** | `tests/unit/test_audit_chain.py` — 9 |
| Evidence-dependent routing contract | **VERIFIED (local)** | `tests/unit/test_routing.py` — 7 |
| Trusted/untrusted evidence separation | **VERIFIED (local)** | `tests/policy/test_decision_matrix.py` |
| Gemini 3.7 Flash via Vertex AI | `NOT INTEGRATED` | Gate A pending |
| Google ADK | `NOT INTEGRATED` | Gate A pending |
| Cloud Run services | `NOT INTEGRATED` | Gate B pending |
| Firestore durable state | `NOT INTEGRATED` | Gate B pending |
| Real IAM permission boundaries | `NOT INTEGRATED` | Gate C pending |
| Real remediation on a live service | `NOT INTEGRATED` | pending |
| Cloud Logging / Trace correlation | `NOT INTEGRATED` | pending |
| Model Armor | `NOT INTEGRATED` | pending |
| Resumable human approval | `NOT INTEGRATED` | out of slice 1 |
| Web UI | `NOT INTEGRATED` | out of slice 1 |

**No Google Cloud service is currently integrated.** The deterministic core is
built and tested locally; cloud work is blocked on the Google Cloud SDK not
being installed on the build machine.

## What exists today

- `src/scf/domain/` — closed action enum, evidence provenance, deterministic
  idempotency derivation, 17-state incident machine, routing contract.
- `src/scf/policy/` — the gate. Loads `policies/action_policy.json`, reads only
  `TRUSTED_TOOL` evidence, returns a versioned decision with a reason code.
- `src/scf/audit/` — append-only hash chain with tamper detection.
- `src/scf/config.py` — frozen region and model decisions.

## Region decisions

Core stack is single-region **Sydney (`australia-southeast1`)**: Cloud Run,
Firestore, Vertex AI, Artifact Registry, Logging, Trace, Secret Manager.

Model Armor has no Sydney region, so security inspection crosses to
**Melbourne (`australia-southeast2`)**. That hop is deliberate, stays inside
Australia, and is documented in `ARCHITECTURE.md` rather than glossed over.

The global Gemini endpoint is **not** a silent fallback. If Sydney cannot serve
the model, the build stops and the decision is escalated.

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
