# STATUS

CURRENT PHASE: Gate D.2 complete

WED AUG 19 — FULL AUTONOMOUS SLICE: VERIFIED
(achieved 2026-08-15, ahead of the wall-plan date)

## VERIFIED

Real execution proof exists in `docs/evidence/`.

- Gemini 3.7 Flash via Vertex AI (`global` inference location)
- Google ADK typed agent output
- Evidence-dependent specialist routing (not fixed fan-out)
- Cloud Run orchestrator (`scf-orchestrator`, Sydney, authenticated)
- Firestore durable incident state (`(default)`, Sydney, Native)
- Structured Cloud Logging correlation across all four services
- Real Cloud Run target with genuine healthy/broken revisions
- Real IAM investigator denial (`sa-agent-systems` → `dispatch-web`, 403)
- Scoped executor mutation (`sa-executor` → `dispatch-web`, success)
- Executor blast-radius denial (`sa-executor` → `site-directory`, 403)
- Real 503 → 200 infrastructure recovery
- Deterministic policy gate over TRUSTED_TOOL evidence
- Hash-chained audit with tamper detection
- **Systems Investigator as its own Cloud Run runtime, read-only**
- **Independent verifier under a separate read-only identity**
- **Persisted authorization decisions the executor re-reads**
- **Live Firestore-atomic idempotency: 3 replays, 1 mutation**
- **Executor refuses fabricated, denied, revoked and forged authority**
- **Full autonomous 503 → 200 with no operator action after submission**
- **Two-plane Firestore isolation: executor is read-only on the authoritative
  database and append-only on the execution database, enforced by per-database
  IAM conditions. It holds no project-level datastore role.**
- **Decision-bound execution identity: no caller field can create a second
  execution for the same authorization**
- **Datastore-atomic ownership proven under 10 concurrent requests: one
  owner, one mutation**
- **Reconciliation after crash: re-delivery observes the authorized target
  already active and does not mutate again**
- **Known-good candidate proven by operator tag plus direct probe, never
  inferred from being inactive**
- **Exact authorized revision pinned; HTTP 200 from the wrong revision does
  not resolve**
- **Stale-evidence precondition fails closed with no mutation**
- **State transition and audit record committed in one Firestore transaction**

## IN PROGRESS

Nothing. Gate D.2 is closed.

## NOT STARTED

- Human approval and resume
- Crash-resumable workflow
- Model Armor (Melbourne `australia-southeast2`)
- Cloud Trace end-to-end spans
- Network Investigator runtime
- Security & Identity Investigator runtime
- Continuity Coordinator runtime
- Duty-manager UI
- Evaluation suite
- Additional Google models / bonus categories

## HONEST LIMITATIONS

- Execution is duplicate-safe, recoverable and effect-idempotent with
  reconciliation. It is NOT globally exactly-once distributed execution.
- Audit is tamper-evident, NOT immutable.
- Firestore isolation is database-level, NOT collection-level.
- Cloud Run v2 does not accept the service etag as an enforced update
  precondition on our call; the compare-before-update guard is
  expected_source_revision.
- No prompt-injection resistance is claimed. Model Armor is not integrated.
- No Cloud Trace spans exist.

## NEXT HARD GATE

Failure engineering. Not yet authorized. Candidates in priority order: human approval with
resumable state, Model Armor inspection of untrusted content before agent use,
and the remaining fleet investigators.

## FROZEN ARCHITECTURE RULES

- LLM PROPOSES. DETERMINISTIC CODE DECIDES. SCOPED IDENTITY EXECUTES.
- TRUSTED_TOOL vs UNTRUSTED_INPUT; policy reads only TRUSTED_TOOL.
- Closed action enum; dangerous actions stay proposable so the gate refuses
  them on the record.
- Firestore CAS state transitions; deterministic idempotency keys.
- Investigators are read-only and never perform privileged mutations.
- The executor never accepts caller-supplied authorization.
- The component that acts never grades its own work.
- Denials come from Google IAM, never from application-level allowlists.
- Synthetic data only. No secrets committed. No service-account key files.
- No capability marked VERIFIED without a real execution artifact.

## KEY FACTS

```
project        site-continuity-fleet
core region    australia-southeast1 (Sydney)
model          gemini-3.7-flash, Vertex AI, location=global
model armor    australia-southeast2 (Melbourne), not integrated yet
firestore      (default)        australia-southeast1  authoritative control plane
               execution-state  australia-southeast1  idempotency + receipts

services       scf-orchestrator    sa-orchestrator
               scf-agent-systems   sa-agent-systems   (read-only)
               scf-executor        sa-executor        (only mutating identity)
               scf-verifier        sa-verifier        (read-only)
               dispatch-web        sa-dispatch-web    (zero project roles)
               site-directory      blast-radius control

revisions      healthy = dispatch-web-00003-x87
               broken  = dispatch-web-00004-jqm

custom roles   scfRemediator      run.services.get, run.services.update
               scfArtifactReader  artifactregistry.repositories.downloadArtifacts
               scfDecisionReader  read (default), IAM-conditioned
               scfExecutionWriter write execution-state, IAM-conditioned

repo           https://github.com/aish2897/after-hours-site-continuity-fleet
```

Complete Australian model-processing residency is not claimed: state, audit
and privileged execution are Australian; Gemini 3.7 Flash inference uses the
global endpoint because no Australian regional inference endpoint exists.
