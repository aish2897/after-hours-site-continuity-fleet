# STATUS

CURRENT PHASE: Gate C complete

## VERIFIED

Real execution proof exists in `docs/evidence/`.

- Gemini 3.7 Flash via Vertex AI (`global` inference location)
- Google ADK typed agent output
- Evidence-dependent specialist routing (not fixed fan-out)
- Cloud Run orchestrator (`scf-orchestrator`, Sydney, authenticated)
- Firestore durable incident state (`(default)`, Sydney, Native)
- Structured Cloud Logging correlation by trace id
- Real Cloud Run target with genuine healthy/broken revisions
- Real IAM investigator denial (`sa-agent-systems` → `dispatch-web`, 403)
- Scoped executor mutation (`sa-executor` → `dispatch-web`, success)
- Executor blast-radius denial (`sa-executor` → `site-directory`, 403)
- Real 503 → 200 infrastructure recovery via Cloud Run traffic migration
- Deterministic policy gate over TRUSTED_TOOL evidence
- Hash-chained audit with tamper detection

## IN PROGRESS

Nothing. Gate C is closed.

## NOT STARTED

- Full autonomous 503 → 200 slice driven end-to-end by the agent workflow
- Idempotent execution against Firestore (derivation implemented, not enforced
  in a live execution path)
- Human approval and resume
- Crash-resumable workflow
- Model Armor (Melbourne `australia-southeast2`)
- Cloud Trace end-to-end spans
- Additional fleet agents (network, security, continuity investigators)
- Duty-manager UI
- Evaluation suite

## NEXT HARD GATE

Full autonomous 503 → 200 slice: the orchestrator routes to the Systems
Investigator, the investigator gathers trusted evidence from the real
`dispatch-web`, proposes `FLIP_TRAFFIC_TO_LAST_GOOD`, the deterministic policy
gate authorizes it, the scoped executor performs the real traffic migration
under `sa-executor`, verification confirms 200 from a separate read-only
identity, and replaying the same execution three times produces exactly one
mutation.

## FROZEN ARCHITECTURE RULES

- LLM PROPOSES. DETERMINISTIC CODE DECIDES. SCOPED IDENTITY EXECUTES.
- TRUSTED_TOOL vs UNTRUSTED_INPUT; policy reads only TRUSTED_TOOL.
- Closed action enum; dangerous actions stay proposable so the gate refuses
  them on the record.
- Firestore CAS state transitions; deterministic idempotency keys.
- Investigators are read-only and never perform privileged mutations in the
  normal workflow.
- Denials come from Google IAM, never from application-level allowlists.
- Synthetic data only. No secrets committed. No service-account key files.
- No capability marked VERIFIED without a real execution artifact.

## KEY FACTS

```
project        site-continuity-fleet
core region    australia-southeast1 (Sydney)
model          gemini-3.7-flash, Vertex AI, location=global
model armor    australia-southeast2 (Melbourne), not integrated yet
firestore      (default), australia-southeast1, FIRESTORE_NATIVE
orchestrator   scf-orchestrator  (sa-orchestrator)
target         dispatch-web      healthy=dispatch-web-00003-x87
                                 broken =dispatch-web-00004-jqm
                                 runtime=sa-dispatch-web (zero project roles)
control        site-directory    (blast-radius negative target)
custom roles   scfRemediator, scfArtifactReader
repo           https://github.com/aish2897/after-hours-site-continuity-fleet
```

Complete Australian model-processing residency is not claimed: state, audit
and privileged execution are Australian; Gemini 3.7 Flash inference uses the
global endpoint because no Australian regional inference endpoint exists.
