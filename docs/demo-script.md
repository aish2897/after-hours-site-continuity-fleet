# Four-Minute Demo Spine

**Status: planning document.** The moments below are the intended shape of the
final video. Only the parts backed by rows marked `VERIFIED` in the README
integration table exist today. Nothing here may be filmed as working before its
evidence artifact exists.

The earlier version of this file referenced prototype CLI commands
(`web_down`, `db_restart`, `prompt_injection`, `permission_denied`). Those were
removed with the prototype and are not coming back.

## 0:00–0:25 — Problem

A non-technical duty manager at a distributed site has an outage after hours.
They should not have to work out whether it is network, systems, identity,
security, or a vendor.

Show: the report as they would actually type it — lowercase, no service names,
no error codes.

## 0:25–1:10 — Evidence-dependent delegation *(available now)*

Show the orchestrator running on Google ADK against Gemini 3.7 Flash, emitting
a typed routing decision.

The point to land: **one** of four specialists is invoked, and the declines are
reasoned. The model rules out network because the report says phones and wifi
are fine. This is delegation, not fan-out.

## 1:10–2:00 — Governed remediation *(pending Gate B + dispatch-web)*

- Systems Investigator gathers trusted evidence from a real Cloud Run service.
- It proposes a remediation from a closed enum.
- The deterministic policy gate authorizes from trusted evidence only.
- The scoped executor performs a real Cloud Run traffic flip.
- `dispatch-web` genuinely goes 503 → 200.
- Verification runs under a different, read-only identity.

## 2:00–2:45 — The boundary is Google's, not ours *(pending IAM proofs)*

Three real, Google-generated results:

- **A.** Systems Investigator attempts the mutation → real `403 PERMISSION_DENIED`.
- **B.** Remediation Executor performs the authorized mutation → succeeds.
- **C.** Remediation Executor attempts the same mutation on an unrelated
  service → real `403 PERMISSION_DENIED`.

C is the one that matters: the boundary is scoped to a resource, not merely to
an identity.

## 2:45–3:20 — Replay and audit *(pending Firestore)*

Deliver the same execution request three times. Show exactly one mutation and
two duplicate suppressions in persisted action and audit state. Then show the
hash-chained audit trail failing verification after a single record is edited.

## 3:20–4:00 — Google Cloud proof

Cloud Run services and revisions, Firestore incident documents, one correlated
Cloud Trace spanning the whole flow, repository, and architecture diagram.

Close on the honest residency line: authoritative state, audit records, and
privileged execution stay on Australian infrastructure; model inference uses
the global endpoint because Gemini 3.7 Flash has no Australian regional
inference endpoint.
