# Gate B — Cloud Run + Firestore + deployed ADK

**Status: PASSED**

Sanitized. No bearer tokens, identity tokens, or credential material recorded.
Authentication used Application Default Credentials and Cloud Run's attached
service-account identity throughout. **No service-account key was created or
downloaded.**

## Infrastructure

| Item | Value |
|---|---|
| Project | `site-continuity-fleet` |
| Firestore database | `(default)` |
| Firestore location | **`australia-southeast1`** |
| Firestore type | `FIRESTORE_NATIVE`, PESSIMISTIC concurrency, free tier |
| Firestore created | 2026-08-15T15:06:38Z |
| Cloud Run service | `scf-orchestrator` |
| Cloud Run region | **`australia-southeast1`** |
| Revisions | `scf-orchestrator-00001-5rk`, `scf-orchestrator-00002-bqn` |
| Service URL | `https://scf-orchestrator-booyfgej7a-ts.a.run.app` |
| Ingress auth | authenticated only (`--no-allow-unauthenticated`) |
| Runtime identity | `sa-orchestrator@site-continuity-fleet.iam.gserviceaccount.com` |
| Model | `gemini-3.7-flash` via Vertex AI, `global` |

No `(default)` database existed before this gate — verified by
`gcloud firestore databases list` returning `[]` and `describe` returning
`NOT_FOUND`. The Sydney location was chosen on an empty project, so the
immutable location decision is correct on the first attempt.

## APIs enabled during Gate B

`firestore.googleapis.com`, `run.googleapis.com`, `cloudbuild.googleapis.com`,
`artifactregistry.googleapis.com`. `aiplatform.googleapis.com` was already
enabled by Gate A. Nothing else was enabled.

## Service account roles

`sa-orchestrator` holds exactly three project roles:

```
roles/datastore.user
roles/aiplatform.user
roles/logging.logWriter
```

No Owner, no Editor, no `run.admin`, no IAM administration, no remediation
permissions. Cloud Run uses the attached identity; there is no key file.

## Incident A — application symptom

**Input** (the caller supplies no service, category, specialist, cause, or
remediation):

```json
{"description": "The dispatch screens are showing an error page. Phones and Wi-Fi seem fine.",
 "site_id": "MEL-WAREHOUSE-01", "reported_by": "duty-manager"}
```

`HTTP 201` → `INC-20260815-37F150`, status `INVESTIGATING`,
trace `7053fac8c3ed3dd7f2543ff7d5581bfd`

| Specialist | Decision | Model's reason |
|---|---|---|
| network | declined | Phones and Wi-Fi are working normally, indicating local connectivity is intact. |
| **systems** | **REQUIRED** | The dispatch screens are displaying an application error page, pointing to a service or application issue. |
| security | declined | No unauthorized access, malicious activity, or suspicious identity events have been reported. |
| continuity | declined | The issue is currently localized to internal dispatch displays and does not yet require vendor handoff or external communications. |

## Incident B — network symptom

```json
{"description": "Nothing at the site can reach our internal services, and staff say Wi-Fi devices have also lost connectivity.",
 "site_id": "MEL-WAREHOUSE-01", "reported_by": "duty-manager"}
```

`HTTP 201` → `INC-20260815-4D7BA0`, status `INVESTIGATING`,
trace `9b67efe7792f78470a2e4794a7bc57e3`

| Specialist | Decision | Model's reason |
|---|---|---|
| **network** | **REQUIRED** | Site-wide loss of Wi-Fi and general connectivity directly points to a local network or gateway failure. |
| systems | declined | Unreachability of internal services appears secondary to the broader site network drop rather than a server-side outage. |
| security | declined | There is no evidence of unauthorized access, account compromise, or malicious activity in the report. |
| continuity | declined | Initial technical troubleshooting can proceed without broad stakeholder communications or external vendor handoffs at this stage. |

## Routing differs — delegation is evidence-dependent

| | Incident A | Incident B |
|---|---|---|
| Required | `["systems"]` | `["network"]` |
| Specialists invoked | 1 of 4 | 1 of 4 |

Two reports from the same site produced **different single-specialist
routing**. Neither invoked all four. Incident A declined network by reasoning
over the detail that phones and Wi-Fi work; Incident B reached the opposite
conclusion from the opposite evidence, and additionally reasoned that the
systems symptom was *secondary* to the network failure.

No specialist list is hardcoded in application logic. The closed
`SpecialistName` enum constrains which names are legal; it does not decide
which are required.

## Persistence proof

Both incidents were created by revision `scf-orchestrator-00001-5rk`.
A second revision, `scf-orchestrator-00002-bqn`, was then deployed, replacing
all running instances. Re-reading the same incidents:

```
INC-20260815-37F150  status=INVESTIGATING  required=['systems']  audit=3  served_by=scf-orchestrator-00002-bqn
INC-20260815-4D7BA0  status=INVESTIGATING  required=['network']  audit=3  served_by=scf-orchestrator-00002-bqn
```

State was written by one container generation and read by another. It comes
from Firestore, not process memory.

This proves **durable incident persistence only**. Crash-resumable workflow is
not claimed and belongs to a later gate.

## Persisted document shape

`incidents/{incident_id}`:

```
audit_record_count (derived)  created_at   current_step   deadline_at
incident_id   lease   report{site_id,description,reported_by,received_at}
routing{routes[],summary,model_id,created_at}   schema_version   severity
status   step_budget_remaining   trace_id   untrusted_content_flags   updated_at
```

Subcollection `incidents/{id}/audit/{seq}` holds the hash-chained trail:
`incident_received`, `routing_decision`, `state_transition`.

`untrusted_content_flags` is `["UNTRUSTED_INPUT"]` — the duty manager's words
are recorded with untrusted provenance and can never satisfy a policy
condition. The routing rationale is stored as display and evidence material
only; the policy gate does not read it.

## Logging correlation

One trace id links the full request chain in Cloud Logging:

```
15:14:03.154  request_received        INC-20260815-37F150  7053fac8…
15:14:03.622  incident_persisted      INC-20260815-37F150  7053fac8…
15:14:03.622  adk_invocation_started  INC-20260815-37F150  7053fac8…
15:14:08.439  routing_decision        INC-20260815-37F150  7053fac8…
15:14:09.005  state_persisted         INC-20260815-37F150  7053fac8…
```

Entries are structured JSON with `logging.googleapis.com/trace`, so Cloud
Logging groups them. A log query for `Bearer`, `ya29.`, or an `authorization`
field returns nothing; `log_event` redacts credential-shaped keys by name.

**Cloud Trace integration is not claimed.** This is structured Cloud Logging
correlation only. No span has been exported to Cloud Trace.

## Findings

1. **Google Frontend intercepts `/healthz`.** The path returned a GFE 404 ahead
   of the container while `/openapi.json` returned 200 and listed the route.
   The endpoint was renamed to `/health`, which works. Cosmetic, not
   architectural — recorded so it is not mistaken for a deployment failure.
2. **`gcloud run deploy` printed a hostname that does not serve the service.**
   Deploy output showed
   `https://scf-orchestrator-911485617985.australia-southeast1.run.app`, which
   returns a GFE 404. The URL from `gcloud run services describe`,
   `https://scf-orchestrator-booyfgej7a-ts.a.run.app`, is the working one.
3. **`requires-python` was relaxed from `>=3.13` to `>=3.11`.** 3.11 is the
   true floor (`StrEnum`); pinning 3.13 would have constrained the buildpack
   for no reason.

## Tests

- Offline: **124 passed, 11 skipped**.
- Deployed (`tests/e2e/test_gate_b_deployed.py`): **9 passed** against the live
  service, covering health/region/revision, evidence-dependent routing without
  fan-out, Firestore readback, 404 handling, four malformed-intake rejections,
  and enforcement of authentication.
