# Google Cloud Checklist

Dedicated personal competition project. Frozen decisions, not open options.

**This file is a setup checklist, not a capability claim.** The authoritative
record of what is and is not integrated is the integration-status table in
`README.md`; where the two ever disagree, the README wins.

## Locations (decided, not to be re-litigated)

| Concern | Location | Status |
|---|---|---|
| Cloud Run | `australia-southeast1` Sydney | **done** |
| Firestore | `australia-southeast1` Sydney | **done** (two databases) |
| Artifact Registry | `australia-southeast1` Sydney | **done** |
| Model Armor | `australia-southeast2` Melbourne | PLANNED, not integrated |
| Gemini 3.7 Flash inference | `global` | **done** |

Gemini 3.7 Flash is not available through an Australian regional inference
endpoint; Sydney returns `404 NOT_FOUND` for the publisher model. Using the
global endpoint is a deliberate architecture decision, not a fallback, and
complete Australian model-processing residency is not claimed. Evidence:
`docs/evidence/gate-a-vertex-gemini.md`.

## Project setup

- [x] Project created: `site-continuity-fleet`
- [x] Billing enabled
- [ ] Budget alerts at $20 / $50 / $100 of the $150 credit
- [x] Application Default Credentials configured (`authorized_user`)

Use ADC or workload identity throughout. **Do not create or download
service-account key JSON files.**

## APIs

Enable only what the current gate needs.

- [x] `aiplatform.googleapis.com` — Gate A
- [x] `run.googleapis.com` — Gate B
- [x] `firestore.googleapis.com` — Gate B
- [x] `cloudbuild.googleapis.com` — Gate B, source deploys
- [x] `artifactregistry.googleapis.com` — Gate B
- [ ] `secretmanager.googleapis.com` — approval signing key, slice 2
- [ ] `modelarmor.googleapis.com` — after the first remediation path
- [x] `logging.googleapis.com`, `cloudtrace.googleapis.com` — already enabled

Deliberately not used: Pub/Sub, GKE, Cloud SQL.

## Cost controls

- Cloud Run `min-instances=0`, low `max-instances` during build.
- Gemini 3.7 Flash is a thinking model: thought tokens are charged against
  `maxOutputTokens`. Budget accordingly and keep prompts short.
- Live tests are opt-in behind `SCF_LIVE=1` so routine test runs cost nothing.
- Small Firestore footprint; no always-on databases.
- Capture demo evidence before scaling anything down.
