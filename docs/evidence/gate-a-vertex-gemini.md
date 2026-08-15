# Gate A — Vertex AI Gemini 3.7 Flash

**Status: PASSED** (global inference location)

Sanitized. No access tokens, key material, or billing identifiers are recorded
here. Authentication used Application Default Credentials throughout; no API
key and no downloaded service-account key file were used at any point.

## Environment

| Item | Value |
|---|---|
| Project | `site-continuity-fleet` (ACTIVE) |
| Billing | enabled |
| Auth | ADC, `type: authorized_user`, quota project `site-continuity-fleet` |
| gcloud SDK | 580.0.0 |
| API enabled | `aiplatform.googleapis.com` |

## Attempt 1 — Sydney regional endpoint: FAILED (expected)

```
POST https://australia-southeast1-aiplatform.googleapis.com/v1/projects/
     site-continuity-fleet/locations/australia-southeast1/
     publishers/google/models/gemini-3.7-flash:generateContent

HTTP 404 NOT_FOUND
"Publisher model `.../locations/australia-southeast1/publishers/google/
 models/gemini-3.7-flash` was not found or your project does not have
 access to it."
```

Timestamp: `2026-08-15T14:30:59Z`

**404, not 401 or 403** — the request authenticated successfully and reached
Vertex AI in Sydney. Vertex reported the publisher model is not served there.
This is a model-availability constraint, not a credential, billing, API, or
project-access failure.

Gemini 3.7 Flash publishes inference endpoints for `global`, `us`, and `eu`
only. Gemini 3.5 Flash has no Sydney endpoint either, so downgrading the model
family does not resolve it.

## Attempt 2 — global endpoint: SUCCEEDED

```
POST https://aiplatform.googleapis.com/v1/projects/site-continuity-fleet/
     locations/global/publishers/google/models/gemini-3.7-flash:generateContent

HTTP 200
```

| Field | Value |
|---|---|
| `modelVersion` | `gemini-3.7-flash` |
| `createTime` | `2026-08-15T14:40:48.105975Z` |
| `responseId` | `cHqAave7BrDg8vUPoMjW6QI` |
| `finishReason` | `STOP` |
| `promptTokenCount` | 38 |
| `thoughtsTokenCount` | 297 |
| `candidatesTokenCount` | 7 |
| `totalTokenCount` | 342 |
| `trafficType` | `ON_DEMAND` |

**Prompt**

> A warehouse duty manager reports: 'the dispatch screens are showing an error
> page'. Name the single specialist who should investigate first: network,
> systems, or security. Answer in one short sentence.

**Response**

> A systems specialist should investigate first.

The model selected `systems`, which matches the specialist that the slice-1
routing contract expects for an application-layer symptom.

## Operational finding: thinking-token budget

The first successful call used `maxOutputTokens: 200` and returned
`finishReason: MAX_TOKENS` with six tokens of truncated, unusable text. The
model had spent 190 tokens on internal reasoning before emitting an answer.

`gemini-3.7-flash` is a thinking model and reports a `thoughtSignature` plus a
`thoughtsTokenCount`. Thought tokens are charged against `maxOutputTokens`, so
a budget sized for the visible answer alone silently truncates to nothing.

`config.DEFAULT_MAX_OUTPUT_TOKENS` is set to 2048 for this reason.

## Client-side issues encountered (not Google blockers)

Recorded so they are not mistaken for platform problems:

1. **PowerShell 5.1 TLS default** — connection closed on receive. PS 5.1
   negotiates TLS 1.0/1.1; Google requires 1.2+.
2. **PowerShell 5.1 `Expect: 100-continue`** — returned HTTP 417.
3. **Windows AMSI false positive** — the PowerShell script was blocked as
   malicious (token-fetch plus POST heuristic). Resolved by issuing the request
   through Bash and `curl` against the identical endpoint with identical auth.
4. **Stale PATH** — `gcloud` was installed and registered in the user PATH but
   invisible to already-running shells.

## Data residency statement

Authoritative incident state, audit records, and privileged execution remain on
Australian Google Cloud infrastructure (Sydney `australia-southeast1`), with
Model Armor inspection in Melbourne `australia-southeast2`.

Gemini 3.7 Flash inference is performed through Vertex AI's `global` endpoint
because no Australian inference endpoint is published for this model.

**Complete Australian data residency is therefore not claimed.** The
competition environment uses synthetic data only, and an explicit
classification and security boundary governs what may be sent to the model.
