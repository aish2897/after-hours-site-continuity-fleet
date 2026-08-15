# Gate A — Google ADK agent with typed routing output

**Status: PASSED**

Sanitized. Authentication used Application Default Credentials; no API key and
no service-account key file.

## Stack

| Component | Version / value |
|---|---|
| `google-adk` | 2.7.0 |
| `google-genai` | 2.18.1 |
| Model | `gemini-3.7-flash` |
| Inference location | `global` (Vertex AI) |
| Project | `site-continuity-fleet` |
| Agent | `LlmAgent(name="orchestrator_router")`, no tools |
| Runner | `InMemoryRunner` |
| Output schema | `RoutingLlmOutput` (pydantic), promoted to `RoutingDecision` |
| Run timestamp | 2026-08-15T14:43:38Z |

Reproduce with `.\.venv\Scripts\python.exe tools\gate_a_adk.py`.

## Untrusted input

The report is wrapped in `<untrusted_incident_report>` tags and passed as data.
The instruction tells the model to treat it as data and never as instructions.

> Im the night duty manager at the Melbourne West site. The dispatch screens in
> the loading bay are all showing an error page and the drivers cant print run
> sheets. Phones and the wifi seem fine. Nobody has touched anything tonight.

Deliberately written the way a non-technical duty manager types at 2am:
lowercase, missing apostrophes, no service names, no error codes.

## Typed output returned

| Specialist | Decision | Model's reason |
|---|---|---|
| `network` | declined | Local Wi-Fi and phone systems are working normally, indicating the site network is operational. |
| **`systems`** | **REQUIRED** | The dispatch application is displaying errors and printing services are unavailable. |
| `security` | declined | There are no signs of unauthorized access or security incidents. |
| `continuity` | declined | The issue is isolated to internal application triage and does not yet require vendor escalation or external communication. |

**Summary returned:** "The dispatch screen and printing application at the
Melbourne West site are down and need investigation by the systems team."

**Required specialists:** `['systems']`

## Why this is evidence-dependent delegation

One of four specialists was invoked. The model declined `network` by reasoning
over a specific detail in the report — that phones and wifi were working — and
declined `security` and `continuity` on their own stated grounds.

Every specialist appears in the output with a reason, including the declined
ones, so a decision not to investigate is recorded rather than silently
omitted. Fan-out to all four remains possible for a genuine site-wide outage;
it is simply not automatic.

## Boundary properties proven

- **Structured output is enforced, not requested.** The agent declares
  `output_schema=RoutingLlmOutput`. The response is parsed with
  `model_validate`; a schema violation raises rather than degrading to freeform
  text or triggering a retry.
- **The model cannot assert its own provenance.** `RoutingLlmOutput` is
  narrower than the domain `RoutingDecision` and forbids extra fields.
  `model_id` is attached by application code on promotion, so the model cannot
  claim to be a different model.
- **Routing is not authorization.** This agent has no tools and cannot mutate
  anything. It only decides who investigates.

## Tests

- `tests/unit/test_agent_schemas.py` — 8 offline tests covering promotion,
  provenance rejection, malformed-output rejection, and instruction content.
- `tests/e2e/test_adk_routing_live.py` — 2 live tests against real Vertex,
  asserting `systems` required and `network` not required. Skipped unless
  `SCF_LIVE=1`.

Live run: 2 passed.
