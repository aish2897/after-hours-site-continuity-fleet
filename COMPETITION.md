# Competition Rule Lock

Source documents reviewed:

- Local PDF export of the competition prize listing (not redistributed here).
- Local DOCX resource pack supplied with the hackathon (not redistributed here).
- Official Devpost rules, overview, FAQ, resources, and current Google documentation checked on 2026-08-15.

## Hard Requirements

- Competition: All Things Agentic Hackathon.
- Track: Fortified Enterprise Fleet.
- Deadline: 2026-08-31 5:00 PM Pacific Time, which is 2026-09-01 10:00 AM Melbourne time.
- Project must be newly created during the submission period.
- Mandatory tech:
  - Gemini 3.5 or newer via Gemini API or Vertex AI.
  - At least one Google agent framework: Google ADK, GenAI SDK, Antigravity SDK, or Genkit.
  - At least one Google Cloud infrastructure service, such as Cloud Run, Firestore, Pub/Sub, Cloud SQL, or GKE.
- Submission must include:
  - One selected category.
  - Hosted project URL if available.
  - Text description with features, technologies, data sources, findings, and learnings.
  - Public or private GitHub, GitLab, or Bitbucket repo.
  - README spin-up instructions.
  - Architecture diagram.
  - Public YouTube or Vimeo demo video in English or with English subtitles.
  - Demo video maximum: 4 minutes; only the first 4 minutes may be evaluated.
  - Visible proof that backend ran on Google Cloud.

## Fortified Enterprise Fleet Target

The official track asks for scalable institutional agents connected to enterprise infrastructure. The expected evidence is:

- Agent discovery and lifecycle management.
- Long-running asynchronous execution.
- Persistent state and memory across extended timelines.
- Zero-trust identity.
- Gateway policy enforcement.
- Prompt-injection, tool-poisoning, and PII-leak protection.
- OpenTelemetry-style audit logs and reasoning traces.
- Compliance, data sovereignty, and security handling.

The Google Enterprise Agent Platform capabilities are recommended rather than all mandatory, but they are the shape of the judging expectation.

## Scoring Strategy

Stage One is pass/fail. We must satisfy every submission requirement and show a viable, working project.

Stage Two is scored 1 to 5 per criterion:

- Innovation and Operational Utility, 40 percent.
- Architectural Discipline and Tech Stack, 30 percent.
- Demo and Production Readiness, 30 percent.

Stage Three bonuses:

- Public build content: +0.2.
- Public social post using `#AllThingsAgenticHackathon`: +0.2.
- Additional Google AI models, such as Gemma, Veo, or Lyria: +0.2 each, capped at +0.6.

Maximum final score: 6.0.

## Positioning Decision

We are not building another generic IT incident-response copilot. The stronger project is:

> A secure autonomous multi-agent Site Continuity Fleet that lets non-technical frontline duty managers resolve and coordinate complex enterprise outages, while enforcing scoped identity, deterministic policy, a gate that routes risky actions to human approval rather than acting on them, and a tamper-evident audit trail.

Note on wording: this positioning deliberately does **not** claim data
sovereignty. Authoritative operational state, audit records, and privileged
execution remain on Australian Google Cloud infrastructure, but Gemini 3.7
Flash inference uses Vertex AI's global endpoint because the model is not
available through an Australian regional inference endpoint. See
`ARCHITECTURE.md`. Multimodal intake is also not claimed; it is out of scope
until the first vertical slice is verified.

Why this is stronger:

- It directly targets the Fortified Enterprise Fleet "Unlikely Hero" wording.
- It makes the need for multiple agents obvious.
- It can show real autonomous action instead of chat.
- It creates a credible path to Best Multimodal UX.
- It uses the entrant's systems administration judgment without importing employer data.

## Eligibility and Compliance Notes

- Australia is not listed as an excluded jurisdiction in the official rules reviewed.
- Residence, age of majority, sanctions/export controls, and conflict/employment restrictions matter.
- This must remain a personal project unless employer consent is explicit and documented.
- Do not use employer data, employer code, real credentials, internal IP addresses, screenshots, policy text, ticket history, or brand assets.
- Use a personal repository and personal Google Cloud project.

## Immediate Account Tasks

While the local project is being built:

1. Join the Devpost hackathon.
2. Select Fortified Enterprise Fleet.
3. Request the $150 Google Cloud credit before 2026-08-28 12:00 PM PT, while supplies last.
4. Create a new Google Cloud project dedicated to this competition.
5. Enable budget alerts immediately.

