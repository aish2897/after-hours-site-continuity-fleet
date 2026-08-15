# Site Continuity Fleet

Secure autonomous site-continuity agents for the All Things Agentic Hackathon, Fortified Enterprise Fleet track.

## Product Thesis

Enterprise agents should not only make IT experts faster. They should safely give non-technical frontline supervisors the operational reach of an entire support organization when a physical site is failing after hours.

The first build target is a deterministic local vertical slice:

1. A site supervisor reports an outage.
2. Specialist agents gather context, network, systems, and security evidence from a synthetic enterprise simulator.
3. A deterministic policy gate decides whether a remediation is auto-allowed, approval-required, or denied.
4. A remediation agent executes only authorized low-risk changes.
5. A verification agent proves recovery.
6. Every decision and tool result is written into an audit trail.

## Current Status

This is the Day 1 foundation. It is intentionally small, testable, and built from scratch during the hackathon period. It does not yet claim Gemini, ADK, or Google Cloud execution. Those are the next integration steps after the Devpost and Google Cloud account setup is ready.

## Local Run

```powershell
cd D:\Agentic\site-continuity-fleet
python -m unittest discover -s tests
python -m scf.cli web_down
python -m scf.cli db_restart
python -m scf.cli prompt_injection
python -m scf.cli permission_denied
```

If your shell cannot import `scf`, run:

```powershell
$env:PYTHONPATH = "D:\Agentic\site-continuity-fleet\src"
```

## Competition Artifacts

- `COMPETITION.md`: verified rule lock and scoring strategy.
- `ARCHITECTURE.md`: system architecture, execution model, and risk gates.
- `AGENT_CONTRACTS.md`: agent responsibilities, allowed tools, and prohibited actions.
- `docs/demo-script.md`: four-minute demo spine.
- `agent_catalog/catalog.json`: first versioned agent catalog.
- `policies/action_policy.json`: deterministic action policy.

## Non-Negotiables

- No employer data, names, IP addresses, screenshots, credentials, policies, or source code.
- Synthetic company, synthetic sites, synthetic logs, synthetic users.
- LLMs may investigate and propose. Deterministic policy decides mutating actions.
- Every mutating action must carry `incident_id`, `action_id`, `idempotency_key`, `actor_identity`, evidence, and policy decision.

