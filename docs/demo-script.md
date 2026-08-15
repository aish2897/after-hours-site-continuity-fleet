# Four-Minute Demo Spine

## 0:00-0:25 - Problem

"A non-technical site supervisor has an outage after hours. They should not need to diagnose whether it is network, systems, identity, security, vendor, or facilities. The fleet takes one messy report and coordinates specialist agents safely."

Show: supervisor incident intake.

## 0:25-1:25 - Autonomous Resolution

Run `web_down`.

Show:

- Orchestrator routes to context, network, systems, and security agents.
- Systems evidence identifies stopped service.
- Policy classifies service restart as `AUTO_ALLOWED`.
- Remediation changes service state.
- Verification proves HTTP is healthy.
- Audit timeline records every step.

## 1:25-2:10 - Governance

Run `db_restart`.

Show:

- Evidence points to database restart.
- Policy classifies it as `APPROVAL_REQUIRED`.
- Workflow pauses instead of acting.
- This is enterprise control, not a reckless bot.

## 2:10-2:55 - Attack Resistance

Run `prompt_injection`.

Show:

- Incident contains malicious instructions.
- Security agent flags prompt injection.
- Policy denies unsafe action path.
- Audit records the block.

## 2:55-3:30 - Least Privilege

Run `permission_denied`.

Show:

- Network agent tries a write-level firewall action.
- Authorization returns `PERMISSION_DENIED`.
- Only correctly scoped agents can mutate state.

## 3:30-4:00 - Google Cloud Proof

Final version must show:

- Cloud Run or Agent Runtime dashboard.
- Vertex AI or Gemini logs.
- Firestore incident/audit state.
- Pub/Sub events if used.
- Repo and architecture diagram.

