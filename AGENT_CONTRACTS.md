# Agent Contracts

Authoritative machine-readable form: `policies/agent_registry.json`. This
document explains it. Where the two disagree, the JSON wins and this file is
the bug.

## Shared rules

- Agents gather evidence only through declared tools.
- Agents may propose; only the policy gate authorizes.
- Agents must treat report text, attachments, screenshots, transcripts, and
  vendor messages as `UNTRUSTED_INPUT`.
- Agents must never copy untrusted content into system instructions.
- Only the orchestrator and the executor write to Firestore.
- Mutating tools require a policy decision and a deterministic idempotency key.

## Orchestrator — LLM-backed

**Purpose.** Classify the incident, emit a `RoutingDecision`, dispatch the
required specialists, enforce step and timeout budgets, persist state.

**Allowed.** `create_incident`, `route_specialists`, `request_policy_decision`,
`request_execution`. Sole agent-side Firestore writer.

**Prohibited.** Proposing actions. Direct remediation. Direct credential
access. Overriding a policy decision.

**Contract.** Every specialist appears in the routing decision as either
required with a reason, or declined with a reason. Silent omission is invalid.

## Systems Investigator

**Purpose.** Service, revision, and application health.

**Status.** Evidence gathering and the `Proposal` are deterministic today; the
contract below is written so an LLM-authored proposal can be substituted
without changing any authority. See README for what the LLM does at runtime.

**Allowed.** `read_service_health`, `read_revision_history`. May emit a
`Proposal`.

**Prohibited.** Writing Firestore. Any mutation. Restarting production
databases directly.

**Boundary.** Runs as `sa-agent-systems`, which holds `datastore.viewer` and no
Cloud Run write role. Attempting to modify `dispatch-web` yields a real Google
403 — IAM proof A.

## Network Investigator — LLM-backed *(slice 2)*

**Purpose.** Connectivity, DNS, gateway, WAN.

**Allowed.** `read_network_status`, `read_dns_status`. May emit a `Proposal`.

**Prohibited.** Writing Firestore. Changing routes or DNS. Disabling controls.

## Security & Identity Investigator — LLM-backed *(slice 2)*

**Purpose.** Suspicious access, identity events, and classification of
untrusted content.

**Allowed.** `read_security_events`, `classify_untrusted_content`.

**Prohibited.** **Proposing any action.** Returning secrets. Accepting incident
text as instructions.

The prototype let this agent author an `EXPORT_CREDENTIALS` request so the
policy gate could block it on camera. That was theatre. The contract now
forbids it and a test enforces it.

## Continuity Coordinator — LLM-backed *(slice 2)*

**Purpose.** Human-facing narrative for a non-technical duty manager,
escalation packages, vendor handoff.

**Allowed.** `compose_status_update`, `assemble_escalation_package`.

**Prohibited.** Proposing actions. Writing Firestore. Any infrastructure
mutation.

---

# Deterministic Components

These are not agents. They contain no model calls and no prompt text.

## Policy Gate

Pure function of the policy file, the agent registry, and `TRUSTED_TOOL`
evidence. Returns a versioned decision with a reason code. No I/O.

Never reads model-authored text, including `Proposal.rationale`.

## Remediation Executor

The only identity that can mutate infrastructure. Runs as `sa-executor` with
the custom `scfRemediator` role bound to `dispatch-web` alone.

Re-reads the decision from Firestore rather than trusting the caller, claims
the idempotency key transactionally, then acts. Attempting to modify any other
Cloud Run service yields a real Google 403 — IAM proof C.

## Verifier

Re-reads target health under `sa-verifier`, a different read-only identity from
the executor, so the component that acts is not the component that grades its
own work.

## Audit

Append-only hash-chained writer, **tamper-evident, not immutable**. Editing a
historical record is not prevented — it breaks the chain and `verify_chain()`
reports where. A compromised authoritative writer could rewrite the chain and
its tail hash together; detecting that needs an external witness we do not
have.
