# IAM matrix — as provisioned

Read from the live project on **2026-08-22**, not from intent. Where a row could
not be verified it says `UNKNOWN` rather than guessing.

Project `site-continuity-fleet`, region `australia-southeast1`.

## Project-level roles

Every service account also holds `roles/logging.logWriter`; it is omitted below.

| Service account | Project-level roles beyond logging |
|---|---|
| `sa-orchestrator` | `roles/aiplatform.user`, `roles/datastore.user`, custom `scfPromptScreener` |
| `sa-agent-systems` | **none** |
| `sa-agent-network` | **none** |
| `sa-agent-security` | **none** |
| `sa-agent-continuity` | **none** |
| `sa-executor` | custom `scfDecisionReader`, custom `scfExecutionWriter` |
| `sa-verifier` | **none** |
| `sa-approval` | `roles/datastore.user` |

No service account holds project-level `roles/run.admin`.

The three investigators and the verifier hold **no Firestore access at all** —
not `datastore.user`, not `datastore.viewer`. This is tighter than originally
planned. They are stateless: they receive identifiers, perform tool calls under
their own identity, and return typed evidence over authenticated HTTP. The
orchestrator is the only agent-side writer.

## Per-service invoker policy

| Cloud Run service | Bindings on the service |
|---|---|
| `scf-orchestrator` | none — reachable only via project-level permission (the human operator) |
| `scf-agent-systems` | `run.invoker`: `sa-orchestrator` |
| `scf-agent-network` | `run.invoker`: `sa-orchestrator` |
| `scf-agent-security` | `run.invoker`: `sa-orchestrator` |
| `scf-agent-continuity` | `run.invoker`: `sa-orchestrator` |
| `scf-executor` | `run.invoker`: `sa-orchestrator` |
| `scf-verifier` | `run.invoker`: `sa-orchestrator` |
| **`scf-approval`** | `run.invoker`: **`user:arslanali.2897@gmail.com`** — one human, no service account |
| `dispatch-web` (target) | `run.invoker`: `allUsers`; `run.viewer`: `sa-agent-systems`, `sa-agent-security`, `sa-verifier`; custom **`scfRemediator`: `sa-executor`** |

`dispatch-web` is public on purpose: it is the synthetic outage target, and its
health has to be probeable the way a real site would be. It holds no data.

## The boundaries that matter

**Only `sa-executor` can mutate.** The custom `scfRemediator` role
(`run.services.get`, `run.services.update`, `run.revisions.get`,
`run.revisions.list`) is bound **on the `dispatch-web` service resource only**,
never project-wide. A fully compromised executor cannot touch any other service.

**No autonomous identity can approve.** `run.invoker` on `scf-approval` is held
by one human principal. Proven live against all six fleet identities, an
unauthenticated caller, and forged identity headers — see
[`codex-high-2`](../docs/evidence/codex-high-2-approval-authorization.md).

**Investigators cannot change anything.** Real Google 403s for Cloud Run
mutation and Firestore writes, for all three — see
[`gate-h`](../docs/evidence/gate-h-fleet-registry.md). Network and Continuity are
denied at `run.services.get`; Security is denied at `run.services.update`,
because reading the IAM policy is its job and it is stopped exactly at the write.

**Verification is not self-grading.** `sa-verifier` holds `run.viewer` on the
target and no mutation capability, so the identity that acts is never the
identity that confirms the act.

## Honest caveats

- **Firestore IAM is per-database, not per-collection.** The read/write split
  above is genuinely enforced; finer-grained scoping within a database is not.
  Two databases are used — `(default)` for the authoritative plane and
  `execution-state` for the execution plane — with per-database conditions.
- **`sa-approval` holds `datastore.user`**, which is broader than "approvals
  only". The approval service writes only approval decisions, but that
  restriction is application code, not IAM.
- **Impersonation grants used for denial proofs were temporary.** Where
  `roles/iam.serviceAccountTokenCreator` was needed to mint a token for a proof,
  it was granted to the human principal, the proof run, and the grant revoked.
  `sa-agent-systems` and `sa-executor` retain it from the Gate C denial work.
- No `sa-approval-api` and no Secret Manager binding exist. An earlier plan
  named them; the approval service uses Cloud Run IAM instead and holds no
  signing key.
