# IAM Matrix

Every identity below is a distinct Google service account. No account holds
project-level `roles/run.admin`.

## Custom role: `scfRemediator`

```
run.services.get
run.services.update
run.revisions.get
run.revisions.list
```

Bound **only on the `dispatch-web` service resource**, never at project level.
This is the difference between "the executor is allowed to remediate" and "the
executor is allowed to remediate *one specific service*".

## Accounts

| Service account | Firestore | Cloud Run | Vertex | Notes |
|---|---|---|---|---|
| `sa-orchestrator` | `datastore.user` | `run.invoker` on tools-*, executor | `aiplatform.user` | Sole agent-side writer |
| `sa-agent-systems` | `datastore.viewer` | — | `aiplatform.user` | Stateless investigator |
| `sa-agent-network` | `datastore.viewer` | — | `aiplatform.user` | Slice 2 |
| `sa-agent-security` | `datastore.viewer` | — | `aiplatform.user` | Slice 2; Model Armor caller |
| `sa-agent-continuity` | `datastore.viewer` | — | `aiplatform.user` | Slice 2 |
| `sa-executor` | `datastore.user` | **`scfRemediator` on `dispatch-web` only** | — | Only mutating identity |
| `sa-verifier` | `datastore.viewer` | `run.viewer` + public GET | — | Grades the executor's work |
| `sa-approval-api` | `datastore.user` | — | — | `secretAccessor` on signing key only |

All accounts additionally hold `logging.logWriter` and `cloudtrace.agent`.

The verifier deliberately runs under a different, read-only identity than the
executor, so the component that acts is not the component that grades itself.

## Required proofs

All three must produce a real, Google-generated response captured in Cloud
Logging and saved to `docs/evidence/`. None are currently captured.

| # | Actor | Attempt | Expected | Status |
|---|---|---|---|---|
| **A** | `sa-agent-systems` | modify `dispatch-web` | real 403 | `NOT CAPTURED` |
| **B** | `sa-executor` | modify `dispatch-web` | success | `NOT CAPTURED` |
| **C** | `sa-executor` | modify `site-directory` (unrelated service) | real 403 | `NOT CAPTURED` |

Proof C is the one that matters most: it demonstrates the boundary is scoped to
a resource, not merely to an identity. An executor that can fix anything is not
a least-privilege design.

A fourth, incidental proof is available at no extra cost: `sa-agent-systems`
attempting a Firestore write receives a real 403 because investigators hold
`datastore.viewer` only.

## Blocked

The Google Cloud SDK is not installed on the build machine, so no account,
role, or binding has been created and no proof has been captured.
