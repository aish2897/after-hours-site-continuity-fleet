# IAM Matrix

What actually exists. This file describes provisioned reality, not intent.

Every identity is a distinct Google service account. **No account holds
project-level `roles/run.admin`, Owner, Editor, or IAM administration.** No
service-account key file was ever created or downloaded.

## Provisioned identities

| Identity | Binding | Bound at |
|---|---|---|
| `sa-orchestrator` | `datastore.user`, `aiplatform.user`, `logging.logWriter` | project |
| `sa-orchestrator` | `roles/run.invoker` | `scf-agent-systems`, `scf-executor`, `scf-verifier` |
| `sa-agent-systems` | `roles/run.viewer` | `dispatch-web` service |
| `sa-agent-systems` | `logging.logWriter` | project |
| `sa-executor` | `scfRemediator` (custom) | `dispatch-web` service |
| `sa-executor` | `scfArtifactReader` (custom) | `cloud-run-source-deploy` repository |
| `sa-executor` | `roles/iam.serviceAccountUser` | `sa-dispatch-web` account |
| `sa-executor` | `scfDecisionReader` (custom) | Firestore `(default)`, IAM-conditioned, **read only** |
| `sa-executor` | `scfExecutionWriter` (custom) | Firestore `execution-state`, IAM-conditioned, **no delete** |
| `sa-executor` | `logging.logWriter` | project |
| `sa-verifier` | `roles/run.viewer` | `dispatch-web` service |
| `sa-verifier` | `logging.logWriter` | project |
| `sa-dispatch-web` | *(none)* | — |

The orchestrator can *invoke* the executor but holds none of its
infrastructure privileges. The verifier runs under a different identity from
the executor, so the component that acts never grades its own work.

Not yet created: `sa-agent-network`, `sa-agent-security`, `sa-agent-continuity`,
`sa-approval-api`. Those belong to later gates.

## Custom roles

```
scfRemediator        run.services.get
                     run.services.update
  bound on: dispatch-web service resource only

scfArtifactReader    artifactregistry.repositories.downloadArtifacts
  bound on: cloud-run-source-deploy repository resource only

scfDecisionReader    datastore.databases.get, datastore.entities.get
  condition: resource.name.startsWith(".../databases/(default)")

scfExecutionWriter   datastore.databases.get, datastore.entities.get,
                     datastore.entities.create, datastore.entities.update
  condition: resource.name.startsWith(".../databases/execution-state")
```

Every permission set was minimised empirically, not assumed:

- `run.revisions.get` and `run.revisions.list` were candidates and proved
  unnecessary for traffic migration.
- `run.operations.get` was initially included, then removed: a Cloud Run
  operation is a distinct resource from the service, so a service-scoped role
  cannot read it. Rather than broaden the grant, operation polling was deleted
  and the independent verifier establishes recovery instead.
- `artifactregistry.repositories.downloadArtifacts` surfaced only by attempting
  the operation — Cloud Run validates the revision's image reference during a
  traffic update.
- No predefined `datastore.viewer` or `datastore.user` was needed for the
  executor.

**Condition syntax finding:** `resource.name == ".../databases/(default)"` does
not match. Firestore evaluates the condition against the document resource
path, so `startsWith` on the database prefix is required.

Neither Firestore role grants `datastore.entities.delete`, so an idempotency
claim cannot be retracted to permit a replay.

## Why `sa-dispatch-web` exists

Cloud Run requires `iam.serviceAccounts.actAs` over the target service's
runtime identity. By default that is the project's default compute service
account, which holds **`roles/editor`**. Granting the executor actAs over it
would have allowed deploying a revision running as an Editor-privileged
identity — a project-wide escalation disguised as a narrow traffic permission.

`dispatch-web` therefore runs as `sa-dispatch-web`, which holds no project
roles, and the executor's actAs is scoped to that one account resource.

## Two-plane Firestore isolation

| Plane | Database | Executor access |
|---|---|---|
| Authoritative control | `(default)` | read only |
| Execution | `execution-state` | create/update, no delete |

The rule: **the identity able to mutate Cloud Run must be unable to modify the
authorization decision permitting that mutation.**

This is database-level isolation. Firestore IAM cannot scope below a database;
within `execution-state` the executor can write any collection. The boundary is
that no authorization truth lives there.

## Proofs captured

All are real Google responses, saved under `docs/evidence/`.

| # | Actor | Attempt | Result |
|---|---|---|---|
| **A** | `sa-agent-systems` | update traffic on `dispatch-web` | 403 `run.services.update` denied |
| **B** | `sa-executor` | update traffic on `dispatch-web` | success, 503 → 200 |
| **C** | `sa-executor` | update traffic on `site-directory` | 403 `run.services.get` denied |
| **D.1a** | `sa-executor` | read decision in `(default)` | allowed |
| **D.1b** | `sa-executor` | create / update / delete decision in `(default)` | 403 on all three |
| **D.1c** | `sa-executor` | write audit or incident in `(default)` | 403 |
| **D.1d** | `sa-executor` | create idempotency claim in `execution-state` | allowed |
| **D.1e** | `sa-executor` | delete idempotency claim in `execution-state` | 403 |

Proof C matters most for blast radius: the boundary is scoped to a resource,
not merely to an identity. Proof D.1b matters most for integrity: the executor
cannot author the authority it acts on.

Transcripts: `gate-c-iam-boundary.md`, `gate-d1-executor-firestore-isolation.md`.

## Gate D.3 — no IAM was changed

Moving the mutation from Cloud Run v2 `services.patch` to v1
`namespaces.services.replaceService` required **no additional permission**. The
existing resource-scoped `scfRemediator` (`run.services.get`,
`run.services.update` on `dispatch-web` only) covers both.

Re-tested after the change, as the real `sa-executor`:

| Attempt | Result |
|---|---|
| v1 `GET` `site-directory` | 403 `run.services.get` denied |
| v1 `PUT` `site-directory` | 403 `run.services.update` denied |
| v1 `GET` `dispatch-web` | 200 — the authorized target is still readable |
| Firestore `(default)` read incident | 200 |
| Firestore `(default)` create forged decision | 403 |
| Firestore `(default)` patch incident status to RESOLVED | 403 |
| Firestore `execution-state` delete execution record | 403 |

Changing API version did not widen authority, and the Gate D.1 two-plane
boundary is intact. Transcript: `gate-d3-lease-fencing-cas.md`.
