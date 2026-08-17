# Gate C — Real target and zero-trust execution boundary

**Status: PASSED**

Sanitized. No access tokens or credential material. All identities used
Application Default Credentials with service-account impersonation. **No
service-account key file was created or downloaded at any point.**

## Real infrastructure

| Service | Region | Purpose | Access |
|---|---|---|---|
| `dispatch-web` | `australia-southeast1` | synthetic site dispatch app — the remediation target | public (`allUsers` → `run.invoker`) |
| `site-directory` | `australia-southeast1` | unrelated service, blast-radius control | authenticated |
| `scf-orchestrator` | `australia-southeast1` | Gate B orchestrator | authenticated |

`dispatch-web` is public deliberately: it models a staff-facing site
application, holds no data and no credentials, and the demo must show a real
503 → 200 in a browser.

### Revisions

| Revision | Mode | Runtime identity |
|---|---|---|
| `dispatch-web-00003-x87` | healthy → HTTP 200 | `sa-dispatch-web` |
| `dispatch-web-00004-jqm` | broken → HTTP 503 | `sa-dispatch-web` |

Health is baked into the revision through `SERVICE_MODE` at deploy time, so it
belongs to the revision itself. There is no in-memory flag an orchestrator
could flip; the only way to change what the service returns is a genuine Cloud
Run traffic migration.

Revisions `00001-g5c` and `00002-x5g` are earlier builds that ran under the
default compute service account and are superseded — see the security finding
below.

## C0 — empirically minimised permissions

Candidate permissions were tested and reduced, not assumed.

**`scfRemediator`** (custom role) — 3 permissions at Gate C:

```
run.services.get
run.services.update
run.operations.get
```

> **Reduced at Gate D.** `run.operations.get` was removed. A Cloud Run
> operation is a distinct resource from the service, so a service-scoped role
> cannot read it; rather than broaden the grant, operation polling was deleted
> and the independent verifier establishes recovery instead. The role is now
> **2 permissions**. `infra/iam-matrix.md` is the authoritative record.

`run.revisions.get` and `run.revisions.list` were in the candidate set and
proved **unnecessary** for traffic migration. They were left out.

Two further permissions surfaced only by attempting the operation for real:

| Permission | Why required | Scope granted |
|---|---|---|
| `artifactregistry.repositories.downloadArtifacts` | Cloud Run validates the revision's image reference during the update | custom role `scfArtifactReader`, bound on the `cloud-run-source-deploy` **repository resource** only |
| `iam.serviceAccounts.actAs` | Cloud Run requires actAs over the service's runtime identity | `roles/iam.serviceAccountUser`, bound on the `sa-dispatch-web` **service-account resource** only |

### Was actAs required, and how is it scoped?

**Yes, it was required.** It is scoped to exactly one service-account
resource: `sa-dispatch-web`, which is `dispatch-web`'s runtime identity and
holds **zero project roles**. It is not project-wide Service Account User.

## Security finding — actAs on the default compute SA would have been an escalation

The first attempt at Proof B failed with actAs denied on
`911485617985-compute@developer.gserviceaccount.com`, the default runtime
identity Cloud Run assigns when none is specified.

That account holds **`roles/editor`** on the project.

Granting the executor actAs over it would have let the executor deploy a
revision running as an Editor-privileged identity — a project-wide privilege
escalation dressed up as a narrow traffic permission, and a direct violation
of the architecture's blast-radius claim.

Instead, `dispatch-web` was given a dedicated runtime identity,
`sa-dispatch-web`, with **no project roles at all**, and actAs was scoped to
that identity alone. This tightened the design rather than broadening it.

## Effective IAM

Neither `sa-executor` nor `sa-agent-systems` holds **any project-level role**.

| Identity | Binding | Scope |
|---|---|---|
| `sa-agent-systems` | `roles/run.viewer` | `dispatch-web` service resource |
| `sa-executor` | `scfRemediator` | `dispatch-web` service resource |
| `sa-executor` | `scfArtifactReader` | `cloud-run-source-deploy` repository |
| `sa-executor` | `roles/iam.serviceAccountUser` | `sa-dispatch-web` account resource |
| `sa-dispatch-web` | *(none)* | — |

No `roles/run.admin`, no `roles/run.developer`, no Editor, no Owner, no IAM
administration, no wildcard remediation.

---

## IAM PROOF A — investigator denied

**Actor** `sa-agent-systems` · **Target** `dispatch-web` ·
**Operation** `run.services.update` (traffic migration)

A read as the same identity succeeded first, proving the impersonation is real
and the identity is genuinely in use:

```
$ gcloud run services describe dispatch-web --impersonate-service-account=sa-agent-systems@...
dispatch-web    {'percent': 100, 'revisionName': 'dispatch-web-00001-g5c'}
```

The mutation was refused by Google:

```
ERROR: (gcloud.run.services.update-traffic) PERMISSION_DENIED:
Permission 'run.services.update' denied on resource
'namespaces/site-continuity-fleet/services/dispatch-web'
```

Traffic was unchanged afterwards. **Result: real Google denial.**

An earlier attempt failed at the impersonation step
(`iam.serviceAccounts.getAccessToken`) due to IAM propagation delay. That was
discarded as an invalid proof — it denied the wrong operation. Recorded here
because a 403 that proves the wrong thing is worse than no proof.

---

## IAM PROOF B — executor succeeds, 503 → 200

**Actor** `sa-executor` · **Target** `dispatch-web`

**Before** — traffic on the broken revision:

```
{'percent': 100, 'revisionName': 'dispatch-web-00004-jqm'}

HTTP/1.1 503 Service Unavailable
x-service-mode: broken
x-revision: dispatch-web-00004-jqm
dispatch service unavailable
```

**Migration** performed as `sa-executor`:

```
$ gcloud run services update-traffic dispatch-web \
    --to-revisions=dispatch-web-00003-x87=100 \
    --impersonate-service-account=sa-executor@...
Routing traffic....done
Traffic: 100% dispatch-web-00003-x87
```

**After**:

```
{'percent': 100, 'revisionName': 'dispatch-web-00003-x87'}

HTTP/1.1 200 OK
x-service-mode: healthy
x-revision: dispatch-web-00003-x87
dispatch service healthy
```

**Result: real infrastructure recovery.** This proves scoped execution
capability only. Full autonomous remediation is not claimed — the flip here
was invoked directly as a boundary test, not driven end-to-end by the agent
workflow.

---

## IAM PROOF C — executor blast radius bounded

**Actor** `sa-executor` (the same identity that had just succeeded on
`dispatch-web`) · **Target** `site-directory`

```
ERROR: (gcloud.run.services.update-traffic) PERMISSION_DENIED:
Permission 'run.services.get' denied on resource
'namespaces/site-continuity-fleet/services/site-directory'
```

The executor cannot even **read** the unrelated service, let alone mutate it:

```
$ gcloud run services describe site-directory --impersonate-service-account=sa-executor@...
ERROR: PERMISSION_DENIED: Permission 'run.services.get' denied on resource
'namespaces/site-continuity-fleet/services/site-directory'
```

**Result: real Google denial.** The boundary is scoped to a resource, not
merely to an identity. There is no application-level allowlist involved, and a
test forbids any shipped module from fabricating a 403.

---

## Evidence contract (C7)

The Systems Investigator gathers real Cloud Run state as `TRUSTED_TOOL`
evidence and proposes without authorizing.

**Healthy state:**

```
active_revision              dispatch-web-00003-x87
http_status                  200
service_unhealthy            False
last_good_revision_exists    True
proposal                     None
```

**Broken state, through the full deterministic chain:**

```
active_revision              dispatch-web-00004-jqm
http_status                  503
service_unhealthy            True
last_good_revision           dispatch-web-00003-x87

proposal      FLIP_TRAFFIC_TO_LAST_GOOD  target=dispatch-web  by=agent:systems
policy        AUTO_ALLOWED  reason=LOW_RISK_TRAFFIC_FLIP  policy_version=1.0.0
idempotency   b70e6e7d3dcc0cbc5e70e89d39ccea4d… (derived from the decision)
```

The same evidence relabelled `UNTRUSTED_INPUT` is denied by the policy gate.
Evidence carries no authorization decision; only `PolicyDecision` does.

## Tests

Offline suite plus Gate C contract tests covering proposal gating, closed
enum, trusted-evidence requirement, investigator having no mutating
capability, executor target scope, and the absence of any fabricated
application-level 403.
