# Gate D.1 — Executor Firestore isolation

**Status: PASSED**

Sanitized. No credentials or bearer tokens.

## The problem this fixes

After Gate D, `sa-executor` held project-level `roles/datastore.user`. Its
Cloud Run authority was tightly resource-scoped, but its Firestore authority
was not: the identity able to mutate infrastructure could also have rewritten
the authorization decision that permitted the mutation.

## The split

| Plane | Database | Location | Contents |
|---|---|---|---|
| Authoritative control | `(default)` | `australia-southeast1` | incidents, evidence, decisions, audit |
| Execution | `execution-state` | `australia-southeast1` | idempotency claims, executor receipts |

`execution-state` created 2026-08-16, Native mode, Sydney. The authoritative
database was not migrated or recreated.

**No authorization truth is duplicated into the execution plane.** The executor
still obtains authority from `(default)` on every call.

## Removed binding

```
$ gcloud projects remove-iam-policy-binding site-continuity-fleet \
    --member=serviceAccount:sa-executor@... --role=roles/datastore.user
removed

$ gcloud projects get-iam-policy ... --filter=...sa-executor...
roles/logging.logWriter
```

Project-level `roles/datastore.user` is gone and was not reinstated as a
fallback.

## Final conditional bindings

| Role | Permissions | IAM condition |
|---|---|---|
| `scfDecisionReader` | `datastore.databases.get`, `datastore.entities.get` | `resource.name.startsWith("projects/site-continuity-fleet/databases/(default)")` |
| `scfExecutionWriter` | `datastore.databases.get`, `datastore.entities.get`, `datastore.entities.create`, `datastore.entities.update` | `resource.name.startsWith("projects/site-continuity-fleet/databases/execution-state")` |
| `roles/logging.logWriter` | — | none |

Both are custom roles built from the minimum permission set that actually
worked. No predefined `roles/datastore.viewer` or `roles/datastore.user` was
needed. Neither role grants `datastore.entities.delete`.

**Condition syntax finding:** `resource.name == "projects/…/databases/(default)"`
does **not** match. Firestore data-plane requests evaluate the condition
against the document resource path, not the bare database path, so every
operation was denied. `startsWith` on the database prefix is the form that
works. This was determined empirically, not assumed.

## D1.7 — authorization integrity proof

Executed as the real `sa-executor` identity via impersonation. Every denial
below comes from Google IAM at Firestore, not from application validation.

```
1 READ   (default) decision       : OK  decision=AUTO_ALLOWED
2 CREATE decision  (default)      : DENIED by Google IAM
2 UPDATE decision  (default)      : DENIED by Google IAM
2 DELETE decision  (default)      : DENIED by Google IAM
2 WRITE  audit     (default)      : DENIED by Google IAM
2 WRITE  incident  (default)      : DENIED by Google IAM
3 CREATE claim     execution-state: OK
4 DELETE claim     execution-state: DENIED (claims are append-only)
```

Row 4 is a property worth stating: the executor cannot retract its own
idempotency claim, so it cannot manufacture a replay.

The UPDATE attempt tried to rewrite the decision's `target_ref` to
`site-directory` — the exact escalation the split is designed to prevent.

## D1.8 — autonomous recovery after the split

Test setup, operator-controlled, before submission: traffic moved to
`dispatch-web-00004-jqm`, confirmed `HTTP 503`.

Submitted 2026-08-16T01:07:16Z. Same plain-language report, no technical
metadata. **No operator or CLI action after submission.**

| Field | Value |
|---|---|
| Incident | `INC-20260816-D686BE` |
| Routing | `['systems']` |
| Decision | `AUTO_ALLOWED` / `LOW_RISK_TRAFFIC_FLIP`, `DEC-79A34DC59A` |
| Authoritative database read | `(default)` |
| Execution database written | `execution-state` |
| Execution | `mutated=True`, `SUCCEEDED` |
| Verification | `RECOVERED`, HTTP 200, `dispatch-web-00003-x87` |
| **Final state** | **`RESOLVED`** |

Live service after, no operator action:

```
HTTP/1.1 200 OK
x-service-mode: healthy
x-revision: dispatch-web-00003-x87
dispatch service healthy
```

Completed in 22 seconds with **no project-level datastore role on the executor**.

## D1.9 — replay proof from the execution plane

```
Cloud Run generation BEFORE replays: 17

replay 1  {"duplicate":true,"state":"DUPLICATE_SUPPRESSED","execution_database":"execution-state"}
replay 2  {"duplicate":true,"state":"DUPLICATE_SUPPRESSED","execution_database":"execution-state"}
replay 3  {"duplicate":true,"state":"DUPLICATE_SUPPRESSED","execution_database":"execution-state"}

Cloud Run generation AFTER replays:  17
dispatch-web: 200
```

Firestore state confirms the source of the guarantee:

```
execution-state idempotency claims : 1  | this decision: True
execution-state receipts           : 1  | states: ['SUCCEEDED']
(default) idempotency collection   : 0  (legacy pre-split docs removed)
```

**Total infrastructure mutations for `DEC-79A34DC59A`: 1**, proven by Cloud
Run's own generation counter rather than a count of HTTP responses. The
idempotency guarantee now lives entirely in `execution-state`.

## Application split

`config.AUTHORITATIVE_DATABASE` and `config.EXECUTION_DATABASE` are explicit
constants. Both stores call `validate_database_config()` before connecting and
fail closed if either is blank or if the two collapse to the same value.

The executor no longer writes the control plane at all. It returns a receipt,
and the orchestrator — an authoritative writer — records the action and audit
entry. This also removes a concurrent writer from the hash-chained audit log,
so sequence numbers cannot race.

## Final IAM matrix change

| Identity | Before D.1 | After D.1 |
|---|---|---|
| `sa-executor` | project `roles/datastore.user` | `scfDecisionReader` on `(default)`, `scfExecutionWriter` on `execution-state`, both IAM-conditioned |

Cloud Run remediation scope is unchanged: `scfRemediator`
(`run.services.get`, `run.services.update`) bound on the `dispatch-web`
service resource alone.

## Scope of the claim

This is **database-level IAM isolation**, not collection-level. Firestore IAM
cannot scope below a database. Within `execution-state` the executor can write
any collection; the boundary is that `execution-state` holds no authorization
truth. `SECURITY.md` states this rather than implying finer granularity than
Google provides.
