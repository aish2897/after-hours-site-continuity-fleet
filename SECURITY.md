# Security Model

## Trust boundary for evidence

Every piece of evidence carries a provenance label:

| Trust level | Origin | May reach the policy gate |
|---|---|---|
| `TRUSTED_TOOL` | Returned by a declared tool call executed under a scoped service account | **Yes** |
| `UNTRUSTED_INPUT` | Human report text, attachments, screenshots, transcripts, vendor mail | **No** |

The policy gate filters to `TRUSTED_TOOL` before evaluating anything
(`src/scf/policy/engine.py`). Injected instructions are therefore
*architecturally incapable* of satisfying a required-evidence condition — not
merely filtered by a blocklist.

The prototype this replaced used substring matching over six phrases. That
approach fails on any paraphrase. The current design does not care what the
injected text says, because untrusted content never reaches the code path that
grants authority.

Proven by `tests/policy/test_decision_matrix.py`:

- `flip/untrusted-only` — evidence sufficient for approval, but untrusted, is denied.
- `test_untrusted_evidence_cannot_override_trusted_denial`
- `test_untrusted_evidence_cannot_revoke_trusted_authorization`
- `test_evidence_snapshot_hash_ignores_untrusted_noise`

## What the LLM may and may not do

Gemini may interpret reports, choose which specialists to invoke and say why,
summarize evidence, and emit a `Proposal`.

The `Proposal` schema is closed: `action_type` must be a member of
`ActionType`, `target_ref` must resolve in `policies/action_policy.json`, and
`confidence` is bounded. A malformed proposal is rejected and audited, never
retried as freeform text. `rationale` is display-only and is never read by the
policy gate.

Dangerous actions (`EXPORT_CREDENTIALS`, `DISABLE_FIREWALL`) deliberately
remain *proposable*. The deterministic gate is what refuses them, on the
record. The prototype had the security agent fabricate such a request so it
could be blocked on camera; that is now a contract violation
(`tests/policy/test_registry.py::test_security_agent_cannot_propose_actions`).

## Identity boundaries

Authorization is enforced by Google IAM, not by in-process string comparison.
The in-code tool allowlist in `policies/agent_registry.json` is defence in
depth only.

Investigators are stateless and never write Firestore; the orchestrator
persists on their behalf. That is what makes `datastore.viewer` a real,
demonstrable boundary rather than a convention.

The Remediation Executor holds a custom role, `scfRemediator`, bound **only on
the `dispatch-web` service resource**. A fully compromised executor still
cannot touch any other Cloud Run service.

All three IAM proofs are captured. See `infra/iam-matrix.md` and
`docs/evidence/gate-c-iam-boundary.md`.

## Known limitations

Stated plainly rather than implied away.

1. **Firestore isolation is database-level, not collection-level.** Google IAM
   cannot scope below a database. Two databases are used, separated by IAM
   conditions on `resource.name`:

   | Plane | Database | Executor's access |
   |---|---|---|
   | Authoritative control | `(default)` | **read only** |
   | Execution | `execution-state` | create/update, **no delete** |

   The identity able to mutate Cloud Run therefore cannot modify the
   authorization decision permitting that mutation, and cannot retract its own
   idempotency claim to permit a replay. Within `execution-state` it can write
   any collection; the boundary is that no authorization truth lives there.
   Proof: `docs/evidence/gate-d1-executor-firestore-isolation.md`.
2. **Audit truncation leaves a valid prefix.** The hash chain detects edits,
   reordering, deletion in the middle, and forged appends, but a truncated tail
   still links correctly. `verify_incident_chain()` therefore checks the trail
   against the incident document's own `audit_seq` and `audit_tail_hash`,
   written in the same transaction as each record, which detects a missing
   tail, an unaccounted append, and a tail-hash mismatch. Covered by
   `test_truncating_the_tail_is_detected_by_length` and
   `test_incident_chain_verification_detects_a_truncated_tail`, and exercised
   live against resolved incidents in
   `docs/evidence/gate-d3-lease-fencing-cas.md`.
3. **Model inference leaves Australia.** Gemini 3.7 Flash is not available
   through an Australian regional inference endpoint — Sydney returns
   `404 NOT_FOUND` for the publisher model, confirmed by a real call
   (`docs/evidence/gate-a-vertex-gemini.md`). Inference therefore uses Vertex
   AI's `global` endpoint. Model Armor inspection additionally crosses from
   Sydney to Melbourne, though that leg stays within Australia. See the data
   handling section below.
4. **Audit is tamper-evident, not immutable.** The chain detects edits, but a
   compromised authoritative writer could rewrite a record and the incident's
   `audit_tail_hash` together. Detecting that needs an external witness we do
   not have.
5. **Execution is not globally exactly-once.** Firestore and the Cloud Run
   Admin API cannot be committed together. The claim is fenced, duplicate-safe,
   recoverable, effect-idempotent execution with reconciliation.
6. **The stale-worker window is narrowed, not eliminated.** Ownership is fenced
   by a `lease_epoch`, so a worker whose lease was taken cannot advance
   execution state, renew, or terminalize — proven live. Cloud Run v1
   `resourceVersion` optimistic concurrency separately stops an obsolete
   Service snapshot from overwriting a newer one, with a real HTTP 409 ABORTED
   from Google. But a worker that lost its lease *after* its final ownership
   check can still reach the Cloud Run API if the Service has not changed in
   the interim. It can only ever request the exact `authorized_target_revision`
   from the persisted decision, so the effect is identical to the one already
   authorized. It cannot advance the execution lifecycle state and cannot
   write a receipt — both writes are fenced and the attempt is logged at ERROR.
   It can still return a truthful response saying the mutation was issued, and
   the orchestrator records that as an action; the record is accurate, and
   terminalization is gated on re-observed infrastructure rather than on it.
   Two systems that cannot be committed together leave this window; it is
   documented, not denied.
7. **Cloud Run v2 `etag` is not a concurrency control.** Tested live against
   the real service, a stale etag in the body, a stale `If-Match:` header and a
   bogus etag string were all accepted with HTTP 200 on the traffic update. The
   executor therefore mutates through v1 `replaceService`, where
   `resourceVersion` is genuinely enforced. No claim rests on v2.
8. **Control-plane compromise is only partly addressed.** Gate D.1 stops the
   *executor* forging authorization. It does not protect against full
   compromise of the authoritative policy writer. An authorization fingerprint
   — incident, action, target, exact revision, policy version, evidence
   snapshot — binds to exactly one execution identity, so an *equivalent*
   re-issued decision cannot become a second infrastructure effect. A
   compromised writer can still author a *materially different* authorization,
   which by definition has a different fingerprint. That remains open.
9. **Control-plane closure is enforced at the mutating boundary, twice.** The
   executor refuses any decision whose incident is `RESOLVED` or `ESCALATED`,
   once before doing any work and again immediately before the Cloud Run
   snapshot is read. Because the two systems cannot be committed together, that
   second check narrows the window rather than eliminating it — the same
   limitation as the ownership fence, stated the same way.
10. **One authorization is not an open-ended licence.** An execution that has
    already *issued* its mutation refuses to issue another if the target is no
    longer live: a fresh failure requires a fresh incident and a fresh
    authorization, so an operator's deliberate rollback is never overwritten.
    "Issued" deliberately includes a mutation Google accepted whose success
    write was fenced — that record never advances past `MUTATION_REQUESTED`, so
    that state must count as attempted. The one case treated as definitely not
    applied is a 409 ABORTED, which is proof the write was refused: the record
    is wound back to `PRECONDITION_CHECKED` and the incident is left
    reconcilable rather than closed. That rewind is ownership-bound, so if the
    lease was taken while the conflicting call was in flight it is refused, the
    execution stays marked as attempted, and the incident escalates — reported
    explicitly rather than assumed.
11. **Candidate freshness is point-in-time.** The rollback target is re-probed
   through its own tag URL immediately before mutating, and a stale or
   unhealthy candidate produces `TARGET_NO_LONGER_HEALTHY` and no mutation.
   Nothing guarantees the target stays healthy afterwards.
12. **No capability is claimed before its evidence exists.** The README
    integration table is authoritative for what is and is not integrated.

## Data handling and processing location

Authoritative operational state, audit records, and privileged execution remain
on Australian Google Cloud infrastructure. Gemini 3.7 Flash inference uses
Vertex AI's global endpoint because the model is not available through an
Australian regional inference endpoint. **Complete Australian model-processing
residency is therefore not claimed.**

| Concern | Location |
|---|---|
| Cloud Run, Firestore, Artifact Registry | Sydney `australia-southeast1` |
| Model Armor inspection *(PLANNED, not integrated)* | Melbourne `australia-southeast2` |
| Gemini 3.7 Flash inference | `global` |

Because inference leaves the country, the classification and security boundary
is load-bearing rather than decorative. The boundary that exists today is the
trust-level separation described above. **Model Armor inspection is PLANNED and
not integrated**, so no prompt-injection resistance is claimed — only that
untrusted content cannot reach an authorization path.

Synthetic company, sites, users, services, and logs only. No employer data,
code, names, policies, addresses, configurations, or IP. Personal Google Cloud
project and personal repository.
