/**
 * The Director console.
 *
 * One rule governs this file: it renders backend truth and nothing else. Every
 * status, every specialist state, every sentence shown to the duty manager is
 * derived from a field the backend actually returned. Where the backend does
 * not know something, this says so rather than filling the gap.
 *
 * The one piece of stagecraft is the reveal: once a response arrives, the
 * stages appear in sequence over about two seconds so the story is readable
 * rather than landing all at once. The values are already final when the
 * animation starts — nothing is guessed ahead of the data.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ApiError,
  checkSession,
  clearToken,
  decideApproval,
  readImageFile,
  readToken,
  resumeIncident,
  submitIncident,
  tokenExpiresIn,
  writeToken,
  type Incident,
} from "./api";
import {
  approvalView,
  escalationMessage,
  managerStatus,
  specialistViews,
  stages,
  type Stage,
} from "./incident";

type Phase = "idle" | "working" | "done";

export default function App() {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [incident, setIncident] = useState<Incident | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [error, setError] = useState<string>("");

  useEffect(() => {
    if (!readToken()) {
      setSignedIn(false);
      return;
    }
    checkSession()
      .then((state) => setSignedIn(state.signed_in))
      .catch(() => setSignedIn(false));
  }, []);

  const reset = useCallback(() => {
    setIncident(null);
    setPhase("idle");
    setError("");
  }, []);

  if (signedIn === null) {
    return (
      <Shell>
        <div className="working">
          <span className="spinner" /> Checking your access…
        </div>
      </Shell>
    );
  }

  if (!signedIn) {
    return <SignIn onSignedIn={() => setSignedIn(true)} />;
  }

  return (
    <Shell onReset={incident ? reset : undefined}>
      {phase === "idle" && (
        <Intake
          onSubmitted={(result) => {
            setIncident(result);
            setPhase("done");
            setError("");
          }}
          onWorking={() => {
            setPhase("working");
            setError("");
          }}
          onError={(message) => {
            setPhase("idle");
            setError(message);
          }}
          error={error}
          onExpired={() => setSignedIn(false)}
        />
      )}

      {phase === "working" && <Working />}

      {phase === "done" && incident && (
        <Result
          incident={incident}
          onUpdated={setIncident}
          onExpired={() => setSignedIn(false)}
        />
      )}
    </Shell>
  );
}

/* -------------------------------------------------------------------------- */

function Shell({
  children,
  onReset,
}: {
  children: React.ReactNode;
  onReset?: () => void;
}) {
  return (
    <div className="shell">
      <header className="topbar">
        <div className="mark">SC</div>
        <div className="wordmark">
          Site Continuity
          <span>After-hours response</span>
        </div>
        <div className="topbar-right">
          <span className="site-chip">Melbourne warehouse</span>
          {onReset && (
            <button className="ghost" onClick={onReset}>
              Report something else
            </button>
          )}
        </div>
      </header>
      <main className="main">{children}</main>
    </div>
  );
}

/* --- sign in -------------------------------------------------------------- */

function SignIn({ onSignedIn }: { onSignedIn: () => void }) {
  const [token, setToken] = useState("");
  const [checking, setChecking] = useState(false);
  const [problem, setProblem] = useState("");

  async function go() {
    setChecking(true);
    setProblem("");
    const remaining = tokenExpiresIn(token.trim());
    if (remaining !== null && remaining <= 0) {
      setProblem("That token has already expired. Run the command again for a fresh one.");
      setChecking(false);
      return;
    }
    writeToken(token);
    try {
      const state = await checkSession();
      if (state.signed_in) {
        onSignedIn();
      } else {
        setProblem(
          `Google accepted the console but not this identity: orchestrator ${state.reachable.orchestrator}.`,
        );
        clearToken();
      }
    } catch (err) {
      setProblem(
        err instanceof ApiError && err.status === 401
          ? "That does not look like a valid identity token."
          : "Could not reach the response service.",
      );
      clearToken();
    } finally {
      setChecking(false);
    }
  }

  return (
    <div className="shell">
      <header className="topbar">
        <div className="mark">SC</div>
        <div className="wordmark">
          Site Continuity
          <span>After-hours response</span>
        </div>
      </header>
      <main className="main">
        <div className="signin-wrap">
          <div className="card card-pad">
            <h1 className="ask">Sign in to continue</h1>
            <p className="ask-sub">
              This console holds no credentials of its own. It acts only as you,
              using an identity Google issues to you — which is why no part of
              the automated fleet can use it to approve its own work.
            </p>

            <div className="step">
              <div className="step-num">1</div>
              <div>
                <p>Run this once, on a machine signed in to Google Cloud:</p>
                <code className="code">gcloud auth print-identity-token</code>
              </div>
            </div>

            <div className="step">
              <div className="step-num">2</div>
              <div style={{ width: "100%" }}>
                <p>Paste the result here.</p>
                <input
                  className="token"
                  type="password"
                  value={token}
                  placeholder="eyJhbGciOi…"
                  onChange={(event) => setToken(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" && token.trim()) void go();
                  }}
                />
              </div>
            </div>

            {problem && (
              <div className="banner stop" style={{ marginBottom: 18 }}>
                <div>{problem}</div>
              </div>
            )}

            <div className="actions">
              <button
                className="primary"
                disabled={!token.trim() || checking}
                onClick={() => void go()}
              >
                {checking ? "Checking…" : "Continue"}
              </button>
              <span className="hint">
                Kept in this browser tab only. Never sent anywhere but the
                response service, and never stored on the server.
              </span>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

/* --- intake --------------------------------------------------------------- */

function Intake({
  onSubmitted,
  onWorking,
  onError,
  error,
  onExpired,
}: {
  onSubmitted: (incident: Incident) => void;
  onWorking: () => void;
  onError: (message: string) => void;
  error: string;
  onExpired: () => void;
}) {
  const [description, setDescription] = useState("");
  const [image, setImage] = useState<{
    base64: string;
    mediaType: string;
    name: string;
    preview: string;
  } | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  async function pick(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    if (file.size > 2_000_000) {
      onError("That image is larger than 2 MB. A screenshot is usually much smaller.");
      return;
    }
    const { base64, mediaType } = await readImageFile(file);
    setImage({
      base64,
      mediaType,
      name: file.name,
      preview: URL.createObjectURL(file),
    });
  }

  async function start() {
    onWorking();
    try {
      const result = await submitIncident({
        description: description.trim(),
        ...(image
          ? { image_base64: image.base64, image_media_type: image.mediaType }
          : {}),
      });
      onSubmitted(result);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        clearToken();
        onExpired();
        return;
      }
      onError(
        err instanceof ApiError
          ? `The response service could not accept that (${err.detail}).`
          : "Could not reach the response service.",
      );
    }
  }

  const tooShort = description.trim().length < 10;

  return (
    <div className="card card-pad">
      <h1 className="ask">What is happening at your site?</h1>
      <p className="ask-sub">
        Describe it in your own words. You do not need to know what caused it.
      </p>

      <textarea
        className="report"
        value={description}
        onChange={(event) => setDescription(event.target.value)}
        placeholder="For example: the dispatch screens in the warehouse are showing an error and the night shift cannot pick orders."
      />

      <div className="attach-row">
        <input
          ref={fileRef}
          type="file"
          accept="image/png,image/jpeg,image/webp"
          hidden
          onChange={(event) => void pick(event)}
        />
        {!image ? (
          <button className="attach" onClick={() => fileRef.current?.click()}>
            <span>＋</span> Attach a photo or screenshot
          </button>
        ) : (
          <div className="thumb">
            <img src={image.preview} alt="" />
            <span>{image.name}</span>
            <button
              className="ghost"
              style={{ padding: "4px 10px", fontSize: 12.5 }}
              onClick={() => setImage(null)}
            >
              Remove
            </button>
          </div>
        )}
        <span className="hint">Optional. A photo of the screen often says more than words.</span>
      </div>

      {error && (
        <div className="banner stop" style={{ marginTop: 20 }}>
          <div>{error}</div>
        </div>
      )}

      <div className="actions">
        <button className="primary" disabled={tooShort} onClick={() => void start()}>
          Start Continuity Response
        </button>
        {tooShort && <span className="hint">A sentence or two is enough.</span>}
      </div>
    </div>
  );
}

/* --- working -------------------------------------------------------------- */

const WORKING_NOTES = [
  "Checking what was reported…",
  "Working out which part of your site is affected…",
  "Asking the specialists that are needed…",
  "Gathering evidence from your systems…",
  "Checking what is allowed to be done automatically…",
];

function Working() {
  const [note, setNote] = useState(0);
  useEffect(() => {
    const timer = setInterval(
      () => setNote((n) => Math.min(n + 1, WORKING_NOTES.length - 1)),
      6000,
    );
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="card card-pad">
      <div className="eyebrow">Incident active</div>
      <h2 className="headline">{WORKING_NOTES[note]}</h2>
      <p className="ask-sub" style={{ marginBottom: 0 }}>
        Nothing on your site is changed without either an automatic safety check
        passing or your explicit approval.
      </p>
      <div className="working" style={{ marginTop: 22 }}>
        <span className="spinner" /> This usually takes under a minute.
      </div>
    </div>
  );
}

/* --- result --------------------------------------------------------------- */

function Result({
  incident,
  onUpdated,
  onExpired,
}: {
  incident: Incident;
  onUpdated: (incident: Incident) => void;
  onExpired: () => void;
}) {
  const allStages = useMemo(() => stages(incident), [incident]);
  const [shown, setShown] = useState(0);

  useEffect(() => {
    setShown(0);
    let index = 0;
    const timer = setInterval(() => {
      index += 1;
      setShown(index);
      if (index >= allStages.length) clearInterval(timer);
    }, 210);
    return () => clearInterval(timer);
  }, [allStages]);

  const settled = shown >= allStages.length;
  const status = incident.status;
  const manager = managerStatus(incident);
  const approval = approvalView(incident);
  const escalation = escalationMessage(incident);
  const fleet = specialistViews(incident, !settled);

  const tone =
    status === "RESOLVED"
      ? "good"
      : status === "WAITING_FOR_APPROVAL"
        ? "warn"
        : status === "ESCALATED"
          ? "stop"
          : "";

  return (
    <>
      <div className="card headline-card">
        <div className={`headline-bar ${tone}`} />
        <div className="headline-body">
          <div className="eyebrow">
            {status === "RESOLVED"
              ? "Resolved"
              : status === "WAITING_FOR_APPROVAL"
                ? "Your decision needed"
                : status === "ESCALATED"
                  ? "Handed to a person"
                  : "Incident active"}
          </div>
          <h2 className="headline">
            {manager?.headline ??
              (status === "RESOLVED"
                ? "Your dispatch service has been restored."
                : "We are working on your dispatch service.")}
          </h2>

          {escalation && (
            <div className={`banner ${status === "ESCALATED" ? "warn" : "info"}`}>
              <div>{escalation}</div>
            </div>
          )}

          {manager && manager.found.length > 0 && (
            <div className="found">
              {manager.found.map((line) => (
                <div className="found-item" key={line}>
                  {line}
                </div>
              ))}
            </div>
          )}

          {manager?.next && <p className="next">{manager.next}</p>}
        </div>
      </div>

      {approval && approval.state === "PENDING" && (
        <ApprovalPanel
          incident={incident}
          approval={approval}
          onUpdated={onUpdated}
          onExpired={onExpired}
        />
      )}

      <div className="grid">
        <div className="card">
          <div className="section-title">What happened</div>
          <div className="stages">
            {allStages.slice(0, Math.max(shown, 1)).map((stage, index) => (
              <StageRow
                key={stage.key}
                stage={stage}
                last={index === allStages.length - 1}
              />
            ))}
          </div>
        </div>

        <div className="card">
          <div className="section-title">Who was consulted</div>
          <div className="fleet">
            {fleet.map((agent) => (
              <div className="agent" key={agent.name} title={agent.why}>
                <span className={`dot ${dotClass(agent.state)}`} />
                <div className="agent-main">
                  <div className="agent-name">{agent.label}</div>
                  <div className="agent-role">{agent.role}</div>
                  {agent.delegated && (
                    <div className="delegated-tag">
                      Brought in after the evidence pointed here
                    </div>
                  )}
                </div>
                <span className={`state ${agent.state.replace(" ", "")}`}>
                  {agent.state}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <EvidenceDrawer incident={incident} />
    </>
  );
}

function dotClass(state: string): string {
  switch (state) {
    case "ACTIVE":
      return "active";
    case "COMPLETE":
      return "complete";
    case "UNAVAILABLE":
      return "unavailable";
    case "WITHHELD":
      return "withheld";
    default:
      return "idle";
  }
}

function StageRow({ stage, last }: { stage: Stage; last: boolean }) {
  return (
    <div className="stage reveal">
      <div className="rail">
        <span className={`node ${stage.state}`} />
        {!last && <span className="thread" />}
      </div>
      <div className="stage-body">
        <div
          className={`stage-title ${stage.state === "skipped" ? "muted" : ""}`}
        >
          {stage.title}
        </div>
        <div className="stage-detail">{stage.detail}</div>
      </div>
    </div>
  );
}

/* --- approval ------------------------------------------------------------- */

function ApprovalPanel({
  incident,
  approval,
  onUpdated,
  onExpired,
}: {
  incident: Incident;
  approval: NonNullable<ReturnType<typeof approvalView>>;
  onUpdated: (incident: Incident) => void;
  onExpired: () => void;
}) {
  const [busy, setBusy] = useState<"approve" | "reject" | null>(null);
  const [problem, setProblem] = useState("");
  const [outcome, setOutcome] = useState("");

  async function decide(verb: "approve" | "reject") {
    setBusy(verb);
    setProblem("");
    try {
      await decideApproval(approval.approvalId, verb, "Decided in the console.");
      if (verb === "reject") {
        setOutcome("Recorded. Nothing on your site has been changed.");
        setBusy(null);
        return;
      }
      setOutcome("Approved. Carrying out the recovery…");
      const resumed = await resumeIncident(incident.incident_id);
      onUpdated({
        ...incident,
        status: String(resumed.final_status ?? incident.status),
        remediation: {
          ...incident.remediation,
          ...resumed,
          approval: { ...incident.remediation?.approval, state: "APPROVED" },
        },
      });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        clearToken();
        onExpired();
        return;
      }
      // A 403 here is Google refusing this identity, and saying so plainly is
      // more useful than a generic apology — it is the boundary working.
      setProblem(
        err instanceof ApiError && err.status === 403
          ? "Google did not permit this account to approve. Approval is restricted to the configured incident commander."
          : err instanceof ApiError
            ? `The approval service could not accept that (${err.detail}).`
            : "Could not reach the approval service.",
      );
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="card headline-card approval">
      <div className="headline-bar warn" />
      <div className="headline-body">
        <div className="eyebrow">Your approval is required</div>
        <h2 className="headline">{approval.headline}</h2>

        <div className="approval-grid">
          {approval.whatWillHappen && (
            <div className="approval-cell">
              <div className="approval-key">What will happen</div>
              <div className="approval-val">{approval.whatWillHappen}</div>
            </div>
          )}
          {approval.whyAsked && (
            <div className="approval-cell">
              <div className="approval-key">Why you are being asked</div>
              <div className="approval-val">{approval.whyAsked}</div>
            </div>
          )}
          {approval.scope && (
            <div className="approval-cell">
              <div className="approval-key">What is affected</div>
              <div className="approval-val">{approval.scope}</div>
            </div>
          )}
          {approval.whatWillNot && (
            <div className="approval-cell">
              <div className="approval-key">What stays protected</div>
              <div className="approval-val">{approval.whatWillNot}</div>
            </div>
          )}
        </div>

        {problem && (
          <div className="banner stop" style={{ marginTop: 18 }}>
            <div>{problem}</div>
          </div>
        )}
        {outcome && (
          <div className="banner info" style={{ marginTop: 18 }}>
            <div>{outcome}</div>
          </div>
        )}

        <div className="actions">
          <button
            className="primary approve-btn"
            disabled={busy !== null}
            onClick={() => void decide("approve")}
          >
            {busy === "approve" ? "Approving…" : "Approve recovery"}
          </button>
          <button
            className="ghost"
            disabled={busy !== null}
            onClick={() => void decide("reject")}
          >
            Escalate instead
          </button>
        </div>
      </div>
    </div>
  );
}

/* --- evidence drawer ------------------------------------------------------ */

function EvidenceDrawer({ incident }: { incident: Incident }) {
  const [open, setOpen] = useState(false);
  const remediation = incident.remediation ?? {};
  const execution = remediation.execution ?? {};
  const result = execution.result ?? {};
  const verification = remediation.verification ?? {};
  const terminalization = remediation.terminalization ?? {};
  const screening = incident.screening ?? {};
  const approval = remediation.approval ?? {};

  return (
    <div className="card drawer">
      <button className="drawer-toggle" onClick={() => setOpen(!open)}>
        <span className={`chev ${open ? "open" : ""}`}>▶</span>
        View technical evidence
        <span className="hint" style={{ marginLeft: "auto" }}>
          {incident.incident_id}
        </span>
      </button>

      {open && (
        <div className="drawer-body">
          <Group title="Incoming content">
            <Row k="Model Armor" v={verdictText(screening, remediation)} plain />
            {screening.template && <Row k="Screening template" v={screening.template} />}
            <Row k="Screenshot attached" v={incident.image_attached ? "yes" : "no"} />
            {incident.observed_text && (
              <>
                <Row k="Read from screenshot" v="transcribed below, untrusted" plain />
                <div className="quote">{incident.observed_text}</div>
              </>
            )}
          </Group>

          <Group title="Routing (Gemini via ADK)">
            <Row k="Summary" v={incident.summary} plain />
            <Row
              k="Requested"
              v={incident.required_specialists.join(", ") || "none"}
            />
            <Row
              k="Consulted"
              v={(remediation.specialists_consulted ?? []).join(", ") || "none"}
            />
            {remediation.specialists_withheld_by_registry && (
              <Row
                k="Withheld by catalog"
                v={remediation.specialists_withheld_by_registry.join(", ")}
              />
            )}
            {remediation.secondary_delegation && (
              <Row
                k="Secondary delegation"
                v={`${remediation.secondary_delegation.delegated_to} — because ${remediation.secondary_delegation.because}`}
                plain
              />
            )}
          </Group>

          <Group title="Trusted evidence">
            <Row k="Findings" v={String(remediation.evidence_count ?? 0)} />
            {remediation.evidence_keys && (
              <Row k="Keys" v={remediation.evidence_keys.join(", ")} />
            )}
            {remediation.service_http_status !== undefined && (
              <Row k="Observed health" v={`HTTP ${remediation.service_http_status}`} />
            )}
          </Group>

          <Group title="Deterministic policy">
            <Row k="Decision" v={remediation.decision ?? "none"} />
            <Row k="Reason code" v={remediation.reason_code ?? "—"} />
            <Row k="Proposal" v={remediation.proposal ?? "none"} />
            {remediation.failure_category && (
              <Row k="Failure category" v={remediation.failure_category} />
            )}
            {approval.approval_id && (
              <>
                <Row k="Approval" v={`${approval.approval_id} — ${approval.state}`} />
                <Row k="Required role" v={approval.required_approval_role ?? "—"} />
              </>
            )}
          </Group>

          {(result.service || execution.action_id) && (
            <Group title="Execution">
              <Row k="Executed by" v="sa-executor (scoped to dispatch-web only)" plain />
              <Row k="Target" v={result.service ?? "—"} />
              <Row k="Authorized revision" v={result.revision ?? "—"} />
              <Row k="API" v={result.api ?? "—"} />
              {result.resource_version_before && (
                <Row
                  k="resourceVersion"
                  v={`${result.resource_version_before} → ${result.resource_version_after ?? "?"}`}
                />
              )}
              <Row k="Conflict (OCC)" v={String(result.conflict ?? false)} />
              <Row k="Duplicate suppressed" v={String(execution.duplicate ?? false)} />
              <Row
                k="Infrastructure changed"
                v={
                  remediation.mutated_infrastructure === null
                    ? "could not be established"
                    : String(remediation.mutated_infrastructure ?? false)
                }
              />
            </Group>
          )}

          {(verification.http_status || terminalization.state) && (
            <Group title="Independent verification">
              <Row k="Verified by" v="sa-verifier (read-only, cannot mutate)" plain />
              <Row k="Health" v={verification.http_status ? `HTTP ${verification.http_status}` : "—"} />
              <Row
                k="Serving authorized revision"
                v={String(verification.revision_matches_authorized ?? "—")}
              />
              <Row
                k="Traffic exclusive"
                v={String(verification.traffic_allocation_exclusive ?? "—")}
              />
              <Row k="Terminal state" v={terminalization.state ?? "—"} />
            </Group>
          )}

          <Group title="Correlation">
            <Row k="Incident" v={incident.incident_id} />
            <Row k="Trace" v={incident.trace_id ?? "—"} />
            {remediation.decision_id && <Row k="Decision" v={remediation.decision_id} />}
            {execution.action_id && <Row k="Action" v={execution.action_id} />}
          </Group>
        </div>
      )}
    </div>
  );
}

function verdictText(
  screening: Record<string, any>,
  remediation: Record<string, any>,
): string {
  if (remediation.failure_category === "UNTRUSTED_CONTENT_BLOCKED") {
    return "BLOCKED — the report was refused before any model read it";
  }
  if (remediation.failure_category === "SECURITY_SCREENING_UNAVAILABLE") {
    return "UNAVAILABLE — failed closed, nothing proceeded";
  }
  if (Object.keys(screening).length === 0) return "no verdict recorded";
  return "allowed";
}

function Group({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="ev-group">
      <div className="ev-group-title">{title}</div>
      {children}
    </div>
  );
}

function Row({ k, v, plain }: { k: string; v: string; plain?: boolean }) {
  return (
    <div className="ev-row">
      <div className="ev-key">{k}</div>
      <div className={`ev-val ${plain ? "plain" : ""}`}>{v}</div>
    </div>
  );
}
