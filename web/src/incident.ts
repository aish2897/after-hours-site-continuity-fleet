/**
 * Reading the backend's answer. This file interprets; it never invents.
 *
 * Two rules hold everywhere below:
 *
 * 1. A specialist is only shown as having done something if the backend says
 *    it was consulted. Routing asking for a specialist is not the same as that
 *    specialist running, and the difference is exactly what the withheld and
 *    unavailable states exist to show.
 * 2. Where the backend does not know, the UI says so. "We could not confirm"
 *    is a real outcome and gets its own state; it is never rendered as failure,
 *    because reporting a failure we cannot substantiate is its own kind of lie.
 */

import type { Incident, Route } from "./api";

export type SpecialistState =
  | "ACTIVE"
  | "COMPLETE"
  | "NOT REQUIRED"
  | "UNAVAILABLE"
  | "WITHHELD";

export const SPECIALIST_LABELS: Record<string, string> = {
  systems: "Systems Investigator",
  network: "Network Investigator",
  security: "Security & Identity",
  continuity: "Continuity Coordinator",
};

export const SPECIALIST_ROLES: Record<string, string> = {
  systems: "the dispatch application",
  network: "the site's network and connection",
  security: "sign-in and access settings",
  continuity: "what you are told, and the handover",
};

export interface SpecialistView {
  name: string;
  label: string;
  role: string;
  state: SpecialistState;
  why: string;
  delegated: boolean;
}

const ORDER = ["systems", "network", "security", "continuity"];

export function specialistViews(
  incident: Incident | null,
  live: boolean,
): SpecialistView[] {
  const remediation = incident?.remediation ?? {};
  const consulted: string[] = remediation.specialists_consulted ?? [];
  const withheld: string[] = remediation.specialists_withheld_by_registry ?? [];
  const delegation = remediation.secondary_delegation ?? null;
  const routes: Route[] = incident?.routes ?? [];
  const required = new Set(incident?.required_specialists ?? []);

  const byName = new Map(routes.map((route) => [route.specialist, route]));

  return ORDER.map((name) => {
    const route = byName.get(name);
    const wasConsulted = consulted.includes(name);
    const wasWithheld = withheld.includes(name);
    const wasRequired = required.has(name) || route?.required === true;
    const delegated = delegation?.delegated_to === name && wasConsulted;

    let state: SpecialistState;
    if (wasWithheld) {
      // The catalog refused to let this agent be selected. It never ran.
      state = "WITHHELD";
    } else if (wasConsulted) {
      state = live ? "ACTIVE" : "COMPLETE";
    } else if (wasRequired) {
      // Routing asked for it and no evidence came back.
      state = live ? "ACTIVE" : "UNAVAILABLE";
    } else {
      state = "NOT REQUIRED";
    }

    return {
      name,
      label: SPECIALIST_LABELS[name] ?? name,
      role: SPECIALIST_ROLES[name] ?? "",
      state,
      why: route?.why ?? "",
      delegated,
    };
  });
}

export type StageState = "pending" | "running" | "done" | "blocked" | "skipped";

export interface Stage {
  key: string;
  title: string;
  detail: string;
  state: StageState;
}

function screeningVerdict(incident: Incident): {
  blocked: boolean;
  ran: boolean;
  detail: string;
} {
  const screening = incident.screening ?? {};
  const category = incident.remediation?.failure_category;
  if (category === "UNTRUSTED_CONTENT_BLOCKED") {
    return {
      blocked: true,
      ran: true,
      detail: "Unsafe instructions were detected and refused.",
    };
  }
  if (category === "SECURITY_SCREENING_UNAVAILABLE") {
    return {
      blocked: true,
      ran: false,
      detail: "Safety screening was unavailable, so nothing was allowed through.",
    };
  }
  if (Object.keys(screening).length === 0) {
    return { blocked: false, ran: false, detail: "No verdict was recorded." };
  }
  return { blocked: false, ran: true, detail: "Report checked and cleared." };
}

/** The nine steps, each resolved against what the backend actually reported. */
export function stages(incident: Incident): Stage[] {
  const remediation = incident.remediation ?? {};
  const status = incident.status;
  const consulted: string[] = remediation.specialists_consulted ?? [];
  const screening = screeningVerdict(incident);
  const decision = remediation.decision as string | undefined;
  const awaiting = status === "WAITING_FOR_APPROVAL";
  const resolved = status === "RESOLVED";
  const escalated = status === "ESCALATED";
  const mutated = remediation.mutated_infrastructure;
  const verification = remediation.verification ?? remediation.verification_checked;

  const evidenceCount = remediation.evidence_count as number | undefined;

  const list: Stage[] = [
    {
      key: "report",
      title: "Incident reported",
      detail: incident.image_attached
        ? "Your description and screenshot were received."
        : "Your description was received.",
      state: "done",
    },
    {
      key: "screening",
      title: "Safety screening",
      detail: screening.detail,
      state: screening.blocked ? "blocked" : screening.ran ? "done" : "skipped",
    },
    {
      key: "understand",
      title: "Understanding what failed",
      detail: screening.blocked
        ? "Not attempted — the report was refused before this point."
        : incident.summary || "Working out which part of your site is affected.",
      state: screening.blocked ? "skipped" : "done",
    },
    {
      key: "specialists",
      title: "Specialists consulted",
      detail: screening.blocked
        ? "Not attempted."
        : consulted.length
          ? consulted.map((name) => SPECIALIST_LABELS[name] ?? name).join(", ")
          : "No specialist was consulted.",
      state: screening.blocked ? "skipped" : consulted.length ? "done" : "skipped",
    },
    {
      key: "evidence",
      title: "Trusted evidence gathered",
      detail:
        evidenceCount === undefined
          ? "No checks returned a trustworthy answer."
          : `${evidenceCount} findings from tools running under their own identity.`,
      state: evidenceCount ? "done" : "skipped",
    },
  ];

  list.push({
    key: "policy",
    title: "Policy decision",
    detail: policyDetail(decision, remediation.failure_category),
    state: decision ? "done" : "skipped",
  });

  list.push({
    key: "recovery",
    title: awaiting ? "Waiting for your approval" : "Recovery",
    detail: recoveryDetail(status, mutated, decision),
    state: awaiting
      ? "running"
      : mutated === true
        ? "done"
        : mutated === null
          ? "blocked"
          : "skipped",
  });

  list.push({
    key: "verification",
    title: "Independent verification",
    detail: verificationDetail(verification, resolved, mutated),
    state: resolved ? "done" : mutated === true ? "blocked" : "skipped",
  });

  list.push({
    key: "outcome",
    title: resolved ? "Resolved" : escalated ? "Handed to a person" : "Outcome",
    detail: outcomeDetail(status),
    state: resolved ? "done" : escalated ? "blocked" : "pending",
  });

  return list;
}

function policyDetail(
  decision: string | undefined,
  failure: string | undefined,
): string {
  if (decision === "AUTO_ALLOWED") {
    return "This recovery is low risk and reversible, so it was allowed automatically.";
  }
  if (decision === "APPROVAL_REQUIRED") {
    return "This recovery needs a person to authorise it.";
  }
  if (decision === "DENIED") {
    return "The policy refused this action outright.";
  }
  if (failure === "INSUFFICIENT_EVIDENCE") {
    return "There was not enough trustworthy evidence to authorise anything.";
  }
  return "No action was proposed, so there was nothing to authorise.";
}

function recoveryDetail(
  status: string,
  mutated: unknown,
  decision: string | undefined,
): string {
  if (status === "WAITING_FOR_APPROVAL") {
    return "A recovery has been prepared. Nothing has changed yet.";
  }
  if (mutated === true) return "The recovery was carried out.";
  if (mutated === null) {
    return "A repair was sent but we could not confirm whether it took effect.";
  }
  if (decision === "APPROVAL_REQUIRED") return "Not carried out.";
  return "Nothing on your site was changed.";
}

function verificationDetail(
  verification: unknown,
  resolved: boolean,
  mutated: unknown,
): string {
  if (resolved) return "A separate check confirmed the service is answering normally.";
  if (mutated === true) return "Verification did not confirm the recovery.";
  if (verification) return "Checked.";
  return "Not reached.";
}

function outcomeDetail(status: string): string {
  switch (status) {
    case "RESOLVED":
      return "Your dispatch service is working again.";
    case "ESCALATED":
      return "The details have been prepared for a technical responder.";
    case "WAITING_FOR_APPROVAL":
      return "Waiting on your decision.";
    default:
      return status.replaceAll("_", " ").toLowerCase();
  }
}

/** The Coordinator's own words, when it produced any. */
export function managerStatus(incident: Incident): {
  headline: string;
  found: string[];
  next: string;
  who: string[];
} | null {
  const status = incident.remediation?.manager_status;
  if (!status) return null;
  return {
    headline: status.headline ?? "",
    found: status.what_we_found ?? [],
    next: status.what_happens_next ?? "",
    who: status.who_checked ?? [],
  };
}

export interface ApprovalView {
  approvalId: string;
  state: string;
  headline: string;
  whatWillHappen: string;
  whyAsked: string;
  scope: string;
  whatWillNot: string;
  role: string;
}

export function approvalView(incident: Incident): ApprovalView | null {
  const approval = incident.remediation?.approval;
  if (!approval?.approval_id) return null;
  const prompt = incident.remediation?.manager_prompt ?? {};
  return {
    approvalId: approval.approval_id,
    state: approval.state ?? "PENDING",
    headline: prompt.headline ?? "Your approval is required.",
    whatWillHappen: prompt.what_will_happen ?? "",
    whyAsked: prompt.why_you_are_being_asked ?? "",
    scope: prompt.scope ?? "",
    whatWillNot: prompt.what_will_not_happen ?? "",
    role: approval.required_approval_role ?? "",
  };
}

/** Plain-language framing for the failure taxonomy (I11). */
export function escalationMessage(incident: Incident): string | null {
  const category = incident.remediation?.failure_category as string | undefined;
  if (!category) return null;
  const messages: Record<string, string> = {
    UNTRUSTED_CONTENT_BLOCKED:
      "Potentially unsafe instructions were detected in what was submitted. No privileged action was taken and nothing on your site was changed.",
    SECURITY_SCREENING_UNAVAILABLE:
      "The safety check could not run, so nothing was allowed to proceed. This is deliberate: when we cannot screen, we do not act.",
    INSUFFICIENT_EVIDENCE:
      "We could not gather enough trustworthy evidence to act safely. The details have been prepared for a technical responder.",
    WORKER_UNAVAILABLE:
      "A specialist could not be reached, so we stopped rather than guessing. Nothing on your site was changed.",
    EXECUTION_OUTCOME_UNKNOWN:
      "We could not confirm the recovery safely. Technical escalation has been prepared, and the incident is being re-checked before anything is reported as done.",
    APPROVAL_REJECTED:
      "The recovery was declined. Nothing on your site was changed.",
    APPROVAL_EXPIRED:
      "The approval request expired before it was answered. Nothing on your site was changed.",
    MODEL_OUTPUT_INVALID:
      "The system could not produce a usable plan, so it stopped rather than acting on a guess.",
  };
  return (
    messages[category] ??
    "We stopped safely rather than act on something we could not confirm. The details have been prepared for a technical responder."
  );
}
