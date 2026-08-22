/**
 * The console's one job is to not lie.
 *
 * Every test here is a way the UI could have claimed something the backend
 * never said: showing a specialist as having worked when it was refused,
 * turning an unknown outcome into a failure, or reporting a recovery on an
 * incident where nothing was executed. Those are the failure modes that matter
 * for a product whose entire pitch is that it tells a duty manager the truth.
 */

import { describe, expect, it } from "vitest";
import type { Incident } from "./api";
import {
  approvalView,
  escalationMessage,
  managerStatus,
  specialistViews,
  stages,
} from "./incident";

function incident(overrides: Partial<Incident> = {}): Incident {
  return {
    incident_id: "INC-TEST",
    status: "RESOLVED",
    summary: "The dispatch application is not responding.",
    required_specialists: ["systems"],
    routes: [
      { specialist: "systems", required: true, why: "application error" },
      { specialist: "network", required: false, why: "page loads" },
      { specialist: "security", required: false, why: "no access issues" },
      { specialist: "continuity", required: false, why: "no vendor handoff" },
    ],
    remediation: {},
    trace_id: "trace-1",
    observed_text: "",
    image_attached: false,
    screening: { allowed: true },
    ...overrides,
  };
}

describe("specialist states reflect the backend, never the request", () => {
  it("shows a consulted specialist as complete", () => {
    const view = specialistViews(
      incident({ remediation: { specialists_consulted: ["systems"] } }),
      false,
    );
    expect(view.find((s) => s.name === "systems")?.state).toBe("COMPLETE");
  });

  it("never shows a withheld agent as having worked", () => {
    // The catalog refused it. Routing asked for it. It did not run.
    const view = specialistViews(
      incident({
        required_specialists: ["network"],
        routes: [{ specialist: "network", required: true, why: "wifi drops" }],
        remediation: {
          specialists_consulted: [],
          specialists_withheld_by_registry: ["network"],
        },
      }),
      false,
    );
    const network = view.find((s) => s.name === "network");
    expect(network?.state).toBe("WITHHELD");
    expect(network?.state).not.toBe("COMPLETE");
    expect(network?.state).not.toBe("ACTIVE");
  });

  it("distinguishes 'not required' from 'asked for but never answered'", () => {
    const view = specialistViews(
      incident({
        required_specialists: ["systems", "security"],
        remediation: { specialists_consulted: ["systems"] },
      }),
      false,
    );
    expect(view.find((s) => s.name === "security")?.state).toBe("UNAVAILABLE");
    expect(view.find((s) => s.name === "network")?.state).toBe("NOT REQUIRED");
  });

  it("marks a delegated specialist only when it was actually consulted", () => {
    const delegated = specialistViews(
      incident({
        required_specialists: ["network"],
        remediation: {
          specialists_consulted: ["network", "systems"],
          secondary_delegation: {
            delegated_to: "systems",
            because: "network_reachable",
          },
        },
      }),
      false,
    );
    expect(delegated.find((s) => s.name === "systems")?.delegated).toBe(true);

    const claimedOnly = specialistViews(
      incident({
        remediation: {
          specialists_consulted: [],
          secondary_delegation: { delegated_to: "systems", because: "x" },
        },
      }),
      false,
    );
    expect(claimedOnly.find((s) => s.name === "systems")?.delegated).toBe(false);
  });

  it("shows nothing as active once the incident has settled", () => {
    const view = specialistViews(
      incident({ remediation: { specialists_consulted: ["systems"] } }),
      false,
    );
    expect(view.every((s) => s.state !== "ACTIVE")).toBe(true);
  });
});

describe("an unknown outcome is never rendered as failure", () => {
  it("keeps 'could not confirm' distinct from 'nothing changed'", () => {
    const unknown = stages(
      incident({
        status: "ESCALATED",
        remediation: {
          decision: "AUTO_ALLOWED",
          mutated_infrastructure: null,
          failure_category: "EXECUTION_OUTCOME_UNKNOWN",
        },
      }),
    );
    const recovery = unknown.find((s) => s.key === "recovery");
    expect(recovery?.detail).toContain("could not confirm");
    expect(recovery?.state).toBe("blocked");

    const nothing = stages(
      incident({ status: "ESCALATED", remediation: { mutated_infrastructure: false } }),
    );
    expect(nothing.find((s) => s.key === "recovery")?.detail).toContain(
      "Nothing on your site was changed",
    );
  });

  it("gives the unknown outcome a plain-language escalation message", () => {
    const message = escalationMessage(
      incident({ remediation: { failure_category: "EXECUTION_OUTCOME_UNKNOWN" } }),
    );
    expect(message).toContain("could not confirm");
    expect(message).not.toMatch(/failed/i);
  });

  it("never claims a recovery on an incident that executed nothing", () => {
    const escalated = stages(
      incident({
        status: "ESCALATED",
        remediation: { failure_category: "INSUFFICIENT_EVIDENCE" },
      }),
    );
    expect(escalated.find((s) => s.key === "recovery")?.detail).toContain(
      "Nothing on your site was changed",
    );
    expect(escalated.find((s) => s.key === "verification")?.state).toBe("skipped");
  });
});

describe("a blocked report stops the story where it actually stopped", () => {
  const blocked = incident({
    status: "ESCALATED",
    summary: "",
    required_specialists: [],
    routes: [],
    remediation: { failure_category: "UNTRUSTED_CONTENT_BLOCKED" },
  });

  it("marks screening as the blocking step", () => {
    const list = stages(blocked);
    expect(list.find((s) => s.key === "screening")?.state).toBe("blocked");
  });

  it("does not claim any model understood the report", () => {
    const list = stages(blocked);
    const understand = list.find((s) => s.key === "understand");
    expect(understand?.state).toBe("skipped");
    expect(understand?.detail).toContain("refused before this point");
  });

  it("says plainly that no privileged action was taken", () => {
    const message = escalationMessage(blocked);
    expect(message).toContain("No privileged action was taken");
  });

  it("shows no specialist as having run", () => {
    const view = specialistViews(blocked, false);
    expect(view.every((s) => s.state === "NOT REQUIRED")).toBe(true);
  });
});

describe("approval", () => {
  const waiting = incident({
    status: "WAITING_FOR_APPROVAL",
    remediation: {
      decision: "APPROVAL_REQUIRED",
      specialists_consulted: ["systems"],
      approval: {
        approval_id: "APR-1",
        state: "PENDING",
        required_approval_role: "incident_commander",
      },
      manager_prompt: {
        headline: "Automatic recovery found a higher-impact action.",
        what_will_happen: "Traffic will move to a version that is answering.",
        why_you_are_being_asked: "No version has been marked known good.",
        scope: "The dispatch-web service only.",
        what_will_not_happen: "No other service can be changed.",
      },
    },
  });

  it("surfaces the backend's own prompt rather than inventing one", () => {
    const view = approvalView(waiting);
    expect(view?.approvalId).toBe("APR-1");
    expect(view?.whyAsked).toContain("known good");
    expect(view?.scope).toContain("dispatch-web");
  });

  it("says nothing has changed while waiting", () => {
    const recovery = stages(waiting).find((s) => s.key === "recovery");
    expect(recovery?.detail).toContain("Nothing has changed yet");
    expect(recovery?.state).toBe("running");
  });

  it("returns nothing when there is no approval to make", () => {
    expect(approvalView(incident())).toBeNull();
  });
});

describe("the Coordinator's words are passed through, not rewritten", () => {
  it("uses the backend narrative verbatim", () => {
    const view = managerStatus(
      incident({
        remediation: {
          manager_status: {
            headline: "Your dispatch service has been restored.",
            what_we_found: ["The site network is reachable."],
            what_happens_next: "The service has been restored.",
            who_checked: ["the dispatch application"],
          },
        },
      }),
    );
    expect(view?.headline).toBe("Your dispatch service has been restored.");
    expect(view?.found).toEqual(["The site network is reachable."]);
  });

  it("returns null rather than fabricating a narrative", () => {
    expect(managerStatus(incident())).toBeNull();
  });
});

describe("screenshot handling", () => {
  it("acknowledges an attached image without treating it as authority", () => {
    const withImage = incident({
      image_attached: true,
      observed_text: "503 Service Unavailable",
    });
    const report = stages(withImage).find((s) => s.key === "report");
    expect(report?.detail).toContain("screenshot");
    // The transcription is never used to decide a stage outcome.
    expect(JSON.stringify(stages(withImage))).not.toContain("503 Service Unavailable");
  });
});
