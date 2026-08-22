/**
 * Every call carries the Director's own Google identity token.
 *
 * The console holds no credential of its own — see `src/scf/app/director.py`.
 * If the token is missing or wrong, the backend returns the refusal Google
 * produced and we show it as-is rather than softening it.
 */

const TOKEN_KEY = "scf.director.token";

export function readToken(): string {
  return sessionStorage.getItem(TOKEN_KEY) ?? "";
}

export function writeToken(token: string): void {
  sessionStorage.setItem(TOKEN_KEY, token.trim());
}

export function clearToken(): void {
  sessionStorage.removeItem(TOKEN_KEY);
}

/** Seconds until the pasted token expires, or null if it cannot be read. */
export function tokenExpiresIn(token: string): number | null {
  try {
    const [, payload] = token.split(".");
    const claims = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
    if (typeof claims.exp !== "number") return null;
    return claims.exp - Math.floor(Date.now() / 1000);
  } catch {
    return null;
  }
}

export class ApiError extends Error {
  status: number;
  detail: string;

  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
    this.detail = detail;
  }
}

async function call<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const token = readToken();
  const response = await fetch(path, {
    ...init,
    headers: {
      ...(init.headers ?? {}),
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });

  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }

  if (!response.ok) {
    const detail =
      (body as { detail?: string } | null)?.detail ?? `request_failed_${response.status}`;
    throw new ApiError(response.status, detail);
  }
  return body as T;
}

export interface SessionState {
  signed_in: boolean;
  reachable: Record<string, string>;
  core_region: string;
}

export function checkSession(): Promise<SessionState> {
  return call<SessionState>("/api/session");
}

export interface Route {
  specialist: string;
  required: boolean;
  why: string;
}

export interface Incident {
  incident_id: string;
  status: string;
  summary: string;
  required_specialists: string[];
  routes: Route[];
  remediation: Record<string, any>;
  trace_id: string | null;
  observed_text: string;
  image_attached: boolean;
  screening: Record<string, any>;
}

export interface NewIncident {
  description: string;
  image_base64?: string;
  image_media_type?: string;
}

export function submitIncident(report: NewIncident): Promise<Incident> {
  return call<Incident>("/api/incidents", {
    method: "POST",
    body: JSON.stringify(report),
  });
}

export function readIncident(id: string): Promise<Record<string, any>> {
  return call<Record<string, any>>(`/api/incidents/${encodeURIComponent(id)}`);
}

export function decideApproval(
  approvalId: string,
  verb: "approve" | "reject",
  note: string,
): Promise<Record<string, any>> {
  return call<Record<string, any>>(
    `/api/approvals/${encodeURIComponent(approvalId)}/${verb}`,
    { method: "POST", body: JSON.stringify({ note }) },
  );
}

export function resumeIncident(id: string): Promise<Record<string, any>> {
  return call<Record<string, any>>(
    `/api/incidents/${encodeURIComponent(id)}/resume`,
    { method: "POST", body: "{}" },
  );
}

/** Strip the data: prefix a FileReader gives us; the API wants raw base64. */
export function readImageFile(
  file: File,
): Promise<{ base64: string; mediaType: string }> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("could not read that file"));
    reader.onload = () => {
      const result = String(reader.result ?? "");
      const comma = result.indexOf(",");
      resolve({
        base64: comma >= 0 ? result.slice(comma + 1) : result,
        mediaType: file.type,
      });
    };
    reader.readAsDataURL(file);
  });
}
