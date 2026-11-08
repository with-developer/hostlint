import type { AgentInfo, ControlDetail, ControlInfo, ControlSummary, Diff, HostDetail, HostSummary, Matrix, Overview, ProfileList, ScanDoc, ScanJob, TrendPoint } from "./types";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

let onUnauthorized: () => void = () => {};
/** The app is told when the server stops recognizing the session, so it can show the sign-in form. */
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { credentials: "same-origin", ...init });
  const text = await res.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    // not JSON: reported below
  }
  if (res.status === 401 && !path.startsWith("/api/v1/login") && !path.startsWith("/api/v1/session")) onUnauthorized();
  if (!res.ok) {
    const message = body && typeof body === "object" && "error" in body ? String((body as { error: unknown }).error) : res.statusText;
    throw new ApiError(res.status, message);
  }
  return body as T;
}

export interface HostsParams {
  q?: string;
  status?: string;
  sort?: string;
  limit?: number;
  offset?: number;
  kind?: "host" | "image";
  label?: string;
  staleDays: number;
}

export function hostsQuery(p: HostsParams): string {
  const q = new URLSearchParams({ staleDays: String(p.staleDays) });
  if (p.q) q.set("q", p.q);
  if (p.status) q.set("status", p.status);
  if (p.sort) q.set("sort", p.sort);
  if (p.limit !== undefined) q.set("limit", String(p.limit));
  if (p.offset !== undefined) q.set("offset", String(p.offset));
  if (p.kind) q.set("kind", p.kind);
  if (p.label) q.set("label", p.label);
  return q.toString();
}

let profile = "";
/** The profile whose numbers the pages show: sent with every call that counts controls. */
export function setProfile(p: string): void {
  profile = p;
}

/** Adds the selected profile to a path of the read API. */
function withProfile(path: string): string {
  if (!profile) return path;
  return path + (path.includes("?") ? "&" : "?") + "profile=" + encodeURIComponent(profile);
}

const json = { "Content-Type": "application/json" };

export const api = {
  session: () => request<{ authenticated: boolean; canScan?: boolean }>("/api/v1/session"),
  login: (token: string) => request<{ ok: boolean; name: string }>("/api/v1/login", { method: "POST", headers: json, body: JSON.stringify({ token }) }),
  logout: () => request<{ ok: boolean }>("/api/v1/logout", { method: "POST", headers: json, body: "{}" }),
  profiles: () => request<ProfileList>("/api/v1/profiles"),
  overview: (staleDays: number) => request<Overview>(withProfile(`/api/v1/overview?staleDays=${staleDays}`)),
  hosts: (params: HostsParams) => request<{ hosts: HostSummary[]; total: number }>(withProfile(`/api/v1/hosts?${hostsQuery(params)}`)),
  hostsCSV: (params: HostsParams) => withProfile(`/api/v1/hosts?${hostsQuery({ ...params, limit: undefined, offset: undefined })}&format=csv`),
  trend: (days: number) => request<{ points: TrendPoint[] }>(withProfile(`/api/v1/trend?days=${days}`)),
  controls: () => request<{ controls: ControlSummary[] }>(withProfile("/api/v1/controls")),
  control: (profile: string, id: string, staleDays: number) =>
    request<{ control: ControlDetail; info: ControlInfo | null }>(`/api/v1/controls/${encodeURIComponent(profile)}/${encodeURIComponent(id)}?staleDays=${staleDays}`),
  matrix: (staleDays: number) => request<Matrix>(withProfile(`/api/v1/matrix?staleDays=${staleDays}`)),
  host: (id: number, staleDays: number) => request<HostDetail>(withProfile(`/api/v1/hosts/${id}?staleDays=${staleDays}`)),
  hostAgent: (id: number) => request<AgentInfo>(`/api/v1/hosts/${id}/agent`),
  requestScan: (id: number, profile: string) => request<{ job: ScanJob }>(`/api/v1/hosts/${id}/scan`, { method: "POST", headers: json, body: JSON.stringify({ profile }) }),
  scan: (id: number) => request<ScanDoc>(`/api/v1/scans/${id}`),
  diff: (oldId: number, newId: number) => request<Diff>(`/api/v1/diff?old=${oldId}&new=${newId}`),
};
