import type { Diff, HostDetail, HostSummary, Matrix, Overview, ScanDoc } from "./types";

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
  staleDays: number;
}

export function hostsQuery(p: HostsParams): string {
  const q = new URLSearchParams({ staleDays: String(p.staleDays) });
  if (p.q) q.set("q", p.q);
  if (p.status) q.set("status", p.status);
  if (p.sort) q.set("sort", p.sort);
  if (p.limit !== undefined) q.set("limit", String(p.limit));
  if (p.offset !== undefined) q.set("offset", String(p.offset));
  return q.toString();
}

const json = { "Content-Type": "application/json" };

export const api = {
  session: () => request<{ authenticated: boolean }>("/api/v1/session"),
  login: (token: string) => request<{ ok: boolean; name: string }>("/api/v1/login", { method: "POST", headers: json, body: JSON.stringify({ token }) }),
  logout: () => request<{ ok: boolean }>("/api/v1/logout", { method: "POST", headers: json, body: "{}" }),
  overview: (staleDays: number) => request<Overview>(`/api/v1/overview?staleDays=${staleDays}`),
  hosts: (params: HostsParams) => request<{ hosts: HostSummary[]; total: number }>(`/api/v1/hosts?${hostsQuery(params)}`),
  hostsCSV: (params: HostsParams) => `/api/v1/hosts?${hostsQuery({ ...params, limit: undefined, offset: undefined })}&format=csv`,
  matrix: (staleDays: number) => request<Matrix>(`/api/v1/matrix?staleDays=${staleDays}`),
  host: (id: number, staleDays: number) => request<HostDetail>(`/api/v1/hosts/${id}?staleDays=${staleDays}`),
  scan: (id: number) => request<ScanDoc>(`/api/v1/scans/${id}`),
  diff: (oldId: number, newId: number) => request<Diff>(`/api/v1/diff?old=${oldId}&new=${newId}`),
};
