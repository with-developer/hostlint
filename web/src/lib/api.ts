import type { Diff, HostDetail, HostSummary, Overview, ScanDoc } from "./types";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
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
  if (!res.ok) {
    const message = body && typeof body === "object" && "error" in body ? String((body as { error: unknown }).error) : res.statusText;
    throw new ApiError(res.status, message);
  }
  return body as T;
}

const json = { "Content-Type": "application/json" };

export const api = {
  session: () => request<{ authenticated: boolean }>("/api/v1/session"),
  login: (token: string) => request<{ ok: boolean; name: string }>("/api/v1/login", { method: "POST", headers: json, body: JSON.stringify({ token }) }),
  logout: () => request<{ ok: boolean }>("/api/v1/logout", { method: "POST", headers: json, body: "{}" }),
  overview: (staleDays: number) => request<Overview>(`/api/v1/overview?staleDays=${staleDays}`),
  hosts: (params: { q?: string; status?: string; staleDays: number }) => {
    const q = new URLSearchParams({ limit: "500", staleDays: String(params.staleDays) });
    if (params.q) q.set("q", params.q);
    if (params.status) q.set("status", params.status);
    return request<{ hosts: HostSummary[]; total: number }>(`/api/v1/hosts?${q}`);
  },
  host: (id: number, staleDays: number) => request<HostDetail>(`/api/v1/hosts/${id}?staleDays=${staleDays}`),
  scan: (id: number) => request<ScanDoc>(`/api/v1/scans/${id}`),
  diff: (oldId: number, newId: number) => request<Diff>(`/api/v1/diff?old=${oldId}&new=${newId}`),
};
