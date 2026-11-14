// The live demo (site/demo): the dashboard without a server. `scripts/record-demo.mjs` saved what the dashboard asks of
// `vmsctl server demo` in demo-data.json; this answers the same requests from it. The fleet is made up. Lists are filtered and
// sorted here the way the server does it, since a search box or a sort button asks for a list nobody recorded.
import { demoKey } from "./demoKey.js";
import type { HostSummary } from "./types";

export class DemoError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

type Data = Record<string, unknown>;
let loading: Promise<Data> | null = null;

/** The fields of the API that hold a moment; other strings (a scan's evidence, a name) are never moved. */
const timeFields = new Set(["receivedAt", "lastScanAt", "at", "startedAt", "finishedAt", "scanned", "createdAt"]);
const timestamp = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/;

/** Moves every timestamp of the recorded answers forward by ms, so that the fleet looks as fresh as it did when it was recorded. */
export function shiftTimes<T>(value: T, ms: number, field = ""): T {
  if (typeof value === "string") {
    return (timeFields.has(field) && timestamp.test(value) ? new Date(Date.parse(value) + ms).toISOString() : value) as T;
  }
  if (Array.isArray(value)) return value.map((v) => shiftTimes(v, ms, field)) as T;
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, shiftTimes(v, ms, k)])) as T;
  }
  return value;
}

function load(): Promise<Data> {
  // "no-cache": the browser asks again whether the file changed, so a new deployment is not read with an old copy.
  loading ??= fetch(new URL("demo-data.json", document.baseURI).toString(), { cache: "no-cache" })
    .then(async (r) => {
      if (!r.ok) throw new DemoError(r.status, "the demo data is missing");
      const data = (await r.json()) as Data;
      const recorded = Date.parse(String(data.__recordedAt ?? ""));
      return Number.isNaN(recorded) ? data : shiftTimes(data, Date.now() - recorded);
    })
    .catch((e) => {
      loading = null; // a failed load is tried again, not remembered
      throw e;
    });
  return loading;
}

export { demoKey };

/** The host list as the server answers it: the recorded list of the kind, filtered, sorted and paged. */
export function filterHosts(list: HostSummary[], params: URLSearchParams): { hosts: HostSummary[]; total: number } {
  const q = (params.get("q") ?? "").trim().toLowerCase();
  const status = params.get("status") ?? "";
  const label = params.get("label") ?? "";
  const eq = label.indexOf("=");
  let out = list.filter((h) => {
    if (q && !h.name.toLowerCase().includes(q)) return false;
    if (eq >= 0 && h.labels?.[label.slice(0, eq)] !== label.slice(eq + 1)) return false;
    if (status === "failing" && !(h.counts?.FAIL ?? 0)) return false;
    if (status === "stale" && !h.stale) return false;
    return true;
  });
  const sort = params.get("sort") ?? "";
  const byName = (a: HostSummary, b: HostSummary) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  out = [...out].sort(byName);
  if (sort === "score") out.sort((a, b) => (a.score ?? 2) - (b.score ?? 2));
  else if (sort === "last") out.sort((a, b) => (a.lastScanAt < b.lastScanAt ? -1 : a.lastScanAt > b.lastScanAt ? 1 : 0));
  else if (sort === "recent") out.sort((a, b) => (a.lastScanAt < b.lastScanAt ? 1 : a.lastScanAt > b.lastScanAt ? -1 : 0));
  const total = out.length;
  const offset = Math.max(0, Number(params.get("offset") ?? 0) || 0);
  const asked = Number(params.get("limit") ?? 0);
  const limit = asked > 0 ? Math.min(500, asked) : 100; // like the server: no limit, or none above zero, is 100
  return { hosts: out.slice(offset, offset + limit), total };
}

export async function demoRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const url = new URL(path, "http://demo.invalid");
  const method = init?.method ?? "GET";
  if (url.pathname === "/api/v1/session") return { authenticated: true, canScan: false } as T;
  if (url.pathname === "/api/v1/login" || url.pathname === "/api/v1/logout") return { ok: true, name: "demo" } as T;
  if (method !== "GET") throw new DemoError(403, "this is a demo with made-up data: nothing can be changed here");
  const data = await load();
  if (url.pathname === "/api/v1/hosts") {
    const kind = url.searchParams.get("kind") === "image" ? "image" : "host";
    const recorded = data[`/api/v1/hosts?kind=${kind}&limit=500`] as { hosts: HostSummary[] } | undefined;
    return filterHosts(recorded?.hosts ?? [], url.searchParams) as T;
  }
  const hit = data[demoKey(path)];
  if (hit !== undefined) return hit as T;
  if (/^\/api\/v1\/hosts\/\d+\/agent$/.test(url.pathname)) return { online: false, profiles: [] } as T;
  throw new DemoError(404, "this part is not in the demo: install vmsctl and run `vmsctl server demo` to see all of it");
}
