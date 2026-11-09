import type { Counts, Status } from "./types";

/** PASS ÷ (PASS + FAIL + ERROR + MANUAL), as the server computes it. */
export function score(c: Counts): number | null {
  const den = (c.PASS ?? 0) + (c.FAIL ?? 0) + (c.ERROR ?? 0) + (c.MANUAL ?? 0);
  return den === 0 ? null : (c.PASS ?? 0) / den;
}

export const percent = (v: number | null): string => (v === null ? "–" : `${Math.round(v * 100)}%`);

/** Seconds, minutes, hours or days since an RFC 3339 time, for a given "now". */
export function ago(iso: string, now: number, t: (key: string, n?: number) => string): string {
  const then = Date.parse(iso);
  if (!iso || Number.isNaN(then)) return "–";
  const s = Math.max(0, Math.round((now - then) / 1000));
  if (s < 60) return t("ago.now");
  if (s < 3600) return t("ago.minutes", Math.floor(s / 60));
  if (s < 86400) return t("ago.hours", Math.floor(s / 3600));
  return t("ago.days", Math.floor(s / 86400));
}

export function total(c: Counts): number {
  return Object.values(c).reduce((a, b) => a + (b ?? 0), 0);
}

export const SEVERITY_RANK: Record<string, number> = { high: 0, medium: 1, low: 2 };

/** Controls in the order a reader wants them: failing first, then by severity, then by ID. */
const STATUS_RANK: Record<Status, number> = { FAIL: 0, ERROR: 1, MANUAL: 2, WAIVED: 3, PASS: 4, NOT_APPLICABLE: 5 };
export function compareControls(a: { status: Status; severity: string; id: string }, b: { status: Status; severity: string; id: string }): number {
  return (
    STATUS_RANK[a.status] - STATUS_RANK[b.status] ||
    (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) ||
    a.id.localeCompare(b.id, undefined, { numeric: true })
  );
}

/** The title of a control in the language of the page; the English one when there is no translation. */
export function ctitle(c: { title: string; titleKo?: string }, lang: string): string {
  return lang === "ko" && c.titleKo ? c.titleKo : c.title;
}

/** A route of the hash-based router: "#/hosts/3" → ["hosts", "3"]. */
export function parseRoute(hash: string): string[] {
  return hash
    .replace(/^#\/?/, "")
    .split("?")[0]
    .split("/")
    .filter(Boolean)
    .map((part) => {
      try {
        return decodeURIComponent(part);
      } catch {
        return part; // a garbled escape in a link is a path that matches nothing, not a crash
      }
    });
}

/** The query of a route: "#/hosts?status=failing" → status=failing. Filters live in the address, so a link or the back button keeps them. */
export function hashParams(hash: string): URLSearchParams {
  const i = hash.indexOf("?");
  return new URLSearchParams(i < 0 ? "" : hash.slice(i + 1));
}

export type HostFilter = "" | "failing" | "stale";
export type HostSort = "name" | "score" | "last";
export interface HostsView {
  q: string;
  filter: HostFilter;
  sort: HostSort;
  label: string;
}
const HOST_FILTERS: readonly string[] = ["", "failing", "stale"];
const HOST_SORTS: readonly string[] = ["name", "score", "last"];

/** The host list's filters as an address says them; an unknown status or sort is the default, not an error. */
export function parseHostsView(hash: string): HostsView {
  const p = hashParams(hash);
  const status = p.get("status") ?? "";
  const sort = p.get("sort") ?? "name";
  return {
    q: p.get("q") ?? "",
    filter: HOST_FILTERS.includes(status) ? (status as HostFilter) : "",
    sort: HOST_SORTS.includes(sort) ? (sort as HostSort) : "name",
    label: p.get("label") ?? "",
  };
}

/** The address of the host list with these filters; the defaults are left out. */
export function hostsAddress(v: HostsView): string {
  const p = new URLSearchParams();
  if (v.q) p.set("q", v.q);
  if (v.filter) p.set("status", v.filter);
  if (v.sort !== "name") p.set("sort", v.sort);
  if (v.label) p.set("label", v.label);
  const qs = p.toString(); // not p.size: older browsers have no such property
  return "#/hosts" + (qs ? "?" + qs : "");
}

/** The list itself ("#/hosts", with or without a query), not a detail page that shows the same component for a bad id. */
export function isList(hash: string, list: "hosts" | "controls"): boolean {
  const r = parseRoute(hash);
  return r.length === 1 && r[0] === list;
}

export interface ControlsView {
  q: string;
  failing: boolean;
}

/** The control list's filters as an address says them. */
export function parseControlsView(hash: string): ControlsView {
  const p = hashParams(hash);
  return { q: p.get("q") ?? "", failing: p.get("status") === "failing" };
}

/** The address of the control list with these filters; the defaults are left out. */
export function controlsAddress(v: ControlsView): string {
  const p = new URLSearchParams();
  if (v.q) p.set("q", v.q);
  if (v.failing) p.set("status", "failing");
  const qs = p.toString();
  return "#/controls" + (qs ? "?" + qs : "");
}

/** A stable hue (0-359) for a name, for the avatars. */
export function hue(name: string): number {
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.codePointAt(0)!) % 360;
  return h;
}
