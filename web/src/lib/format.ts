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

/** A route of the hash-based router: "#/hosts/3" → ["hosts", "3"]. */
export function parseRoute(hash: string): string[] {
  return hash.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
}
