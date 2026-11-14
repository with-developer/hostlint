import { describe, expect, it } from "vitest";
import { demoKey, filterHosts, shiftTimes } from "./demoApi";
import type { HostSummary } from "./types";

const host = (name: string, over: Partial<HostSummary> = {}): HostSummary =>
  ({ id: 1, name, hostId: "", lastScanAt: "2026-11-01T00:00:00Z", stale: false, score: 0.5, counts: {}, labels: {}, ...over }) as unknown as HostSummary;

describe("demo api", () => {
  it("keys a request by its path and sorted query, without the profile and the stale days", () => {
    expect(demoKey("/api/v1/overview?staleDays=7&profile=kisa-2026")).toBe("/api/v1/overview");
    expect(demoKey("/api/v1/hosts?limit=500&kind=host&staleDays=7")).toBe("/api/v1/hosts?kind=host&limit=500");
    expect(demoKey("/api/v1/controls/kisa-2026/U-01?staleDays=7")).toBe("/api/v1/controls/kisa-2026/U-01");
  });
  const list = [
    host("web-02", { score: 0.9, lastScanAt: "2026-11-03T00:00:00Z", labels: { env: "prod" } }),
    host("api-01", { score: 0.2, stale: true, counts: { FAIL: 3 }, lastScanAt: "2026-11-01T00:00:00Z", labels: { env: "dev" } }),
    host("web-01", { score: null as unknown as number, counts: { FAIL: 1 }, lastScanAt: "2026-11-02T00:00:00Z", labels: { env: "prod" } }),
  ];
  it("filters, sorts and pages the host list like the server", () => {
    const names = (q: string) => filterHosts(list, new URLSearchParams(q)).hosts.map((h) => h.name);
    expect(names("")).toEqual(["api-01", "web-01", "web-02"]);
    expect(names("q=WEB")).toEqual(["web-01", "web-02"]);
    expect(names("status=failing")).toEqual(["api-01", "web-01"]);
    expect(names("status=stale")).toEqual(["api-01"]);
    expect(names("label=env%3Dprod")).toEqual(["web-01", "web-02"]);
    expect(names("sort=score")).toEqual(["api-01", "web-02", "web-01"]); // an undecided host last
    expect(names("sort=recent")).toEqual(["web-02", "web-01", "api-01"]);
    expect(names("sort=last")).toEqual(["api-01", "web-01", "web-02"]);
    const page = filterHosts(list, new URLSearchParams("limit=1&offset=1"));
    expect(page.total).toBe(3);
    expect(page.hosts.map((h) => h.name)).toEqual(["web-01"]);
    expect(filterHosts(list, new URLSearchParams("limit=-5")).hosts).toHaveLength(3); // a limit that is not above zero is 100, as on the server
  });
  it("moves timestamps forward and leaves everything else alone", () => {
    const day = 24 * 3600 * 1000;
    const out = shiftTimes(
      { at: "2026-11-01T00:00:00Z", receivedAt: "2026-11-01T10:00:00.123456789Z", name: "2026-11-01", n: 3, list: [{ at: "2026-11-02T00:00:00Z" }], flag: true, evidence: { text: "2026-11-01T00:00:00Z" } },
      2 * day,
    );
    expect(out.at).toBe("2026-11-03T00:00:00.000Z");
    expect(out.receivedAt).toBe("2026-11-03T10:00:00.123Z");
    expect(out.name).toBe("2026-11-01");
    expect(out.n).toBe(3);
    expect(out.list[0].at).toBe("2026-11-04T00:00:00.000Z");
    expect(out.flag).toBe(true);
    expect(out.evidence.text).toBe("2026-11-01T00:00:00Z"); // a value a scan observed is not a time of the API
  });
});
