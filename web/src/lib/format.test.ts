import { describe, expect, it } from "vitest";
import { ago, compareControls, ctitle, hashParams, controlsAddress, hostsAddress, hue, isList, parseControlsView, parseHostsView, parseRoute, percent, score, total } from "./format";

const t = (key: string, n?: number) => `${key}:${n ?? ""}`;

describe("score", () => {
  it("is PASS over the decided results, counting MANUAL and ERROR against it", () => {
    expect(score({ PASS: 3, FAIL: 1, MANUAL: 1, ERROR: 1, WAIVED: 9, NOT_APPLICABLE: 9 })).toBeCloseTo(0.5);
  });
  it("is null when nothing was decided", () => {
    expect(score({ NOT_APPLICABLE: 4 })).toBeNull();
    expect(percent(null)).toBe("–");
    expect(percent(0.876)).toBe("88%");
  });
});

describe("ago", () => {
  const now = Date.parse("2026-11-06T12:00:00Z");
  it("picks the unit", () => {
    expect(ago("2026-11-06T11:59:30Z", now, t)).toBe("ago.now:");
    expect(ago("2026-11-06T11:15:00Z", now, t)).toBe("ago.minutes:45");
    expect(ago("2026-11-06T07:00:00Z", now, t)).toBe("ago.hours:5");
    expect(ago("2026-11-01T12:00:00Z", now, t)).toBe("ago.days:5");
    expect(ago("", now, t)).toBe("–");
    expect(ago("nonsense", now, t)).toBe("–");
  });
});

describe("compareControls", () => {
  it("puts failures first, then severity, then the number in the ID", () => {
    const rows = [
      { status: "PASS", severity: "high", id: "U-02" },
      { status: "FAIL", severity: "low", id: "U-10" },
      { status: "FAIL", severity: "high", id: "U-09" },
      { status: "FAIL", severity: "high", id: "U-2" },
    ] as const;
    expect([...rows].sort(compareControls).map((r) => r.id)).toEqual(["U-2", "U-09", "U-10", "U-02"]);
  });
});

describe("ctitle", () => {
  it("uses the Korean title for Korean and falls back to English", () => {
    expect(ctitle({ title: "Password policy", titleKo: "비밀번호 정책" }, "ko")).toBe("비밀번호 정책");
    expect(ctitle({ title: "Password policy", titleKo: "비밀번호 정책" }, "en")).toBe("Password policy");
    expect(ctitle({ title: "Password policy" }, "ko")).toBe("Password policy");
  });
});

describe("parseRoute and total", () => {
  it("splits and decodes", () => {
    expect(parseRoute("#/hosts/3")).toEqual(["hosts", "3"]);
    expect(parseRoute("#/hosts?status=failing&q=a/b")).toEqual(["hosts"]);
    expect(parseRoute("#/")).toEqual([]);
    expect(parseRoute("")).toEqual([]);
    expect(parseRoute("#/a%20b")).toEqual(["a b"]);
    expect(total({ PASS: 2, FAIL: 3 })).toBe(5);
  });
  it("does not throw on a garbled escape", () => {
    expect(parseRoute("#/hosts/%E0%A4%A")).toEqual(["hosts", "%E0%A4%A"]);
    expect(parseRoute("#/%")).toEqual(["%"]);
  });
  it("reads the query of a route", () => {
    const p = hashParams("#/hosts?status=failing&label=env%3Dprod&q=web%2001");
    expect(p.get("status")).toBe("failing");
    expect(p.get("label")).toBe("env=prod");
    expect(p.get("q")).toBe("web 01");
    expect(hashParams("#/hosts").get("status")).toBeNull();
    expect(hashParams("").toString()).toBe("");
  });
  it("gives a name a stable hue", () => {
    expect(hue("web-01")).toBe(hue("web-01"));
    expect(hue("web-01")).toBeGreaterThanOrEqual(0);
    expect(hue("web-01")).toBeLessThan(360);
  });
});

describe("the address of the host list", () => {
  it("leaves the defaults out and round-trips the filters", () => {
    expect(hostsAddress({ q: "", filter: "", sort: "name", label: "" })).toBe("#/hosts");
    const v = { q: "web 01+a", filter: "failing" as const, sort: "score" as const, label: "env=prod" };
    const a = hostsAddress(v);
    expect(a).toBe("#/hosts?q=web+01%2Ba&status=failing&sort=score&label=env%3Dprod");
    expect(parseHostsView(a)).toEqual(v);
  });
  it("takes an unknown status or sort as the default", () => {
    expect(parseHostsView("#/hosts?status=bogus&sort=nope")).toEqual({ q: "", filter: "", sort: "name", label: "" });
    expect(parseHostsView("#/hosts")).toEqual({ q: "", filter: "", sort: "name", label: "" });
  });
  it("tells the list from a host page", () => {
    expect(isList("#/hosts", "hosts")).toBe(true);
    expect(isList("#/hosts?status=stale", "hosts")).toBe(true);
    expect(isList("#/hosts/3", "hosts")).toBe(false);
    expect(isList("#/hosts/abc", "hosts")).toBe(false);
    expect(isList("#/images", "hosts")).toBe(false);
  });
});

describe("the address of the control list", () => {
  it("leaves the defaults out and round-trips the filters", () => {
    expect(controlsAddress({ q: "", failing: false })).toBe("#/controls");
    expect(controlsAddress({ q: "ssh 22", failing: true })).toBe("#/controls?q=ssh+22&status=failing");
    expect(parseControlsView("#/controls?q=ssh+22&status=failing")).toEqual({ q: "ssh 22", failing: true });
    expect(parseControlsView("#/controls?status=bogus")).toEqual({ q: "", failing: false });
  });
  it("tells the list from a control page", () => {
    expect(isList("#/controls?q=a", "controls")).toBe(true);
    expect(isList("#/controls/kisa-2026/U-01", "controls")).toBe(false);
  });
});
