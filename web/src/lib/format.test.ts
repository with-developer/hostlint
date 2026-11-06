import { describe, expect, it } from "vitest";
import { ago, compareControls, hue, parseRoute, percent, score, total } from "./format";

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

describe("parseRoute and total", () => {
  it("splits and decodes", () => {
    expect(parseRoute("#/hosts/3")).toEqual(["hosts", "3"]);
    expect(parseRoute("#/")).toEqual([]);
    expect(parseRoute("")).toEqual([]);
    expect(parseRoute("#/a%20b")).toEqual(["a b"]);
    expect(total({ PASS: 2, FAIL: 3 })).toBe(5);
  });
  it("does not throw on a garbled escape", () => {
    expect(parseRoute("#/hosts/%E0%A4%A")).toEqual(["hosts", "%E0%A4%A"]);
    expect(parseRoute("#/%")).toEqual(["%"]);
  });
  it("gives a name a stable hue", () => {
    expect(hue("web-01")).toBe(hue("web-01"));
    expect(hue("web-01")).toBeGreaterThanOrEqual(0);
    expect(hue("web-01")).toBeLessThan(360);
  });
});
