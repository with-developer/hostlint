import { describe, expect, it } from "vitest";
import { segments } from "./charts";

describe("segments", () => {
  const x = (i: number) => i * 10;
  const y = (v: number) => 100 - v * 100;
  it("draws one line over points that all have a value", () => {
    expect(segments([0.5, 0.6, 0.7], x, y)).toEqual(["M0.0 50.0L10.0 40.0L20.0 30.0"]);
  });
  it("breaks the line at a day with nothing decided, instead of dropping to zero", () => {
    const got = segments([null, 0.5, 0.6, null, 0.8], x, y);
    expect(got).toEqual(["M10.0 50.0L20.0 40.0", "M40.0 20.0"]);
  });
  it("is empty when nothing was decided", () => {
    expect(segments([null, null], x, y)).toEqual([]);
    expect(segments([], x, y)).toEqual([]);
  });
});

import { yAxis } from "./charts";

describe("yAxis", () => {
  it("is 0-100 % when there is no data", () => {
    expect(yAxis([null, null])).toEqual({ lo: 0, hi: 1, step: 0.25 });
  });
  it("follows the data on round ticks, with room", () => {
    const a = yAxis([0.52, 0.55, 0.54]);
    expect(a.step).toBe(0.05);
    expect(a.lo).toBeCloseTo(0.45);
    expect(a.hi).toBeCloseTo(0.6);
  });
  it("ticks are whole steps, at least three steps tall, inside 0-100 %", () => {
    for (const data of [[0.5, 0.5], [0.99, 1], [0, 0.01], [0.3], [0.1, 0.9], [0.47, 0.63]]) {
      const { lo, hi, step } = yAxis(data);
      const steps = (hi - lo) / step;
      expect(Math.abs(steps - Math.round(steps))).toBeLessThan(1e-9);
      expect(Math.round(steps)).toBeGreaterThanOrEqual(3);
      expect(lo).toBeGreaterThanOrEqual(0);
      expect(hi).toBeLessThanOrEqual(1 + 1e-9);
      for (const v of data) {
        expect(v).toBeGreaterThanOrEqual(lo - 1e-9);
        expect(v).toBeLessThanOrEqual(hi + 1e-9);
      }
    }
  });
});
