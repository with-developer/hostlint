import { useRef, useState } from "react";
import { useI18n } from "../lib/i18n";
import { percent } from "../lib/format";

/** One point of a trend: when, the pass rate (null: nothing was decided), and what to say about it. */
export interface ChartPoint {
  at: string;
  score: number | null;
  detail: string;
}

const W = 800;
const H = 220;
const PAD = { l: 44, r: 16, t: 14, b: 28 };

/**
 * The path of a line over points where some have no value: a gap ends one segment and starts the next, so a day with
 * no hosts is a break in the line, not a drop to zero.
 */
export function segments(scores: (number | null)[], x: (i: number) => number, y: (v: number) => number): string[] {
  const out: string[] = [];
  let cur = "";
  scores.forEach((v, i) => {
    if (v === null) {
      if (cur) out.push(cur);
      cur = "";
      return;
    }
    cur += `${cur ? "L" : "M"}${x(i).toFixed(1)} ${y(v).toFixed(1)}`;
  });
  if (cur) out.push(cur);
  return out;
}

/**
 * The vertical axis: the data with some room, on round values (ticks every 5, 10 or 25 points), and at least three
 * steps tall, so a change of a few points does not look like a collapse and a flat line does not look like a cliff.
 */
export function yAxis(scores: (number | null)[]): { lo: number; hi: number; step: number } {
  const vals = scores.filter((v): v is number => v !== null);
  if (vals.length === 0) return { lo: 0, hi: 1, step: 0.25 };
  const rawLo = Math.min(...vals) - 0.03;
  const rawHi = Math.max(...vals) + 0.03;
  const span = rawHi - rawLo;
  const step = span <= 0.25 ? 0.05 : span <= 0.6 ? 0.1 : 0.25;
  // work in whole steps: no floating point drift in the ticks
  let lo = Math.max(0, Math.floor(rawLo / step + 1e-9));
  let hi = Math.min(Math.round(1 / step), Math.ceil(rawHi / step - 1e-9));
  while (hi - lo < 3) {
    if (lo > 0) lo--;
    if (hi - lo < 3 && hi < Math.round(1 / step)) hi++;
  }
  return { lo: lo * step, hi: hi * step, step };
}

/** The area under a run of points, closed down to the axis. */
function area(line: string, baseline: number): string {
  const nums = line.match(/-?\d+(\.\d+)?/g)?.map(Number) ?? [];
  if (nums.length < 4) return "";
  const firstX = nums[0];
  const lastX = nums[nums.length - 2];
  return `${line} L${lastX} ${baseline} L${firstX} ${baseline} Z`;
}

/** The pass rate over time, with a guide and a tooltip under the pointer. */
export function TrendChart({ points, label }: { points: ChartPoint[]; label: string }) {
  const { lang } = useI18n();
  const [hover, setHover] = useState<number | null>(null);
  const box = useRef<SVGSVGElement>(null);
  const n = points.length;
  const x = (i: number) => PAD.l + (n <= 1 ? 0.5 : i / (n - 1)) * (W - PAD.l - PAD.r);
  const scores = points.map((p) => p.score);
  const { lo, hi, step } = yAxis(scores);
  const y = (v: number) => PAD.t + (1 - (v - lo) / (hi - lo)) * (H - PAD.t - PAD.b);
  const lines = segments(scores, x, y);
  const baseline = H - PAD.b;
  const date = (iso: string) => new Date(iso).toLocaleDateString(lang === "ko" ? "ko-KR" : "en-US", { month: "short", day: "numeric" });
  const ticks = Array.from({ length: Math.round((hi - lo) / step) + 1 }, (_, k) => lo + k * step);
  const labelAt = n <= 1 ? [0] : n === 2 ? [0, 1] : [0, Math.floor((n - 1) / 2), n - 1];

  const move = (e: React.MouseEvent<SVGSVGElement>) => {
    const r = box.current?.getBoundingClientRect();
    if (!r || r.width === 0 || n === 0) return;
    const px = ((e.clientX - r.left) / r.width) * W;
    const i = Math.round(((px - PAD.l) / (W - PAD.l - PAD.r)) * (n - 1));
    setHover(Math.max(0, Math.min(n - 1, i)));
  };
  const h = hover === null ? null : points[hover];
  const tipLeft = hover === null ? 0 : (x(hover) / W) * 100;

  return (
    <div className="trend">
      <svg ref={box} className="trend-svg" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={label} onMouseMove={move} onMouseLeave={() => setHover(null)}>
        {ticks.map((t) => (
          <g key={t}>
            <line className="trend-grid" x1={PAD.l} x2={W - PAD.r} y1={y(t)} y2={y(t)} />
            <text className="trend-axis" x={PAD.l - 8} y={y(t) + 4} textAnchor="end">
              {Math.round(t * 100)}%
            </text>
          </g>
        ))}
        {labelAt.map((i) => (
          <text key={i} className="trend-axis" x={x(i)} y={H - 8} textAnchor={i === 0 ? "start" : i === n - 1 ? "end" : "middle"}>
            {date(points[i].at)}
          </text>
        ))}
        {lines.map((l, k) => (
          <g key={k}>
            <path className="trend-area" d={area(l, baseline)} />
            <path className="trend-line" d={l} />
          </g>
        ))}
        {/* a run of one point shows as a dot */}
        {scores.map((v, i) =>
          v !== null && scores[i - 1] == null && scores[i + 1] == null ? <circle key={i} className="trend-dot" cx={x(i)} cy={y(v)} r="3.5" /> : null,
        )}
        {hover !== null && h && (
          <g>
            <line className="trend-guide" x1={x(hover)} x2={x(hover)} y1={PAD.t} y2={baseline} />
            {h.score !== null && <circle className="trend-dot" cx={x(hover)} cy={y(h.score)} r="4.5" />}
          </g>
        )}
      </svg>
      {h && (
        <div className="trend-tip" style={{ left: `${Math.min(86, Math.max(14, tipLeft))}%` }} role="status">
          <strong>{h.score === null ? "–" : percent(h.score)}</strong> <span className="muted">{date(h.at)}</span>
          <div className="muted small">{h.detail}</div>
        </div>
      )}
    </div>
  );
}

/** A host's pass rate over its latest scans, small enough for a table row; the colour says which way it went. */
export function MiniSpark({ values }: { values: number[] }) {
  if (values.length < 2) return null;
  const w = 76;
  const h = 22;
  // At least ten points of pass rate fill the height: a few points of change must not look like a collapse.
  const mid = (Math.min(...values) + Math.max(...values)) / 2;
  const span = Math.max(Math.max(...values) - Math.min(...values), 0.1);
  const lo = mid - span / 2;
  const x = (i: number) => 2 + (i / (values.length - 1)) * (w - 4);
  const y = (v: number) => h - 3 - ((v - lo) / span) * (h - 6);
  const d = values.map((v, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)} ${y(v).toFixed(1)}`).join(" ");
  const delta = values[values.length - 1] - values[0];
  const dir = Math.abs(delta) < 0.005 ? "flat" : delta > 0 ? "up" : "down";
  return (
    <svg className={`mini mini-${dir}`} width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={values.map(percent).join(" → ")}>
      <path d={d} />
      <circle cx={x(values.length - 1)} cy={y(values[values.length - 1])} r="2.2" />
    </svg>
  );
}
