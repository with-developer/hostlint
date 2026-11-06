import type { ReactNode } from "react";
import { useI18n } from "../lib/i18n";
import { percent, total } from "../lib/format";
import { STATUSES, type Counts, type Status } from "../lib/types";
import type { Async } from "../lib/hooks";

export function StatusBadge({ status }: { status: Status | "" }) {
  const { t } = useI18n();
  if (!status) return <span className="badge none">–</span>;
  return <span className={`badge s-${status}`}>{t(`status.${status}`)}</span>;
}

export function Severity({ value }: { value: string }) {
  const { t } = useI18n();
  return <span className={`sev sev-${value}`}>{t(`severity.${value}`)}</span>;
}

/** The counts of a fleet or a host as one stacked bar and a legend. Hidden statuses are 0. */
export function StatusBar({ counts, legend = false }: { counts: Counts; legend?: boolean }) {
  const { t } = useI18n();
  const sum = total(counts);
  return (
    <div className="statusbar-wrap">
      <div className="statusbar" role="img" aria-label={STATUSES.map((s) => `${t(`status.${s}`)} ${counts[s] ?? 0}`).join(", ")}>
        {STATUSES.filter((s) => (counts[s] ?? 0) > 0).map((s) => (
          <span key={s} className={`seg s-${s}`} style={{ width: `${(100 * (counts[s] ?? 0)) / sum}%` }} title={`${t(`status.${s}`)}: ${counts[s]}`} />
        ))}
      </div>
      {legend && (
        <ul className="legend">
          {STATUSES.map((s) => (
            <li key={s}>
              <span className={`dot s-${s}`} />
              {t(`status.${s}`)} <strong>{counts[s] ?? 0}</strong>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** A ring with the pass rate in the middle. */
export function ScoreRing({ score, size = 96 }: { score: number | null; size?: number }) {
  const r = 40;
  const c = 2 * Math.PI * r;
  const v = score ?? 0;
  const tone = score === null ? "none" : v >= 0.9 ? "good" : v >= 0.6 ? "warn" : "bad";
  return (
    <svg className={`ring ring-${tone}`} width={size} height={size} viewBox="0 0 100 100" role="img" aria-label={percent(score)}>
      <circle className="ring-bg" cx="50" cy="50" r={r} />
      <circle className="ring-fg" cx="50" cy="50" r={r} strokeDasharray={`${c * v} ${c}`} transform="rotate(-90 50 50)" />
      <text x="50" y="56" textAnchor="middle" className="ring-text">
        {percent(score)}
      </text>
    </svg>
  );
}

/** A line of the pass rate over scans, oldest to newest. */
export function Sparkline({ points }: { points: (number | null)[] }) {
  const w = 240;
  const h = 48;
  const vals = points.map((p, i) => ({ p, i })).filter((x): x is { p: number; i: number } => x.p !== null);
  if (vals.length < 2) return null;
  const x = (i: number) => (points.length === 1 ? w / 2 : (i / (points.length - 1)) * (w - 8) + 4);
  const y = (p: number) => h - 4 - p * (h - 8);
  const d = vals.map((v, k) => `${k === 0 ? "M" : "L"}${x(v.i).toFixed(1)} ${y(v.p).toFixed(1)}`).join(" ");
  const last = vals[vals.length - 1];
  return (
    <svg className="spark" width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={vals.map((v) => percent(v.p)).join(" → ")}>
      <path d={d} />
      <circle cx={x(last.i)} cy={y(last.p)} r="3" />
    </svg>
  );
}

export function Tile({ value, label, tone, help }: { value: ReactNode; label: string; tone?: "bad" | "warn" | "good"; help?: string }) {
  return (
    <div className={`tile ${tone ?? ""}`} title={help}>
      <div className="tile-value">{value}</div>
      <div className="tile-label">{label}</div>
    </div>
  );
}

/** Loading, error and empty states around an async result. */
export function Await<T>({ state, children }: { state: Async<T>; children: (data: T) => ReactNode }) {
  const { t } = useI18n();
  if (state.error) {
    return (
      <div className="notice error" role="alert">
        <p>
          {t("error")}: {state.error.message}
        </p>
        <button onClick={state.reload}>{t("retry")}</button>
      </div>
    );
  }
  if (!state.data) return <p className="muted">{t("loading")}</p>;
  return <>{children(state.data)}</>;
}
