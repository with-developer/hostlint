import type { ReactNode } from "react";
import { useI18n } from "../lib/i18n";
import { IconKey } from "./icons";
import { hue, percent, total } from "../lib/format";
import { STATUSES, type Counts, type Status } from "../lib/types";
import type { Async } from "../lib/hooks";

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="pagehead">
      <div>
        <h1>{title}</h1>
        {subtitle && <p className="muted">{subtitle}</p>}
      </div>
      {actions && <div className="pagehead-actions">{actions}</div>}
    </div>
  );
}

export function StatusBadge({ status }: { status: Status | "" }) {
  const { t } = useI18n();
  if (!status) return <span className="badge none">–</span>;
  return <span className={`badge s-${status}`}>{t(`status.${status}`)}</span>;
}

/** The host signs its results: shown with the key it registered. */
export function SignedBadge({ fingerprint }: { fingerprint?: string }) {
  const { t } = useI18n();
  return (
    <span className="signed" title={t("signed.help", { key: fingerprint ?? "" })}>
      <IconKey /> {t("signed")}
    </span>
  );
}

export function Severity({ value }: { value: string }) {
  const { t } = useI18n();
  return (
    <span className={`sev sev-${value}`}>
      <span className="sev-dot" />
      {t(`severity.${value}`)}
    </span>
  );
}

/** A round avatar with the host's initial, in a colour that is the same every time. */
export function Avatar({ name, size = 32 }: { name: string; size?: number }) {
  return (
    <span className="avatar" style={{ width: size, height: size, background: `hsl(${hue(name)} 55% 46%)`, fontSize: size * 0.42 }} aria-hidden="true">
      {name.trim().charAt(0).toUpperCase() || "?"}
    </span>
  );
}

/** The counts as one stacked bar, with the legend when asked for. */
export function StatusBar({ counts, legend = false, thin = false }: { counts: Counts; legend?: boolean; thin?: boolean }) {
  const { t } = useI18n();
  const sum = total(counts);
  return (
    <div className="statusbar-wrap">
      <div className={`statusbar ${thin ? "thin" : ""}`} role="img" aria-label={STATUSES.map((s) => `${t(`status.${s}`)} ${counts[s] ?? 0}`).join(", ")}>
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

function tone(score: number | null): "none" | "good" | "warn" | "bad" {
  return score === null ? "none" : score >= 0.9 ? "good" : score >= 0.6 ? "warn" : "bad";
}

/** The pass rate as a pill: green, amber or red. */
export function ScorePill({ score }: { score: number | null }) {
  return <span className={`pill pill-${tone(score)}`}>{percent(score)}</span>;
}

/** A half-circle gauge with the pass rate. */
export function Gauge({ score, label }: { score: number | null; label: string }) {
  const r = 70;
  const arc = Math.PI * r;
  const v = score ?? 0;
  return (
    <div className={`gauge gauge-${tone(score)}`}>
      <svg viewBox="0 0 180 104" role="img" aria-label={`${label}: ${percent(score)}`}>
        <path className="gauge-bg" d="M20 90 A70 70 0 0 1 160 90" />
        <path className="gauge-fg" d="M20 90 A70 70 0 0 1 160 90" strokeDasharray={`${arc * v} ${arc}`} />
        <text x="90" y="82" textAnchor="middle" className="gauge-value">
          {percent(score)}
        </text>
      </svg>
      <div className="gauge-label">{label}</div>
    </div>
  );
}

/** A ring chart of the counts with the number of controls in the middle. */
export function Donut({ counts, label }: { counts: Counts; label: string }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const sum = total(counts);
  let offset = 0;
  return (
    <svg className="donut" viewBox="0 0 140 140" role="img" aria-label={label}>
      <circle className="donut-bg" cx="70" cy="70" r={r} />
      {STATUSES.filter((s) => (counts[s] ?? 0) > 0).map((s) => {
        const len = (c * (counts[s] ?? 0)) / sum;
        const el = <circle key={s} className={`donut-seg s-${s}`} cx="70" cy="70" r={r} strokeDasharray={`${Math.max(len - 1.5, 0)} ${c}`} strokeDashoffset={-offset} transform="rotate(-90 70 70)" />;
        offset += len;
        return el;
      })}
      <text x="70" y="68" textAnchor="middle" className="donut-total">
        {sum}
      </text>
      <text x="70" y="86" textAnchor="middle" className="donut-caption">
        {label}
      </text>
    </svg>
  );
}

/** The pass rate over scans, oldest to newest. */
export function Sparkline({ points }: { points: (number | null)[] }) {
  const w = 260;
  const h = 56;
  const vals = points.map((p, i) => ({ p, i })).filter((x): x is { p: number; i: number } => x.p !== null);
  if (vals.length < 3) return null; // two points are a line, not a trend
  // The scale follows the data, so a change of a few points shows.
  const lo = Math.max(0, Math.min(...vals.map((v) => v.p)) - 0.05);
  const hi = Math.min(1, Math.max(...vals.map((v) => v.p)) + 0.05);
  const x = (i: number) => (i / (points.length - 1)) * (w - 12) + 6;
  const y = (p: number) => h - 8 - ((p - lo) / (hi - lo || 1)) * (h - 16);
  const line = vals.map((v, k) => `${k === 0 ? "M" : "L"}${x(v.i).toFixed(1)} ${y(v.p).toFixed(1)}`).join(" ");
  const first = vals[0];
  const last = vals[vals.length - 1];
  const area = `${line} L${x(last.i).toFixed(1)} ${h - 4} L${x(first.i).toFixed(1)} ${h - 4} Z`;
  return (
    <svg className="spark" width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={vals.map((v) => percent(v.p)).join(" → ")}>
      <path className="spark-area" d={area} />
      <path className="spark-line" d={line} />
      <circle cx={x(last.i)} cy={y(last.p)} r="3.5" />
    </svg>
  );
}

export function Stat({ icon, value, label, tone, help }: { icon: ReactNode; value: ReactNode; label: string; tone?: "bad" | "warn" | "good"; help?: string }) {
  return (
    <div className={`stat ${tone ?? ""}`} title={help}>
      <span className="stat-icon">{icon}</span>
      <div>
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}

export function Skeleton({ height = 16, width = "100%" }: { height?: number; width?: number | string }) {
  return <div className="skeleton" style={{ height, width }} />;
}

export function PageSkeleton() {
  return (
    <div className="stack" aria-busy="true">
      <div className="grid4">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="card">
            <Skeleton height={28} width="40%" />
            <Skeleton height={12} width="70%" />
          </div>
        ))}
      </div>
      <div className="card">
        <Skeleton height={12} width="30%" />
        <Skeleton height={140} />
      </div>
    </div>
  );
}

/** Loading, error and refresh states around an async result. */
export function Await<T>({ state, children, skeleton }: { state: Async<T>; children: (data: T) => ReactNode; skeleton?: ReactNode }) {
  const { t } = useI18n();
  if (state.error && !state.data) {
    return (
      <div className="notice error" role="alert">
        <p>
          {t("error")}: {state.error.message}
        </p>
        <button onClick={state.reload}>{t("retry")}</button>
      </div>
    );
  }
  if (!state.data) return <>{skeleton ?? <PageSkeleton />}</>;
  return <div className={state.loading ? "refreshing" : ""}>{children(state.data)}</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}
