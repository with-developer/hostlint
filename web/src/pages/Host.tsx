import { useMemo, useState } from "react";
import { api } from "../lib/api";
import { useAsync, useNow } from "../lib/hooks";
import { useI18n } from "../lib/i18n";
import { ago, compareControls, percent } from "../lib/format";
import { Await, ScoreRing, Severity, Sparkline, StatusBadge, StatusBar } from "../components/ui";
import { STATUSES, type ControlRow, type Diff, type ControlChange, type ScanDoc, type Status } from "../lib/types";
import { STALE_DAYS } from "./Overview";

export function HostPage({ id }: { id: number }) {
  const { t } = useI18n();
  const now = useNow();
  const state = useAsync(() => api.host(id, STALE_DAYS), [id]);
  return (
    <>
      <p>
        <a href="#/hosts">{t("host.back")}</a>
      </p>
      <Await state={state}>
        {(h) => (
          <>
            <header className="hosthead">
              <div>
                <h1>{h.name}</h1>
                <p className="muted small">
                  {h.hostId && (
                    <>
                      {t("host.hostId")}: <span className="mono">{h.hostId}</span> ·{" "}
                    </>
                  )}
                  {t("host.lastScan")}: {ago(h.lastScanAt, now, t)}
                  {h.stale && <span className="badge s-MANUAL">{t("stale")}</span>}
                </p>
                <StatusBar counts={h.counts} legend />
              </div>
              <ScoreRing score={h.score} />
            </header>

            <section className="card">
              <h2>{t("host.controls")}</h2>
              <Controls controls={h.controls} scanId={h.latestScan} />
            </section>

            <section className="card">
              <h2>{t("host.history")}</h2>
              <Sparkline points={[...h.scans].reverse().map((s) => s.score)} />
              <History scans={h.scans} />
            </section>
          </>
        )}
      </Await>
    </>
  );
}

function Controls({ controls, scanId }: { controls: ControlRow[]; scanId: number }) {
  const { t } = useI18n();
  const [q, setQ] = useState("");
  const [shown, setShown] = useState<Set<Status>>(new Set(["FAIL", "ERROR", "MANUAL", "WAIVED"]));
  const [open, setOpen] = useState<string | null>(null);
  const doc = useAsync(() => (open ? api.scan(scanId) : Promise.resolve(null as ScanDoc | null)), [open ? scanId : 0]);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return controls
      .filter((c) => shown.has(c.status) && (!needle || c.id.toLowerCase().includes(needle) || c.title.toLowerCase().includes(needle)))
      .sort(compareControls);
  }, [controls, q, shown]);

  if (controls.length === 0) return <p className="muted">{t("host.noControls")}</p>;
  const toggle = (s: Status) =>
    setShown((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });

  return (
    <>
      <div className="toolbar">
        <input type="search" placeholder={t("host.filter")} aria-label={t("host.filter")} value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="chips" role="group">
          {STATUSES.map((s) => (
            <button key={s} className={`chip s-${s} ${shown.has(s) ? "on" : ""}`} aria-pressed={shown.has(s)} onClick={() => toggle(s)}>
              {t(`status.${s}`)} {controls.filter((c) => c.status === s).length}
            </button>
          ))}
        </div>
      </div>
      <div className="table-wrap">
        <table>
          <tbody>
            {rows.map((c) => {
              const key = `${c.profile}/${c.id}`;
              const expanded = open === key;
              return (
                <ControlLine key={key} control={c} expanded={expanded} doc={expanded ? doc.data : null} loading={expanded && doc.loading} error={expanded ? doc.error : null} onToggle={() => setOpen(expanded ? null : key)} />
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

function ControlLine({ control: c, expanded, doc, loading, error, onToggle }: { control: ControlRow; expanded: boolean; doc: ScanDoc | null; loading: boolean; error: Error | null; onToggle: () => void }) {
  const { t } = useI18n();
  return (
    <>
      <tr className="clickable" onClick={onToggle} onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onToggle()} tabIndex={0} aria-expanded={expanded}>
        <td>
          <span className="caret" aria-hidden="true">
            {expanded ? "▾" : "▸"}
          </span>
        </td>
        <td className="mono">{c.id}</td>
        <td>{c.title}</td>
        <td>
          <Severity value={c.severity} />
        </td>
        <td>
          <StatusBadge status={c.status} />
        </td>
      </tr>
      {expanded && (
        <tr className="detail">
          <td colSpan={5}>
            {loading && <p className="muted">{t("loading")}</p>}
            {error && <p className="error-text">{error.message}</p>}
            {doc && <ControlDetail control={c} doc={doc} />}
          </td>
        </tr>
      )}
    </>
  );
}

/** The checks of a control and what they observed. All of it is host text: shown as text only. */
function ControlDetail({ control, doc }: { control: ControlRow; doc: ScanDoc }) {
  const { t } = useI18n();
  const dc = doc.controls.find((x) => x.profile === control.profile && x.id === control.id);
  const checks = (dc?.checks ?? []).map((ref) => doc.checks.find((c) => c.ref === ref)).filter((c) => c !== undefined);
  return (
    <div className="control-detail">
      {dc?.reason && <p className="muted">{dc.reason}</p>}
      {dc?.waiver && <p className="notice">{t("host.waived", { reason: dc.waiver.reason, expires: dc.waiver.expires })}</p>}
      <h3>{t("host.checks")}</h3>
      {checks.length === 0 && <p className="muted">{t("host.noEvidence")}</p>}
      {checks.map((ch) => (
        <div key={ch.ref} className="check">
          <div className="check-head">
            <StatusBadge status={ch.status} /> <span className="mono">{ch.ref}</span> <span className="muted">— {ch.title}</span>
          </div>
          {ch.reason && <p className="muted small">{ch.reason}</p>}
          {(ch.evidence?.length ?? 0) > 0 ? (
            <ul className="evidence">
              {ch.evidence?.map((e, i) => (
                <li key={i}>
                  {!e.text.startsWith(e.key) && <span className="mono">{e.key} </span>}
                  {e.text}
                  {e.source && <span className="muted mono"> {e.source}</span>}
                </li>
              ))}
              {(ch.evidenceOmitted ?? 0) > 0 && <li className="muted">… +{ch.evidenceOmitted}</li>}
            </ul>
          ) : (
            <p className="muted small">{t("host.noEvidence")}</p>
          )}
        </div>
      ))}
    </div>
  );
}

function History({ scans }: { scans: { id: number; receivedAt: string; toolVersion: string; score: number | null; counts: Record<string, number | undefined> }[] }) {
  const { t } = useI18n();
  const now = useNow();
  const [pair, setPair] = useState<[number, number] | null>(null);
  const diff = useAsync(() => (pair ? api.diff(pair[0], pair[1]) : Promise.resolve(null as Diff | null)), [pair?.[0], pair?.[1]]);
  return (
    <>
      <div className="table-wrap">
        <table>
          <tbody>
            {scans.map((s, i) => {
              const previous = scans[i + 1];
              return (
                <tr key={s.id}>
                  <td>
                    <a href={`/api/v1/scans/${s.id}`} target="_blank" rel="noreferrer" title={t("host.raw")}>
                      {t("host.scan", { id: s.id })}
                    </a>
                  </td>
                  <td>{ago(s.receivedAt, now, t)}</td>
                  <td className="muted small mono">{s.toolVersion}</td>
                  <td className="num">{percent(s.score)}</td>
                  <td>
                    <span className="small">
                      {s.counts.FAIL ? <span className="badge s-FAIL">{s.counts.FAIL}</span> : null}
                      {s.counts.ERROR ? <span className="badge s-ERROR">{s.counts.ERROR}</span> : null}
                    </span>
                  </td>
                  <td>{previous && <button onClick={() => setPair([previous.id, s.id])}>{t("host.compare")}</button>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {pair && (
        <div className="card inner">
          <div className="titlebar">
            <h3>
              {t("host.scan", { id: pair[0] })} → {t("host.scan", { id: pair[1] })}
            </h3>
            <button onClick={() => setPair(null)}>{t("diff.close")}</button>
          </div>
          <Await state={diff as never}>{(d: Diff | null) => (d ? <DiffView diff={d} /> : null)}</Await>
        </div>
      )}
    </>
  );
}

function DiffView({ diff }: { diff: Diff }) {
  const { t } = useI18n();
  const section = (title: string, list: ControlChange[]) =>
    list.length === 0 ? null : (
      <div key={title}>
        <h4>
          {title} ({list.length})
        </h4>
        <ul className="difflist">
          {list.map((c) => (
            <li key={`${c.profile}/${c.id}`}>
              <span className="mono">{c.id}</span> {c.title} <StatusBadge status={c.old} /> → <StatusBadge status={c.new} />
              {c.checks.length > 0 && (
                <ul>
                  {c.checks.map((ch) => (
                    <li key={ch.ref} className="small">
                      <span className="mono">{ch.ref}</span> <StatusBadge status={ch.old} /> → <StatusBadge status={ch.new} />
                    </li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ul>
      </div>
    );
  return (
    <>
      {diff.notes.map((n) => (
        <p key={n} className="notice">
          {n}
        </p>
      ))}
      {section(t("diff.regressed"), diff.regressed)}
      {section(t("diff.fixed"), diff.fixed)}
      {section(t("diff.changed"), diff.changed)}
      {section(t("diff.added"), diff.added)}
      {section(t("diff.removed"), diff.removed)}
      <p className="muted small">{t("diff.unchanged", diff.unchanged)}</p>
    </>
  );
}
