import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import { useAsync, useNow } from "../lib/hooks";
import { useI18n } from "../lib/i18n";
import { ago, compareControls } from "../lib/format";
import { Avatar, Await, Empty, Gauge, ScorePill, Severity, Sparkline, StatusBadge, StatusBar } from "../components/ui";
import { IconChevron, IconSearch } from "../components/icons";
import { STATUSES, type ControlChange, type ControlRow, type Diff, type ScanDoc, type ScanRow, type Status } from "../lib/types";
import { STALE_DAYS } from "./Overview";

export function HostPage({ id }: { id: number }) {
  const { t } = useI18n();
  const now = useNow();
  const [tab, setTab] = useState<"controls" | "history">("controls");
  const state = useAsync(() => api.host(id, STALE_DAYS), [id], false);
  return (
    <>
      <p className="crumb">
        <a href="#/hosts">{t("host.back")}</a>
      </p>
      <Await state={state}>
        {(h) => (
          <div className="stack">
            <header className="card hosthead">
              <Avatar name={h.name} size={52} />
              <div className="hosthead-main">
                <h1>{h.name}</h1>
                <p className="muted small">
                  {h.hostId && (
                    <>
                      {t("host.hostId")}: <span className="mono">{h.hostId}</span> ·{" "}
                    </>
                  )}
                  {t("host.lastScan")}: {ago(h.lastScanAt, now, t)} {h.stale && <span className="badge s-MANUAL">{t("stale")}</span>}
                </p>
                <StatusBar counts={h.counts} legend />
              </div>
              <Gauge score={h.score} label={t("host.passRate")} />
            </header>

            <div className="tabs" role="tablist">
              <button role="tab" aria-selected={tab === "controls"} className={tab === "controls" ? "on" : ""} onClick={() => setTab("controls")}>
                {t("host.tabControls")} <span className="count">{h.controls.length}</span>
              </button>
              <button role="tab" aria-selected={tab === "history"} className={tab === "history" ? "on" : ""} onClick={() => setTab("history")}>
                {t("host.tabHistory")} <span className="count">{h.scans.length}</span>
              </button>
            </div>

            {tab === "controls" ? <Controls controls={h.controls} scanId={h.latestScan} /> : <History scans={h.scans} />}
          </div>
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
  // The stored result holds the evidence. It is fetched the first time a control is opened and kept.
  const [wanted, setWanted] = useState(false);
  const doc = useAsync(() => (wanted ? api.scan(scanId) : Promise.resolve(null as ScanDoc | null)), [wanted, scanId]);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return controls.filter((c) => shown.has(c.status) && (!needle || c.id.toLowerCase().includes(needle) || c.title.toLowerCase().includes(needle))).sort(compareControls);
  }, [controls, q, shown]);

  if (controls.length === 0) return <Empty>{t("host.noControls")}</Empty>;
  const toggleStatus = (s: Status) =>
    setShown((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  const toggleOpen = (key: string) => {
    setWanted(true);
    setOpen((cur) => (cur === key ? null : key));
  };

  return (
    <section className="card flush">
      <div className="toolbar pad">
        <label className="search">
          <IconSearch />
          <input type="search" placeholder={t("host.filter")} aria-label={t("host.filter")} value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
        <div className="chips" role="group">
          {STATUSES.map((s) => (
            <button key={s} className={`chip s-${s} ${shown.has(s) ? "on" : ""} ${controls.some((c) => c.status === s) ? "" : "zero"}`} aria-pressed={shown.has(s)} onClick={() => toggleStatus(s)}>
              {t(`status.${s}`)} <span className="count">{controls.filter((c) => c.status === s).length}</span>
            </button>
          ))}
        </div>
      </div>
      {rows.length === 0 ? (
        <Empty>{t("host.empty")}</Empty>
      ) : (
        <ul className="controls">
          {rows.map((c) => {
            const key = `${c.profile}/${c.id}`;
            const expanded = open === key;
            return (
              <li key={key} className={expanded ? "open" : ""}>
                <div
                  className="control-row"
                  role="button"
                  tabIndex={0}
                  aria-expanded={expanded}
                  aria-label={t("host.toggle")}
                  onClick={() => toggleOpen(key)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault(); // Space must not scroll the page
                      toggleOpen(key);
                    }
                  }}
                >
                  <IconChevron open={expanded} />
                  <span className="mono id">{c.id}</span>
                  <span className="control-title">{c.title}</span>
                  <Severity value={c.severity} />
                  <StatusBadge status={c.status} />
                </div>
                {expanded && (
                  <div className="control-body">
                    {doc.loading && !doc.data && <p className="muted">{t("loading")}</p>}
                    {doc.error && <p className="error-text">{doc.error.message}</p>}
                    {doc.data && <ControlDetail control={c} doc={doc.data} />}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

/** The checks of a control and what they observed. All of it is host text: shown as text only. */
function ControlDetail({ control, doc }: { control: ControlRow; doc: ScanDoc }) {
  const { t } = useI18n();
  const dc = doc.controls.find((x) => x.profile === control.profile && x.id === control.id);
  const checks = (dc?.checks ?? []).map((ref) => doc.checks.find((c) => c.ref === ref)).filter((c) => c !== undefined);
  return (
    <>
      {dc?.reason && <p className="muted">{dc.reason}</p>}
      {dc?.waiver && <p className="notice">{t("host.waived", { reason: dc.waiver.reason, expires: dc.waiver.expires })}</p>}
      {checks.length === 0 && <p className="muted">{t("host.noEvidence")}</p>}
      {checks.map((ch) => (
        <div key={ch.ref} className="check">
          <div className="check-head">
            <StatusBadge status={ch.status} /> <span className="mono">{ch.ref}</span> <span className="muted">{ch.title}</span>
          </div>
          {ch.reason && <p className="muted small">{ch.reason}</p>}
          {(ch.evidence?.length ?? 0) > 0 ? (
            <pre className="evidence">
              {ch.evidence?.map((e) => `${e.text.startsWith(e.key) ? "" : `${e.key} `}${e.text}${e.source ? `   ${e.source}` : ""}`).join("\n")}
              {(ch.evidenceOmitted ?? 0) > 0 ? `\n… +${ch.evidenceOmitted}` : ""}
            </pre>
          ) : (
            <p className="muted small">{t("host.noEvidence")}</p>
          )}
        </div>
      ))}
    </>
  );
}

function History({ scans }: { scans: ScanRow[] }) {
  const { t } = useI18n();
  const now = useNow();
  const [pair, setPair] = useState<[number, number] | null>(null);
  useEffect(() => setPair(null), [scans]);
  const diff = useAsync(() => (pair ? api.diff(pair[0], pair[1]) : Promise.resolve(null as Diff | null)), [pair?.[0], pair?.[1]], false);
  return (
    <div className="stack">
      <section className="card">
        <h2>{t("host.history")}</h2>
        <Sparkline points={[...scans].reverse().map((s) => s.score)} />
      </section>
      <section className="card flush">
        <ul className="scans">
          {scans.map((s, i) => {
            const previous = scans[i + 1];
            return (
              <li key={s.id}>
                <a href={`/api/v1/scans/${s.id}`} target="_blank" rel="noreferrer" title={t("host.raw")}>
                  {t("host.scan", { id: s.id })}
                </a>
                <span className="muted small">{ago(s.receivedAt, now, t)}</span>
                <span className="muted small mono">{s.toolVersion}</span>
                <ScorePill score={s.score} />
                <span className="small">
                  {s.counts.FAIL ? <span className="badge s-FAIL">{s.counts.FAIL}</span> : null}
                  {s.counts.ERROR ? <span className="badge s-ERROR">{s.counts.ERROR}</span> : null}
                </span>
                <span className="push">{previous && <button onClick={() => setPair([previous.id, s.id])}>{t("host.compare")}</button>}</span>
              </li>
            );
          })}
        </ul>
      </section>
      {pair && (
        <section className="card">
          <div className="titlebar">
            <h2>
              {t("host.scan", { id: pair[0] })} → {t("host.scan", { id: pair[1] })}
            </h2>
            <button onClick={() => setPair(null)}>{t("diff.close")}</button>
          </div>
          <Await state={diff} skeleton={<p className="muted">{t("loading")}</p>}>
            {(d) => (d ? <DiffView diff={d} /> : null)}
          </Await>
        </section>
      )}
    </div>
  );
}

function DiffView({ diff }: { diff: Diff }) {
  const { t } = useI18n();
  const section = (title: string, tone: string, list: ControlChange[]) =>
    !list || list.length === 0 ? null : (
      <div key={title} className={`diffgroup ${tone}`}>
        <h3>
          {title} <span className="count">{list.length}</span>
        </h3>
        <ul className="difflist">
          {list.map((c) => (
            <li key={`${c.profile}/${c.id}`}>
              <div>
                <span className="mono id">{c.id}</span> {c.title} <StatusBadge status={c.old} />
                {c.old === c.new ? <span className="muted small"> {t("diff.checksChanged")}</span> : <> → <StatusBadge status={c.new} /></>}
              </div>
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
      {section(t("diff.regressed"), "bad", diff.regressed)}
      {section(t("diff.fixed"), "good", diff.fixed)}
      {section(t("diff.changed"), "warn", diff.changed)}
      {section(t("diff.added"), "", diff.added)}
      {section(t("diff.removed"), "", diff.removed)}
      <p className="muted small">{t("diff.unchanged", diff.unchanged)}</p>
    </>
  );
}
