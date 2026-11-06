import { useMemo, useState } from "react";
import { api } from "../lib/api";
import { useAsync } from "../lib/hooks";
import { useI18n } from "../lib/i18n";
import { Await, Empty, PageHeader, Skeleton } from "../components/ui";
import { ctitle } from "../lib/format";
import { STATUSES, type Matrix, type Status } from "../lib/types";
import { STALE_DAYS } from "./Overview";

const LETTER: Record<string, Status | "-"> = { F: "FAIL", E: "ERROR", M: "MANUAL", W: "WAIVED", P: "PASS", N: "NOT_APPLICABLE", "-": "-" };
const ROWS = 60;

export function MatrixPage() {
  const { t } = useI18n();
  const state = useAsync(() => api.matrix(STALE_DAYS), []);
  return (
    <>
      <PageHeader title={t("matrix.title")} subtitle={t("matrix.subtitle")} />
      <Await state={state} skeleton={<div className="card"><Skeleton height={300} /></div>}>
        {(m) => (m.hosts.length === 0 ? <Empty>{t("overview.empty")}</Empty> : <Heatmap matrix={m} />)}
      </Await>
    </>
  );
}

function Heatmap({ matrix }: { matrix: Matrix }) {
  const { t, lang } = useI18n();
  const [rows, setRows] = useState(ROWS);
  const [tip, setTip] = useState<{ x: number; y: number; text: string } | null>(null);
  const hosts = useMemo(() => matrix.hosts.slice(0, rows), [matrix.hosts, rows]);

  function over(e: React.MouseEvent<HTMLTableElement>) {
    const cell = (e.target as HTMLElement).closest<HTMLElement>("td[data-r]");
    if (!cell) return setTip(null);
    const h = matrix.hosts[Number(cell.dataset.r)];
    const c = matrix.controls[Number(cell.dataset.c)];
    const status = LETTER[h.statuses[Number(cell.dataset.c)]];
    const rect = cell.getBoundingClientRect();
    setTip({ x: rect.left + rect.width / 2, y: rect.top, text: `${h.name} · ${c.id} ${ctitle(c, lang)} · ${status === "-" ? "–" : t(`status.${status}`)}` });
  }
  function click(e: React.MouseEvent<HTMLTableElement>) {
    const cell = (e.target as HTMLElement).closest<HTMLElement>("td[data-r]");
    if (cell) location.hash = `#/hosts/${matrix.hosts[Number(cell.dataset.r)].id}`;
  }

  return (
    <section className="card flush">
      <div className="matrix-legend">
        {STATUSES.map((s) => (
          <span key={s}>
            <span className={`dot s-${s}`} /> {t(`status.${s}`)}
          </span>
        ))}
        <span className="muted small push">{t("matrix.legend")}</span>
      </div>
      <div className="matrix-scroll">
        <table className="matrix" onMouseOver={over} onMouseLeave={() => setTip(null)} onClick={click}>
          <thead>
            <tr>
              <th className="corner" />
              {matrix.controls.map((c) => (
                <th key={`${c.profile}/${c.id}`} className="col">
                  <a href={`#/controls/${c.profile}/${c.id}`} title={ctitle(c, lang)}>
                    <span>{c.id}</span>
                  </a>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {hosts.map((h, r) => (
              <tr key={h.id}>
                <th className="rowhead">
                  <a href={`#/hosts/${h.id}`} onClick={(e) => e.stopPropagation()}>
                    {h.name}
                  </a>
                </th>
                {[...h.statuses].map((ch, c) => (
                  <td key={c} data-r={r} data-c={c} className={`cell m-${ch}`} />
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows < matrix.hosts.length && (
        <div className="tablefoot">
          <span className="muted small">{t("hosts.showing", { n: hosts.length, total: matrix.hosts.length })}</span>
          <button onClick={() => setRows((n) => n + ROWS)}>{t("matrix.moreHosts")}</button>
        </div>
      )}
      {tip && (
        <div className="tooltip" style={{ left: tip.x, top: tip.y }} role="tooltip">
          {tip.text}
        </div>
      )}
    </section>
  );
}
