import { useMemo, useState } from "react";
import { api } from "../lib/api";
import { useAsync, useDebounced, useNow } from "../lib/hooks";
import { useI18n } from "../lib/i18n";
import { ago, percent } from "../lib/format";
import { Await, StatusBar } from "../components/ui";
import type { HostSummary } from "../lib/types";
import { STALE_DAYS } from "./Overview";

type Filter = "" | "failing" | "stale";
type Sort = "name" | "score" | "last";

export function HostsPage() {
  const { t } = useI18n();
  const now = useNow();
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<Filter>("");
  const [sort, setSort] = useState<Sort>("name");
  const query = useDebounced(q, 250);
  const state = useAsync(() => api.hosts({ q: query, status: filter, staleDays: STALE_DAYS }), [query, filter]);

  const sorted = useMemo(() => {
    const hosts = [...(state.data?.hosts ?? [])];
    const by: Record<Sort, (a: HostSummary, b: HostSummary) => number> = {
      name: (a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }),
      score: (a, b) => (a.score ?? 2) - (b.score ?? 2), // worst first; undecided last
      last: (a, b) => a.lastScanAt.localeCompare(b.lastScanAt), // longest silent first
    };
    return hosts.sort(by[sort]);
  }, [state.data, sort]);

  const filters: [Filter, string][] = [
    ["", t("hosts.all")],
    ["failing", t("hosts.failing")],
    ["stale", t("hosts.stale")],
  ];
  const sorts: [Sort, string][] = [
    ["name", t("hosts.name")],
    ["score", t("hosts.score")],
    ["last", t("hosts.lastScan")],
  ];

  return (
    <>
      <div className="titlebar">
        <h1>{t("hosts.title")}</h1>
        <a className="button" href="/api/v1/hosts?format=csv" download>
          {t("hosts.export")}
        </a>
      </div>
      <div className="toolbar">
        <input type="search" placeholder={t("hosts.search")} aria-label={t("hosts.search")} value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="chips" role="group">
          {filters.map(([value, label]) => (
            <button key={value} className={`chip ${filter === value ? "on" : ""}`} aria-pressed={filter === value} onClick={() => setFilter(value)}>
              {label}
            </button>
          ))}
        </div>
        <div className="chips" role="group">
          {sorts.map(([value, label]) => (
            <button key={value} className={`chip ${sort === value ? "on" : ""}`} aria-pressed={sort === value} onClick={() => setSort(value)}>
              ↕ {label}
            </button>
          ))}
        </div>
      </div>
      <Await state={state}>
        {(d) => (
          <>
            <p className="muted small">{t("hosts.total", d.total)}</p>
            <div className="table-wrap">
              <table className="hosts">
                <thead>
                  <tr>
                    <th>{t("hosts.name")}</th>
                    <th>{t("hosts.status")}</th>
                    <th className="num">{t("hosts.score")}</th>
                    <th>{t("hosts.lastScan")}</th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((h) => (
                    <tr key={h.id}>
                      <td>
                        <a href={`#/hosts/${h.id}`}>{h.name}</a>
                      </td>
                      <td className="bar-cell">
                        <StatusBar counts={h.counts} />
                      </td>
                      <td className="num">{percent(h.score)}</td>
                      <td className={h.stale ? "stale" : ""}>
                        {ago(h.lastScanAt, now, t)} {h.stale && <span className="badge s-MANUAL">{t("stale")}</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Await>
    </>
  );
}
