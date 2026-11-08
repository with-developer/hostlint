import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { useAsync, useDebounced, useNow } from "../lib/hooks";
import { useI18n } from "../lib/i18n";
import { ago } from "../lib/format";
import { Avatar, Await, Empty, PageHeader, ScorePill, Skeleton, SignedBadge, StatusBar } from "../components/ui";
import { MiniSpark } from "../components/charts";
import { IconDownload, IconSearch } from "../components/icons";
import type { HostSummary } from "../lib/types";
import { STALE_DAYS } from "./Overview";

type Filter = "" | "failing" | "stale";
type Sort = "name" | "score" | "last";
const PAGE = 50;

export function HostsPage() {
  const { t } = useI18n();
  const now = useNow();
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<Filter>("");
  const [sort, setSort] = useState<Sort>("name");
  const [label, setLabel] = useState(""); // "key=value": only the hosts with that label
  const [pages, setPages] = useState(1);
  const query = useDebounced(q, 250);
  useEffect(() => setPages(1), [query, filter, sort, label]);
  const params = { q: query, status: filter, sort, label, staleDays: STALE_DAYS };
  // One request for everything shown so far: the server sorts the whole fleet, not a page of it.
  const state = useAsync(() => api.hosts({ ...params, limit: PAGE * pages, offset: 0 }), [query, filter, sort, label, pages]);

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
      <PageHeader
        title={t("hosts.title")}
        subtitle={t("hosts.subtitle")}
        actions={
          <a className="button" href={api.hostsCSV(params)} download>
            <IconDownload /> {t("hosts.export")}
          </a>
        }
      />
      <div className="toolbar">
        <label className="search">
          <IconSearch />
          <input type="search" placeholder={t("hosts.search")} aria-label={t("hosts.search")} value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
        <div className="segmented" role="group">
          {filters.map(([value, label]) => (
            <button key={value} className={filter === value ? "on" : ""} aria-pressed={filter === value} onClick={() => setFilter(value)}>
              {label}
            </button>
          ))}
        </div>
        {label && (
          <button className="chip-label active" onClick={() => setLabel("")} title={t("hosts.clearLabel")}>
            {label} ×
          </button>
        )}
        <div className="segmented" role="group" aria-label={t("hosts.sortBy")}>
          {sorts.map(([value, label]) => (
            <button key={value} className={sort === value ? "on" : ""} aria-pressed={sort === value} onClick={() => setSort(value)}>
              {label}
            </button>
          ))}
        </div>
      </div>
      <Await state={state} skeleton={<div className="card"><Skeleton height={220} /></div>}>
        {(d) => (
          <section className="card flush">
            {d.hosts.length === 0 ? (
              <Empty>{t("hosts.none")}</Empty>
            ) : (
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
                    {d.hosts.map((h) => (
                      <HostRow key={h.id} host={h} now={now} onLabel={(k, v) => setLabel(`${k}=${v}`)} />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <div className="tablefoot">
              <span className="muted small">{t("hosts.showing", { n: d.hosts.length, total: d.total })}</span>
              {d.hosts.length < d.total && <button onClick={() => setPages((p) => p + 1)}>{t("hosts.more")}</button>}
            </div>
          </section>
        )}
      </Await>
    </>
  );
}

function HostRow({ host: h, now, onLabel }: { host: HostSummary; now: number; onLabel: (key: string, value: string) => void }) {
  const { t } = useI18n();
  return (
    <tr onClick={() => (location.hash = `#/hosts/${h.id}`)} className="clickable">
      <td>
        <a className="hostname" href={`#/hosts/${h.id}`} onClick={(e) => e.stopPropagation()}>
          <Avatar name={h.name} /> {h.name}
        </a>{" "}
        {h.signed && <SignedBadge fingerprint={h.keyFingerprint} />}
        {h.agentOnline && (
          <span className="agent-badge" title={t("hosts.agentHelp")}>
            <span className="agent-dot" /> {t("hosts.agent")}
          </span>
        )}
        {(h.os || h.labels) && (
          <div className="hostmeta muted small">
            {h.os && <span>{h.os}</span>}
            {Object.entries(h.labels ?? {}).map(([k, v]) => (
              <button
                key={k}
                className="chip-label"
                title={t("hosts.filterLabel", { label: `${k}=${v}` })}
                onClick={(e) => {
                  e.stopPropagation(); // the row opens the host: the label filters the list
                  onLabel(k, v);
                }}
              >
                {k}={v}
              </button>
            ))}
          </div>
        )}
      </td>
      <td className="bar-cell">
        {h.otherProfile ? <span className="muted small">{t("profile.otherHost")}</span> : <StatusBar counts={h.counts} thin />}
        <div className="muted small counts">
          {h.counts.FAIL ? <span className="c-FAIL">{h.counts.FAIL} FAIL</span> : null}
          {h.counts.ERROR ? <span className="c-ERROR">{h.counts.ERROR} ERROR</span> : null}
          {h.counts.MANUAL ? <span>{h.counts.MANUAL} MANUAL</span> : null}
        </div>
      </td>
      <td className="num scorecell">
        {h.otherProfile ? "–" : (
          <>
            {h.trend && <MiniSpark values={h.trend} />}
            <ScorePill score={h.score} />
          </>
        )}
      </td>
      <td className={h.stale ? "stale" : ""}>
        {ago(h.lastScanAt, now, t)} {h.stale && <span className="badge s-MANUAL">{t("stale")}</span>}
      </td>
    </tr>
  );
}
