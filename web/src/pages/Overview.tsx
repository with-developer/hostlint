import { api } from "../lib/api";
import { useState } from "react";
import { useAsync, useNow } from "../lib/hooks";
import { useI18n } from "../lib/i18n";
import { ago, ctitle } from "../lib/format";
import { Avatar, Await, Donut, Empty, Gauge, PageHeader, Severity, StatusBadge, StatusBar, Stat } from "../components/ui";
import { IconAlert, IconClock, IconServer } from "../components/icons";
import { TrendChart } from "../components/charts";
import { GettingStarted } from "../components/start";

export const STALE_DAYS = 7;

export function OverviewPage() {
  const { t, lang } = useI18n();
  const now = useNow();
  const state = useAsync(() => api.overview(STALE_DAYS), []);
  const stale = useAsync(() => api.hosts({ status: "stale", sort: "last", limit: 5, staleDays: STALE_DAYS }), []);
  return (
    <>
      <PageHeader title={t("overview.title")} subtitle={t("overview.subtitle")} />
      <Await state={state}>
        {(o) =>
          o.hosts === 0 ? (
            <>
              {o.hostsOther ? <p className="muted small">{t("profile.other", { n: o.hostsOther })}</p> : null}
              {o.hostsOther ? <Empty>{t("overview.empty")}</Empty> : <GettingStarted />}
            </>
          ) : (
            <div className="stack">
              {o.hostsOther ? <p className="muted small">{t("profile.other", { n: o.hostsOther })}</p> : null}
              <section className="hero card">
                <Gauge score={o.score} label={t("overview.score")} />
                <div className="hero-body">
                  <h2>{t("overview.distribution")}</h2>
                  <StatusBar counts={o.counts} legend />
                  <p className="muted small">{t("overview.scoreHelp")}</p>
                </div>
                <Donut counts={o.counts} label={t("overview.results")} />
              </section>

              <TrendCard />

              <section className="grid3">
                <Stat icon={<IconServer />} value={o.hosts} label={t("overview.hosts")} />
                <Stat icon={<IconAlert />} value={o.hostsFailing} label={t("overview.failing")} tone={o.hostsFailing > 0 ? "bad" : "good"} help={t("overview.failRate", { n: o.hostsFailing, total: o.hosts })} />
                <Stat icon={<IconClock />} value={o.hostsStale} label={t("overview.stale", o.staleAfterDays)} tone={o.hostsStale > 0 ? "warn" : "good"} />
              </section>

              <div className="two">
                <section className="card">
                  <h2>{t("overview.topFailing")}</h2>
                  {o.topFailing.length === 0 ? (
                    <Empty>{t("overview.none")}</Empty>
                  ) : (
                    <ol className="ranked">
                      {o.topFailing.map((c) => (
                        <li key={`${c.profile}/${c.id}`}>
                          <div className="ranked-head">
                            <a className="mono id" href={`#/controls/${c.profile}/${c.id}`}>
                              {c.id}
                            </a>
                            <span className="ranked-title">{ctitle(c, lang)}</span>
                            <Severity value={c.severity} />
                            <strong className="num">
                              {c.hosts}
                              <span className="muted small"> / {o.hosts}</span>
                            </strong>
                          </div>
                          <div className="meter">
                            <span className={`sev-${c.severity}`} style={{ width: `${(100 * c.hosts) / o.hosts}%` }} />
                          </div>
                        </li>
                      ))}
                    </ol>
                  )}
                </section>

                <div className="stack">
                  <section className="card">
                    <h2>{t("overview.regressions")}</h2>
                    <p className="muted small">{t("overview.regressionsHelp")}</p>
                    {o.recentRegressions.length === 0 ? (
                      <Empty>{t("overview.none")}</Empty>
                    ) : (
                      <ul className="timeline">
                        {o.recentRegressions.map((r) => (
                          <li key={`${r.hostId}/${r.profile}/${r.id}`}>
                            <span className="timeline-dot s-FAIL" />
                            <div>
                              <a href={`#/hosts/${r.hostId}`}>{r.host}</a> <span className="mono id">{r.id}</span> {ctitle(r, lang)} <StatusBadge status={r.status} />
                              <div className="muted small">{ago(r.receivedAt, now, t)}</div>
                            </div>
                          </li>
                        ))}
                      </ul>
                    )}
                  </section>
                  {(stale.data?.hosts.length ?? 0) > 0 && (
                    <section className="card">
                      <h2>{t("overview.attention")}</h2>
                      <p className="muted small">{t("overview.attentionHelp")}</p>
                      <ul className="plain">
                        {stale.data?.hosts.map((h) => (
                          <li key={h.id} className="rowline">
                            <Avatar name={h.name} size={26} /> <a href={`#/hosts/${h.id}`}>{h.name}</a>
                            <span className="muted small push">{ago(h.lastScanAt, now, t)}</span>
                          </li>
                        ))}
                      </ul>
                    </section>
                  )}
                </div>
              </div>
            </div>
          )
        }
      </Await>
    </>
  );
}

/** The fleet's pass rate over the last days (7, 30 or 90), one point a day. */
function TrendCard() {
  const { t } = useI18n();
  const [days, setDays] = useState(30);
  const state = useAsync(() => api.trend(days), [days]);
  // The chart starts where the fleet does: days before the first scan have nothing to show.
  const all = state.data?.points ?? [];
  const first = all.findIndex((p) => p.score !== null);
  const points = first < 0 ? [] : all.slice(first);
  const any = points.length >= 2; // one day is a dot, not a trend
  return (
    <section className="card">
      <div className="titlebar">
        <div>
          <h2>{t("overview.trend")}</h2>
          <p className="muted small">{t("overview.trendHelp")}</p>
        </div>
        <div className="segmented" role="group" aria-label={t("overview.trend")}>
          {[7, 30, 90].map((d) => (
            <button key={d} className={days === d ? "on" : ""} aria-pressed={days === d} onClick={() => setDays(d)}>
              {t("trend.days", { n: d })}
            </button>
          ))}
        </div>
      </div>
      {state.error ? (
        <p className="error-text">{state.error.message}</p>
      ) : !state.data ? (
        <p className="muted">{t("loading")}</p>
      ) : !any ? (
        <Empty>{t("trend.none")}</Empty>
      ) : (
        <TrendChart
          label={t("overview.trend")}
          points={points.map((p) => ({ at: p.at, score: p.score, detail: p.hosts === 0 ? "" : t("trend.detail", { hosts: p.hosts, failing: p.failing }) }))}
        />
      )}
    </section>
  );
}
