import { api } from "../lib/api";
import { useAsync, useNow } from "../lib/hooks";
import { useI18n } from "../lib/i18n";
import { ago, ctitle } from "../lib/format";
import { Avatar, Await, Donut, Empty, Gauge, PageHeader, Severity, StatusBadge, StatusBar, Stat } from "../components/ui";
import { IconAlert, IconClock, IconServer } from "../components/icons";

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
            <Empty>{t("overview.empty")}</Empty>
          ) : (
            <div className="stack">
              <section className="hero card">
                <Gauge score={o.score} label={t("overview.score")} />
                <div className="hero-body">
                  <h2>{t("overview.distribution")}</h2>
                  <StatusBar counts={o.counts} legend />
                  <p className="muted small">{t("overview.scoreHelp")}</p>
                </div>
                <Donut counts={o.counts} label={t("overview.hosts")} />
              </section>

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
