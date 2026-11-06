import { api } from "../lib/api";
import { useAsync, useNow } from "../lib/hooks";
import { useI18n } from "../lib/i18n";
import { ago } from "../lib/format";
import { Await, ScoreRing, Severity, StatusBadge, StatusBar, Tile } from "../components/ui";

export const STALE_DAYS = 7;

export function OverviewPage() {
  const { t } = useI18n();
  const now = useNow();
  const state = useAsync(() => api.overview(STALE_DAYS), []);
  return (
    <>
      <h1>{t("overview.title")}</h1>
      <Await state={state}>
        {(o) =>
          o.hosts === 0 ? (
            <div className="notice">{t("overview.empty")}</div>
          ) : (
            <>
              <section className="tiles">
                <Tile value={o.hosts} label={t("overview.hosts")} />
                <Tile value={o.hostsFailing} label={t("overview.failing")} tone={o.hostsFailing > 0 ? "bad" : "good"} />
                <Tile value={o.hostsStale} label={t("overview.stale", o.staleAfterDays)} tone={o.hostsStale > 0 ? "warn" : "good"} />
                <div className="tile score" title={t("overview.scoreHelp")}>
                  <ScoreRing score={o.score} />
                  <div className="tile-label">{t("overview.score")}</div>
                </div>
              </section>

              <section className="card">
                <h2>{t("overview.distribution")}</h2>
                <StatusBar counts={o.counts} legend />
                <p className="muted small">{t("overview.scoreHelp")}</p>
              </section>

              <div className="two">
                <section className="card">
                  <h2>{t("overview.topFailing")}</h2>
                  {o.topFailing.length === 0 ? (
                    <p className="muted">{t("overview.none")}</p>
                  ) : (
                    <table>
                      <tbody>
                        {o.topFailing.map((c) => (
                          <tr key={`${c.profile}/${c.id}`}>
                            <td className="mono">{c.id}</td>
                            <td>{c.title}</td>
                            <td>
                              <Severity value={c.severity} />
                            </td>
                            <td className="num">
                              <strong>{c.hosts}</strong>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </section>

                <section className="card">
                  <h2>{t("overview.regressions")}</h2>
                  <p className="muted small">{t("overview.regressionsHelp")}</p>
                  {o.recentRegressions.length === 0 ? (
                    <p className="muted">{t("overview.none")}</p>
                  ) : (
                    <table>
                      <tbody>
                        {o.recentRegressions.map((r) => (
                          <tr key={`${r.hostId}/${r.profile}/${r.id}`}>
                            <td>
                              <a href={`#/hosts/${r.hostId}`}>{r.host}</a>
                            </td>
                            <td className="mono">{r.id}</td>
                            <td>{r.title}</td>
                            <td>
                              <StatusBadge status={r.status} />
                            </td>
                            <td className="muted small">{ago(r.receivedAt, now, t)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </section>
              </div>
            </>
          )
        }
      </Await>
    </>
  );
}
