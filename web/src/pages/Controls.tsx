import { useMemo, useState } from "react";
import { api } from "../lib/api";
import { useAsync } from "../lib/hooks";
import { useI18n } from "../lib/i18n";
import { compareControls, controlsAddress, ctitle, parseControlsView } from "../lib/format";
import { lastListAddress, useListAddress } from "../lib/listAddress";
import { Avatar, Await, Empty, Inline, PageHeader, Severity, Skeleton, StatusBadge, StatusBar } from "../components/ui";
import { IconSearch } from "../components/icons";
import { STATUSES, type Status } from "../lib/types";
import { STALE_DAYS } from "./Overview";

export function ControlsPage() {
  const { t, lang } = useI18n();
  const state = useAsync(() => api.controls(), []);
  const [initial] = useState(() => parseControlsView(location.hash));
  const [q, setQ] = useState(initial.q);
  const [failing, setFailing] = useState(initial.failing);
  // The filters are in the address, as on the host list.
  useListAddress(
    "controls",
    { q, failing },
    (v) => {
      setQ(v.q);
      setFailing(v.failing);
    },
    parseControlsView,
    controlsAddress,
  );
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (state.data?.controls ?? [])
      .filter((c) => (!failing || (c.counts.FAIL ?? 0) > 0) && (!needle || c.id.toLowerCase().includes(needle) || c.title.toLowerCase().includes(needle) || (c.titleKo ?? "").toLowerCase().includes(needle)))
      .sort((a, b) => (b.counts.FAIL ?? 0) - (a.counts.FAIL ?? 0) || compareControls({ status: "PASS", severity: a.severity, id: a.id }, { status: "PASS", severity: b.severity, id: b.id }));
  }, [state.data, q, failing]);
  return (
    <>
      <PageHeader title={t("controls.title")} subtitle={t("controls.subtitle")} />
      <div className="toolbar">
        <label className="search">
          <IconSearch />
          <input type="search" placeholder={t("controls.search")} aria-label={t("controls.search")} value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
        <div className="segmented" role="group">
          <button className={!failing ? "on" : ""} aria-pressed={!failing} onClick={() => setFailing(false)}>
            {t("hosts.all")}
          </button>
          <button className={failing ? "on" : ""} aria-pressed={failing} onClick={() => setFailing(true)}>
            {t("controls.failingOnly")}
          </button>
        </div>
      </div>
      <Await state={state} skeleton={<div className="card"><Skeleton height={260} /></div>}>
        {() =>
          rows.length === 0 ? (
            <Empty>{t("controls.noMatch")}</Empty>
          ) : (
            <section className="card flush">
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>{t("controls.title")}</th>
                      <th>{t("controls.hosts")}</th>
                      <th className="num">{t("status.FAIL")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((c) => (
                      <tr key={`${c.profile}/${c.id}`} className="clickable" onClick={() => (location.hash = `#/controls/${c.profile}/${c.id}`)}>
                        <td className="mono id">
                          <a href={`#/controls/${c.profile}/${c.id}`} onClick={(e) => e.stopPropagation()}>
                            {c.id}
                          </a>
                        </td>
                        <td>
                          {ctitle(c, lang)} <Severity value={c.severity} />
                        </td>
                        <td className="bar-cell">
                          <StatusBar counts={c.counts} thin />
                        </td>
                        <td className="num">{c.counts.FAIL ? <strong className="c-FAIL">{c.counts.FAIL}</strong> : <span className="muted">0</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )
        }
      </Await>
    </>
  );
}

export function ControlPage({ profile, id }: { profile: string; id: string }) {
  const { t, lang } = useI18n();
  const state = useAsync(() => api.control(profile, id, STALE_DAYS), [profile, id], false);
  const [shown, setShown] = useState<Set<Status>>(new Set(["FAIL", "ERROR", "MANUAL", "WAIVED"]));
  return (
    <>
      <p className="crumb">
        <a href={lastListAddress("controls")}>{t("controls.back")}</a>
      </p>
      <Await state={state}>
        {({ control: c, info }) => {
          const toggle = (s: Status) =>
            setShown((prev) => {
              const next = new Set(prev);
              if (next.has(s)) next.delete(s);
              else next.add(s);
              return next;
            });
          const hosts = c.hosts.filter((h) => shown.has(h.status));
          return (
            <div className="stack">
              <header className="card">
                <div className="titlebar">
                  <h1>
                    <span className="mono">{c.id}</span> {ctitle({ title: c.title, titleKo: c.titleKo ?? info?.titleKo }, lang)}
                  </h1>
                  <Severity value={c.severity} />
                </div>
                <p className="muted small">{c.profile}</p>
                <StatusBar counts={c.counts} legend />
              </header>

              {info?.manual && (
                <section className="card">
                  <h2>{t("controls.review")}</h2>
                  <p>{lang === "ko" && info.manualKo ? info.manualKo : info.manual}</p>
                </section>
              )}
              {info?.checks.map((ch) => (
                <section className="card" key={ch.id}>
                  <h2>
                    <span className="mono">{ch.id}</span> {lang === "ko" && ch.titleKo ? ch.titleKo : ch.title}
                  </h2>
                  {(lang === "ko" && ch.descriptionKo ? ch.descriptionKo : ch.description) && (
                    <>
                      <h3>{t("controls.what")}</h3>
                      <p className="prose"><Inline text={lang === "ko" && ch.descriptionKo ? ch.descriptionKo : ch.description} /></p>
                    </>
                  )}
                  {(lang === "ko" && ch.rationaleKo ? ch.rationaleKo : ch.rationale) && (
                    <>
                      <h3>{t("controls.why")}</h3>
                      <p className="prose"><Inline text={lang === "ko" && ch.rationaleKo ? ch.rationaleKo : ch.rationale} /></p>
                    </>
                  )}
                  {(lang === "ko" && ch.remediationKo ? ch.remediationKo : ch.remediation) && (
                    <>
                      <h3>{t("controls.fix")}</h3>
                      <p className="prose remedy"><Inline text={lang === "ko" && ch.remediationKo ? ch.remediationKo : ch.remediation} /></p>
                    </>
                  )}
                </section>
              ))}

              <section className="card flush">
                <div className="toolbar pad">
                  <strong>{t("controls.onHosts")}</strong>
                  <div className="chips" role="group">
                    {STATUSES.filter((s) => (c.counts[s] ?? 0) > 0).map((s) => (
                      <button key={s} className={`chip s-${s} ${shown.has(s) ? "on" : ""}`} aria-pressed={shown.has(s)} onClick={() => toggle(s)}>
                        {t(`status.${s}`)} <span className="count">{c.counts[s]}</span>
                      </button>
                    ))}
                  </div>
                </div>
                {hosts.length === 0 ? (
                  <Empty>{t("overview.none")}</Empty>
                ) : (
                  <ul className="hostlist">
                    {hosts.map((h) => (
                      <li key={h.hostId}>
                        <a className="hostname" href={`#/hosts/${h.hostId}`}>
                          <Avatar name={h.host} size={28} /> {h.host}
                        </a>
                        {h.stale && <span className="badge s-MANUAL">{t("stale")}</span>}
                        <span className="push">
                          <StatusBadge status={h.status} />
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            </div>
          );
        }}
      </Await>
    </>
  );
}
