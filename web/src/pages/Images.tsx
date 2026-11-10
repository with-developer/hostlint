import { useState } from "react";
import { api } from "../lib/api";
import { useAsync, useDebounced, useNow } from "../lib/hooks";
import { useI18n } from "../lib/i18n";
import { ago, imagesAddress, parseImagesView } from "../lib/format";
import { useListAddress } from "../lib/listAddress";
import { Avatar, Await, Empty, PageHeader, ScorePill, Skeleton, SignedBadge, StatusBar } from "../components/ui";
import { MiniSpark } from "../components/charts";
import { IconSearch } from "../components/icons";
import type { HostSummary } from "../lib/types";
import { STALE_DAYS } from "./Overview";

/** Container images that CI pushed (ADR 0016): one row per image, its latest scan counted, with the tag and image ID of it. */
export function ImagesPage() {
  const { t } = useI18n();
  const now = useNow();
  const [q, setQ] = useState(() => parseImagesView(location.hash).q);
  useListAddress("images", { q }, (v) => setQ(v.q), parseImagesView, imagesAddress);
  const query = useDebounced(q, 250);
  const state = useAsync(() => api.hosts({ q: query, kind: "image", sort: "recent", limit: 200, staleDays: STALE_DAYS }), [query]);
  return (
    <>
      <PageHeader title={t("images.title")} subtitle={t("images.subtitle")} />
      <div className="toolbar">
        <label className="search">
          <IconSearch />
          <input type="search" placeholder={t("images.search")} aria-label={t("images.search")} value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
      </div>
      <Await state={state} skeleton={<div className="card"><Skeleton height={180} /></div>}>
        {(d) => (
          <section className="card flush">
            {d.hosts.length === 0 ? (
              <Empty>{t("images.none")}</Empty>
            ) : (
              <div className="table-wrap">
                <table className="hosts">
                  <thead>
                    <tr>
                      <th>{t("images.title")}</th>
                      <th>{t("hosts.status")}</th>
                      <th className="num">{t("hosts.score")}</th>
                      <th>{t("hosts.lastScan")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.hosts.map((h) => (
                      <ImageRow key={h.id} image={h} now={now} />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}
      </Await>
    </>
  );
}

function ImageRow({ image: h, now }: { image: HostSummary; now: number }) {
  const { t } = useI18n();
  return (
    <tr onClick={() => (location.hash = `#/images/${h.id}`)} className="clickable">
      <td>
        <a className="hostname" href={`#/images/${h.id}`} onClick={(e) => e.stopPropagation()}>
          <Avatar name={h.name} /> {h.name}
        </a>{" "}
        {h.signed && <SignedBadge fingerprint={h.keyFingerprint} />}
        <div className="hostmeta muted small">
          {h.imageRef && <span className="mono">{h.imageRef}</span>}
          {h.imageDigest && (
            <span className="mono" title={h.imageDigest}>
              {h.imageDigest.slice(0, 19)}
            </span>
          )}
          {h.os && <span>{h.os}</span>}
        </div>
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
      <td>{ago(h.lastScanAt, now, t)}</td>
    </tr>
  );
}
