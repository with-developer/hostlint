// Records what the dashboard asks of `vmsctl server demo`, for the static live demo (site/demo): the answers are saved as one JSON
// file, which the demo build reads instead of a server (src/lib/demoApi.ts). The demo fleet is made up, so nothing here is real data.
//
// usage: node scripts/record-demo.mjs BASE_URL READ_TOKEN OUT.json
import { writeFileSync } from "node:fs";

const [base, token, out] = process.argv.slice(2);
if (!base || !token || !out) {
  console.error("usage: node scripts/record-demo.mjs BASE_URL READ_TOKEN OUT.json");
  process.exit(2);
}

const STALE = 7;
const data = {};

async function get(path, { optional = false } = {}) {
  const res = await fetch(base + path, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) {
    if (optional) return null;
    throw new Error(`${path}: ${res.status}`);
  }
  return res.json();
}

// The key a request is looked up by: the path, without the profile and the stale-days (the demo has one profile and one value).
function key(path) {
  const u = new URL(path, "http://x");
  u.searchParams.delete("profile");
  u.searchParams.delete("staleDays");
  u.searchParams.sort();
  const q = u.searchParams.toString();
  return u.pathname + (q ? "?" + q : "");
}

async function record(path, opts) {
  const body = await get(path, opts);
  if (body !== null) data[key(path)] = body;
  return body;
}

await record("/api/v1/profiles");
await record(`/api/v1/overview?staleDays=${STALE}`);
for (const days of [7, 30, 90]) await record(`/api/v1/trend?days=${days}`);
await record("/api/v1/controls");
await record(`/api/v1/matrix?staleDays=${STALE}`);

// Every host and image the lists can show: the list of each kind in full (the demo filters and sorts it itself).
const hosts = await record(`/api/v1/hosts?staleDays=${STALE}&limit=500&kind=host`);
const images = await record(`/api/v1/hosts?staleDays=${STALE}&limit=500&kind=image`, { optional: true });
const all = [...(hosts?.hosts ?? []), ...(images?.hosts ?? [])];

const latest = [];
for (const h of all) {
  const detail = await record(`/api/v1/hosts/${h.id}?staleDays=${STALE}`);
  await record(`/api/v1/hosts/${h.id}/agent`, { optional: true });
  if (detail.scans?.length) latest.push(detail.scans[0].id);
  // The "compare" button of a scan in the history: it asks for the scan and the one before it.
  for (let i = 0; i + 1 < (detail.scans?.length ?? 0); i++) {
    await record(`/api/v1/diff?old=${detail.scans[i + 1].id}&new=${detail.scans[i].id}`, { optional: true });
  }
}
for (const id of latest) await record(`/api/v1/scans/${id}`);

const controls = data["/api/v1/controls"]?.controls ?? [];
for (const c of controls) {
  await record(`/api/v1/controls/${encodeURIComponent(c.profile)}/${encodeURIComponent(c.id)}?staleDays=${STALE}`);
}

// When it was recorded: the demo moves every time forward by the age of the file, so "41 minutes ago" stays that.
data.__recordedAt = new Date().toISOString();
writeFileSync(out, JSON.stringify(data));
const kb = Math.round(JSON.stringify(data).length / 1024);
console.error(`recorded ${Object.keys(data).length} answers, ${kb} KB, ${all.length} hosts and images, ${controls.length} controls`);
