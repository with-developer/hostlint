// The key a request is recorded under: the path and the sorted query, without the profile and the stale-days (the demo has one
// profile and one value of the latter). Plain JavaScript so that the recorder (scripts/record-demo.mjs, run by node) and the demo
// (demoApi.ts) share one function and cannot disagree.

/** @param {string} path */
export function demoKey(path) {
  const u = new URL(path, "http://demo.invalid");
  u.searchParams.delete("profile");
  u.searchParams.delete("staleDays");
  u.searchParams.sort();
  const q = u.searchParams.toString();
  return u.pathname + (q ? "?" + q : "");
}
