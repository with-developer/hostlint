// The address of a list (hosts, controls, images): the filters live in it, so a link shares a filtered list and a detail page's
// "back" link returns to the same list as the browser's back button does.
import { useEffect, useRef } from "react";
import { isList, parseRoute } from "./format";
import type { ListName } from "./format";
import { useDebounced } from "./hooks";

const DEFAULTS: Record<ListName, string> = { hosts: "#/hosts", controls: "#/controls", images: "#/images" };
const last: Record<ListName, string> = { ...DEFAULTS };

export function rememberListAddress(list: ListName, address: string): void {
  last[list] = address;
}

export function lastListAddress(list: ListName): string {
  return last[list];
}

/** Forget the filters: a detail page opened from somewhere else than the list goes back to the plain list. */
export function resetListAddresses(): void {
  Object.assign(last, DEFAULTS);
}

// Leaving for a page that is not a list or a detail of one (the overview, the matrix) forgets the remembered filters.
if (typeof addEventListener === "function") {
  addEventListener("hashchange", () => {
    const page = parseRoute(location.hash)[0];
    if (page !== "hosts" && page !== "controls" && page !== "images") resetListAddresses();
  });
}

/**
 * Keeps a list's filters in the address: the address follows the view (replacing the history entry, and not on every
 * keystroke: browsers limit how often it may change), and following a link to the list sets the view from the address.
 */
export function useListAddress<V>(list: ListName, view: V, apply: (v: V) => void, parse: (hash: string) => V, build: (v: V) => string): void {
  const address = build(view);
  const settled = useDebounced(address, 250);
  useEffect(() => {
    if (isList(location.hash, list)) rememberListAddress(list, address);
  }, [list, address]);
  useEffect(() => {
    if (!isList(location.hash, list) || location.hash === settled) return;
    try {
      history.replaceState(null, "", settled);
    } catch {
      // the address is a convenience: a browser that refuses the change leaves the list working
    }
  }, [list, settled]);
  const applyRef = useRef(apply);
  applyRef.current = apply;
  useEffect(() => {
    const on = () => {
      if (isList(location.hash, list)) applyRef.current(parse(location.hash));
    };
    addEventListener("hashchange", on);
    return () => removeEventListener("hashchange", on);
  }, [list, parse]);
}
