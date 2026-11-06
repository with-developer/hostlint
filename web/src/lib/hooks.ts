import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "./api";

export interface Async<T> {
  data: T | null;
  error: ApiError | Error | null;
  loading: boolean;
  reload: () => void;
}

/** Runs an async function when its dependencies change; a late answer for an old request is dropped. */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]): Async<T> {
  const [state, setState] = useState<{ data: T | null; error: Error | null; loading: boolean }>({ data: null, error: null, loading: true });
  const [tick, setTick] = useState(0);
  const latest = useRef(0);
  useEffect(() => {
    const id = ++latest.current;
    setState((s) => ({ ...s, loading: true, error: null }));
    fn().then(
      (data) => id === latest.current && setState({ data, error: null, loading: false }),
      (error: Error) => id === latest.current && setState({ data: null, error, loading: false }),
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  const reload = useCallback(() => setTick((n) => n + 1), []);
  return { ...state, reload };
}

/** The current time, refreshed every minute, so "5 min ago" stays true. */
export function useNow(): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 60_000);
    return () => clearInterval(id);
  }, []);
  return now;
}

/** The hash of the URL, as the router's state. */
export function useHash(): string {
  const [hash, setHash] = useState(() => location.hash);
  useEffect(() => {
    const on = () => setHash(location.hash);
    addEventListener("hashchange", on);
    return () => removeEventListener("hashchange", on);
  }, []);
  return hash;
}

/** A value that follows another one after a pause: for search boxes. */
export function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setV(value), ms);
    return () => clearTimeout(id);
  }, [value, ms]);
  return v;
}
