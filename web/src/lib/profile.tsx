import { createContext, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, setProfile } from "./api";
import type { ProfileList } from "./types";

interface ProfileState {
  list: ProfileList | null;
  selected: string;
  select: (id: string) => void;
}

const Ctx = createContext<ProfileState>({ list: null, selected: "", select: () => {} });

const KEY = "hostlint.profile";

function remembered(): string {
  try {
    return localStorage.getItem(KEY) ?? "";
  } catch {
    return "";
  }
}

/** Knows the profiles of the latest scans and which one the pages show; renders its children once that is known. */
export function ProfileProvider({ children }: { children: ReactNode }) {
  const [list, setList] = useState<ProfileList | null>(null);
  const [selected, setSelected] = useState("");
  const [ready, setReady] = useState(false);

  const current = useRef("");
  current.current = selected;

  useEffect(() => {
    let alive = true;
    // The profiles of the latest scans change as hosts scan: ask again now and then, and when the tab is shown again.
    const load = () =>
      api.profiles().then(
        (l) => {
          if (!alive) return;
          const want = current.current || remembered();
          const pick = l.profiles.some((p) => p.id === want) ? want : l.default;
          setProfile(pick);
          setList(l);
          setSelected(pick); // the chosen profile is gone from the scans: the default takes its place
          setReady(true);
        },
        () => {
          // The pages show the server's default when they are not told.
          if (alive) setReady(true);
        },
      );
    void load();
    const timer = setInterval(() => void load(), 5 * 60_000);
    const visible = () => document.visibilityState === "visible" && void load();
    document.addEventListener("visibilitychange", visible);
    return () => {
      alive = false;
      clearInterval(timer);
      document.removeEventListener("visibilitychange", visible);
      setProfile(""); // signed out: nothing of this session is sent in the next one
    };
  }, []);

  const value = useMemo<ProfileState>(
    () => ({
      list,
      selected,
      select: (id) => {
        setProfile(id);
        setSelected(id);
        try {
          localStorage.setItem(KEY, id);
        } catch {
          // not remembered
        }
      },
    }),
    [list, selected],
  );
  if (!ready) return null;
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useProfile(): ProfileState {
  return useContext(Ctx);
}
