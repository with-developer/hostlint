import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
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

  useEffect(() => {
    let alive = true;
    api.profiles().then(
      (l) => {
        if (!alive) return;
        const want = remembered();
        const pick = l.profiles.some((p) => p.id === want) ? want : l.default;
        setProfile(pick);
        setList(l);
        setSelected(pick);
        setReady(true);
      },
      () => {
        // The pages show the server's default when they are not told.
        if (alive) setReady(true);
      },
    );
    return () => {
      alive = false;
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
