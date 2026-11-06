import { useEffect, useState } from "react";
import { api, ApiError } from "./lib/api";
import { useHash } from "./lib/hooks";
import { useI18n } from "./lib/i18n";
import { parseRoute } from "./lib/format";
import { Login } from "./pages/Login";
import { OverviewPage } from "./pages/Overview";
import { HostsPage } from "./pages/Hosts";
import { HostPage } from "./pages/Host";

type Auth = "checking" | "in" | "out";

function applyTheme(theme: string | null) {
  if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
}

export function App() {
  const { t, toggle, lang } = useI18n();
  const hash = useHash();
  const [auth, setAuth] = useState<Auth>("checking");

  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  useEffect(() => {
    try {
      applyTheme(localStorage.getItem("hostlint.theme"));
    } catch {
      // the system theme stays
    }
    api.session().then(
      () => setAuth("in"),
      (e: unknown) => setAuth(e instanceof ApiError && e.status === 401 ? "out" : "out"),
    );
  }, []);

  function toggleTheme() {
    const dark = document.documentElement.dataset.theme === "dark" || (!document.documentElement.dataset.theme && matchMedia("(prefers-color-scheme: dark)").matches);
    const next = dark ? "light" : "dark";
    applyTheme(next);
    try {
      localStorage.setItem("hostlint.theme", next);
    } catch {
      // not remembered
    }
  }

  async function logout() {
    try {
      await api.logout();
    } finally {
      setAuth("out");
    }
  }

  if (auth === "checking") return <p className="muted center">{t("loading")}</p>;
  if (auth === "out") return <Login onLogin={() => setAuth("in")} />;

  const [page, arg] = parseRoute(hash);
  const hostId = Number(arg);
  let view;
  if (page === "hosts" && arg && Number.isInteger(hostId) && hostId > 0) view = <HostPage key={hostId} id={hostId} />;
  else if (page === "hosts") view = <HostsPage />;
  else view = <OverviewPage />;

  return (
    <>
      <header className="topbar">
        <a className="brand" href="#/">
          {t("app.name")}
        </a>
        <nav>
          <a href="#/" aria-current={page === undefined ? "page" : undefined}>
            {t("nav.overview")}
          </a>
          <a href="#/hosts" aria-current={page === "hosts" ? "page" : undefined}>
            {t("nav.hosts")}
          </a>
        </nav>
        <span className="spacer" />
        <button className="ghost" onClick={toggleTheme} title={t("theme.toggle")} aria-label={t("theme.toggle")}>
          ◐
        </button>
        <button className="ghost" onClick={toggle}>
          {t("lang.switch")}
        </button>
        <button className="ghost" onClick={logout}>
          {t("nav.logout")}
        </button>
      </header>
      <main>{view}</main>
    </>
  );
}
