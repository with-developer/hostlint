import { useCallback, useEffect, useState } from "react";
import { api, setUnauthorizedHandler } from "./lib/api";
import { useHash } from "./lib/hooks";
import { ProfileProvider, useProfile } from "./lib/profile";
import { useI18n } from "./lib/i18n";
import { parseRoute } from "./lib/format";
import { Login } from "./pages/Login";
import { OverviewPage } from "./pages/Overview";
import { HostsPage } from "./pages/Hosts";
import { HostPage } from "./pages/Host";
import { MatrixPage } from "./pages/Matrix";
import { ControlPage, ControlsPage } from "./pages/Controls";
import { IconGlobe, IconGrid, IconList, IconLogout, IconMoon, IconOverview, IconServer, IconShield, IconSun } from "./components/icons";

type Auth = "checking" | "in" | "out" | "failed";

function isDark(): boolean {
  const set = document.documentElement.dataset.theme;
  return set ? set === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
}

export function App() {
  const { t, lang } = useI18n();
  const hash = useHash();
  const [auth, setAuth] = useState<Auth>("checking");
  const [expired, setExpired] = useState(false);
  const [dark, setDark] = useState(isDark);

  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  const check = useCallback(() => {
    setAuth("checking");
    api.session().then(
      () => setAuth("in"),
      (e: { status?: number }) => setAuth(e.status === 401 ? "out" : "failed"),
    );
  }, []);

  useEffect(() => {
    try {
      const theme = localStorage.getItem("hostlint.theme");
      if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
    } catch {
      // the system theme stays
    }
    setDark(isDark());
    // A request the server answers with 401 means the session ended: show the sign-in form.
    setUnauthorizedHandler(() => {
      setExpired(true);
      setAuth("out");
    });
    check();
  }, [check]);

  function toggleTheme() {
    const next = isDark() ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    setDark(next === "dark");
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
      setExpired(false);
      setAuth("out");
    }
  }

  if (auth === "checking") return <p className="muted center">{t("loading")}</p>;
  if (auth === "failed")
    return (
      <div className="center">
        <p className="error-text">{t("loadFailed")}</p>
        <button onClick={check}>{t("retry")}</button>
      </div>
    );
  if (auth === "out")
    return (
      <Login
        notice={expired ? t("sessionExpired") : undefined}
        onLogin={() => {
          setExpired(false);
          setAuth("in");
        }}
      />
    );

  return (
    <ProfileProvider>
      <Shell hash={hash} dark={dark} toggleTheme={toggleTheme} logout={logout} />
    </ProfileProvider>
  );
}

/** The sidebar and the page, once the person is signed in and the profiles are known. */
function Shell({ hash, dark, toggleTheme, logout }: { hash: string; dark: boolean; toggleTheme: () => void; logout: () => void }) {
  const { t, toggle } = useI18n();
  const { list, selected, select } = useProfile();
  const [page, arg, arg2] = parseRoute(hash);
  const hostId = Number(arg);
  let view;
  if (page === "hosts" && arg && Number.isInteger(hostId) && hostId > 0) view = <HostPage key={hostId} id={hostId} />;
  else if (page === "hosts") view = <HostsPage />;
  else if (page === "matrix") view = <MatrixPage />;
  else if (page === "controls" && arg && arg2) view = <ControlPage key={`${arg}/${arg2}`} profile={arg} id={arg2} />;
  else if (page === "controls") view = <ControlsPage />;
  else view = <OverviewPage />;
  const current = page === "hosts" || page === "matrix" || page === "controls" ? page : "overview";

  const nav: [string, string, string, JSX.Element][] = [
    ["overview", "#/", t("nav.overview"), <IconOverview key="o" />],
    ["hosts", "#/hosts", t("nav.hosts"), <IconServer key="h" />],
    ["controls", "#/controls", t("nav.controls"), <IconList key="c" />],
    ["matrix", "#/matrix", t("nav.matrix"), <IconGrid key="m" />],
  ];

  return (
    <div className="app">
      <aside className="sidebar">
        <a className="brand" href="#/">
          <IconShield size={24} />
          <span>{t("app.name")}</span>
        </a>
        <nav aria-label={t("nav.section")}>
          <span className="nav-section">{t("nav.section")}</span>
          {nav.map(([key, href, label, icon]) => (
            <a key={key} href={href} aria-current={current === key ? "page" : undefined}>
              {icon}
              <span>{label}</span>
            </a>
          ))}
        </nav>
        {list && list.profiles.length > 1 && (
          <div className="profile-select">
            <label htmlFor="profile">{t("profile.label")}</label>
            <select id="profile" value={selected} onChange={(e) => select(e.target.value)}>
              {list.profiles.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.id} ({t("profile.hosts", { n: p.hosts })})
                </option>
              ))}
            </select>
          </div>
        )}
        <div className="sidebar-foot">
          <button className="ghost" onClick={toggleTheme}>
            {dark ? <IconSun /> : <IconMoon />}
            <span>{dark ? t("theme.light") : t("theme.dark")}</span>
          </button>
          <button className="ghost" onClick={toggle}>
            <IconGlobe />
            <span>{t("lang.switch")}</span>
          </button>
          <button className="ghost" onClick={logout}>
            <IconLogout />
            <span>{t("nav.logout")}</span>
          </button>
        </div>
      </aside>
      <main key={selected}>{view}</main>
    </div>
  );
}
