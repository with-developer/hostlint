import { useState, type FormEvent } from "react";
import { api, ApiError } from "../lib/api";
import { useI18n } from "../lib/i18n";
import { IconGlobe, IconShield } from "../components/icons";

export function Login({ onLogin, notice }: { onLogin: () => void; notice?: string }) {
  const { t, toggle } = useI18n();
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.login(token.trim());
      setToken("");
      onLogin();
    } catch (err) {
      setError(err instanceof ApiError && err.status === 401 ? t("login.failed") : (err as Error).message || t("loadFailed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <aside className="login-art">
        <div className="login-brand">
          <IconShield size={28} /> {t("app.name")}
        </div>
        <p className="login-tagline">{t("login.tagline")}</p>
        <div className="login-bars" aria-hidden="true">
          {[92, 74, 58, 83, 66].map((w, i) => (
            <span key={i} style={{ width: `${w}%` }} />
          ))}
        </div>
      </aside>
      <section className="login-form">
        <button className="ghost lang" onClick={toggle}>
          <IconGlobe /> {t("lang.switch")}
        </button>
        <form onSubmit={submit}>
          <h1>{t("login.title")}</h1>
          <p className="muted">{t("login.hint")}</p>
          {notice && <p className="notice">{notice}</p>}
          <label htmlFor="token">{t("login.token")}</label>
          <input id="token" type="password" autoComplete="off" spellCheck={false} value={token} onChange={(e) => setToken(e.target.value)} placeholder="hlt_api_…" autoFocus required />
          <p className="muted small">{t("login.help")}</p>
          {error && (
            <p className="error-text" role="alert">
              {error}
            </p>
          )}
          <button type="submit" className="primary wide" disabled={busy || token.trim() === ""}>
            {t("login.submit")}
          </button>
        </form>
      </section>
    </main>
  );
}
