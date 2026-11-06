import { useState, type FormEvent } from "react";
import { api, ApiError } from "../lib/api";
import { useI18n } from "../lib/i18n";

export function Login({ onLogin }: { onLogin: () => void }) {
  const { t } = useI18n();
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
      setError(err instanceof ApiError && err.status === 401 ? t("login.failed") : (err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <form className="card" onSubmit={submit}>
        <h1>{t("login.title")}</h1>
        <p className="muted">{t("login.help")}</p>
        <label>
          {t("login.token")}
          <input type="password" autoComplete="off" spellCheck={false} value={token} onChange={(e) => setToken(e.target.value)} autoFocus required />
        </label>
        {error && (
          <p className="error-text" role="alert">
            {error}
          </p>
        )}
        <button type="submit" className="primary" disabled={busy || token.trim() === ""}>
          {t("login.submit")}
        </button>
      </form>
    </main>
  );
}
