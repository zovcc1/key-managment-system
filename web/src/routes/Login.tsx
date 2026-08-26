import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { useLocale } from "../i18n/LocaleContext";
import { ApiError } from "../api/client";

const PROVIDERS = ["file", "env", "vault", "kms"];

export default function Login() {
  const { login } = useAuth();
  const { t } = useLocale();
  const navigate = useNavigate();
  const [apiKey, setApiKey] = useState("");
  const [provider, setProvider] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(apiKey.trim(), provider || undefined);
      navigate("/dashboard", { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("common.error_generic"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="kr-login-wrap">
      <form className="card elev-lg kr-login-card" onSubmit={submit}>
        <div className="card-kicker">{t("app.title")}</div>
        <h2 className="card-title">{t("login.subtitle")}</h2>

        <div className="field">
          <label htmlFor="apiKey">{t("login.api_key_label")}</label>
          <input
            id="apiKey"
            className="input"
            type="password"
            autoComplete="off"
            placeholder={t("login.api_key_placeholder")}
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            required
          />
        </div>

        <div className="field">
          <label htmlFor="provider">{t("login.provider_label")}</label>
          <select
            id="provider"
            className="input"
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
          >
            <option value="">—</option>
            {PROVIDERS.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        </div>

        {error && <p className="card-body" style={{ color: "#d97878" }}>{error}</p>}

        <button type="submit" className="btn btn-primary btn-block" disabled={busy || !apiKey.trim()}>
          {busy ? t("login.submitting") : t("login.submit")}
        </button>
      </form>
    </div>
  );
}
