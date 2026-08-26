import { useNavigate } from "react-router-dom";
import { useLocale } from "../i18n/LocaleContext";

export default function Locked() {
  const { t } = useLocale();
  const navigate = useNavigate();

  return (
    <div className="kr-locked-wrap">
      <div className="card elev-lg kr-login-card">
        <div className="card-kicker">{t("app.title")}</div>
        <h2 className="card-title">{t("locked.title")}</h2>
        <p className="card-body">{t("locked.body")}</p>
        <p className="text-muted" style={{ fontSize: 12 }}>{t("locked.hint")}</p>
        <button type="button" className="btn btn-primary btn-block" onClick={() => navigate("/login", { replace: true })}>
          {t("locked.reauth")}
        </button>
      </div>
    </div>
  );
}
