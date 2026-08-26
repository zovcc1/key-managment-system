import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { useLocale } from "../i18n/LocaleContext";
import type { ChromeKey, Locale } from "../i18n/chrome";

const NAV: { to: string; key: ChromeKey; titleKey: ChromeKey }[] = [
  { to: "/dashboard", key: "nav.dashboard", titleKey: "title.dashboard" },
  { to: "/map", key: "nav.map", titleKey: "title.map" },
  { to: "/keys", key: "nav.keys", titleKey: "title.keys" },
  { to: "/rewrap", key: "nav.rewrap", titleKey: "title.rewrap" },
  { to: "/privacy", key: "nav.privacy", titleKey: "title.privacy" },
  { to: "/audit", key: "nav.audit", titleKey: "title.audit" },
  { to: "/settings", key: "nav.settings", titleKey: "title.settings" },
];

function formatCountdown(ms: number): string {
  const totalSeconds = Math.floor(ms / 1000);
  const m = Math.floor(totalSeconds / 60);
  const s = totalSeconds % 60;
  return `${m}:${String(s).padStart(2, "0")}`;
}

export default function Shell() {
  const { operator, role, provider, lock, msUntilLock } = useAuth();
  const { t, locale, setLocale } = useLocale();
  const location = useLocation();
  const current = NAV.find((n) => location.pathname.startsWith(n.to));

  return (
    <div className="kr-shell">
      <aside className="kr-sidebar">
        <div className="nav-brand">{t("app.title")}</div>
        <div className="kr-sidebar-tagline">{t("app.tagline")}</div>
        <ul className="kr-navlist">
          {NAV.map((item) => (
            <li key={item.to}>
              <NavLink to={item.to} aria-current={location.pathname.startsWith(item.to) ? "page" : undefined}>
                {t(item.key)}
              </NavLink>
            </li>
          ))}
        </ul>
      </aside>
      <div className="kr-main">
        <header className="kr-header">
          <div className="kr-header-titles">
            <h1>{current ? t(current.titleKey) : t("app.title")}</h1>
            <div className="kr-header-path mono-ltr">{location.pathname}</div>
          </div>
          <div className="kr-header-meta">
            {msUntilLock !== null && (
              <span className={`kr-header-lockin${msUntilLock < 60_000 ? " kr-lockin-soon" : ""}`}>
                {t("app.locked_hint")} {formatCountdown(msUntilLock)}
              </span>
            )}
            <span className="tag tag-neutral">{t("app.provider")}: {provider}</span>
            <button
              type="button"
              className="btn btn-ghost"
              onClick={() => setLocale((locale === "en" ? "ar" : "en") as Locale)}
              aria-label="Toggle language"
            >
              {locale === "en" ? "AR" : "EN"}
            </button>
            <span className="text-muted" style={{ fontSize: 13 }}>
              {operator} · {role}
            </span>
            <button type="button" className="btn btn-secondary" onClick={() => void lock()}>
              {t("app.lock")}
            </button>
          </div>
        </header>
        <main className="kr-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
