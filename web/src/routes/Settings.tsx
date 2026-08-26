import { useCallback, useEffect, useState } from "react";
import { useAuth, isUnauthorized } from "../auth/AuthContext";
import { useLocale } from "../i18n/LocaleContext";
import { useToast } from "../components/Toast";
import { ApiError } from "../api/client";
import { activateProvider, getBackupJob, getSettings, getThreatModel, listProviders, patchSettings, startBackupVerify } from "../api/endpoints";
import type { BackupJobStatus, ProvidersResponse, SettingsResponse, ThreatModelResponse } from "../api/types";

export default function Settings() {
  const { hasScope, reportUnauthorized } = useAuth();
  const { t } = useLocale();
  const toast = useToast();

  const [settings, setSettings] = useState<SettingsResponse | null>(null);
  const [providers, setProviders] = useState<ProvidersResponse | null>(null);
  const [threatModel, setThreatModel] = useState<ThreatModelResponse | null>(null);
  const [rotationDays, setRotationDays] = useState("");
  const [alertThreshold, setAlertThreshold] = useState("");
  const [savingSettings, setSavingSettings] = useState(false);
  const [activating, setActivating] = useState<string | null>(null);
  const [backupBusy, setBackupBusy] = useState(false);
  const [backupResult, setBackupResult] = useState<BackupJobStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [s, p, tm] = await Promise.all([getSettings(), listProviders(), getThreatModel()]);
      setSettings(s);
      setRotationDays(String(s.rotationIntervalDays));
      setAlertThreshold(String(s.alertThreshold));
      setProviders(p);
      setThreatModel(tm);
    } catch (err) {
      if (isUnauthorized(err)) return reportUnauthorized();
      setError(err instanceof ApiError ? err.message : t("common.error_generic"));
    }
  }, [reportUnauthorized, t]);

  useEffect(() => { void load(); }, [load]);

  async function saveSettings() {
    setSavingSettings(true);
    try {
      const res = await patchSettings({
        rotationIntervalDays: Number(rotationDays) || undefined,
        alertThreshold: Number(alertThreshold) || undefined,
      });
      setSettings(res);
      toast.push(t("toast.settings_saved"));
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : t("common.error_generic"), "danger");
    } finally {
      setSavingSettings(false);
    }
  }

  async function activate(providerId: string) {
    setActivating(providerId);
    try {
      await activateProvider(providerId);
      await load();
      toast.push(t("toast.provider_set", { label: providerId }));
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : t("common.error_generic"), "danger");
    } finally {
      setActivating(null);
    }
  }

  async function runBackupVerify() {
    setBackupBusy(true);
    setBackupResult(null);
    try {
      const { jobId } = await startBackupVerify();
      setBackupResult(await getBackupJob(jobId));
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : t("common.error_generic"), "danger");
    } finally {
      setBackupBusy(false);
    }
  }

  if (error) return <p style={{ color: "#d97878" }}>{error}</p>;
  if (!settings || !providers) return <p className="text-muted">{t("common.loading")}</p>;

  return (
    <div className="kr-stack">
      <div className="card">
        <div className="card-title">{t("settings.provider_title")}</div>
        <p className="card-body">{t("settings.provider_body")}</p>
        <div className="seg">
          {providers.items.map((p) => (
            <label key={p.id} className="seg-opt">
              <input
                type="radio"
                name="provider"
                checked={p.active}
                disabled={!p.available || activating !== null || !hasScope("provider_activate")}
                onChange={() => void activate(p.id)}
              />
              {p.id}{!p.available && ` (${t("dash.status.missing")})`}
            </label>
          ))}
        </div>
      </div>

      <div className="card">
        <div className="card-title">{t("settings.rotation_title")}</div>
        <div className="kr-grid-2">
          <div className="field">
            <label htmlFor="rotationDays">{t("settings.rotation_interval")}</label>
            <input id="rotationDays" className="input" type="number" min={1} value={rotationDays} onChange={(e) => setRotationDays(e.target.value)} disabled={!hasScope("settings_write")} />
          </div>
          <div className="field">
            <label htmlFor="alertThreshold">{t("settings.alert_threshold")}</label>
            <input id="alertThreshold" className="input" type="number" min={1} value={alertThreshold} onChange={(e) => setAlertThreshold(e.target.value)} disabled={!hasScope("settings_write")} />
          </div>
        </div>
        {hasScope("settings_write") && (
          <button type="button" className="btn btn-primary" style={{ alignSelf: "flex-start" }} disabled={savingSettings} onClick={() => void saveSettings()}>
            {t("settings.save")}
          </button>
        )}
      </div>

      <div className="card">
        <div className="card-title">{t("settings.backup_title")}</div>
        <p className="card-body">{t("settings.backup_body")}</p>
        {hasScope("settings_write") && (
          <button type="button" className="btn btn-secondary" style={{ alignSelf: "flex-start" }} disabled={backupBusy} onClick={() => void runBackupVerify()}>
            {backupBusy ? t("settings.running") : t("settings.run_backup")}
          </button>
        )}
        {backupResult && (
          <div className="kr-row">
            <span className={`tag ${backupResult.ok ? "tag-accent" : "tag-neutral"}`}>{backupResult.status}</span>
            {backupResult.error && <span className="text-muted" style={{ fontSize: 12 }}>{backupResult.error}</span>}
          </div>
        )}
      </div>

      {threatModel && (
        <div className="card">
          <div className="card-title">{threatModel.title}</div>
          <p className="card-body">{threatModel.scopeIntro}</p>
          <h6>{t("settings.does_not_protect")}</h6>
          <ul style={{ margin: 0, paddingInlineStart: 18, fontSize: 13 }}>
            {threatModel.doesNotProtectAgainst.map((line) => <li key={line}>{line}</li>)}
          </ul>
          <p className="text-muted" style={{ fontSize: 12 }}>{threatModel.closing}</p>
        </div>
      )}
    </div>
  );
}
