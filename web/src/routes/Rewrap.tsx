import { useCallback, useEffect, useState } from "react";
import { useAuth, isUnauthorized } from "../auth/AuthContext";
import { useLocale } from "../i18n/LocaleContext";
import { useToast } from "../components/Toast";
import { ApiError } from "../api/client";
import { currentRewrapJob, pauseRewrapJob, resumeRewrapJob, retryRewrapFailure, rewrapFailures } from "../api/endpoints";
import type { RewrapFailureItem, RewrapJobResponse } from "../api/types";

export default function Rewrap() {
  const { hasScope, reportUnauthorized } = useAuth();
  const { t } = useLocale();
  const toast = useToast();

  const [job, setJob] = useState<RewrapJobResponse | null | "none">(null);
  const [showFailures, setShowFailures] = useState(false);
  const [failures, setFailures] = useState<RewrapFailureItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setJob(await currentRewrapJob());
    } catch (err) {
      if (isUnauthorized(err)) return reportUnauthorized();
      if (err instanceof ApiError && err.status === 404) return setJob("none");
      setError(err instanceof ApiError ? err.message : t("common.error_generic"));
    }
  }, [reportUnauthorized, t]);

  useEffect(() => {
    void load();
    const interval = window.setInterval(() => void load(), 3000);
    return () => window.clearInterval(interval);
  }, [load]);

  const loadFailures = useCallback(async () => {
    if (!job || job === "none") return;
    try {
      const res = await rewrapFailures(job.jobId);
      setFailures(res.items);
    } catch (err) {
      if (isUnauthorized(err)) return reportUnauthorized();
      toast.push(err instanceof ApiError ? err.message : t("common.error_generic"), "danger");
    }
  }, [job, reportUnauthorized, t, toast]);

  useEffect(() => { if (showFailures) void loadFailures(); }, [showFailures, loadFailures]);

  async function togglePause() {
    if (!job || job === "none") return;
    setBusy(true);
    try {
      const res = job.state === "running" ? await pauseRewrapJob(job.jobId) : await resumeRewrapJob(job.jobId);
      setJob(res);
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : t("common.error_generic"), "danger");
    } finally {
      setBusy(false);
    }
  }

  async function retry(itemId: string) {
    if (!job || job === "none") return;
    try {
      const res = await retryRewrapFailure(job.jobId, itemId);
      setFailures((cur) => cur.map((f) => (f.itemId === itemId ? { ...f, resolved: res.resolved, attempts: res.attempts } : f)));
      toast.push(t("rewrap.retried"));
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : t("common.error_generic"), "danger");
    }
  }

  if (error) return <p style={{ color: "#d97878" }}>{error}</p>;
  if (job === null) return <p className="text-muted">{t("common.loading")}</p>;
  if (job === "none") return <div className="kr-empty">{t("rewrap.none")}</div>;

  const pct = job.total > 0 ? Math.min(100, Math.round((job.done / job.total) * 100)) : 0;

  return (
    <div className="kr-stack">
      <div className="card elev-sm">
        <div className="card-kicker">{t("rewrap.job")}</div>
        <div className="card-title mono-ltr">{job.from} → {job.to}</div>
        <div className="kr-bar-track"><div className="kr-bar-fill" style={{ width: `${pct}%` }} /></div>
        <div className="kr-row-between">
          <span className="text-muted" style={{ fontSize: 12 }}>{job.done} / {job.total} ({pct}%)</span>
          <span className="text-muted" style={{ fontSize: 12 }}>{job.rate.toFixed(1)}/s · ETA {job.eta ?? "—"}s</span>
        </div>
        <div className="text-muted" style={{ fontSize: 12 }}>
          {job.state === "running" && t("rewrap.running")}
          {job.state === "paused" && t("rewrap.paused")}
          {job.state === "completed" && t("rewrap.completed")}
        </div>
        {hasScope("rewrap_manage") && job.state !== "completed" && (
          <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => void togglePause()}>
            {job.state === "running" ? t("rewrap.pause") : t("rewrap.resume")}
          </button>
        )}
      </div>

      <div className="card">
        <div className="card-body">{t("rewrap.banner_title")} {t("rewrap.banner_body")}</div>
      </div>

      <button type="button" className="btn btn-ghost" style={{ alignSelf: "flex-start" }} onClick={() => setShowFailures((s) => !s)}>
        {showFailures ? t("rewrap.hide_failures") : t("rewrap.view_failures")}
      </button>

      {showFailures && (
        <table className="table">
          <thead>
            <tr>
              <th>{t("rewrap.col.item")}</th>
              <th>{t("rewrap.col.subject")}</th>
              <th>{t("rewrap.col.reason")}</th>
              <th>{t("rewrap.col.attempts")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {failures.map((f) => (
              <tr key={f.itemId}>
                <td className="mono-ltr">{f.itemId}</td>
                <td className="mono-ltr">{f.subjectKeyId}</td>
                <td>{f.reason}</td>
                <td>{f.attempts}</td>
                <td>
                  {!f.resolved && (
                    <button type="button" className="btn btn-ghost" onClick={() => void retry(f.itemId)}>{t("rewrap.retry")}</button>
                  )}
                  {f.resolved && <span className="tag tag-accent">{t("rewrap.resolved")}</span>}
                </td>
              </tr>
            ))}
            {failures.length === 0 && <tr><td colSpan={5} className="kr-empty">—</td></tr>}
          </tbody>
        </table>
      )}
    </div>
  );
}
