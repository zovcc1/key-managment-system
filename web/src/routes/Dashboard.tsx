import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth, isUnauthorized } from "../auth/AuthContext";
import { useLocale } from "../i18n/LocaleContext";
import { useToast } from "../components/Toast";
import { ApiError } from "../api/client";
import { approveApproval, getApproval, getDashboard, getDecryptFailures } from "../api/endpoints";
import type { ApprovalResponse, DashboardResponse, DecryptFailuresResponse } from "../api/types";
import RotateDialog from "../components/RotateDialog";

function statusDot(status: string) {
  if (status === "ok" || status === "connected") return "kr-dot-ok";
  if (status === "warn" || status === "degraded") return "kr-dot-warn";
  return "kr-dot-bad";
}

function Sparkline({ data }: { data: DecryptFailuresResponse["buckets"] }) {
  if (data.length === 0) return <div className="text-muted" style={{ fontSize: 12 }}>—</div>;
  const max = Math.max(1, ...data.map((b) => b.count));
  const w = 240;
  const h = 48;
  const barW = w / data.length;
  return (
    <svg className="kr-spark" width={w} height={h} role="img" aria-label="decrypt failures per hour">
      {data.map((b, i) => {
        const barH = (b.count / max) * h;
        return (
          <rect
            key={b.hour}
            className="kr-spark-bar"
            x={i * barW + 1}
            y={h - barH}
            width={Math.max(1, barW - 2)}
            height={barH}
          />
        );
      })}
    </svg>
  );
}

function ApprovalLookup() {
  const { t } = useLocale();
  const toast = useToast();
  const [id, setId] = useState("");
  const [found, setFound] = useState<ApprovalResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function lookup() {
    setBusy(true);
    setError(null);
    setFound(null);
    try {
      setFound(await getApproval(id.trim()));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("common.error_generic"));
    } finally {
      setBusy(false);
    }
  }

  async function approve() {
    if (!found) return;
    setBusy(true);
    setError(null);
    try {
      const res = await approveApproval(found.id);
      setFound(res);
      toast.push(t("toast.settings_saved"));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("common.error_generic"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <div className="card-title">{t("dash.approve_title")}</div>
      <p className="card-body text-muted">{t("dash.approve_hint")}</p>
      <div className="kr-row">
        <input
          className="input mono-ltr"
          value={id}
          onChange={(e) => setId(e.target.value)}
          placeholder={t("dash.approve_placeholder")}
        />
        <button type="button" className="btn btn-secondary" disabled={!id.trim() || busy} onClick={() => void lookup()}>
          {t("dash.approve_lookup")}
        </button>
      </div>
      {found && (
        <div className="card" style={{ background: "var(--color-bg)" }}>
          <div className="kr-row-between">
            <span className="text-muted" style={{ fontSize: 12 }}>{found.operation} → {found.targetId}</span>
            <span className={`tag ${found.status === "approved" ? "tag-accent" : "tag-neutral"}`}>{found.status}</span>
          </div>
          <div className="text-muted" style={{ fontSize: 12 }}>
            {t("dash.approve_requested_by", { who: found.requestedBy, count: found.recordCount })}
          </div>
          {found.status === "pending" && (
            <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void approve()}>
              {t("dash.approve_button")}
            </button>
          )}
        </div>
      )}
      {error && <p style={{ color: "#d97878", fontSize: 13 }}>{error}</p>}
    </div>
  );
}

export default function Dashboard() {
  const { hasScope, reportUnauthorized } = useAuth();
  const { t } = useLocale();
  const navigate = useNavigate();
  const [data, setData] = useState<DashboardResponse | null>(null);
  const [failures, setFailures] = useState<DecryptFailuresResponse | null>(null);
  const [rotating, setRotating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [d, f] = await Promise.all([getDashboard(), getDecryptFailures()]);
      setData(d);
      setFailures(f);
    } catch (err) {
      if (isUnauthorized(err)) return reportUnauthorized();
      setError(err instanceof ApiError ? err.message : t("common.error_generic"));
    }
  }, [reportUnauthorized, t]);

  useEffect(() => { void load(); }, [load]);

  if (error) return <p style={{ color: "#d97878" }}>{error}</p>;
  if (!data) return <p className="text-muted">{t("common.loading")}</p>;

  const kek = data.activeKek;
  const rotationPct = kek ? Math.min(100, (kek.ageDays / kek.rotationDeadlineDays) * 100) : 0;
  const overdue = kek ? kek.ageDays >= kek.rotationDeadlineDays : false;

  return (
    <div className="kr-stack">
      <div className="kr-grid-2">
        <div className="card elev-sm">
          <div className="card-kicker">{t("dash.active_kek")}</div>
          {kek ? (
            <>
              <div className="card-title mono-ltr">{kek.id}</div>
              <div className="text-muted" style={{ fontSize: 12 }}>{kek.algorithm} · {t("dash.age_days", { days: kek.ageDays })}</div>
              <div className="kr-bar-track">
                <div className={`kr-bar-fill${overdue ? " kr-bar-danger" : ""}`} style={{ width: `${rotationPct}%` }} />
              </div>
              <div className="kr-row-between">
                <span className="text-muted" style={{ fontSize: 11 }}>{t("dash.rotation_deadline", { days: kek.rotationDeadlineDays })}</span>
                {hasScope("rotate") && (
                  <button type="button" className="btn btn-primary" onClick={() => setRotating(true)}>
                    {t("dash.rotate")}
                  </button>
                )}
              </div>
            </>
          ) : (
            <div className="card-body">{t("dash.no_active_kek")}</div>
          )}
        </div>

        <div className="card elev-sm">
          <div className="card-kicker">{t("dash.failures_title")}</div>
          <Sparkline data={failures?.buckets ?? []} />
          <button type="button" className="btn btn-ghost" style={{ alignSelf: "flex-start" }} onClick={() => navigate("/audit")}>
            {t("dash.open_audit")}
          </button>
        </div>
      </div>

      <div className="kr-grid-4">
        <div className="card">
          <div className="kr-tile-value">{data.tileCounts.keks}</div>
          <div className="kr-tile-label">{t("dash.tile.keks")}</div>
        </div>
        <div className="card">
          <div className="kr-tile-value">{data.tileCounts.subjectKeys}</div>
          <div className="kr-tile-label">{t("dash.tile.subject_keys")}</div>
        </div>
        <div className="card">
          <div className="kr-tile-value">{data.tileCounts.encryptedItems}</div>
          <div className="kr-tile-label">{t("dash.tile.items")}</div>
        </div>
        <div className="card">
          <div className="kr-tile-value">{data.tileCounts.pendingApprovals}</div>
          <div className="kr-tile-label">{t("dash.tile.pending_approvals")}</div>
        </div>
      </div>

      <div className="kr-grid-4">
        {data.healthStrip.map((h) => (
          <div key={h.label} className="card kr-row">
            <span className={`kr-dot ${statusDot(h.status)}`} />
            <div>
              <div style={{ fontSize: 13 }}>{h.label}</div>
              <div className="text-muted" style={{ fontSize: 11, textTransform: "capitalize" }}>{h.status}</div>
            </div>
          </div>
        ))}
      </div>

      {hasScope("approve") && <ApprovalLookup />}

      {rotating && kek && (
        <RotateDialog
          keyId={kek.id}
          onClose={() => setRotating(false)}
          onDone={() => {
            setRotating(false);
            void load();
          }}
        />
      )}
    </div>
  );
}
