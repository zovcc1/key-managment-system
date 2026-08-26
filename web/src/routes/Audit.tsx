import { useCallback, useEffect, useState } from "react";
import { useAuth, isUnauthorized } from "../auth/AuthContext";
import { useLocale } from "../i18n/LocaleContext";
import { useToast } from "../components/Toast";
import { ApiError } from "../api/client";
import { exportAuditCsv, listActors, listAudit, listOperations, verifyAuditChain } from "../api/endpoints";
import type { AuditRow, AuditVerifyResponse } from "../api/types";

export default function Audit() {
  const { reportUnauthorized } = useAuth();
  const { t } = useLocale();
  const toast = useToast();

  const [actors, setActors] = useState<string[]>([]);
  const [operations, setOperations] = useState<string[]>([]);
  const [actor, setActor] = useState("");
  const [operation, setOperation] = useState("");
  const [keyId, setKeyId] = useState("");
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [cursor, setCursor] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<AuditVerifyResponse | null>(null);

  useEffect(() => {
    listActors().then((r) => setActors(r.actors)).catch(() => {});
    listOperations().then((r) => setOperations(r.operations)).catch(() => {});
  }, []);

  const load = useCallback(async (reset: boolean) => {
    try {
      const res = await listAudit({
        actor: actor || undefined,
        operation: operation || undefined,
        keyId: keyId || undefined,
        cursor: reset ? undefined : cursor ?? undefined,
        limit: 50,
      });
      setRows((cur) => (reset ? res.items : [...cur, ...res.items]));
      setCursor(res.nextCursor);
    } catch (err) {
      if (isUnauthorized(err)) return reportUnauthorized();
      setError(err instanceof ApiError ? err.message : t("common.error_generic"));
    }
  }, [actor, operation, keyId, cursor, reportUnauthorized, t]);

  // Intentionally reset-only: this effect fires on filter change, not on
  // every `load` identity change (which also flips whenever `cursor`
  // advances) — otherwise paging forward would loop back to page 1.
  useEffect(() => {
    void load(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [actor, operation, keyId]);

  async function runVerify() {
    setVerifying(true);
    setVerifyResult(null);
    try {
      setVerifyResult(await verifyAuditChain());
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : t("common.error_generic"), "danger");
    } finally {
      setVerifying(false);
    }
  }

  async function exportCsv() {
    try {
      const blob = await exportAuditCsv();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "audit-log.csv";
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : t("common.error_generic"), "danger");
    }
  }

  return (
    <div className="kr-stack">
      <div className="kr-row">
        <select className="input" style={{ maxWidth: 200 }} value={actor} onChange={(e) => setActor(e.target.value)}>
          <option value="">{t("audit.filter.actor")}</option>
          {actors.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
        <select className="input" style={{ maxWidth: 200 }} value={operation} onChange={(e) => setOperation(e.target.value)}>
          <option value="">{t("audit.filter.operation")}</option>
          {operations.map((o) => <option key={o} value={o}>{o}</option>)}
        </select>
        <input className="input mono-ltr" style={{ maxWidth: 220 }} placeholder="key id" value={keyId} onChange={(e) => setKeyId(e.target.value)} />
        <button type="button" className="btn btn-secondary" style={{ marginInlineStart: "auto" }} disabled={verifying} onClick={() => void runVerify()}>
          {verifying ? t("audit.verifying") : t("audit.verify")}
        </button>
        <button type="button" className="btn btn-secondary" onClick={() => void exportCsv()}>{t("audit.export")}</button>
      </div>

      {verifyResult && (
        <div className="card" style={verifyResult.ok ? undefined : { borderInlineStart: "3px solid #d97878" }}>
          <div className="kr-row">
            <span className={`tag ${verifyResult.ok ? "tag-accent" : "tag-neutral"}`}>
              {verifyResult.ok ? t("audit.chain_ok") : t("audit.chain_broken")}
            </span>
          </div>
          {!verifyResult.ok && (
            <div className="card-body">
              {t("audit.chain_broken_detail", { entry: verifyResult.firstBrokenEntry ?? "?" })}
              <div className="text-muted mono-ltr" style={{ fontSize: 11, marginTop: 4 }}>
                expected: {verifyResult.expectedDigest} · stored: {verifyResult.storedDigest}
              </div>
            </div>
          )}
        </div>
      )}

      {error && <p style={{ color: "#d97878" }}>{error}</p>}

      <table className="table">
        <thead>
          <tr>
            <th>{t("audit.col.timestamp")}</th>
            <th>{t("audit.col.actor")}</th>
            <th>{t("audit.col.operation")}</th>
            <th>{t("audit.col.key_id")}</th>
            <th>{t("audit.col.item_id")}</th>
            <th>{t("audit.col.result")}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td className="mono-ltr">{new Date(r.timestamp).toLocaleString()}</td>
              <td>{r.actor}</td>
              <td>{r.operation}</td>
              <td className="mono-ltr">{r.keyId ?? "—"}</td>
              <td className="mono-ltr">{r.itemId ?? "—"}</td>
              <td>
                <span className={`tag ${r.result === "ok" ? "tag-accent" : "tag-neutral"}`}>{r.result}</span>
              </td>
            </tr>
          ))}
          {rows.length === 0 && <tr><td colSpan={6} className="kr-empty">—</td></tr>}
        </tbody>
      </table>

      {cursor !== null && (
        <button type="button" className="btn btn-ghost" onClick={() => void load(false)}>{t("common.load_more")}</button>
      )}

      <div className="text-muted" style={{ fontSize: 11 }}>{t("audit.disclaimer")}</div>
    </div>
  );
}
