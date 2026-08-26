import { useCallback, useEffect, useState } from "react";
import { useAuth, isUnauthorized } from "../auth/AuthContext";
import { useLocale } from "../i18n/LocaleContext";
import { useToast } from "../components/Toast";
import { ApiError } from "../api/client";
import { getKey, listKeys } from "../api/endpoints";
import type { KeyDetail, KeySummary } from "../api/types";
import RotateDialog from "../components/RotateDialog";
import RevokeDialog from "../components/RevokeDialog";
import DestroyFlowDialog from "../components/DestroyFlowDialog";

const STATES = ["pending", "active", "deprecated", "revoked", "destroyed"];
const TYPES: { value: "" | "kek" | "subject_key"; label: string }[] = [
  { value: "", label: "all types" },
  { value: "kek", label: "kek" },
  { value: "subject_key", label: "subject key" },
];

type SortKey = "createdAt" | "id" | "lastRotatedAt" | "dependentCount";

export default function Keys() {
  const { hasScope, reportUnauthorized } = useAuth();
  const { t } = useLocale();
  const toast = useToast();

  const [q, setQ] = useState("");
  const [type, setType] = useState<"" | "kek" | "subject_key">("");
  const [state, setState] = useState("");
  const [sort, setSort] = useState<SortKey>("createdAt");
  const [dir, setDir] = useState<"asc" | "desc">("desc");
  const [items, setItems] = useState<KeySummary[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const [detail, setDetail] = useState<KeyDetail | null>(null);
  const [rotating, setRotating] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [destroying, setDestroying] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await listKeys({ q: q || undefined, type: type || undefined, state: state || undefined, sort, dir, page: 1, pageSize: 50 });
      setItems(res.items);
      setTotal(res.total);
    } catch (err) {
      if (isUnauthorized(err)) return reportUnauthorized();
      setError(err instanceof ApiError ? err.message : t("common.error_generic"));
    }
  }, [q, type, state, sort, dir, reportUnauthorized, t]);

  useEffect(() => { void load(); }, [load]);

  function toggleSort(key: SortKey) {
    if (sort === key) setDir(dir === "asc" ? "desc" : "asc");
    else { setSort(key); setDir("desc"); }
  }

  async function inspect(id: string) {
    try {
      setDetail(await getKey(id));
    } catch (err) {
      if (isUnauthorized(err)) return reportUnauthorized();
      toast.push(err instanceof ApiError ? err.message : t("common.error_generic"), "danger");
    }
  }

  return (
    <div className="kr-stack">
      <div className="kr-row">
        <input className="input" style={{ maxWidth: 280 }} placeholder={t("keys.search_placeholder")} value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="seg">
          {TYPES.map((opt) => (
            <label key={opt.value} className="seg-opt">
              <input type="radio" name="type" checked={type === opt.value} onChange={() => setType(opt.value)} />
              {opt.label}
            </label>
          ))}
        </div>
        <select className="input" style={{ maxWidth: 160 }} value={state} onChange={(e) => setState(e.target.value)}>
          <option value="">all states</option>
          {STATES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <span className="text-muted" style={{ fontSize: 12, marginInlineStart: "auto" }}>
          {t("keys.count", { shown: items.length, total })}
        </span>
      </div>

      {error && <p style={{ color: "#d97878" }}>{error}</p>}

      <table className="table">
        <thead>
          <tr>
            <th onClick={() => toggleSort("id")} style={{ cursor: "pointer" }}>{t("keys.col.id")}</th>
            <th>{t("keys.col.type")}</th>
            <th>{t("keys.col.state")}</th>
            <th onClick={() => toggleSort("createdAt")} style={{ cursor: "pointer" }}>{t("keys.col.created")}</th>
            <th onClick={() => toggleSort("dependentCount")} style={{ cursor: "pointer" }}>{t("keys.col.deps")}</th>
            <th onClick={() => toggleSort("lastRotatedAt")} style={{ cursor: "pointer" }}>{t("keys.col.rotated")}</th>
            <th>{t("keys.col.actions")}</th>
          </tr>
        </thead>
        <tbody>
          {items.map((k) => (
            <tr key={k.id}>
              <td className="mono-ltr">{k.id}</td>
              <td>{k.type}</td>
              <td><span className="tag tag-neutral">{k.state}</span></td>
              <td>{new Date(k.createdAt).toLocaleDateString()}</td>
              <td>{k.dependentCount}</td>
              <td>{k.lastRotatedAt ? new Date(k.lastRotatedAt).toLocaleDateString() : "—"}</td>
              <td>
                <div className="kr-row">
                  {k.type === "kek" && k.state === "active" && hasScope("rotate") && (
                    <button type="button" className="btn btn-ghost" onClick={() => setRotating(k.id)}>{t("keys.action.rotate")}</button>
                  )}
                  {k.state === "active" && hasScope("revoke") && (
                    <button type="button" className="btn btn-ghost" onClick={() => setRevoking(k.id)}>{t("keys.action.revoke")}</button>
                  )}
                  {(k.state === "deprecated" || k.state === "revoked") && hasScope("destroy") && (
                    <button type="button" className="btn btn-ghost" onClick={() => setDestroying(k.id)}>{t("keys.action.destroy")}</button>
                  )}
                  <button type="button" className="btn btn-ghost" onClick={() => void inspect(k.id)}>{t("keys.action.inspect")}</button>
                </div>
              </td>
            </tr>
          ))}
          {items.length === 0 && (
            <tr><td colSpan={7} className="kr-empty">{t("keys.no_actions")}</td></tr>
          )}
        </tbody>
      </table>

      {detail && (
        <div className="dialog-backdrop" role="dialog" aria-modal="true" onClick={() => setDetail(null)}>
          <div className="dialog" onClick={(e) => e.stopPropagation()}>
            <div className="dialog-title mono-ltr">{detail.id}</div>
            <div className="text-muted" style={{ fontSize: 13 }}>{detail.type} · {detail.state} · {detail.algorithm}</div>
            <div className="text-muted" style={{ fontSize: 13 }}>parent: {detail.parentId ?? "—"}</div>
            <div className="text-muted" style={{ fontSize: 13 }}>dependents: {detail.dependentCount}</div>
            <div className="kr-wrap">
              {detail.legalTransitions.map((tr) => <span key={tr} className="tag tag-outline">{tr}</span>)}
            </div>
            <div className="dialog-actions">
              <button type="button" className="btn btn-secondary" onClick={() => setDetail(null)}>{t("common.close")}</button>
            </div>
          </div>
        </div>
      )}

      {rotating && (
        <RotateDialog
          keyId={rotating}
          onClose={() => setRotating(null)}
          onDone={() => { setRotating(null); void load(); toast.push(t("toast.rotated", { id: rotating })); }}
        />
      )}
      {revoking && (
        <RevokeDialog
          keyId={revoking}
          onClose={() => setRevoking(null)}
          onDone={() => { toast.push(t("toast.revoked", { id: revoking })); setRevoking(null); void load(); }}
        />
      )}
      {destroying && (
        <DestroyFlowDialog
          mode="key"
          targetId={destroying}
          onClose={() => setDestroying(null)}
          onDone={() => { void load(); }}
        />
      )}
    </div>
  );
}
