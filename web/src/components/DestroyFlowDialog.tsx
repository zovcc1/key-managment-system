import { useEffect, useRef, useState, type ClipboardEvent } from "react";
import { useLocale } from "../i18n/LocaleContext";
import { useToast } from "./Toast";
import { ApiError } from "../api/client";
import { createApproval, destroyKey, getApproval, getBlastRadius, requestErasure } from "../api/endpoints";
import type { ApprovalResponse } from "../api/types";

type Mode = "key" | "erasure";

interface Props {
  mode: Mode;
  targetId: string;
  /** Erasure has no blast-radius endpoint of its own — the subject screen
   * already knows recordCount/tables from GET /api/subjects/{id}. */
  knownBlastRadius?: { recordCount: number; tables: string[] };
  onClose: () => void;
  onDone: (result: { recordsUnreadable: number; certificateId?: string }) => void;
}

type Step = 1 | 2 | 3 | 4;

/**
 * Shared 3-step destructive flow (blast radius -> typed confirmation ->
 * second-party approval) used for both KEK/subject-key destroy and subject
 * erasure. The mockup's step 3 was a fake "approve" checkbox; here it is a
 * real POST /api/approvals followed by polling GET /api/approvals/{id} —
 * approval only ever completes once a *different* key-admin approves it
 * from their own session (see the Dashboard's approval-lookup card), since
 * the backend rejects self-approval outright.
 */
export default function DestroyFlowDialog({ mode, targetId, knownBlastRadius, onClose, onDone }: Props) {
  const { t } = useLocale();
  const toast = useToast();

  const [step, setStep] = useState<Step>(1);
  const [blast, setBlast] = useState<{ recordCount: number; tables: string[] } | null>(knownBlastRadius ?? null);
  const [typedValue, setTypedValue] = useState("");
  const [approval, setApproval] = useState<ApprovalResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [doneRecords, setDoneRecords] = useState<number | null>(null);
  const [doneCertId, setDoneCertId] = useState<string | undefined>(undefined);
  const pollRef = useRef<number | undefined>(undefined);

  useEffect(() => {
    if (!blast && mode === "key") {
      getBlastRadius(targetId)
        .then((r) => setBlast({ recordCount: r.recordCount, tables: r.tables }))
        .catch(() => setBlast({ recordCount: 0, tables: [] }));
    }
  }, [blast, mode, targetId]);

  useEffect(() => () => window.clearInterval(pollRef.current), []);

  function startPolling(id: string) {
    pollRef.current = window.setInterval(async () => {
      try {
        const latest = await getApproval(id);
        setApproval(latest);
        if (latest.status === "approved") {
          window.clearInterval(pollRef.current);
        }
      } catch {
        // transient — next tick retries
      }
    }, 2500);
  }

  async function requestApproval() {
    setBusy(true);
    setError(null);
    try {
      const res = await createApproval(mode === "key" ? "destroy" : "erasure", targetId, blast?.recordCount ?? 0);
      setApproval(res);
      if (res.status !== "approved") startPolling(res.id);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("common.error_generic"));
    } finally {
      setBusy(false);
    }
  }

  async function execute() {
    if (!approval) return;
    setBusy(true);
    setError(null);
    try {
      if (mode === "key") {
        const detail = await destroyKey(targetId, typedValue, approval.id);
        setDoneRecords(blast?.recordCount ?? 0);
        setStep(4);
        onDone({ recordsUnreadable: blast?.recordCount ?? 0 });
        toast.push(`${targetId} — ${detail.state}`, "danger");
      } else {
        const res = await requestErasure(targetId, typedValue, approval.id);
        setDoneRecords(res.recordsUnreadable);
        setDoneCertId(res.certificateId);
        setStep(4);
        onDone({ recordsUnreadable: res.recordsUnreadable, certificateId: res.certificateId });
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("common.error_generic"));
    } finally {
      setBusy(false);
    }
  }

  function onPasteBlock(e: ClipboardEvent) {
    e.preventDefault();
    setError(t("dialog.destroy.paste_blocked"));
  }

  const matches = typedValue === targetId;

  return (
    <div className="dialog-backdrop" role="dialog" aria-modal="true">
      <div className="dialog">
        {step < 4 && (
          <>
            <div className="kr-steps">
              {[1, 2, 3].map((s) => (
                <div key={s} className={`kr-step${step >= s ? " kr-step-done" : ""}`} />
              ))}
            </div>
            <div className="text-muted" style={{ fontSize: 11 }}>{t("dialog.destroy.step_of", { step })}</div>
          </>
        )}

        {step === 1 && (
          <>
            <div className="dialog-title">{t("dialog.destroy.s1_title")}</div>
            <p className="dialog-body">
              <strong>{blast?.recordCount ?? "…"}</strong> {t("dialog.destroy.s1_body")}
            </p>
            {blast && blast.tables.length > 0 && (
              <div className="kr-wrap">
                {blast.tables.map((tbl) => (
                  <span key={tbl} className="tag tag-neutral">{tbl}</span>
                ))}
              </div>
            )}
            <div className="dialog-actions">
              <button type="button" className="btn btn-secondary" onClick={onClose}>{t("dialog.destroy.cancel")}</button>
              <button type="button" className="btn btn-primary" onClick={() => setStep(2)}>{t("dialog.destroy.next")}</button>
            </div>
          </>
        )}

        {step === 2 && (
          <>
            <div className="dialog-title">{t("dialog.destroy.s2_title")}</div>
            <p className="dialog-body">{t("dialog.destroy.s2_body")}</p>
            <div className="field">
              <label htmlFor="confirmId">
                {t("dialog.destroy.confirm_id")}: <span className="kr-confirm-id mono-ltr">{targetId}</span>
              </label>
              <input
                id="confirmId"
                className="input mono-ltr"
                value={typedValue}
                onChange={(e) => setTypedValue(e.target.value)}
                onPaste={onPasteBlock}
                placeholder={t("dialog.destroy.s2_placeholder")}
                autoComplete="off"
                spellCheck={false}
              />
              <div className="text-muted" style={{ fontSize: 12, marginTop: 4 }}>
                {matches ? t("dialog.destroy.match") : t("dialog.destroy.no_match")}
              </div>
            </div>
            {error && <p style={{ color: "#d97878", fontSize: 13 }}>{error}</p>}
            <div className="dialog-actions">
              <button type="button" className="btn btn-secondary" onClick={onClose}>{t("dialog.destroy.cancel")}</button>
              <button type="button" className="btn btn-primary" disabled={!matches} onClick={() => setStep(3)}>
                {t("dialog.destroy.next")}
              </button>
            </div>
          </>
        )}

        {step === 3 && (
          <>
            <div className="dialog-title">{t("dialog.destroy.s3_title")}</div>
            <p className="dialog-body">{t("dialog.destroy.s3_body")}</p>
            {!approval && (
              <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void requestApproval()}>
                {busy ? t("dialog.destroy.requesting") : t("dialog.destroy.request_approval")}
              </button>
            )}
            {approval && (
              <div className="card">
                <div className="kr-row-between">
                  <span className="text-muted" style={{ fontSize: 12 }}>Approval id</span>
                  <span className="mono-ltr" style={{ fontSize: 12 }}>{approval.id}</span>
                </div>
                <div className="kr-row">
                  <span className={`tag ${approval.status === "approved" ? "tag-accent" : "tag-neutral"}`}>
                    {approval.status === "approved" ? t("dialog.destroy.approved") : t("dialog.destroy.awaiting")}
                  </span>
                </div>
              </div>
            )}
            {error && <p style={{ color: "#d97878", fontSize: 13 }}>{error}</p>}
            <div className="dialog-actions">
              <button type="button" className="btn btn-secondary" onClick={onClose}>{t("dialog.destroy.cancel")}</button>
              <button
                type="button"
                className="btn btn-primary"
                disabled={!approval || approval.status !== "approved" || busy}
                onClick={() => void execute()}
              >
                {busy ? t("dialog.destroy.executing") : t("dialog.destroy.execute")}
              </button>
            </div>
          </>
        )}

        {step === 4 && (
          <>
            <div className="dialog-title">
              {mode === "key" ? t("dialog.destroy.done_key_title") : t("dialog.destroy.done_erasure_title")}
            </div>
            <p className="dialog-body">
              <strong>{doneRecords}</strong>{" "}
              {mode === "key"
                ? t("dialog.destroy.done_key_body")
                : t("dialog.destroy.done_erasure_body", { tables: blast?.tables.length ?? 0 })}
            </p>
            {doneCertId && <div className="text-muted mono-ltr" style={{ fontSize: 12 }}>certificate: {doneCertId}</div>}
            <div className="dialog-actions">
              <button type="button" className="btn btn-primary" onClick={onClose}>{t("dialog.destroy.close")}</button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
