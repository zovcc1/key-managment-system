import { useState } from "react";
import { useLocale } from "../i18n/LocaleContext";
import { ApiError } from "../api/client";
import { revokeKey } from "../api/endpoints";
import type { KeyDetail } from "../api/types";

interface Props {
  keyId: string;
  onClose: () => void;
  onDone: (detail: KeyDetail) => void;
}

/** Revoke stops reads through the key but is not the irreversible
 * crypto-shred that destroy/erasure are, so it gets a lighter one-step
 * confirm rather than the shared blast-radius/typed-confirm/approval flow. */
export default function RevokeDialog({ keyId, onClose, onDone }: Props) {
  const { t } = useLocale();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function confirm() {
    setBusy(true);
    setError(null);
    try {
      const detail = await revokeKey(keyId, reason.trim() || undefined);
      onDone(detail);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("common.error_generic"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="dialog-backdrop" role="dialog" aria-modal="true">
      <div className="dialog">
        <div className="dialog-title mono-ltr">{t("keys.action.revoke")} — {keyId}</div>
        <p className="dialog-body">Reads through this key will start failing immediately. This does not destroy key material.</p>
        <div className="field">
          <label htmlFor="reason">Reason (optional)</label>
          <input id="reason" className="input" value={reason} onChange={(e) => setReason(e.target.value)} />
        </div>
        {error && <p style={{ color: "#d97878", fontSize: 13 }}>{error}</p>}
        <div className="dialog-actions">
          <button type="button" className="btn btn-secondary" onClick={onClose}>{t("common.cancel")}</button>
          <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void confirm()}>
            {t("keys.action.revoke")}
          </button>
        </div>
      </div>
    </div>
  );
}
