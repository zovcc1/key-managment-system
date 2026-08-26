import { useEffect, useState } from "react";
import { useLocale } from "../i18n/LocaleContext";
import { ApiError } from "../api/client";
import { rotateKek, rotatePreview } from "../api/endpoints";
import type { RotateResponse, RotatePreviewResponse } from "../api/types";

interface Props {
  keyId: string;
  onClose: () => void;
  onDone: (result: RotateResponse) => void;
}

export default function RotateDialog({ keyId, onClose, onDone }: Props) {
  const { t } = useLocale();
  const [preview, setPreview] = useState<RotatePreviewResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    rotatePreview(keyId)
      .then(setPreview)
      .catch((err) => setError(err instanceof ApiError ? err.message : t("common.error_generic")));
  }, [keyId, t]);

  async function confirm() {
    setBusy(true);
    setError(null);
    try {
      const res = await rotateKek(keyId);
      onDone(res);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("common.error_generic"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="dialog-backdrop" role="dialog" aria-modal="true">
      <div className="dialog">
        <div className="dialog-title">{t("dialog.rotate.title")}</div>
        <p className="dialog-body">{t("dialog.rotate.body")}</p>
        <div className="kr-grid-2">
          <div className="card">
            <div className="card-meta">{t("dialog.rotate.deks_label")}</div>
            <div className="card-title">{preview ? preview.deksToRewrap : "…"}</div>
          </div>
          <div className="card">
            <div className="card-meta">{t("dialog.rotate.duration_label")}</div>
            <div className="card-title">{preview ? `${preview.estimatedSeconds}s` : "…"}</div>
          </div>
        </div>
        {error && <p style={{ color: "#d97878", fontSize: 13 }}>{error}</p>}
        <div className="dialog-actions">
          <button type="button" className="btn btn-secondary" onClick={onClose}>{t("dialog.rotate.cancel")}</button>
          <button type="button" className="btn btn-primary" disabled={!preview || busy} onClick={() => void confirm()}>
            {busy ? t("dialog.rotate.rotating") : t("dialog.rotate.confirm")}
          </button>
        </div>
      </div>
    </div>
  );
}
