import { useCallback, useEffect, useRef, useState } from "react";
import { useAuth, isUnauthorized } from "../auth/AuthContext";
import { useLocale } from "../i18n/LocaleContext";
import { useToast } from "../components/Toast";
import { ApiError } from "../api/client";
import { downloadFile, getFileCiphertextPreview, getFileKeyTree, listFiles, uploadFile } from "../api/endpoints";
import type { CiphertextPreviewResponse, FileSummary, KeyTreeResponse } from "../api/types";
import { downloadBlob, STATE_DOT } from "../lib/ui";
import type { ChromeKey } from "../i18n/chrome";

const NODE_LABEL_KEY: Record<string, ChromeKey> = {
  root_secret: "files.node.root_secret",
  kek: "files.node.kek",
  subject_key: "files.node.subject_key",
  dek: "files.node.dek",
  envelope: "files.node.envelope",
};

const DEMO_SUBJECT_ID = "demo-subject-0001";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB"];
  let value = n / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return `${value.toFixed(1)} ${units[i]}`;
}

export default function Files() {
  const { hasScope, reportUnauthorized } = useAuth();
  const { t } = useLocale();
  const toast = useToast();

  const [items, setItems] = useState<FileSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [q, setQ] = useState("");
  const [error, setError] = useState<string | null>(null);

  const [uploadSubject, setUploadSubject] = useState(DEMO_SUBJECT_ID);
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [chosenName, setChosenName] = useState<string | null>(null);

  const [selected, setSelected] = useState<FileSummary | null>(null);
  const [tree, setTree] = useState<KeyTreeResponse | null>(null);
  const [preview, setPreview] = useState<CiphertextPreviewResponse | null>(null);
  const [downloading, setDownloading] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await listFiles({ q: q || undefined, page: 1, pageSize: 50 });
      setItems(res.items);
      setTotal(res.total);
    } catch (err) {
      if (isUnauthorized(err)) return reportUnauthorized();
      setError(err instanceof ApiError ? err.message : t("common.error_generic"));
    }
  }, [q, reportUnauthorized, t]);

  useEffect(() => { void load(); }, [load]);

  async function onUpload() {
    const file = fileInputRef.current?.files?.[0];
    if (!file || !uploadSubject.trim()) return;
    setUploading(true);
    try {
      await uploadFile(file, uploadSubject.trim());
      toast.push(t("files.uploaded_toast", { filename: file.name }));
      if (fileInputRef.current) fileInputRef.current.value = "";
      setChosenName(null);
      void load();
    } catch (err) {
      if (isUnauthorized(err)) return reportUnauthorized();
      toast.push(err instanceof ApiError ? err.message : t("common.error_generic"), "danger");
    } finally {
      setUploading(false);
    }
  }

  async function inspect(fo: FileSummary) {
    setSelected(fo);
    setTree(null);
    setPreview(null);
    try {
      const [treeRes, previewRes] = await Promise.all([
        getFileKeyTree(fo.id),
        getFileCiphertextPreview(fo.id),
      ]);
      setTree(treeRes);
      setPreview(previewRes);
    } catch (err) {
      if (isUnauthorized(err)) return reportUnauthorized();
      toast.push(err instanceof ApiError ? err.message : t("common.error_generic"), "danger");
    }
  }

  async function onDownload() {
    if (!selected) return;
    setDownloading(true);
    try {
      const { blob, filename } = await downloadFile(selected.id);
      downloadBlob(blob, filename ?? selected.filename);
      toast.push(t("files.downloaded_toast", { filename: filename ?? selected.filename }));
    } catch (err) {
      if (isUnauthorized(err)) return reportUnauthorized();
      toast.push(err instanceof ApiError ? err.message : t("common.error_generic"), "danger");
    } finally {
      setDownloading(false);
    }
  }

  return (
    <div className="kr-stack">
      {hasScope("file_write") && (
        <div className="card">
          <div className="card-title">{t("files.upload_button")}</div>
          <div className="kr-row">
            <input
              className="input mono-ltr"
              style={{ maxWidth: 320 }}
              placeholder={t("files.upload_subject_placeholder")}
              value={uploadSubject}
              onChange={(e) => setUploadSubject(e.target.value)}
            />
            <input
              ref={fileInputRef}
              type="file"
              style={{ display: "none" }}
              onChange={(e) => setChosenName(e.target.files?.[0]?.name ?? null)}
            />
            <button type="button" className="btn btn-secondary" onClick={() => fileInputRef.current?.click()}>
              {t("files.choose_file")}
            </button>
            <span className="text-muted" style={{ fontSize: 12 }}>{chosenName ?? t("files.no_file_chosen")}</span>
            <button
              type="button"
              className="btn btn-primary"
              disabled={uploading || !chosenName || !uploadSubject.trim()}
              onClick={() => void onUpload()}
            >
              {uploading ? t("files.uploading") : t("files.upload_button")}
            </button>
          </div>
        </div>
      )}

      <div className="kr-row">
        <input
          className="input"
          style={{ maxWidth: 280 }}
          placeholder={t("files.search_placeholder")}
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <span className="text-muted" style={{ fontSize: 12, marginInlineStart: "auto" }}>
          {t("files.count", { shown: items.length, total })}
        </span>
      </div>

      {error && <p style={{ color: "#d97878" }}>{error}</p>}

      <table className="table">
        <thead>
          <tr>
            <th>{t("files.col.filename")}</th>
            <th>{t("files.col.size")}</th>
            <th>{t("files.col.type")}</th>
            <th>{t("files.col.subject")}</th>
            <th>{t("files.col.uploaded_by")}</th>
            <th>{t("files.col.uploaded_at")}</th>
          </tr>
        </thead>
        <tbody>
          {items.map((fo) => (
            <tr key={fo.id} style={{ cursor: "pointer" }} onClick={() => void inspect(fo)}>
              <td>{fo.filename}</td>
              <td>{formatBytes(fo.sizeBytes)}</td>
              <td className="text-muted">{fo.contentType}</td>
              <td className="mono-ltr">{fo.subjectId}</td>
              <td>{fo.uploadedBy}</td>
              <td>{new Date(fo.uploadedAt).toLocaleString()}</td>
            </tr>
          ))}
          {items.length === 0 && (
            <tr><td colSpan={6} className="kr-empty">{t("files.no_files")}</td></tr>
          )}
        </tbody>
      </table>

      {selected && (
        <div className="dialog-backdrop" role="dialog" aria-modal="true" onClick={() => setSelected(null)}>
          <div className="dialog" style={{ width: "min(560px, 100%)" }} onClick={(e) => e.stopPropagation()}>
            <div className="dialog-title">{t("files.detail_title")}: {selected.filename}</div>
            <div className="text-muted" style={{ fontSize: 13 }}>
              {formatBytes(selected.sizeBytes)} · {selected.contentType} · <span className="mono-ltr">{selected.subjectId}</span>
            </div>

            <div className="card-title" style={{ marginTop: "var(--space-3)" }}>{t("files.key_tree_title")}</div>
            {!tree && <p className="text-muted" style={{ fontSize: 12 }}>{t("common.loading")}</p>}
            {tree && (
              <div className="kr-stack" style={{ gap: 4 }}>
                <ul className="kr-keytree">
                  {tree.nodes.map((n) => {
                    const dimmed = tree.brokenAtLevel !== null && n.level >= tree.brokenAtLevel;
                    return (
                      <li key={n.level} className={`kr-keytree-node${dimmed ? " kr-keytree-dimmed" : ""}`}>
                        <span className="kr-dot" style={{ background: STATE_DOT[n.state] ?? "#595d6c" }} />
                        <span className="kr-keytree-kind">{t(NODE_LABEL_KEY[n.kind])}</span>
                        {n.id && <span className="mono-ltr text-muted" style={{ fontSize: 11 }}>{n.id}</span>}
                        <span className="text-muted" style={{ fontSize: 11 }}>{n.state}</span>
                      </li>
                    );
                  })}
                </ul>
                {tree.readable ? (
                  <span className="tag tag-neutral">{t("files.key_tree_readable")}</span>
                ) : (
                  <span className="tag" style={{ borderColor: "#d97878", color: "#d97878" }}>
                    {t("files.key_tree_broken", { kind: tree.nodes.find((n) => n.level === tree.brokenAtLevel)?.kind ?? "" })}
                  </span>
                )}
                {!tree.blobPresent && (
                  <span className="text-muted" style={{ fontSize: 11 }}>{t("files.key_tree_blob_missing")}</span>
                )}
              </div>
            )}

            <div className="card-title" style={{ marginTop: "var(--space-3)" }}>{t("files.ciphertext_title")}</div>
            {preview && preview.blobPresent && (
              <>
                <div className="text-muted" style={{ fontSize: 11 }}>
                  {t("files.ciphertext_hint", { bytes: preview.previewBytes, total: preview.totalBytes })}
                </div>
                <div className="kr-isolated">
                  <div className="kr-isolated-value">{preview.hex}</div>
                </div>
              </>
            )}
            {preview && !preview.blobPresent && (
              <p className="text-muted" style={{ fontSize: 12 }}>{t("files.ciphertext_missing")}</p>
            )}

            <div className="dialog-actions">
              <button type="button" className="btn btn-secondary" onClick={() => setSelected(null)}>{t("files.close")}</button>
              {hasScope("decrypt") && tree?.readable && (
                <button type="button" className="btn btn-primary" disabled={downloading} onClick={() => void onDownload()}>
                  {downloading ? t("files.downloading") : t("files.download")}
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
