import { useState, type FormEvent } from "react";
import { useAuth, isUnauthorized } from "../auth/AuthContext";
import { useLocale } from "../i18n/LocaleContext";
import { useToast } from "../components/Toast";
import { ApiError } from "../api/client";
import { exportCertificate, getCertificate, getFieldDigest, getSubject, verifyUnreadable } from "../api/endpoints";
import type { CertificateResponse, FieldDigestResponse, SubjectResponse, VerifyUnreadableResponse } from "../api/types";
import DestroyFlowDialog from "../components/DestroyFlowDialog";

const DEMO_SUBJECT_ID = "demo-subject-0001";

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function Privacy() {
  const { hasScope, reportUnauthorized } = useAuth();
  const { t } = useLocale();
  const toast = useToast();

  const [query, setQuery] = useState("");
  const [subject, setSubject] = useState<SubjectResponse | null>(null);
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [revealedTable, setRevealedTable] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<FieldDigestResponse | null>(null);

  const [erasing, setErasing] = useState(false);
  const [certificateId, setCertificateId] = useState<string | null>(null);
  const [certificate, setCertificate] = useState<CertificateResponse | null>(null);
  const [certLookupInput, setCertLookupInput] = useState("");

  const [verify, setVerify] = useState<VerifyUnreadableResponse | null>(null);

  async function search(id: string) {
    setSearching(true);
    setError(null);
    setSubject(null);
    setRevealed(null);
    setRevealedTable(null);
    setVerify(null);
    setCertificateId(null);
    setCertificate(null);
    try {
      setSubject(await getSubject(id));
    } catch (err) {
      if (isUnauthorized(err)) return reportUnauthorized();
      setError(err instanceof ApiError ? err.message : t("common.error_generic"));
    } finally {
      setSearching(false);
    }
  }

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (query.trim()) void search(query.trim());
  }

  async function reveal(table: string) {
    if (!subject) return;
    if (revealedTable === table) {
      setRevealedTable(null);
      setRevealed(null);
      return;
    }
    try {
      const res = await getFieldDigest(subject.subjectId, table);
      setRevealed(res);
      setRevealedTable(table);
    } catch (err) {
      if (isUnauthorized(err)) return reportUnauthorized();
      toast.push(err instanceof ApiError ? err.message : t("common.error_generic"), "danger");
    }
  }

  async function runVerify() {
    if (!subject) return;
    try {
      setVerify(await verifyUnreadable(subject.subjectId));
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : t("common.error_generic"), "danger");
    }
  }

  async function loadCertificate(id: string) {
    try {
      setCertificate(await getCertificate(id));
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : t("common.error_generic"), "danger");
    }
  }

  async function lookupCertificate() {
    const id = certLookupInput.trim();
    if (!id) return;
    try {
      setCertificate(await getCertificate(id));
      setCertificateId(id);
    } catch (err) {
      if (isUnauthorized(err)) return reportUnauthorized();
      toast.push(err instanceof ApiError ? err.message : t("common.error_generic"), "danger");
    }
  }

  async function download(format: "json" | "pdf") {
    if (!certificateId) return;
    try {
      const blob = await exportCertificate(certificateId, format);
      downloadBlob(blob, `${certificateId}.${format}`);
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : t("common.error_generic"), "danger");
    }
  }

  return (
    <div className="kr-stack">
      <div className="card">
        <div className="card-body">{t("privacy.banner")}</div>
      </div>

      <form className="kr-row" onSubmit={onSubmit}>
        <input
          className="input mono-ltr"
          style={{ maxWidth: 320 }}
          placeholder={t("privacy.search_placeholder")}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <button type="submit" className="btn btn-primary" disabled={searching || !query.trim()}>
          {searching ? t("privacy.searching") : t("privacy.search")}
        </button>
        <button type="button" className="btn btn-ghost" onClick={() => { setQuery(DEMO_SUBJECT_ID); void search(DEMO_SUBJECT_ID); }}>
          {t("privacy.use_demo")}
        </button>
      </form>

      {error && <p style={{ color: "#d97878" }}>{error}</p>}

      {subject && (
        <div className="kr-stack">
          <div className="card elev-sm">
            <div className="card-kicker">{t("privacy.subject")}</div>
            <div className="card-title mono-ltr">{subject.subjectId}</div>
            <div className="text-muted" style={{ fontSize: 12 }}>
              key: {subject.subjectKeyId} · state: {subject.state} · {t("privacy.records_across", { tables: subject.tables.length })} ({subject.recordCount} total)
            </div>
          </div>

          <div className="card">
            <div className="card-title">{t("privacy.tables_title")}</div>
            <table className="table">
              <thead>
                <tr>
                  <th>{t("privacy.col.table")}</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {subject.tables.map((tbl) => (
                  <tr key={tbl}>
                    <td>{tbl}</td>
                    <td>
                      {hasScope("decrypt") && (
                        <button type="button" className="btn btn-ghost" onClick={() => void reveal(tbl)}>
                          {revealedTable === tbl ? t("privacy.hide") : t("privacy.reveal")}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {revealed && revealedTable && (
              <div className="kr-isolated">
                <div className="card-kicker">{t("privacy.isolated_viewer")}</div>
                <div className="kr-isolated-value">{revealed.column} #{revealed.recordId}: {revealed.maskedValue}</div>
                <div className="text-muted" style={{ fontSize: 11, marginTop: 6 }}>{t("privacy.reveal_note")}</div>
                <button type="button" className="btn btn-ghost" onClick={() => { setRevealed(null); setRevealedTable(null); }}>
                  {t("privacy.close_clear")}
                </button>
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-title">{t("privacy.erasure_title")}</div>
            <p className="card-body">{t("privacy.erasure_body")}</p>
            {subject.state === "destroyed" ? (
              <span className="tag tag-neutral">{t("privacy.already_erased")}</span>
            ) : (
              hasScope("destroy") && (
                <button type="button" className="btn btn-primary" onClick={() => setErasing(true)}>
                  {t("privacy.execute_erasure")}
                </button>
              )
            )}
            {subject.state === "destroyed" && (
              <button type="button" className="btn btn-secondary" onClick={() => void runVerify()}>
                {t("privacy.verify_unreadable")}
              </button>
            )}
            {verify && (
              <div className="text-muted" style={{ fontSize: 12 }}>
                {verify.sampled} sampled · all decrypt failed: {String(verify.allDecryptFailed)}
              </div>
            )}
          </div>

          {certificateId ? (
            <div className="card">
              <div className="card-title">{t("privacy.certificate")}</div>
              {!certificate && (
                <button type="button" className="btn btn-ghost" onClick={() => void loadCertificate(certificateId)}>
                  {t("common.loading")}
                </button>
              )}
              {certificate && (
                <div className="text-muted mono-ltr" style={{ fontSize: 11, wordBreak: "break-all" }}>{certificate.signature}</div>
              )}
              <div className="kr-row">
                <button type="button" className="btn btn-secondary" onClick={() => void download("json")}>{t("privacy.export_certificate")}</button>
                <button type="button" className="btn btn-secondary" onClick={() => void download("pdf")}>{t("privacy.export_pdf")}</button>
              </div>
            </div>
          ) : (
            subject.state === "destroyed" && (
              <div className="card">
                <div className="card-title">{t("privacy.certificate")}</div>
                <p className="text-muted" style={{ fontSize: 12 }}>{t("privacy.certificate_lookup_hint")}</p>
                <div className="kr-row">
                  <input
                    className="input mono-ltr"
                    style={{ maxWidth: 320 }}
                    placeholder={t("privacy.certificate_lookup_placeholder")}
                    value={certLookupInput}
                    onChange={(e) => setCertLookupInput(e.target.value)}
                  />
                  <button type="button" className="btn btn-secondary" disabled={!certLookupInput.trim()} onClick={() => void lookupCertificate()}>
                    {t("privacy.certificate_lookup_button")}
                  </button>
                </div>
              </div>
            )
          )}
        </div>
      )}

      {erasing && subject && (
        <DestroyFlowDialog
          mode="erasure"
          targetId={subject.subjectId}
          knownBlastRadius={{ recordCount: subject.recordCount, tables: subject.tables }}
          onClose={() => setErasing(false)}
          onDone={(res) => {
            setErasing(false);
            if (res.certificateId) setCertificateId(res.certificateId);
            void search(subject.subjectId);
          }}
        />
      )}
    </div>
  );
}
