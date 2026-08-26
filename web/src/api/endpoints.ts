import { api, fetchBlob, newIdempotencyKey } from "./client";
import type {
  ApprovalResponse,
  AuditListResponse,
  AuditVerifyResponse,
  BackupJobStartResponse,
  BackupJobStatus,
  BlastRadiusResponse,
  CertificateResponse,
  DashboardResponse,
  DecryptFailuresResponse,
  DownstreamResponse,
  ErasureResponse,
  FieldDigestResponse,
  GraphResponse,
  KeyDetail,
  KeyListResponse,
  ProvidersResponse,
  RewrapFailuresResponse,
  RewrapJobResponse,
  RotatePreviewResponse,
  RotateResponse,
  SessionOpenResponse,
  SessionStatusResponse,
  SettingsResponse,
  SubjectResponse,
  ThreatModelResponse,
  VerifyUnreadableResponse,
} from "./types";

// ---- session -----------------------------------------------------------

export const openSession = (apiKey: string, provider?: string) =>
  api.post<SessionOpenResponse>(
    "/api/session",
    { provider: provider ?? null },
    { anonymous: true, headers: { "X-Api-Key": apiKey } },
  );

export const lockSession = () => api.del<{ locked: boolean }>("/api/session");
export const sessionStatus = () => api.get<SessionStatusResponse>("/api/session");

// ---- dashboard -----------------------------------------------------------

export const getDashboard = () => api.get<DashboardResponse>("/api/dashboard");
export const getDecryptFailures = (window = "24h") =>
  api.get<DecryptFailuresResponse>(`/api/metrics/decrypt-failures?window=${encodeURIComponent(window)}`);
export const ackAlert = (alertId: string) => api.post<{ id: string; acknowledged: boolean }>(`/api/alerts/${alertId}/ack`);

// ---- keys ------------------------------------------------------------

export interface ListKeysParams {
  type?: "kek" | "subject_key";
  state?: string;
  q?: string;
  sort?: string;
  dir?: "asc" | "desc";
  page?: number;
  pageSize?: number;
}

export const listKeys = (params: ListKeysParams = {}) => {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") qs.set(k, String(v));
  }
  const suffix = qs.toString();
  return api.get<KeyListResponse>(`/api/keys${suffix ? `?${suffix}` : ""}`);
};

export const getKey = (keyId: string) => api.get<KeyDetail>(`/api/keys/${keyId}`);
export const getBlastRadius = (keyId: string) => api.get<BlastRadiusResponse>(`/api/keys/${keyId}/blast-radius`);
export const rotatePreview = (keyId: string) => api.post<RotatePreviewResponse>(`/api/keks/${keyId}/rotate/preview`);
export const rotateKek = (keyId: string) => api.post<RotateResponse>(`/api/keks/${keyId}/rotate`);
export const revokeKey = (keyId: string, reason?: string) => api.post<KeyDetail>(`/api/keys/${keyId}/revoke`, { reason: reason ?? null });

export const destroyKey = (keyId: string, typedConfirmation: string, approvalId: string) =>
  api.post<KeyDetail>(
    `/api/keys/${keyId}/destroy`,
    { typedConfirmation, approvalId },
    { idempotent: true },
  );

// ---- graph -----------------------------------------------------------

export const getGraph = () => api.get<GraphResponse>("/api/graph");
export const getDownstream = (nodeId: string) => api.get<DownstreamResponse>(`/api/graph/${nodeId}/downstream`);

// ---- approvals ---------------------------------------------------------

export const createApproval = (operation: string, targetId: string, recordCount = 0) =>
  api.post<ApprovalResponse>("/api/approvals", { operation, targetId, recordCount });

export const getApproval = (approvalId: string) => api.get<ApprovalResponse>(`/api/approvals/${approvalId}`);
export const approveApproval = (approvalId: string) => api.post<ApprovalResponse>(`/api/approvals/${approvalId}/approve`);

// ---- rewrap ------------------------------------------------------------

export const currentRewrapJob = () => api.get<RewrapJobResponse>("/api/rewrap/jobs/current");
export const pauseRewrapJob = (jobId: string) => api.post<RewrapJobResponse>(`/api/rewrap/jobs/${jobId}/pause`);
export const resumeRewrapJob = (jobId: string) => api.post<RewrapJobResponse>(`/api/rewrap/jobs/${jobId}/resume`);
export const rewrapFailures = (jobId: string, page = 1, pageSize = 20) =>
  api.get<RewrapFailuresResponse>(`/api/rewrap/jobs/${jobId}/failures?page=${page}&pageSize=${pageSize}`);
export const retryRewrapFailure = (jobId: string, itemId: string) =>
  api.post<{ itemId: string; resolved: boolean; attempts: number; reason: string }>(
    `/api/rewrap/jobs/${jobId}/failures/${itemId}/retry`,
  );

// ---- subjects / privacy center -----------------------------------------

export const getSubject = (subjectId: string) => api.get<SubjectResponse>(`/api/subjects/${subjectId}`);
export const getFieldDigest = (subjectId: string, table: string) =>
  api.get<FieldDigestResponse>(`/api/subjects/${subjectId}/fields/${encodeURIComponent(table)}/digest`);

export const requestErasure = (subjectId: string, typedConfirmation: string, approvalId: string) =>
  api.post<ErasureResponse>(
    `/api/subjects/${subjectId}/erasure`,
    { typedConfirmation, approvalId },
    { idempotent: true },
  );

export const verifyUnreadable = (subjectId: string) =>
  api.post<VerifyUnreadableResponse>(`/api/subjects/${subjectId}/verify-unreadable`);

export const getCertificate = (certificateId: string) => api.get<CertificateResponse>(`/api/certificates/${certificateId}`);

export const exportCertificate = (certificateId: string, format: "json" | "pdf" = "json") =>
  fetchBlob(`/api/certificates/${certificateId}/export?format=${format}`);

// ---- audit ------------------------------------------------------------

export interface AuditListParams {
  actor?: string;
  operation?: string;
  keyId?: string;
  from?: string;
  to?: string;
  cursor?: number;
  limit?: number;
}

export const listAudit = (params: AuditListParams = {}) => {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") qs.set(k, String(v));
  }
  const suffix = qs.toString();
  return api.get<AuditListResponse>(`/api/audit${suffix ? `?${suffix}` : ""}`);
};

export const verifyAuditChain = () => api.post<AuditVerifyResponse>("/api/audit/verify");
export const exportAuditCsv = () => fetchBlob("/api/audit/export.csv");
export const listActors = () => api.get<{ actors: string[] }>("/api/audit/actors");
export const listOperations = () => api.get<{ operations: string[] }>("/api/audit/operations");

// ---- settings ------------------------------------------------------------

export const getSettings = () => api.get<SettingsResponse>("/api/settings");
export const patchSettings = (body: { rotationIntervalDays?: number; alertThreshold?: number }) =>
  api.patch<SettingsResponse>("/api/settings", body);
export const listProviders = () => api.get<ProvidersResponse>("/api/providers");
export const activateProvider = (providerId: string) => api.post<{ active: string }>(`/api/providers/${providerId}/activate`);
export const startBackupVerify = () => api.post<BackupJobStartResponse>("/api/backup/verify");
export const getBackupJob = (jobId: string) => api.get<BackupJobStatus>(`/api/backup/verify/${jobId}`);
export const getThreatModel = () => api.get<ThreatModelResponse>("/api/threat-model");

export { newIdempotencyKey };
