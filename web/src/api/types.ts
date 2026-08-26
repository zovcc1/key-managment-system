// Response/request shapes mirrored from keyring/api/serializers.py and
// each router's return dict. Field names are exactly what the backend
// emits (camelCase) — no renaming layer.

export type Role = "operator" | "key-admin" | "auditor";
export type KeyState = "pending" | "active" | "deprecated" | "revoked" | "destroyed";

export interface SessionOpenResponse {
  token: string;
  operator: string;
  role: Role;
  scopes: string[];
  provider: string;
  locked: boolean;
  expiresAt: string;
}

export interface SessionStatusResponse {
  operator: string;
  role: Role;
  locked: boolean;
  providerConnected: boolean;
  provider: string;
  expiresAt: string;
}

export interface DashboardResponse {
  activeKek: { id: string; algorithm: string; ageDays: number; rotationDeadlineDays: number } | null;
  tileCounts: { keks: number; subjectKeys: number; encryptedItems: number; pendingApprovals: number };
  healthStrip: { label: string; status: string }[];
}

export interface DecryptFailuresResponse {
  window: string;
  buckets: { hour: string; count: number }[];
}

export interface KeySummary {
  id: string;
  type: "kek" | "subject_key";
  state: KeyState;
  algorithm: string;
  createdAt: string;
  lastRotatedAt: string | null;
  dependentCount: number;
}

export interface KeyDetail extends KeySummary {
  parentId: string | null;
  legalTransitions: string[];
}

export interface KeyListResponse {
  items: KeySummary[];
  page: number;
  pageSize: number;
  total: number;
}

export interface BlastRadiusResponse {
  recordCount: number;
  tables: string[];
  downstreamKeyCount: number;
}

export interface RotatePreviewResponse {
  deksToRewrap: number;
  estimatedSeconds: number;
}

export interface RotateResponse {
  newKekId: string;
  jobId: string;
}

export interface GraphNode {
  id: string;
  type: "kek" | "subject_key";
  state: KeyState;
  dependentCount: number;
  parentId: string | null;
}

export interface GraphEdge {
  source: string;
  target: string;
}

export interface GraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface DownstreamResponse {
  descendantIds: string[];
}

export interface RewrapJobResponse {
  jobId: string;
  from: string;
  to: string;
  done: number;
  total: number;
  state: "running" | "paused" | "completed";
  rate: number;
  eta: number | null;
}

export interface RewrapFailureItem {
  itemId: string;
  subjectKeyId: string;
  reason: string;
  attempts: number;
  resolved: boolean;
}

export interface RewrapFailuresResponse {
  items: RewrapFailureItem[];
  page: number;
  pageSize: number;
  total: number;
}

export interface SubjectResponse {
  subjectId: string;
  subjectKeyId: string;
  state: KeyState;
  recordCount: number;
  tables: string[];
  lastAccessAt: string | null;
}

export interface FieldDigestResponse {
  table: string;
  column: string;
  recordId: string;
  maskedValue: string;
}

export interface ErasureResponse {
  certificateId: string;
  recordsUnreadable: number;
}

export interface VerifyUnreadableResponse {
  subjectId: string;
  sampled: number;
  allDecryptFailed: boolean;
  results: { envelopeId: string; decryptFailed: boolean }[];
}

export interface CertificateResponse {
  id: string;
  payload: Record<string, unknown>;
  signature: string;
}

export type ApprovalStatus = "pending" | "approved" | "consumed";

export interface ApprovalResponse {
  id: string;
  operation: string;
  targetId: string;
  recordCount: number;
  status: ApprovalStatus;
  requestedBy: string;
  approvedBy: string | null;
  createdAt: string;
  decidedAt: string | null;
  requiredApprovers: string[];
}

export interface AuditRow {
  id: number;
  timestamp: string;
  actor: string;
  operation: string;
  keyId: string | null;
  itemId: string | null;
  result: "ok" | "denied" | "error";
  details: Record<string, unknown> | null;
}

export interface AuditListResponse {
  items: AuditRow[];
  nextCursor: number | null;
}

export interface AuditVerifyResponse {
  ok: boolean;
  firstBrokenEntry?: number;
  expectedDigest?: string;
  storedDigest?: string;
}

export interface SettingsResponse {
  rotationIntervalDays: number;
  alertThreshold: number;
  activeProvider: string;
}

export interface ProviderInfo {
  id: string;
  available: boolean;
  active: boolean;
}

export interface ProvidersResponse {
  items: ProviderInfo[];
}

export interface BackupJobStartResponse {
  jobId: string;
}

export interface BackupJobStatus {
  status: "completed" | "failed";
  ok: boolean;
  error?: string;
}

export interface ThreatModelResponse {
  title: string;
  scopeIntro: string;
  doesNotProtectAgainst: string[];
  closing: string;
}
