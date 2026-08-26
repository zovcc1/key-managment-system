/**
 * Thin fetch wrapper for the Keyring API.
 *
 * - Authorization: Bearer <token> — the session token is held in memory
 *   only (a module-level variable), never localStorage/sessionStorage.
 *   This is a key-management console: a token surviving in web storage
 *   after the tab closes is a needless persistence of a bearer credential.
 * - Accept-Language drives the backend's own bilingual error/label
 *   catalog (see keyring/i18n) — the client never re-implements
 *   translation of server-authored strings.
 * - Idempotency-Key is generated per call-site for destructive POSTs
 *   (destroy, erasure) — see keyring/api/idempotency.py, which rejects
 *   those routes outright without one.
 * - Every non-2xx response is normalized into an ApiError carrying the
 *   backend's own {code, message, ...details} envelope.
 */

// Empty base in production (the SPA is served from the same origin as the
// API, per keyring/main.py's static mount). In dev, Vite proxies /api to
// the uvicorn server (see vite.config.ts) so this can also stay empty.
const BASE_URL = "";

let _token: string | null = null;
let _locale: "en" | "ar" = (localStorage.getItem("kr.locale") as "en" | "ar") || "en";

export function setToken(token: string | null): void {
  _token = token;
}

export function getToken(): string | null {
  return _token;
}

export function setLocale(locale: "en" | "ar"): void {
  _locale = locale;
  localStorage.setItem("kr.locale", locale);
}

export function getLocale(): "en" | "ar" {
  return _locale;
}

export class ApiError extends Error {
  code: string;
  status: number;
  details: Record<string, unknown>;

  constructor(status: number, code: string, message: string, details: Record<string, unknown> = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function newIdempotencyKey(): string {
  return crypto.randomUUID();
}

interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
  headers?: Record<string, string>;
  /** Destructive endpoints require this — pass true to auto-generate one,
   * or pass an explicit string to reuse a key (e.g. on a manual retry of
   * the exact same request). */
  idempotent?: boolean | string;
  /** Skip attaching the Authorization header (session-open only). */
  anonymous?: boolean;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = {
    "Accept-Language": _locale,
    ...options.headers,
  };
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (!options.anonymous && _token) {
    headers["Authorization"] = `Bearer ${_token}`;
  }
  if (options.idempotent) {
    headers["Idempotency-Key"] = typeof options.idempotent === "string" ? options.idempotent : newIdempotencyKey();
  }

  const res = await fetch(BASE_URL + path, {
    method: options.method || "GET",
    headers,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });

  const contentType = res.headers.get("content-type") || "";
  if (!res.ok) {
    if (contentType.includes("application/json")) {
      const payload = await res.json();
      throw new ApiError(res.status, payload.code || "ERROR", payload.message || res.statusText, payload);
    }
    throw new ApiError(res.status, "ERROR", await res.text().catch(() => res.statusText));
  }

  if (res.status === 204) {
    return undefined as T;
  }
  if (contentType.includes("application/json")) {
    return (await res.json()) as T;
  }
  // CSV / PDF export endpoints — caller handles the blob directly.
  return (await res.blob()) as unknown as T;
}

export const api = {
  get: <T>(path: string, opts?: RequestOptions) => request<T>(path, { ...opts, method: "GET" }),
  post: <T>(path: string, body?: unknown, opts?: RequestOptions) => request<T>(path, { ...opts, method: "POST", body }),
  patch: <T>(path: string, body?: unknown, opts?: RequestOptions) => request<T>(path, { ...opts, method: "PATCH", body }),
  del: <T>(path: string, opts?: RequestOptions) => request<T>(path, { ...opts, method: "DELETE" }),
};

export async function fetchBlob(path: string): Promise<Blob> {
  const headers: Record<string, string> = { "Accept-Language": _locale };
  if (_token) headers["Authorization"] = `Bearer ${_token}`;
  const res = await fetch(BASE_URL + path, { headers });
  if (!res.ok) {
    const payload = await res.json().catch(() => ({}));
    throw new ApiError(res.status, payload.code || "ERROR", payload.message || res.statusText, payload);
  }
  return res.blob();
}
