import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { ApiError, setToken } from "../api/client";
import { lockSession, openSession } from "../api/endpoints";
import type { Role } from "../api/types";

/**
 * The mockup's "Locked" overlay offers an instant, unauthenticated "Reopen
 * key provider" button. The real backend has no such endpoint: DELETE
 * /api/session is one-way — it disconnects the provider and the session row
 * is dead from then on (see keyring/api/session.py). So "locked" here always
 * means "go back to the login screen and open a brand-new session" — never
 * a fake unlock. This is a deliberate departure from the mockup to match
 * real one-way session semantics.
 */

type Status = "anonymous" | "authenticated" | "locked";

interface AuthState {
  status: Status;
  operator: string | null;
  role: Role | null;
  scopes: string[];
  provider: string | null;
  expiresAt: string | null;
}

interface AuthCtx extends AuthState {
  login: (apiKey: string, provider?: string) => Promise<void>;
  lock: () => Promise<void>;
  /** Called by screens when a request comes back 401/SESSION_LOCKED — flips
   * to the locked screen without re-calling the (already-dead) lock endpoint. */
  reportUnauthorized: () => void;
  hasScope: (scope: string) => boolean;
  msUntilLock: number | null;
}

const Ctx = createContext<AuthCtx | null>(null);

const initial: AuthState = {
  status: "anonymous",
  operator: null,
  role: null,
  scopes: [],
  provider: null,
  expiresAt: null,
};

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(initial);
  const [msUntilLock, setMsUntilLock] = useState<number | null>(null);
  const tickRef = useRef<number | undefined>(undefined);

  const clearToLocked = useCallback(() => {
    setToken(null);
    setState((s) => ({ ...initial, status: s.status === "anonymous" ? "anonymous" : "locked" }));
    setMsUntilLock(null);
  }, []);

  const login = useCallback(async (apiKey: string, provider?: string) => {
    const res = await openSession(apiKey, provider);
    setToken(res.token);
    setState({
      status: "authenticated",
      operator: res.operator,
      role: res.role,
      scopes: res.scopes,
      provider: res.provider,
      expiresAt: res.expiresAt,
    });
  }, []);

  const lock = useCallback(async () => {
    try {
      await lockSession();
    } catch {
      // Session may already be expired server-side — locking client state
      // still needs to happen either way.
    }
    clearToLocked();
  }, [clearToLocked]);

  const reportUnauthorized = useCallback(() => {
    clearToLocked();
  }, [clearToLocked]);

  // Countdown to the server-issued expiresAt, mirroring the mockup's
  // "Session locks in ..." header text — but driving a real re-login on
  // expiry rather than a fake unlock.
  useEffect(() => {
    if (state.status !== "authenticated" || !state.expiresAt) {
      setMsUntilLock(null);
      return;
    }
    const deadline = new Date(state.expiresAt).getTime();
    const tick = () => {
      const remaining = deadline - Date.now();
      setMsUntilLock(Math.max(0, remaining));
      if (remaining <= 0) {
        window.clearInterval(tickRef.current);
        void lock();
      }
    };
    tick();
    tickRef.current = window.setInterval(tick, 1000);
    return () => window.clearInterval(tickRef.current);
  }, [state.status, state.expiresAt, lock]);

  const hasScope = useCallback((scope: string) => state.scopes.includes(scope), [state.scopes]);

  const value = useMemo<AuthCtx>(
    () => ({ ...state, login, lock, reportUnauthorized, hasScope, msUntilLock }),
    [state, login, lock, reportUnauthorized, hasScope, msUntilLock],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

/** Screens wrap fallible calls with this so a 401 (expired/locked token)
 * always routes to the real re-login flow instead of a raw error toast. */
export function isUnauthorized(err: unknown): err is ApiError {
  return err instanceof ApiError && (err.status === 401 || err.code === "SESSION_LOCKED");
}
