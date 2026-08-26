import type { ReactNode } from "react";
import { Navigate, Route, HashRouter, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import { LocaleProvider } from "./i18n/LocaleContext";
import { ToastProvider } from "./components/Toast";
import Shell from "./components/Shell";
import Login from "./routes/Login";
import Locked from "./routes/Locked";
import Dashboard from "./routes/Dashboard";
import KeyMap from "./routes/KeyMap";
import Keys from "./routes/Keys";
import Rewrap from "./routes/Rewrap";
import Privacy from "./routes/Privacy";
import Audit from "./routes/Audit";
import Settings from "./routes/Settings";

function RequireSession({ children }: { children: ReactNode }) {
  const { status } = useAuth();
  if (status === "locked") return <Navigate to="/locked" replace />;
  if (status === "anonymous") return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function Routed() {
  const { status } = useAuth();
  return (
    <Routes>
      <Route path="/login" element={status === "authenticated" ? <Navigate to="/dashboard" replace /> : <Login />} />
      <Route path="/locked" element={status === "locked" ? <Locked /> : <Navigate to="/login" replace />} />
      <Route
        path="/"
        element={
          <RequireSession>
            <Shell />
          </RequireSession>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="map" element={<KeyMap />} />
        <Route path="keys" element={<Keys />} />
        <Route path="rewrap" element={<Rewrap />} />
        <Route path="privacy" element={<Privacy />} />
        <Route path="audit" element={<Audit />} />
        <Route path="settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <LocaleProvider>
      <ToastProvider>
        <AuthProvider>
          <HashRouter>
            <Routed />
          </HashRouter>
        </AuthProvider>
      </ToastProvider>
    </LocaleProvider>
  );
}
