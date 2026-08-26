import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";

interface ToastItem {
  id: number;
  message: string;
  tone: "default" | "danger";
}

interface ToastCtx {
  push: (message: string, tone?: ToastItem["tone"]) => void;
}

const Ctx = createContext<ToastCtx | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const nextId = useRef(0);

  const push = useCallback((message: string, tone: ToastItem["tone"] = "default") => {
    const id = nextId.current++;
    setItems((cur) => [...cur, { id, message, tone }]);
    window.setTimeout(() => {
      setItems((cur) => cur.filter((i) => i.id !== id));
    }, 5000);
  }, []);

  const value = useMemo(() => ({ push }), [push]);

  return (
    <Ctx.Provider value={value}>
      {children}
      <div className="kr-toast-stack" role="status" aria-live="polite">
        {items.map((i) => (
          <div key={i.id} className="card elev-lg kr-toast" style={i.tone === "danger" ? { borderInlineStart: "3px solid #d97878" } : undefined}>
            {i.message}
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}

export function useToast(): ToastCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
}
