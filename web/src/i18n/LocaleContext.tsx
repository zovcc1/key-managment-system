import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { getLocale, setLocale as setClientLocale } from "../api/client";
import { tc, type ChromeKey, type Locale } from "./chrome";

interface LocaleCtx {
  locale: Locale;
  dir: "ltr" | "rtl";
  setLocale: (l: Locale) => void;
  t: (key: ChromeKey, params?: Record<string, string | number>) => string;
}

const Ctx = createContext<LocaleCtx | null>(null);

export function LocaleProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(getLocale());
  const dir = locale === "ar" ? "rtl" : "ltr";

  useEffect(() => {
    document.documentElement.lang = locale;
    document.documentElement.dir = dir;
  }, [locale, dir]);

  const value = useMemo<LocaleCtx>(
    () => ({
      locale,
      dir,
      setLocale: (l: Locale) => {
        setClientLocale(l);
        setLocaleState(l);
      },
      t: (key, params) => tc(locale, key, params),
    }),
    [locale, dir],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useLocale(): LocaleCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useLocale must be used within LocaleProvider");
  return ctx;
}
