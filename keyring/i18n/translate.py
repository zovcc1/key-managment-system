from __future__ import annotations

import json
from pathlib import Path

_DIR = Path(__file__).parent
SUPPORTED = ("en", "ar")

_catalogs: dict[str, dict[str, str]] = {}
for _lang in SUPPORTED:
    _catalogs[_lang] = json.loads((_DIR / f"{_lang}.json").read_text(encoding="utf-8"))

_reference_keys = set(_catalogs["en"].keys())
for _lang, _catalog in _catalogs.items():
    missing = _reference_keys - set(_catalog.keys())
    if missing:
        raise RuntimeError(f"i18n catalog '{_lang}' is missing keys: {sorted(missing)}")


def negotiate_locale(accept_language: str | None) -> str:
    """Honour Accept-Language: ar / en; unsupported values fall back to en
    without error."""
    if not accept_language:
        return "en"
    for part in accept_language.split(","):
        lang = part.split(";")[0].strip().lower()[:2]
        if lang in SUPPORTED:
            return lang
    return "en"


def t(key: str, locale: str = "en", **params) -> str:
    catalog = _catalogs.get(locale, _catalogs["en"])
    if key not in catalog:
        raise KeyError(f"missing i18n key '{key}' for locale '{locale}'")
    text = catalog[key]
    if params:
        text = text.format(**params)
    return text
