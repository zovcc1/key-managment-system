from __future__ import annotations

from keyring.i18n import t

_BOUNDARY_KEYS = [
    "threat_model.boundary.live_compromise",
    "threat_model.boundary.authz_bugs",
    "threat_model.boundary.root_admin",
    "threat_model.boundary.compromised_clients",
    "threat_model.boundary.exported_plaintext",
]


def render(locale: str = "en") -> dict:
    return {
        "title": t("threat_model.title", locale),
        "scopeIntro": t("threat_model.scope_intro", locale),
        "doesNotProtectAgainst": [t(key, locale) for key in _BOUNDARY_KEYS],
        "closing": t("threat_model.closing", locale),
    }
