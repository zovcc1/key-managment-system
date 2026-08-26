"""FR-9: three roles, non-overlapping destructive capability.

No single role may both destroy a key and mutate the audit log (FR-9.2).
This holds structurally: the audit log has no mutation endpoint at all
(append-only, written only by the service layer itself), so satisfying it
is a matter of never adding one — not a runtime check.
"""
from __future__ import annotations

from keyring.models.enums import Role

SCOPES: dict[str, list[str]] = {
    Role.OPERATOR.value: ["encrypt", "decrypt"],
    Role.KEY_ADMIN.value: [
        "rotate", "revoke", "destroy", "rewrap_manage", "approve",
        "request_approval", "settings_write", "provider_activate",
    ],
    Role.AUDITOR.value: ["audit_read"],
}


def scopes_for(role: str) -> list[str]:
    return SCOPES.get(role, [])


def has_scope(role: str, scope: str) -> bool:
    return scope in scopes_for(role)
