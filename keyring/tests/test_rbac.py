"""FR-9: RBAC scope matrix and the structural separation-of-duty guarantee
(no role may both destroy and mutate/read the audit log in a way that lets
it cover its own tracks)."""
from __future__ import annotations

from keyring.core import rbac
from keyring.models.enums import Role


def test_operator_scopes_are_exactly_encrypt_decrypt_file_read_write():
    assert set(rbac.scopes_for(Role.OPERATOR.value)) == {"encrypt", "decrypt", "file_read", "file_write"}


def test_key_admin_scopes_are_exactly_the_destructive_and_management_set():
    assert set(rbac.scopes_for(Role.KEY_ADMIN.value)) == {
        "rotate", "revoke", "destroy", "rewrap_manage", "approve",
        "request_approval", "settings_write", "provider_activate",
    }


def test_auditor_scopes_are_exactly_audit_read_and_file_read():
    assert set(rbac.scopes_for(Role.AUDITOR.value)) == {"audit_read", "file_read"}


def test_unknown_role_has_no_scopes():
    assert rbac.scopes_for("nonexistent-role") == []


def test_has_scope_matches_scopes_for():
    for role in (Role.OPERATOR.value, Role.KEY_ADMIN.value, Role.AUDITOR.value):
        for scope in rbac.scopes_for(role):
            assert rbac.has_scope(role, scope)
        assert not rbac.has_scope(role, "not-a-real-scope")


def test_no_production_role_holds_both_destroy_and_audit_read():
    """FR-9.2: separation of duty — the role that can destroy a key must
    never be the same role that can read (and thus, in a differently-built
    system, tamper with) the audit trail. Checked over the three
    production roles only; super-admin is a documented dev/demo exception
    (see test_super_admin_is_a_deliberate_break_glass_exception_to_fr9)."""
    for role in (Role.OPERATOR.value, Role.KEY_ADMIN.value, Role.AUDITOR.value):
        scopes = rbac.scopes_for(role)
        assert not ("destroy" in scopes and "audit_read" in scopes), (
            f"role '{role}' holds both destroy and audit_read"
        )


def test_super_admin_is_a_deliberate_break_glass_exception_to_fr9():
    """super-admin intentionally holds every scope, including destroy +
    audit_read together — the one combination FR-9.2 exists to prevent.
    It's a local dev/demo convenience role, not part of the production
    RBAC model (see THREAT_MODEL.md). This test exists so shrinking or
    widening its scope set is a deliberate, reviewed change."""
    assert set(rbac.scopes_for(Role.SUPER_ADMIN.value)) == {
        "encrypt", "decrypt", "file_write", "file_read",
        "rotate", "revoke", "destroy", "rewrap_manage", "approve",
        "request_approval", "settings_write", "provider_activate",
        "audit_read",
    }


def test_operator_cannot_destroy_or_rotate_or_read_audit():
    op_scopes = set(rbac.scopes_for(Role.OPERATOR.value))
    assert "destroy" not in op_scopes
    assert "rotate" not in op_scopes
    assert "audit_read" not in op_scopes


def test_auditor_cannot_encrypt_decrypt_or_destroy():
    auditor_scopes = set(rbac.scopes_for(Role.AUDITOR.value))
    assert not auditor_scopes & {"encrypt", "decrypt", "destroy", "rotate", "revoke"}


def test_only_key_admin_can_approve_or_request_approval():
    for role in (Role.OPERATOR.value, Role.AUDITOR.value):
        scopes = set(rbac.scopes_for(role))
        assert "approve" not in scopes
        assert "request_approval" not in scopes
    assert "approve" in rbac.scopes_for(Role.KEY_ADMIN.value)
    assert "request_approval" in rbac.scopes_for(Role.KEY_ADMIN.value)
