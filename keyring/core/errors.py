"""Domain exceptions. Every one carries a stable `code` and an `message_key`
(looked up in the locale catalogs) so the API layer can translate the
human-facing text without ever localizing the machine-readable `code`."""
from __future__ import annotations


class KeyringError(Exception):
    status_code = 400
    code = "ERROR"
    message_key = "error.generic"

    def __init__(self, message_key: str | None = None, **details):
        self.message_key = message_key or self.message_key
        self.details = details
        super().__init__(self.code)


class NotFoundError(KeyringError):
    status_code = 404
    code = "NOT_FOUND"
    message_key = "error.not_found"


class IllegalTransitionError(KeyringError):
    status_code = 409
    code = "ILLEGAL_TRANSITION"
    message_key = "error.illegal_transition"


class ActiveConflictError(KeyringError):
    status_code = 409
    code = "ACTIVE_CONFLICT"
    message_key = "error.active_conflict"


class BlockingDependentsError(KeyringError):
    status_code = 409
    code = "BLOCKING_DEPENDENTS"
    message_key = "error.blocking_dependents"


class ApprovalRequiredError(KeyringError):
    status_code = 409
    code = "APPROVAL_REQUIRED"
    message_key = "error.approval_required"


class SelfApprovalError(KeyringError):
    status_code = 403
    code = "SELF_APPROVAL_FORBIDDEN"
    message_key = "error.self_approval_forbidden"


class IdempotencyKeyMissingError(KeyringError):
    status_code = 400
    code = "IDEMPOTENCY_KEY_REQUIRED"
    message_key = "error.idempotency_key_required"


class SubjectKeyUnavailableError(KeyringError):
    status_code = 409
    code = "SUBJECT_KEY_UNAVAILABLE"
    message_key = "error.subject_key_unavailable"


class NoActiveKekError(KeyringError):
    status_code = 409
    code = "NO_ACTIVE_KEK"
    message_key = "error.no_active_kek"


class ForbiddenError(KeyringError):
    status_code = 403
    code = "FORBIDDEN"
    message_key = "error.forbidden"


class UnauthorizedError(KeyringError):
    status_code = 401
    code = "UNAUTHORIZED"
    message_key = "error.unauthorized"


class LockedSessionError(KeyringError):
    status_code = 401
    code = "SESSION_LOCKED"
    message_key = "error.session_locked"


class ConfirmationMismatchError(KeyringError):
    status_code = 400
    code = "CONFIRMATION_MISMATCH"
    message_key = "error.confirmation_mismatch"
