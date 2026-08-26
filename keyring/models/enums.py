from __future__ import annotations

import enum


class KeyState(str, enum.Enum):
    PENDING = "pending"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"
    DESTROYED = "destroyed"


class KeyType(str, enum.Enum):
    KEK = "kek"
    SUBJECT_KEY = "subject_key"


class Role(str, enum.Enum):
    OPERATOR = "operator"
    KEY_ADMIN = "key-admin"
    AUDITOR = "auditor"


class Operation(str, enum.Enum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    DECRYPT_FAILED = "decrypt_failed"
    ROTATE_KEK = "rotate_kek"
    REWRAP = "rewrap"
    REVOKE = "revoke"
    DESTROY = "destroy"
    ERASURE = "erasure"
    APPROVE = "approve"
    APPROVAL_REQUEST = "approval_request"
    SESSION_OPEN = "session_open"
    SESSION_LOCK = "session_lock"


class ApprovalStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CONSUMED = "consumed"


# Forward-only lifecycle graphs (FR-4.3). `revoked` and `destroyed` are
# terminal in both. KEKs and subject keys deliberately use different graphs:
# a KEK must pass through deprecated/revoked before destroy (destroying the
# in-service KEK is meant to require rotating away from it first), but a
# subject key must support destroying directly from active — that direct
# active -> destroyed transition *is* crypto-shredding (section 3): a
# subject can be erased on demand without an intermediate revoke step.
KEK_LEGAL_TRANSITIONS: dict[KeyState, list[KeyState]] = {
    KeyState.PENDING: [KeyState.ACTIVE, KeyState.REVOKED],
    KeyState.ACTIVE: [KeyState.DEPRECATED, KeyState.REVOKED],
    KeyState.DEPRECATED: [KeyState.REVOKED, KeyState.DESTROYED],
    KeyState.REVOKED: [KeyState.DESTROYED],
    KeyState.DESTROYED: [],
}

SUBJECT_KEY_LEGAL_TRANSITIONS: dict[KeyState, list[KeyState]] = {
    KeyState.PENDING: [KeyState.ACTIVE, KeyState.REVOKED],
    KeyState.ACTIVE: [KeyState.REVOKED, KeyState.DESTROYED],
    KeyState.DEPRECATED: [KeyState.REVOKED, KeyState.DESTROYED],
    KeyState.REVOKED: [KeyState.DESTROYED],
    KeyState.DESTROYED: [],
}
