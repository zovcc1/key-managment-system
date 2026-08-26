"""Key lifecycle state machine (FR-4). Forward-only; revoked/destroyed are
terminal. This is the single source of truth for legal transitions — the
API layer and the seed script both call into this module rather than
re-implementing the graph."""
from __future__ import annotations

from keyring.models.enums import KEK_LEGAL_TRANSITIONS, SUBJECT_KEY_LEGAL_TRANSITIONS, KeyState

_GRAPHS = {"kek": KEK_LEGAL_TRANSITIONS, "subject_key": SUBJECT_KEY_LEGAL_TRANSITIONS}


class IllegalTransition(Exception):
    def __init__(self, current: str, target: str):
        self.current = current
        self.target = target
        super().__init__(f"illegal transition {current} -> {target}")


def legal_transitions(current: str, key_type: str = "kek") -> list[str]:
    try:
        state = KeyState(current)
    except ValueError:
        return []
    graph = _GRAPHS.get(key_type, KEK_LEGAL_TRANSITIONS)
    return [s.value for s in graph[state]]


def assert_legal(current: str, target: str, key_type: str = "kek") -> None:
    if target not in legal_transitions(current, key_type):
        raise IllegalTransition(current, target)
