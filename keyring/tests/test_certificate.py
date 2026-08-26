"""Signed erasure certificates: sign/verify round trip, tamper detection,
canonical-JSON stability, JSON/PDF export, and the missing-signing-key
failure mode."""
from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest

from keyring.core import certificate as cert_module


@pytest.fixture(autouse=True)
def signing_key(monkeypatch):
    monkeypatch.setenv("KEYRING_CERT_SIGNING_KEY", "unit-test-signing-key")


def _payload(**overrides) -> dict:
    base = dict(
        subject_id="subj-1",
        subject_key_id="sk-1",
        records_unreadable=42,
        tables_affected=["users", "addresses"],
        operator="alice",
        approval_chain=[{"role": "requester", "operatorId": "alice"}, {"role": "approver", "operatorId": "bob"}],
    )
    base.update(overrides)
    return cert_module.build_payload(**base)


def test_build_payload_has_expected_shape():
    payload = _payload()
    assert payload["subjectId"] == "subj-1"
    assert payload["subjectKeyId"] == "sk-1"
    assert payload["recordsUnreadable"] == 42
    assert payload["tablesAffected"] == ["users", "addresses"]
    assert payload["operator"] == "alice"
    assert "timestamp" in payload
    assert "boundary" in payload
    assert len(payload["approvalChain"]) == 2


def test_sign_and_verify_round_trip():
    payload = _payload()
    signature = cert_module.sign_payload(payload)
    assert cert_module.verify_signature(payload, signature)


def test_signature_is_deterministic_for_same_payload():
    payload = _payload()
    sig1 = cert_module.sign_payload(payload)
    sig2 = cert_module.sign_payload(payload)
    assert sig1 == sig2


def test_mutating_any_field_invalidates_signature():
    payload = _payload()
    signature = cert_module.sign_payload(payload)

    mutated = copy.deepcopy(payload)
    mutated["recordsUnreadable"] = 43
    assert not cert_module.verify_signature(mutated, signature)


def test_mutating_nested_approval_chain_invalidates_signature():
    payload = _payload()
    signature = cert_module.sign_payload(payload)

    mutated = copy.deepcopy(payload)
    mutated["approvalChain"][1]["operatorId"] = "eve"
    assert not cert_module.verify_signature(mutated, signature)


def test_signature_forged_with_wrong_key_is_rejected(monkeypatch):
    payload = _payload()
    monkeypatch.setenv("KEYRING_CERT_SIGNING_KEY", "a-different-key")
    forged = cert_module.sign_payload(payload)

    monkeypatch.setenv("KEYRING_CERT_SIGNING_KEY", "unit-test-signing-key")
    assert not cert_module.verify_signature(payload, forged)


def test_canonical_json_ordering_is_stable_regardless_of_key_insertion_order():
    payload_a = {"b": 2, "a": 1, "c": {"z": 1, "y": 2}}
    payload_b = {"a": 1, "c": {"y": 2, "z": 1}, "b": 2}
    assert cert_module.sign_payload(payload_a) == cert_module.sign_payload(payload_b)


def test_sign_payload_raises_when_signing_key_env_var_unset(monkeypatch):
    monkeypatch.delenv("KEYRING_CERT_SIGNING_KEY", raising=False)
    with pytest.raises(cert_module.SigningKeyUnavailable):
        cert_module.sign_payload(_payload())


def _fake_cert_row(payload=None, signature="sig-abc"):
    payload = payload or _payload()
    return SimpleNamespace(id="cert-1", payload=payload, signature=signature)


def test_export_json_round_trips_id_payload_signature():
    row = _fake_cert_row()
    raw = cert_module.export_json(row)
    parsed = json.loads(raw)
    assert parsed["id"] == "cert-1"
    assert parsed["payload"] == row.payload
    assert parsed["signature"] == "sig-abc"


def test_export_pdf_emits_a_valid_pdf_header():
    row = _fake_cert_row()
    raw = cert_module.export_pdf(row, "en")
    assert raw.startswith(b"%PDF-")


def test_export_pdf_works_for_arabic_locale_too():
    row = _fake_cert_row()
    raw = cert_module.export_pdf(row, "ar")
    assert raw.startswith(b"%PDF-")
