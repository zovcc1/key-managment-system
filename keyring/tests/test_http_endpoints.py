"""HTTP-layer coverage for the routers with no prior tests: session,
dashboard, decrypt-failure metrics, alert ack, graph, audit (list/filters/
export.csv/verify), settings, providers, and threat-model. Destroy/erasure/
approval/rewrap/keys-list flows already have dedicated test files."""
from __future__ import annotations

from keyring.core.service import KeyringService
from keyring.models.settings_model import Alert
from keyring.providers.file_provider import FileKeyProvider

ALICE_KEY = "test-key-admin-alice"
CAROL_KEY = "test-auditor-carol"
DAN_KEY = "test-operator-dan"


def _seed_all(client) -> None:
    client.seed_operator("Alice", "key-admin", ALICE_KEY)
    client.seed_operator("Carol", "auditor", CAROL_KEY)
    client.seed_operator("Dan", "operator", DAN_KEY)


def _bootstrap_kek(client) -> str:
    provider = FileKeyProvider()
    provider.connect()
    db = client.session_factory()
    try:
        service = KeyringService(db, provider)
        kek = service.create_kek("bootstrap")
        service.activate_kek(kek.id, "bootstrap")
        db.commit()
        return kek.id
    finally:
        db.close()
        provider.disconnect()


# --- session -----------------------------------------------------------

def test_open_session_returns_token_role_and_scopes(client):
    _seed_all(client)
    resp = client.http.post("/api/session", json={"provider": "file"}, headers={"X-Api-Key": DAN_KEY})
    assert resp.status_code == 200
    body = resp.json()
    assert body["operator"] == "Dan"
    assert body["role"] == "operator"
    assert set(body["scopes"]) == {"encrypt", "decrypt", "file_read", "file_write"}
    assert body["locked"] is False
    assert "token" in body and "expiresAt" in body


def test_open_session_wrong_key_is_unauthorized(client):
    _seed_all(client)
    resp = client.http.post("/api/session", json={"provider": "file"}, headers={"X-Api-Key": "not-a-real-key"})
    assert resp.status_code == 401
    assert resp.json()["code"] == "UNAUTHORIZED"


def test_open_session_missing_header_is_unauthorized(client):
    _seed_all(client)
    resp = client.http.post("/api/session", json={"provider": "file"})
    assert resp.status_code == 401


def test_session_status_requires_auth(client):
    resp = client.http.get("/api/session")
    assert resp.status_code == 401


def test_session_status_returns_expected_shape(client):
    _seed_all(client)
    dan = client.open_session(DAN_KEY)
    resp = client.http.get("/api/session", headers=client.auth(dan["token"]))
    assert resp.status_code == 200
    body = resp.json()
    assert body["operator"] == "Dan"
    assert body["locked"] is False
    assert body["providerConnected"] is True


def test_lock_session_then_status_is_session_locked(client):
    _seed_all(client)
    dan = client.open_session(DAN_KEY)
    resp = client.http.delete("/api/session", headers=client.auth(dan["token"]))
    assert resp.status_code == 200
    assert resp.json()["locked"] is True

    resp = client.http.get("/api/session", headers=client.auth(dan["token"]))
    assert resp.status_code == 401
    assert resp.json()["code"] == "SESSION_LOCKED"


# --- dashboard -----------------------------------------------------------

def test_dashboard_reflects_created_kek_and_item_counts(client):
    _seed_all(client)
    dan = client.open_session(DAN_KEY)
    _bootstrap_kek(client)

    resp = client.http.post(
        "/api/encrypt",
        json={"subjectId": "subj-dash-1", "table": "users", "column": "email", "recordId": "rec-1", "plaintext": "hi"},
        headers=client.auth(dan["token"]),
    )
    assert resp.status_code == 200, resp.text

    resp = client.http.get("/api/dashboard", headers=client.auth(dan["token"]))
    assert resp.status_code == 200
    body = resp.json()
    assert body["activeKek"] is not None
    assert body["tileCounts"]["keks"] >= 1
    assert body["tileCounts"]["subjectKeys"] >= 1
    assert body["tileCounts"]["encryptedItems"] >= 1
    labels = {h["label"]: h["status"] for h in body["healthStrip"]}
    assert labels["provider_connected"] == "ok"
    assert labels["audit_chain"] == "ok"
    assert labels["active_kek"] == "ok"


def test_decrypt_failures_metrics_default_window(client):
    _seed_all(client)
    dan = client.open_session(DAN_KEY)
    resp = client.http.get("/api/metrics/decrypt-failures", headers=client.auth(dan["token"]))
    assert resp.status_code == 200
    body = resp.json()
    assert body["window"] == "24h"
    assert isinstance(body["buckets"], list)


def test_alert_ack_marks_acknowledged_by_actor(client):
    _seed_all(client)
    dan = client.open_session(DAN_KEY)

    db = client.session_factory()
    try:
        db.add(Alert(id="alert-1", kind="rotation_due", message_code="rotation_due"))
        db.commit()
    finally:
        db.close()

    resp = client.http.post("/api/alerts/alert-1/ack", headers=client.auth(dan["token"]))
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "alert-1"
    assert body["acknowledged"] is True


def test_alert_ack_unknown_id_is_not_found(client):
    _seed_all(client)
    dan = client.open_session(DAN_KEY)
    resp = client.http.post("/api/alerts/does-not-exist/ack", headers=client.auth(dan["token"]))
    assert resp.status_code == 404
    assert resp.json()["code"] == "NOT_FOUND"


# --- graph -----------------------------------------------------------

def test_graph_lists_kek_and_subject_key_nodes(client):
    _seed_all(client)
    dan = client.open_session(DAN_KEY)
    kek_id = _bootstrap_kek(client)

    resp = client.http.post(
        "/api/encrypt",
        json={"subjectId": "subj-graph-1", "table": "users", "column": "email", "recordId": "rec-1", "plaintext": "hi"},
        headers=client.auth(dan["token"]),
    )
    assert resp.status_code == 200, resp.text

    resp = client.http.get("/api/graph", headers=client.auth(dan["token"]))
    assert resp.status_code == 200
    body = resp.json()
    node_types = {n["id"]: n["type"] for n in body["nodes"]}
    assert node_types.get(kek_id) == "kek"
    assert any(n["type"] == "subject_key" and n["parentId"] == kek_id for n in body["nodes"])
    assert any(e["source"] == kek_id for e in body["edges"])


def test_graph_downstream_from_kek_lists_its_subject_keys(client):
    _seed_all(client)
    dan = client.open_session(DAN_KEY)
    kek_id = _bootstrap_kek(client)
    client.http.post(
        "/api/encrypt",
        json={"subjectId": "subj-graph-2", "table": "users", "column": "email", "recordId": "rec-1", "plaintext": "hi"},
        headers=client.auth(dan["token"]),
    )

    resp = client.http.get(f"/api/graph/{kek_id}/downstream", headers=client.auth(dan["token"]))
    assert resp.status_code == 200
    assert len(resp.json()["descendantIds"]) >= 1


def test_graph_downstream_from_subject_key_is_empty(client):
    _seed_all(client)
    dan = client.open_session(DAN_KEY)
    _bootstrap_kek(client)
    resp = client.http.post(
        "/api/encrypt",
        json={"subjectId": "subj-graph-3", "table": "users", "column": "email", "recordId": "rec-1", "plaintext": "hi"},
        headers=client.auth(dan["token"]),
    )
    subject_key_id = resp.json()["subjectKeyId"]

    resp = client.http.get(f"/api/graph/{subject_key_id}/downstream", headers=client.auth(dan["token"]))
    assert resp.status_code == 200
    assert resp.json()["descendantIds"] == []


def test_graph_downstream_unknown_node_is_not_found(client):
    _seed_all(client)
    dan = client.open_session(DAN_KEY)
    resp = client.http.get("/api/graph/does-not-exist/downstream", headers=client.auth(dan["token"]))
    assert resp.status_code == 404


# --- audit -----------------------------------------------------------

def test_audit_list_returns_items_generated_by_session_open(client):
    _seed_all(client)
    carol = client.open_session(CAROL_KEY)  # generates a session_open audit row
    resp = client.http.get("/api/audit", headers=client.auth(carol["token"]))
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["items"]) >= 1
    assert body["items"][0]["operation"] == "session_open"
    assert body["nextCursor"] == body["items"][-1]["id"]


def test_audit_list_filters_by_actor(client):
    _seed_all(client)
    client.open_session(DAN_KEY)
    carol = client.open_session(CAROL_KEY)

    resp = client.http.get("/api/audit", params={"actor": "Dan"}, headers=client.auth(carol["token"]))
    assert resp.status_code == 200
    body = resp.json()
    assert body["items"]
    assert all(row["actor"] == "Dan" for row in body["items"])


def test_audit_list_filters_by_operation(client):
    _seed_all(client)
    carol = client.open_session(CAROL_KEY)
    resp = client.http.get("/api/audit", params={"operation": "session_open"}, headers=client.auth(carol["token"]))
    assert resp.status_code == 200
    body = resp.json()
    assert all(row["operation"] == "session_open" for row in body["items"])


def test_audit_list_cursor_paginates_forward(client):
    _seed_all(client)
    client.open_session(DAN_KEY)
    carol = client.open_session(CAROL_KEY)

    first = client.http.get("/api/audit", params={"limit": 1}, headers=client.auth(carol["token"])).json()
    assert len(first["items"]) == 1
    second = client.http.get(
        "/api/audit", params={"limit": 1, "cursor": first["nextCursor"]}, headers=client.auth(carol["token"])
    ).json()
    assert len(second["items"]) == 1
    assert second["items"][0]["id"] > first["items"][0]["id"]


def test_audit_list_requires_audit_read_scope(client):
    _seed_all(client)
    dan = client.open_session(DAN_KEY)
    resp = client.http.get("/api/audit", headers=client.auth(dan["token"]))
    assert resp.status_code == 403
    assert resp.json()["code"] == "FORBIDDEN"


def test_audit_verify_ok_true_on_untampered_chain(client):
    _seed_all(client)
    carol = client.open_session(CAROL_KEY)
    resp = client.http.post("/api/audit/verify", headers=client.auth(carol["token"]))
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_audit_export_csv_default_locale_is_english(client):
    _seed_all(client)
    carol = client.open_session(CAROL_KEY)
    resp = client.http.get("/api/audit/export.csv", headers=client.auth(carol["token"]))
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert resp.headers["content-language"] == "en"
    first_line = resp.text.splitlines()[0]
    assert "actor" in first_line.lower()


def test_audit_export_csv_arabic_locale_has_different_header(client):
    _seed_all(client)
    carol = client.open_session(CAROL_KEY)
    en_resp = client.http.get("/api/audit/export.csv", headers=client.auth(carol["token"]))
    ar_resp = client.http.get(
        "/api/audit/export.csv", headers={**client.auth(carol["token"]), "Accept-Language": "ar"}
    )
    assert ar_resp.status_code == 200
    assert ar_resp.headers["content-language"] == "ar"
    assert ar_resp.text.splitlines()[0] != en_resp.text.splitlines()[0]


def test_audit_actors_and_operations_endpoints(client):
    _seed_all(client)
    client.open_session(DAN_KEY)
    carol = client.open_session(CAROL_KEY)

    resp = client.http.get("/api/audit/actors", headers=client.auth(carol["token"]))
    assert resp.status_code == 200
    assert "Dan" in resp.json()["actors"]

    resp = client.http.get("/api/audit/operations", headers=client.auth(carol["token"]))
    assert resp.status_code == 200
    assert "session_open" in resp.json()["operations"]


# --- settings / providers / backup / threat-model -----------------------

def test_get_settings_requires_settings_write_scope(client):
    _seed_all(client)
    dan = client.open_session(DAN_KEY)
    resp = client.http.get("/api/settings", headers=client.auth(dan["token"]))
    assert resp.status_code == 403


def test_get_and_patch_settings(client):
    _seed_all(client)
    alice = client.open_session(ALICE_KEY)

    resp = client.http.get("/api/settings", headers=client.auth(alice["token"]))
    assert resp.status_code == 200
    assert resp.json()["rotationIntervalDays"] == 90

    resp = client.http.patch(
        "/api/settings", json={"rotationIntervalDays": 60}, headers=client.auth(alice["token"])
    )
    assert resp.status_code == 200
    assert resp.json()["rotationIntervalDays"] == 60

    resp = client.http.get("/api/settings", headers=client.auth(alice["token"]))
    assert resp.json()["rotationIntervalDays"] == 60


def test_list_providers_includes_all_four_with_bool_availability(client):
    _seed_all(client)
    alice = client.open_session(ALICE_KEY)
    resp = client.http.get("/api/providers", headers=client.auth(alice["token"]))
    assert resp.status_code == 200
    items = {i["id"]: i for i in resp.json()["items"]}
    assert set(items) == {"file", "env", "vault", "kms"}
    for item in items.values():
        assert isinstance(item["available"], bool)
    assert items["file"]["active"] is True


def test_activate_provider_switches_active_provider(client):
    _seed_all(client)
    alice = client.open_session(ALICE_KEY)  # connects "file" first

    resp = client.http.post("/api/providers/env/activate", headers=client.auth(alice["token"]))
    assert resp.status_code == 200
    assert resp.json()["active"] == "env"

    resp = client.http.get("/api/providers", headers=client.auth(alice["token"]))
    items = {i["id"]: i for i in resp.json()["items"]}
    assert items["env"]["active"] is True
    assert items["file"]["active"] is False


def test_activate_unknown_provider_is_not_found(client):
    _seed_all(client)
    alice = client.open_session(ALICE_KEY)
    resp = client.http.post("/api/providers/does-not-exist/activate", headers=client.auth(alice["token"]))
    assert resp.status_code == 404


def test_backup_verify_completes_ok_for_file_provider(client):
    _seed_all(client)
    alice = client.open_session(ALICE_KEY)  # connects "file"

    resp = client.http.post("/api/backup/verify", headers=client.auth(alice["token"]))
    assert resp.status_code == 200
    job_id = resp.json()["jobId"]

    resp = client.http.get(f"/api/backup/verify/{job_id}", headers=client.auth(alice["token"]))
    assert resp.status_code == 200
    assert resp.json() == {"status": "completed", "ok": True}


def test_backup_verify_unknown_job_is_not_found(client):
    _seed_all(client)
    alice = client.open_session(ALICE_KEY)
    resp = client.http.get("/api/backup/verify/does-not-exist", headers=client.auth(alice["token"]))
    assert resp.status_code == 404


def test_threat_model_requires_no_auth_and_has_five_boundary_items(client):
    resp = client.http.get("/api/threat-model")
    assert resp.status_code == 200
    body = resp.json()
    assert "title" in body and "scopeIntro" in body and "closing" in body
    assert len(body["doesNotProtectAgainst"]) == 5


def test_threat_model_arabic_locale_differs_from_english(client):
    en = client.http.get("/api/threat-model").json()
    ar = client.http.get("/api/threat-model", headers={"Accept-Language": "ar"}).json()
    assert en["title"] != ar["title"]
