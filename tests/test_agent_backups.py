from __future__ import annotations

import hashlib
import http.client
import io
import json
import sqlite3
import urllib.parse

import pytest

from agent_vault.client import SyncClient, SyncClientError, main as client_main
from agent_vault.memory_store import AgentBackupStore, BackupNotFound, PARTITIONS
from agent_vault.storage import VaultError
from test_memory_store import zip_archive
from test_web import login, request_json, running_web_server, upload_memory_backup


def upload(address, archive, *, bearer="", cookie="", csrf="", **fields):
    connection = http.client.HTTPConnection(*address, timeout=5)
    headers = {"Content-Type": "application/zip"}
    if bearer:
        headers["Authorization"] = bearer
    if cookie:
        headers["Cookie"] = cookie
        headers["X-CSRF-Token"] = csrf
    connection.request("POST", "/api/v1/agent-backups/upload?" + urllib.parse.urlencode(fields)
                       if bearer else "/api/agent-backups/upload?" + urllib.parse.urlencode(fields),
                       body=archive, headers=headers)
    response = connection.getresponse()
    result = response.status, json.loads(response.read())
    connection.close()
    return result


def create_key(address, cookie, csrf, name):
    status, payload, _ = request_json(address, "POST", "/api/api-keys", {"name": name}, cookie=cookie, csrf_token=csrf)
    assert status == 201
    key = payload["api_key"]
    status, _, _ = request_json(address, "POST", f"/api/api-keys/{key['id']}/permissions",
                               {"categories": ["__all__"], "read": True, "add": True, "delete": True,
                                "backup_read": True, "backup_upload": True, "backup_delete": True},
                               cookie=cookie, csrf_token=csrf)
    assert status == 200
    return key, "Bearer " + key["api_key"]


def legacy_backup(home):
    store = AgentBackupStore(home)
    store.packages.mkdir(parents=True)
    archive = zip_archive()
    (store.packages / "legacy.archive").write_bytes(archive)
    with sqlite3.connect(store.path) as connection:
        connection.executescript("""
            CREATE TABLE backups(id TEXT PRIMARY KEY, name TEXT, description TEXT, created_at TEXT, updated_at TEXT);
            CREATE TABLE versions(backup_id TEXT, version TEXT, original_filename TEXT, archive_format TEXT,
                package_path TEXT, bytes INTEGER, sha256 TEXT, uploaded_at TEXT, download_count INTEGER DEFAULT 0,
                PRIMARY KEY(backup_id,version), FOREIGN KEY(backup_id) REFERENCES backups(id) ON DELETE CASCADE);
            INSERT INTO backups VALUES ('memory_abcdefgh', 'Legacy', 'before ownership', '2026-10-01', '2026-10-01');
        """)
        connection.execute("INSERT INTO versions VALUES (?,?,?,?,?,?,?,?,?)",
                           ("memory_abcdefgh", "1", "legacy.zip", "zip", "legacy.archive", len(archive),
                            hashlib.sha256(archive).hexdigest(), "2026-10-01", 4))
    return store, archive


def test_store_isolates_owners_and_partitions(vault_home):
    store = AgentBackupStore(vault_home)
    store.init()
    archive = zip_archive()
    ids = []
    for partition in PARTITIONS:
        backup = store.upload(io.BytesIO(archive), len(archive), original_filename="agent.zip", version="1",
                              name="Lobster", owner_key_id="key_lobster", partition=partition)
        ids.append(backup["id"])
        assert backup["owner_key_id"] == "key_lobster"
        assert backup["partition"] == partition
        assert len(store.list_backups(owner_key_id="key_lobster", partition=partition)) == 1
    assert store.list_backups(owner_key_id="key_other") == []
    for backup_id in ids:
        with pytest.raises(BackupNotFound):
            store.detail(backup_id, owner_key_id="key_other")
        with pytest.raises(BackupNotFound):
            store.download(backup_id, "1", owner_key_id="key_other")
        with pytest.raises(BackupNotFound):
            store.delete(backup_id, owner_key_id="key_other")
        with pytest.raises(BackupNotFound):
            store.upload(io.BytesIO(archive), len(archive), original_filename="agent.zip", version="2",
                         backup_id=backup_id, owner_key_id="key_other")
    with pytest.raises(VaultError, match="分区"):
        store.upload(io.BytesIO(archive), len(archive), original_filename="agent.zip", version="2",
                     backup_id=ids[0], owner_key_id="key_lobster", partition="skills")
    with pytest.raises(VaultError, match="Key"):
        store.upload(io.BytesIO(archive), len(archive), original_filename="agent.zip", version="2",
                     name="No owner", owner_key_id="")
    with pytest.raises(VaultError, match="分区"):
        store.list_backups(partition="workspace")
    assert len(store.list_backups(owner_key_id="key_lobster")) == 3


def test_backup_metadata_edit_preserves_owner_partition_and_archive_versions(vault_home):
    store = AgentBackupStore(vault_home)
    store.init()
    archive = zip_archive()
    original = store.upload(io.BytesIO(archive), len(archive), original_filename="agent.zip", name="Before",
                            version="1", owner_key_id="key_lobster", partition="other")
    changed = store.update_metadata(original["id"], name="After", description="", owner_key_id="key_lobster")
    assert changed["name"] == "After" and changed["description"] == ""
    assert changed["owner_key_id"] == original["owner_key_id"] and changed["partition"] == "other"
    assert changed["versions"] == original["versions"]
    with pytest.raises(BackupNotFound):
        store.update_metadata(original["id"], name="Foreign", owner_key_id="key_other")
    with pytest.raises(VaultError):
        store.update_metadata(original["id"], name=" ", owner_key_id="key_lobster")
    assert len(list(store.packages.glob("*.archive"))) == 1
    assert next(store.packages.glob("*.archive")).read_bytes() == archive


def test_backup_metadata_api_requires_write_permission_owner_and_admin_csrf(vault_home, fake_keyring):
    with running_web_server() as address:
        cookie, csrf = login(address)
        key, bearer = create_key(address, cookie, csrf, "Lobster")
        _, foreign = create_key(address, cookie, csrf, "Other")
        status, payload = upload(address, zip_archive(), bearer=bearer, filename="agent.zip", name="Original", version="1", partition="skills")
        assert status == 201
        original = payload["backup"]
        path = f"/api/v1/agent-backups/{original['id']}/metadata"
        assert request_json(address, "POST", path, {"name": "Foreign"}, authorization=foreign)[0] == 404
        assert request_json(address, "POST", path, {"owner_key_id": "key_other"}, authorization=bearer)[0] == 400
        status, changed, _ = request_json(address, "POST", path, {"name": "Updated", "description": "New note"}, authorization=bearer)
        assert status == 200 and changed["backup"]["name"] == "Updated"
        assert changed["backup"]["versions"] == original["versions"]
        request_json(address, "POST", f"/api/api-keys/{key['id']}/permissions", {"backup_read": True, "backup_upload": False}, cookie=cookie, csrf_token=csrf)
        assert request_json(address, "POST", path, {"name": "Denied"}, authorization=bearer)[0] == 403
        admin_path = path.replace("/api/v1/", "/api/")
        assert request_json(address, "POST", admin_path, {"name": "Admin"}, cookie=cookie)[0] == 403
        status, updated, _ = request_json(address, "POST", admin_path, {"name": "Admin", "description": ""}, cookie=cookie, csrf_token=csrf)
        assert status == 200 and updated["backup"]["name"] == "Admin" and updated["backup"]["description"] == ""
        assert updated["backup"]["owner_key_id"] == key["id"] and updated["backup"]["partition"] == "skills"


def test_legacy_migration_preserves_archives_and_requires_one_time_binding(vault_home):
    store, archive = legacy_backup(vault_home)
    store.init()
    store.init()
    backup = store.detail("memory_abcdefgh")
    assert backup["owner_key_id"] is None and backup["partition"] == "memory"
    assert backup["versions"][0]["download_count"] == 4
    assert (store.packages / "legacy.archive").read_bytes() == archive
    assert store.list_backups(owner_key_id="key_lobster") == []
    with pytest.raises(BackupNotFound):
        store.detail("memory_abcdefgh", owner_key_id="key_lobster")
    store.bind_owner("memory_abcdefgh", "key_lobster")
    assert store.detail("memory_abcdefgh", owner_key_id="key_lobster")["versions"][0]["sha256"] == hashlib.sha256(archive).hexdigest()
    with pytest.raises(VaultError, match="不能更换"):
        store.bind_owner("memory_abcdefgh", "key_other")


def test_http_enforces_key_ownership_on_new_and_legacy_routes(vault_home, fake_keyring):
    archive = zip_archive()
    with running_web_server() as address:
        cookie, csrf = login(address)
        key_a, bearer_a = create_key(address, cookie, csrf, "Lobster")
        key_b, bearer_b = create_key(address, cookie, csrf, "Other agent")
        for partition in PARTITIONS:
            status, payload = upload(address, archive, bearer=bearer_a, name="Lobster", filename="agent.zip", version="1", partition=partition)
            assert status == 201
            backup = payload["backup"]
            backup_id = backup["id"]
            assert backup["owner_key_id"] == key_a["id"] and backup["partition"] == partition
            for prefix in ("/api/v1/agent-backups", "/api/v1/memory-backups"):
                assert request_json(address, "GET", prefix, authorization=bearer_b)[1]["backups"] == []
                assert request_json(address, "GET", prefix + "/" + backup_id, authorization=bearer_b)[0] == 404
                assert request_json(address, "GET", prefix + "/" + backup_id + "/versions/1/download", authorization=bearer_b)[0] == 404
                assert request_json(address, "DELETE", prefix + "/" + backup_id, authorization=bearer_b)[0] == 404
            assert upload(address, archive, bearer=bearer_b, backup_id=backup_id, filename="agent.zip", version="2")[0] == 404
            assert upload_memory_backup(address, bearer_b, archive, backup_id=backup_id, filename="agent.zip", version="2")[0] == 404
        own = request_json(address, "GET", "/api/v1/agent-backups/space", authorization=bearer_b)[1]
        assert own["space"]["owner_key_id"] == key_b["id"] and own["backups"] == []
        assert set(own["partitions"]) == set(PARTITIONS) and "spaces" not in own
        assert request_json(address, "GET", "/api/v1/agent-backups?owner_key_id=" + key_a["id"], authorization=bearer_b)[0] == 400
        assert upload(address, archive, bearer=bearer_b, owner_key_id=key_a["id"], name="Spoof", filename="agent.zip", version="1")[0] == 400
        assert request_json(address, "GET", "/api/agent-backups", authorization=bearer_a)[0] == 403
        assert request_json(address, "GET", "/api/v1/agent-backups", cookie=cookie)[0] == 403
        assert request_json(address, "POST", f"/api/v1/agent-backups/{backup_id}/bind", {"owner_key_id": key_b["id"]}, authorization=bearer_b)[0] == 403
        assert len(request_json(address, "GET", "/api/v1/agent-backups?partition=skills", authorization=bearer_a)[1]["backups"]) == 1
        assert len(request_json(address, "GET", "/api/v1/agent-backups", authorization=bearer_a)[1]["backups"]) == 3
        assert upload(address, archive, bearer=bearer_b, name="Lobster", filename="agent.zip", version="1", partition="memory")[0] == 201
        assert len(request_json(address, "GET", "/api/v1/agent-backups", authorization=bearer_b)[1]["backups"]) == 1
        assert len(request_json(address, "GET", "/api/v1/agent-backups", authorization=bearer_a)[1]["backups"]) == 3


def test_admin_binding_download_key_lifecycle_and_client(vault_home, fake_keyring, capsys, monkeypatch):
    store, archive = legacy_backup(vault_home)
    with running_web_server() as address:
        cookie, csrf = login(address)
        key, bearer = create_key(address, cookie, csrf, "Lobster")
        admin = {"cookie": cookie, "csrf_token": csrf}
        assert upload(address, archive, cookie=cookie, csrf=csrf, name="Unbound", filename="agent.zip", version="1")[0] == 400
        assert upload(address, archive, cookie=cookie, csrf=csrf, name="Unknown", filename="agent.zip", version="1", owner_key_id="key_missing")[0] == 400
        assert request_json(address, "GET", "/api/v1/agent-backups", authorization=bearer)[1]["backups"] == []
        path = "/api/agent-backups/memory_abcdefgh"
        assert request_json(address, "POST", path + "/bind", {"owner_key_id": key["id"]}, cookie=cookie)[0] == 403
        assert request_json(address, "POST", path + "/bind", {"owner_key_id": key["id"]}, **admin)[0] == 200
        assert request_json(address, "POST", path + "/bind", {"owner_key_id": key["id"]}, **admin)[0] == 400
        detail = request_json(address, "GET", path, cookie=cookie)[1]["backup"]
        assert detail["versions"][0]["download_url"].startswith("/api/agent-backups/")
        connection = http.client.HTTPConnection(*address, timeout=5)
        connection.request("GET", detail["versions"][0]["download_url"], headers={"Cookie": cookie})
        response = connection.getresponse()
        assert response.status == 200 and response.read() == archive
        connection.close()
        client = SyncClient(vault_home / "client", profile="lobster")
        client.configure(f"http://{address[0]}:{address[1]}", key["api_key"])
        package = vault_home / "workspace.zip"
        package.write_bytes(archive)
        uploaded = client.upload_agent_backup(package, version="1", name="Workspace", partition="other")["backup"]
        client.upload_agent_backup(package, version="2", backup_id=uploaded["id"])
        assert client.agent_backup_info(uploaded["id"])["backup"]["partition"] == "other"
        output = vault_home / "restored.zip"
        client.download_agent_backup(uploaded["id"], "1", output)
        assert output.read_bytes() == archive
        with pytest.raises(SyncClientError, match="already exists"):
            client.download_agent_backup(uploaded["id"], "1", output)
        monkeypatch.setattr("agent_vault.client.SyncClient", lambda profile=None: client)
        monkeypatch.setattr("agent_vault.web.VaultWebHandler.log_message", lambda *args: None)
        capsys.readouterr()
        assert client_main(["--profile", "lobster", "backups", "list", "--partition", "other"]) == 0
        assert json.loads(capsys.readouterr().out)["backups"][0]["partition"] == "other"
        key_path = f"/api/api-keys/{key['id']}"
        assert request_json(address, "DELETE", key_path, **admin)[0] == 409
        assert request_json(address, "POST", key_path + "/revoke", {}, **admin)[0] == 200
        assert request_json(address, "GET", "/api/v1/agent-backups", authorization=bearer)[0] == 401
        assert request_json(address, "GET", path, cookie=cookie)[1]["backup"]["owner_key_id"] == key["id"]
        assert request_json(address, "DELETE", path, cookie=cookie)[0] == 403
        assert request_json(address, "DELETE", path, **admin)[0] == 200
        assert request_json(address, "DELETE", "/api/agent-backups/" + uploaded["id"], **admin)[0] == 200
        assert request_json(address, "DELETE", key_path, **admin)[0] == 200
