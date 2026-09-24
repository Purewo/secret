from __future__ import annotations

import http.client
import io
import json
import threading
import urllib.parse
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from agent_vault.storage import Vault, VaultError
from agent_vault.client import SyncClient, SyncClientError
from agent_vault.web import DEFAULT_PORT, build_server


@contextmanager
def running_web_server() -> Iterator[tuple[str, int]]:
    server = build_server("127.0.0.1", 0, vault=Vault(), username="admin", password="123456")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield str(host), int(port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request_json(
    address: tuple[str, int],
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    *,
    cookie: str | None = None,
    csrf_token: str | None = None,
    authorization: str | None = None,
) -> tuple[int, dict[str, Any], http.client.HTTPMessage]:
    connection = http.client.HTTPConnection(*address, timeout=3)
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if payload is not None else {}
    if cookie:
        headers["Cookie"] = cookie
    if csrf_token:
        headers["X-CSRF-Token"] = csrf_token
    if authorization:
        headers["Authorization"] = authorization
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    raw = response.read()
    parsed = json.loads(raw.decode("utf-8"))
    result = response.status, parsed, response.headers
    connection.close()
    return result


def login(address: tuple[str, int]) -> tuple[str, str]:
    status, payload, headers = request_json(
        address,
        "POST",
        "/api/login",
        {"username": "admin", "password": "123456"},
    )
    assert status == 200
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    return cookie, payload["csrf_token"]


def skill_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("example/SKILL.md", "---\nname: example\n---\n# Example\n")
        archive.writestr("example/scripts/run.py", "print('hello')\n")
    return buffer.getvalue()


def upload_skill(address: tuple[str, int], cookie: str, csrf: str, archive: bytes, **fields: str):
    query = urllib.parse.urlencode(fields)
    connection = http.client.HTTPConnection(*address, timeout=5)
    connection.request("POST", f"/api/skills/upload?{query}", body=archive, headers={
        "Content-Type": "application/zip", "Cookie": cookie, "X-CSRF-Token": csrf,
    })
    response = connection.getresponse()
    result = response.status, json.loads(response.read().decode("utf-8"))
    connection.close()
    return result


def test_default_web_port_is_2005() -> None:
    assert DEFAULT_PORT == 2005


def test_skill_repository_scope_metadata_and_download(vault_home, fake_keyring) -> None:
    with running_web_server() as address:
        cookie, csrf = login(address)
        assert request_json(address, "POST", "/api/skills/categories", {"id": "documents", "name": "文档"}, cookie=cookie, csrf_token=csrf)[0] == 201
        archive = skill_zip()
        status, created = upload_skill(address, cookie, csrf, archive,
                                       name="Doc Expert", description="Write polished documents", version="1.0.0", category="documents")
        assert status == 201
        skill = created["skill"]
        assert skill["versions"][0]["requires_environment"] is True
        assert skill["versions"][0]["download_count"] == 0
        assert skill["versions"][0]["size_bytes"] == len(archive)
        assert skill["versions"][0]["download_url"].endswith("/versions/1.0.0/download")
        status, next_version = upload_skill(address, cookie, csrf, archive,
                                            name="Doc Expert", description="Write polished documents", version="1.1.0",
                                            category="documents", skill_id=skill["id"], environment="no")
        assert status == 201
        assert [item["version"] for item in next_version["skill"]["versions"]] == ["1.1.0", "1.0.0"]
        assert next_version["skill"]["versions"][0]["requires_environment"] is False
        assert upload_skill(address, cookie, csrf, archive, name="Doc Expert", description="duplicate",
                            version="1.1.0", category="documents", skill_id=skill["id"])[0] == 400
        status, private_skill = upload_skill(address, cookie, csrf, archive,
                                             name="Other Skill", description="Different category", version="1.0.0")
        assert status == 201

        status, key_payload, _ = request_json(address, "POST", "/api/api-keys", {"name": "skill-agent"}, cookie=cookie, csrf_token=csrf)
        assert status == 201
        key = key_payload["api_key"]
        auth = f"Bearer {key['api_key']}"
        assert request_json(address, "GET", "/api/v1/skills/categories", authorization=auth)[0] == 403
        assert request_json(address, "POST", f"/api/api-keys/{key['id']}/permissions",
                            {"categories": [], "read": False, "add": False, "delete": False, "skill_categories": ["documents"]},
                            cookie=cookie, csrf_token=csrf)[0] == 200
        status, categories, _ = request_json(address, "GET", "/api/v1/skills/categories", authorization=auth)
        assert status == 200
        assert [item["id"] for item in categories["categories"]] == ["documents"]
        status, listed, _ = request_json(address, "GET", "/api/v1/skills?category=documents", authorization=auth)
        assert status == 200 and listed["skills"][0]["name"] == "Doc Expert"
        assert request_json(address, "GET", "/api/v1/skills?category=__other__", authorization=auth)[0] == 403
        assert request_json(address, "GET", "/api/v1/skills", authorization=auth)[1]["skills"][0]["id"] == skill["id"]
        assert len(request_json(address, "GET", "/api/v1/skills", authorization=auth)[1]["skills"]) == 1
        assert request_json(address, "GET", f"/api/v1/skills/{private_skill['skill']['id']}", authorization=auth)[0] == 403
        assert request_json(address, "GET", private_skill["skill"]["versions"][0]["download_url"], authorization=auth)[0] == 403
        status, detail, _ = request_json(address, "GET", f"/api/v1/skills/{skill['id']}", authorization=auth)
        assert status == 200 and detail["skill"]["versions"][0]["version"] == "1.1.0"
        connection = http.client.HTTPConnection(*address, timeout=5)
        connection.request("GET", detail["skill"]["versions"][1]["download_url"], headers={"Authorization": auth})
        response = connection.getresponse()
        assert response.status == 200
        assert response.read() == archive
        connection.close()
        status, detail, _ = request_json(address, "GET", f"/api/v1/skills/{skill['id']}", authorization=auth)
        assert detail["skill"]["versions"][1]["download_count"] == 1
        assert request_json(address, "GET", "/api/v1/sync/pull", authorization=auth)[0] == 403

        client = SyncClient(vault_home / "agent-client")
        client.configure(f"http://{address[0]}:{address[1]}", key["api_key"])
        assert [item["id"] for item in client.skill_categories()["categories"]] == ["documents"]
        assert client.list_skills("documents")["skills"][0]["id"] == skill["id"]
        output = vault_home / "downloaded-skill.zip"
        result = client.download_skill(skill["id"], "1.0.0", output)
        assert result["version"] == "1.0.0"
        assert output.read_bytes() == archive
        try:
            client.download_skill(skill["id"], "1.0.0", output)
        except SyncClientError as exc:
            assert "already exists" in str(exc)
        else:
            assert False, "existing download must not be overwritten"

        package = vault_home / "skill-package.zip"
        package.write_bytes(archive)
        try:
            client.upload_skill(package, name="Blocked", description="No upload permission", version="1.0.0", category="documents")
        except SyncClientError as exc:
            assert "无权上传" in str(exc)
        else:
            assert False, "read-only Skill key must not upload"

        status, granted, _ = request_json(address, "POST", f"/api/api-keys/{key['id']}/permissions",
                                          {"categories": [], "read": False, "add": False, "delete": False,
                                           "skill_categories": ["documents"], "skill_upload_categories": ["documents"]},
                                          cookie=cookie, csrf_token=csrf)
        assert status == 200
        assert granted["api_key"]["permissions"]["skill_upload_categories"] == ["documents"]
        uploaded = client.upload_skill(package, name="Agent Published", description="Published through profile",
                                       version="1.0.0", category="documents")
        assert uploaded["skill"]["category"] == "documents"
        try:
            client.upload_skill(package, name="Blocked", description="Wrong category", version="1.0.0", category="__other__")
        except SyncClientError as exc:
            assert "无权上传" in str(exc)
        else:
            assert False, "Skill key must not upload to another category"
        next_version = client.upload_skill(package, version="1.2.0", skill_id=skill["id"])
        assert next_version["skill"]["category"] == "documents"
        assert next_version["skill"]["name"] == "Doc Expert"

        status, full_access, _ = request_json(address, "POST", f"/api/api-keys/{key['id']}/permissions",
                                              {"categories": ["__all__"], "read": True, "add": True, "delete": True,
                                               "skill_categories": [], "skill_upload_categories": ["__all__"]},
                                              cookie=cookie, csrf_token=csrf)
        assert status == 200
        assert full_access["api_key"]["permissions"]["skill_categories"] == ["__all__"]
        assert client.list_skills("__other__")["skills"][0]["id"] == private_skill["skill"]["id"]
        assert client.upload_skill(package, name="Cross Agent", description="Shared result", version="1.0.0",
                                   category="__other__")["skill"]["category"] == "__other__"
        assert request_json(address, "GET", "/api/v1/sync/pull", authorization=auth)[0] == 200


def test_skill_upload_rejects_unsafe_archive(vault_home, fake_keyring) -> None:
    with running_web_server() as address:
        cookie, csrf = login(address)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("../SKILL.md", "# Unsafe\n")
        status, payload = upload_skill(address, cookie, csrf, buffer.getvalue(), name="Unsafe", description="Unsafe path", version="1.0.0")
        assert status == 400
        assert "不安全" in payload["error"]


def test_web_shell_has_security_headers(vault_home, fake_keyring) -> None:
    with running_web_server() as address:
        connection = http.client.HTTPConnection(*address, timeout=3)
        connection.request("GET", "/")
        response = connection.getresponse()
        body = response.read().decode("utf-8")
        assert response.status == 200
        assert "Agent Vault" in body
        assert "default-src 'self'" in response.headers["Content-Security-Policy"]
        assert response.headers["X-Frame-Options"] == "DENY"
        connection.close()


def test_login_rejects_wrong_password(vault_home, fake_keyring) -> None:
    with running_web_server() as address:
        status, payload, headers = request_json(
            address,
            "POST",
            "/api/login",
            {"username": "admin", "password": "wrong"},
        )
        assert status == 401
        assert "不正确" in payload["error"]
        assert headers.get("Set-Cookie") is None


def test_admin_can_change_password_and_must_relogin(vault_home, fake_keyring) -> None:
    with running_web_server() as address:
        cookie, csrf_token = login(address)
        status, payload, headers = request_json(
            address,
            "POST",
            "/api/settings/password",
            {
                "current_password": "123456",
                "new_password": "new-password-123",
                "confirm_password": "new-password-123",
            },
            cookie=cookie,
            csrf_token=csrf_token,
        )
        assert status == 200
        assert payload == {"ok": True, "requires_relogin": True}
        assert "Max-Age=0" in headers["Set-Cookie"]
        assert request_json(address, "GET", "/api/snapshot", cookie=cookie)[0] == 401
        assert "new-password-123" not in (vault_home / "web_auth.json").read_text()

        status, _, _ = request_json(
            address,
            "POST",
            "/api/login",
            {"username": "admin", "password": "123456"},
        )
        assert status == 401

        status, _, _ = request_json(
            address,
            "POST",
            "/api/login",
            {"username": "admin", "password": "new-password-123"},
        )
        assert status == 200

    with running_web_server() as restarted_address:
            status, _, _ = request_json(
                restarted_address,
                "POST",
                "/api/login",
                {"username": "admin", "password": "new-password-123"},
            )
            assert status == 200


def test_password_change_rejects_mismatch_and_short_password(vault_home, fake_keyring) -> None:
    with running_web_server() as address:
        cookie, csrf_token = login(address)
        status, payload, _ = request_json(
            address,
            "POST",
            "/api/settings/password",
            {
                "current_password": "123456",
                "new_password": "short",
                "confirm_password": "different",
            },
            cookie=cookie,
            csrf_token=csrf_token,
        )
        assert status == 400
        assert "至少需要" in payload["error"]


def test_api_requires_session_and_csrf(vault_home, fake_keyring) -> None:
    with running_web_server() as address:
        status, session, _ = request_json(address, "GET", "/api/session")
        assert status == 200
        assert session == {"authenticated": False}

        status, _, _ = request_json(address, "GET", "/api/snapshot")
        assert status == 401

        cookie, _ = login(address)
        status, payload, _ = request_json(
            address,
            "POST",
            "/api/entries",
            {"id": "demo_server", "description": "test server"},
            cookie=cookie,
        )
        assert status == 403
        assert "校验失败" in payload["error"]


def test_create_entry_and_secret_never_returns_secret_value(vault_home, fake_keyring) -> None:
    with running_web_server() as address:
        cookie, csrf_token = login(address)

        status, push_result, _ = request_json(
            address,
            "POST",
            "/api/entries",
            {"id": "demo_server", "description": "test server", "tags": ["server"]},
            cookie=cookie,
            csrf_token=csrf_token,
        )
        assert status == 201

        secret_value = "test-only-secret-value"
        status, payload, _ = request_json(
            address,
            "POST",
            "/api/secrets",
            {
                "name": "demo_server_password",
                "value": secret_value,
                "entry": "demo_server",
                "note": "test credential",
                "tags": ["test"],
            },
            cookie=cookie,
            csrf_token=csrf_token,
        )
        assert status == 201
        assert secret_value not in json.dumps(payload)

        status, snapshot, _ = request_json(address, "GET", "/api/snapshot", cookie=cookie)
        assert status == 200
        serialized = json.dumps(snapshot)
        assert secret_value not in serialized
        assert snapshot["metrics"] == {"entries": 1, "secrets": 1, "unassigned": 0}
        assert snapshot["entries"][0]["variables"][0]["name"] == "demo_server_password"

        status, revealed, headers = request_json(
            address,
            "POST",
            "/api/secrets/reveal",
            {"name": "demo_server_password"},
            cookie=cookie,
            csrf_token=csrf_token,
        )
        assert status == 200
        assert revealed == {"name": "demo_server_password", "value": secret_value}
        assert headers["Cache-Control"] == "no-store"


def test_reveal_requires_csrf(vault_home, fake_keyring) -> None:
    vault = Vault()
    vault.init()
    vault.set_secret("demo_password", "test-only-secret-value")
    with running_web_server() as address:
        cookie, _ = login(address)
        status, payload, _ = request_json(
            address,
            "POST",
            "/api/secrets/reveal",
            {"name": "demo_password"},
            cookie=cookie,
        )
        assert status == 403
        assert "校验失败" in payload["error"]


def test_secret_value_cannot_be_empty(vault_home, fake_keyring) -> None:
    with running_web_server() as address:
        cookie, csrf_token = login(address)
        status, payload, _ = request_json(
            address,
            "POST",
            "/api/secrets",
            {"name": "empty_secret", "value": ""},
            cookie=cookie,
            csrf_token=csrf_token,
        )
        assert status == 400
        assert "不能为空" in payload["error"]


def test_web_categories_create_filter_metadata_and_batch_move(vault_home, fake_keyring) -> None:
    vault = Vault()
    vault.init()
    vault.set_entry("game_account", "游戏账号")
    vault.set_entry("japan_server", "日本服务器")
    with running_web_server() as address:
        cookie, csrf_token = login(address)

        status, payload, _ = request_json(
            address,
            "POST",
            "/api/categories",
            {"id": "servers", "name": "服务器", "color": "blue"},
            cookie=cookie,
            csrf_token=csrf_token,
        )
        assert status == 201
        assert payload["category"]["name"] == "服务器"

        status, payload, _ = request_json(
            address,
            "POST",
            "/api/categories/assign",
            {"category": "servers", "entries": ["japan_server"]},
            cookie=cookie,
            csrf_token=csrf_token,
        )
        assert status == 200
        assert payload == {"assigned": 1}

        status, snapshot, _ = request_json(address, "GET", "/api/snapshot", cookie=cookie)
        assert status == 200
        assert [(category["name"], category["entry_count"]) for category in snapshot["categories"]] == [
            ("服务器", 1),
            ("其他", 1),
        ]
        entries = {entry["id"]: entry for entry in snapshot["entries"]}
        assert entries["japan_server"]["category"] == "servers"
        assert entries["game_account"]["category"] is None


def test_api_key_is_separate_and_bearer_can_use_content_api(vault_home, fake_keyring) -> None:
    with running_web_server() as address:
        cookie, csrf_token = login(address)
        status, created_payload, _ = request_json(
            address,
            "POST",
            "/api/api-keys",
            {"name": "remote-agent", "note": "trusted office agent"},
            cookie=cookie,
            csrf_token=csrf_token,
        )
        assert status == 201
        created = created_payload["api_key"]
        raw_key = created["api_key"]
        assert raw_key.startswith("avk_")
        assert "key_hash" not in created

        status, listed, _ = request_json(address, "GET", "/api/api-keys", cookie=cookie)
        assert status == 200
        assert raw_key not in json.dumps(listed)
        assert listed["api_keys"][0]["permissions"] == {"categories": [], "read": False, "add": False, "delete": False, "skill_categories": [], "skill_upload_categories": []}

        status, revealed, _ = request_json(
            address,
            "POST",
            f"/api/api-keys/{created['id']}/reveal",
            {},
            cookie=cookie,
            csrf_token=csrf_token,
        )
        assert status == 200
        assert revealed["api_key"] == raw_key

        authorization = f"Bearer {raw_key}"
        status, _, _ = request_json(address, "GET", "/api/v1/sync/pull", authorization=authorization)
        assert status == 403

        status, push_result, _ = request_json(
            address,
            "POST",
            f"/api/api-keys/{created['id']}/permissions",
            {"categories": ["__other__"], "read": True, "add": True, "delete": False},
            cookie=cookie,
            csrf_token=csrf_token,
        )
        assert status == 200

        status, snapshot, _ = request_json(address, "GET", "/api/v1/sync/pull", authorization=authorization)
        assert status == 200
        assert "entries" in snapshot

        status, push_result, _ = request_json(
            address,
            "POST",
            "/api/v1/sync/push",
            {"entries": [{"id": "agent_created_entry", "description": "created by trusted agent", "variables": [{"name": "agent_created_secret", "value": "test-only"}]}]},
            authorization=authorization,
        )
        assert status == 200
        assert push_result["results"][0]["ok"] is True
        status, _, _ = request_json(address, "DELETE", "/api/v1/secrets/agent_created_secret", authorization=authorization)
        assert status == 403

        status, _, _ = request_json(
            address,
            "POST",
            f"/api/api-keys/{created['id']}/permissions",
            {"categories": ["__other__"], "read": True, "add": True, "delete": True},
            cookie=cookie,
            csrf_token=csrf_token,
        )
        assert status == 200
        status, _, _ = request_json(address, "DELETE", "/api/v1/secrets/agent_created_secret", authorization=authorization)
        assert status == 200

        status, _, _ = request_json(address, "GET", "/api/api-keys", authorization=authorization)
        assert status == 403

        status, _, _ = request_json(
            address,
            "POST",
            f"/api/api-keys/{created['id']}/revoke",
            {},
            cookie=cookie,
            csrf_token=csrf_token,
        )
        assert status == 200
        status, _, _ = request_json(address, "GET", "/api/v1/sync/pull", authorization=authorization)
        assert status == 401

        assert raw_key.encode("utf-8") not in (vault_home / "vault.db").read_bytes()
        assert (vault_home / "ApiKeys" / "api_keys.db").exists()


def test_api_key_category_scope_filters_snapshot_and_writes(vault_home, fake_keyring) -> None:
    vault = Vault()
    vault.init()
    vault.set_category("servers", "服务器")
    vault.set_entry("server_one", "server", category="servers")
    vault.set_entry("game_one", "game")
    with running_web_server() as address:
        cookie, csrf_token = login(address)
        status, created_payload, _ = request_json(
            address,
            "POST",
            "/api/api-keys",
            {"name": "server-agent"},
            cookie=cookie,
            csrf_token=csrf_token,
        )
        assert status == 201
        created = created_payload["api_key"]
        authorization = f"Bearer {created['api_key']}"

        status, permission_result, _ = request_json(
            address,
            "POST",
            f"/api/api-keys/{created['id']}/permissions",
            {"categories": ["servers"], "read": True, "add": True, "delete": False},
            cookie=cookie,
            csrf_token=csrf_token,
        )
        assert status == 200

        status, snapshot, _ = request_json(address, "GET", "/api/v1/sync/pull", authorization=authorization)
        assert status == 200
        assert [entry["id"] for entry in snapshot["entries"]] == ["server_one"]
        assert snapshot["metrics"]["entries"] == 1

        status, server_push, _ = request_json(
            address,
            "POST",
            "/api/v1/sync/push",
            {"entries": [{"id": "server_two", "description": "another server", "category": "servers"}]},
            authorization=authorization,
        )
        assert status == 200
        assert snapshot["entries"][0]["id"] == "server_one"
        status, blocked_push, _ = request_json(
            address,
            "POST",
            "/api/v1/sync/push",
            {"entries": [{"id": "game_two", "description": "blocked game"}]},
            authorization=authorization,
        )
        assert status == 200
        assert permission_result["api_key"]["permissions"]["categories"] == ["servers"]
        assert server_push["results"][0]["ok"] is True
        assert blocked_push["results"][0]["ok"] is False
        assert blocked_push["results"][0]["code"] == "permission_denied"


def test_api_key_move_requires_access_to_both_categories(vault_home, fake_keyring) -> None:
    vault = Vault()
    vault.init()
    vault.set_category("servers", "Servers")
    vault.set_category("games", "Games")
    vault.set_entry("server_one", "server before", category="servers")
    vault.set_entry("game_one", "game before", category="games")
    vault.set_secret("game_token", "test-only", entry="game_one")
    with running_web_server() as address:
        cookie, csrf_token = login(address)
        status, created, _ = request_json(
            address, "POST", "/api/api-keys", {"name": "restricted-agent"},
            cookie=cookie, csrf_token=csrf_token,
        )
        assert status == 201
        key = created["api_key"]
        bearer = f"Bearer {key['api_key']}"
        status, _, _ = request_json(
            address, "POST", f"/api/api-keys/{key['id']}/permissions",
            {"categories": ["servers"], "read": True, "add": True, "delete": False},
            cookie=cookie, csrf_token=csrf_token,
        )
        assert status == 200

        def push(item: dict[str, Any]) -> dict[str, Any]:
            status, payload, _ = request_json(
                address, "POST", "/api/v1/sync/push", {"entries": [item]}, authorization=bearer,
            )
            assert status == 200
            return payload["results"][0]

        assert push({"id": "game_one", "description": "stolen", "category": "servers"})["code"] == "permission_denied"
        assert vault.get_entry("game_one")["category"] == "games"
        assert vault.get_entry("game_one")["description"] == "game before"

        assert push({"id": "server_one", "description": "moved", "category": "games"})["code"] == "permission_denied"
        assert vault.get_entry("server_one")["category"] == "servers"

        assert push({
            "id": "server_one", "description": "hijack", "category": "servers",
            "variables": [{"name": "game_token", "value": "changed"}],
        })["code"] == "permission_denied"
        assert vault.get_entry("server_one")["description"] == "server before"
        assert vault.get_secret("game_token")["entry"] == "game_one"
        assert vault.get_secret("game_token")["value"] == "test-only"

        status, _, _ = request_json(
            address, "POST", f"/api/api-keys/{key['id']}/permissions",
            {"categories": ["servers", "games"], "read": True, "add": True, "delete": False},
            cookie=cookie, csrf_token=csrf_token,
        )
        assert status == 200
        assert push({"id": "server_one", "description": "moved", "category": "games"})["ok"] is True
        assert vault.get_entry("server_one")["category"] == "games"


def test_api_key_delete_entry_removes_secrets_and_syncs_local_client(vault_home, fake_keyring) -> None:
    vault = Vault()
    vault.init()
    vault.set_category("servers", "Servers")
    vault.set_category("games", "Games")
    vault.set_entry("old_server", "to delete", category="servers")
    vault.set_entry("keep_game", "must stay", category="games")
    vault.set_secret("old_password", "test-only", entry="old_server")
    vault.set_secret("keep_token", "keep-value", entry="keep_game")
    with running_web_server() as address:
        cookie, csrf_token = login(address)
        status, created, _ = request_json(
            address, "POST", "/api/api-keys", {"name": "delete-test"},
            cookie=cookie, csrf_token=csrf_token,
        )
        assert status == 201
        key = created["api_key"]
        bearer = f"Bearer {key['api_key']}"
        permission_path = f"/api/api-keys/{key['id']}/permissions"
        status, _, _ = request_json(
            address, "POST", permission_path,
            {"categories": ["servers", "games"], "read": True, "add": False, "delete": False},
            cookie=cookie, csrf_token=csrf_token,
        )
        assert status == 200

        client_home = vault_home / "offline-client"
        client = SyncClient(client_home)
        client.configure(f"http://{address[0]}:{address[1]}", key["api_key"])
        client.pull()
        assert client.vault.get_secret("old_password")["value"] == "test-only"
        cursor = client.status()["cursor"]

        status, _, _ = request_json(address, "DELETE", "/api/v1/entries/old_server", authorization=bearer)
        assert status == 403
        assert vault.get_entry("old_server")["id"] == "old_server"

        status, _, _ = request_json(
            address, "POST", permission_path,
            {"categories": ["games"], "read": True, "add": False, "delete": True},
            cookie=cookie, csrf_token=csrf_token,
        )
        assert status == 200
        status, _, _ = request_json(address, "DELETE", "/api/v1/entries/old_server", authorization=bearer)
        assert status == 403
        assert vault.get_entry("old_server")["id"] == "old_server"

        status, _, _ = request_json(
            address, "POST", permission_path,
            {"categories": ["servers", "games"], "read": True, "add": False, "delete": True},
            cookie=cookie, csrf_token=csrf_token,
        )
        assert status == 200
        status, result, _ = request_json(address, "DELETE", "/api/v1/entries/old_server", authorization=bearer)
        assert status == 200
        assert result == {"id": "old_server", "deleted_records": 1}
        assert "test-only" not in json.dumps(result)
        with pytest.raises(VaultError, match="not found"):
            vault.get_secret("old_password")
        assert vault.get_secret("keep_token")["value"] == "keep-value"

        status, changes, _ = request_json(
            address, "GET", f"/api/v1/sync/pull?cursor={cursor}", authorization=bearer,
        )
        assert status == 200
        assert changes["deleted_entries"] == [{"id": "old_server", "category": "servers"}]
        assert changes["deleted_records"] == [{"name": "old_password", "entry": "old_server", "category": "servers"}]
        client.pull()
        with pytest.raises(VaultError, match="not found"):
            client.vault.get_entry("old_server")
        with pytest.raises(VaultError, match="not found"):
            client.vault.get_secret("old_password")
        assert client.vault.get_secret("keep_token")["value"] == "keep-value"
