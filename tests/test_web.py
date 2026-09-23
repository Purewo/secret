from __future__ import annotations

import http.client
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from agent_vault.storage import Vault
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


def test_default_web_port_is_2001() -> None:
    assert DEFAULT_PORT == 2001


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
        assert listed["api_keys"][0]["permissions"] == {"categories": [], "read": False, "add": False, "delete": False}

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
