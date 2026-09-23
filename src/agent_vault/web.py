from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import webbrowser
from dataclasses import dataclass
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import parse_qs, unquote, urlsplit

from .api_keys import ApiKeyStore
from .skill_store import MAX_PACKAGE_BYTES, SkillAccessError, SkillStore
from .storage import Vault, VaultError, utc_now

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 2001
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "123456"
SESSION_COOKIE = "agent_vault_session"
SESSION_TTL_SECONDS = 12 * 60 * 60
MAX_BODY_BYTES = 256 * 1024
LOGIN_WINDOW_SECONDS = 60
LOGIN_ATTEMPTS_PER_WINDOW = 8
WEB_AUTH_FILE_NAME = "web_auth.json"
PASSWORD_HASH_ITERATIONS = 310_000
MIN_PASSWORD_LENGTH = 8
CATEGORY_COLORS = {"mint", "blue", "yellow", "coral", "lilac"}


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True)
class WebSession:
    username: str
    csrf_token: str
    expires_at: float


@dataclass(frozen=True)
class RequestPrincipal:
    kind: str
    subject: str
    session: WebSession | None = None
    api_key: dict[str, Any] | None = None


class WebAuthStore:
    """Persist the web administrator password as a salted password hash."""

    def __init__(self, home: Path, username: str, initial_password: str) -> None:
        self.path = Path(home) / WEB_AUTH_FILE_NAME
        self.username = username
        self._lock = threading.Lock()
        self._salt = b""
        self._password_hash = b""
        self._load_or_initialize(initial_password)

    @staticmethod
    def _derive(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PASSWORD_HASH_ITERATIONS,
        )

    def _load_or_initialize(self, initial_password: str) -> None:
        if self.path.exists():
            try:
                payload = json.loads(self.path.read_text(encoding="utf-8"))
                if not isinstance(payload, dict) or payload.get("version") != 1:
                    raise ValueError("invalid version")
                if payload.get("username") != self.username:
                    raise ValueError("username mismatch")
                if payload.get("iterations") != PASSWORD_HASH_ITERATIONS:
                    raise ValueError("invalid hash parameters")
                salt = bytes.fromhex(payload["salt"])
                password_hash = bytes.fromhex(payload["password_hash"])
                if len(salt) < 16 or len(password_hash) != 32:
                    raise ValueError("invalid password hash")
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                raise VaultError("Web 登录凭据文件无效，请检查 web_auth.json。") from exc
            self._salt = salt
            self._password_hash = password_hash
            return

        if not initial_password:
            raise VaultError("Web password cannot be empty.")
        self._set_hash(initial_password)
        self._save()

    def _set_hash(self, password: str) -> None:
        self._salt = secrets.token_bytes(16)
        self._password_hash = self._derive(password, self._salt)

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "username": self.username,
            "salt": self._salt.hex(),
            "password_hash": self._password_hash.hex(),
            "iterations": PASSWORD_HASH_ITERATIONS,
        }
        temporary = self.path.with_name(f".{self.path.name}.{secrets.token_hex(8)}.tmp")
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(json.dumps(payload, ensure_ascii=True, indent=2) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)

    def verify(self, password: str) -> bool:
        if not isinstance(password, str):
            return False
        with self._lock:
            candidate = self._derive(password, self._salt)
            return hmac.compare_digest(candidate, self._password_hash)

    def change_password(self, current_password: str, new_password: str) -> None:
        with self._lock:
            candidate = self._derive(current_password, self._salt)
            if not hmac.compare_digest(candidate, self._password_hash):
                raise ApiError(HTTPStatus.BAD_REQUEST, "当前密码不正确。")
            previous = self._salt, self._password_hash
            try:
                self._set_hash(new_password)
                self._save()
            except OSError:
                self._salt, self._password_hash = previous
                raise


class VaultWebServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        vault: Vault,
        api_keys: ApiKeyStore,
        username: str,
        password: str,
    ) -> None:
        self.vault = vault
        self.api_keys = api_keys
        self.skills = SkillStore(vault.home)
        self.skills.init()
        self.auth_store = WebAuthStore(vault.home, username, password)
        self.username = self.auth_store.username
        self.sessions: dict[str, WebSession] = {}
        self.failed_logins: dict[str, list[float]] = {}
        self.state_lock = threading.RLock()
        super().__init__(server_address, VaultWebHandler)

    def login_allowed(self, client_ip: str) -> bool:
        now = time.monotonic()
        with self.state_lock:
            attempts = [
                attempt
                for attempt in self.failed_logins.get(client_ip, [])
                if now - attempt < LOGIN_WINDOW_SECONDS
            ]
            self.failed_logins[client_ip] = attempts
            return len(attempts) < LOGIN_ATTEMPTS_PER_WINDOW

    def record_failed_login(self, client_ip: str) -> None:
        with self.state_lock:
            self.failed_logins.setdefault(client_ip, []).append(time.monotonic())

    def clear_failed_logins(self, client_ip: str) -> None:
        with self.state_lock:
            self.failed_logins.pop(client_ip, None)

    def issue_session(self) -> tuple[str, WebSession]:
        session_id = secrets.token_urlsafe(32)
        session = WebSession(
            username=self.username,
            csrf_token=secrets.token_urlsafe(24),
            expires_at=time.monotonic() + SESSION_TTL_SECONDS,
        )
        with self.state_lock:
            self._purge_expired_sessions()
            self.sessions[session_id] = session
        return session_id, session

    def get_session(self, session_id: str | None) -> WebSession | None:
        if not session_id:
            return None
        with self.state_lock:
            self._purge_expired_sessions()
            return self.sessions.get(session_id)

    def drop_session(self, session_id: str | None) -> None:
        if not session_id:
            return
        with self.state_lock:
            self.sessions.pop(session_id, None)

    def change_password(self, session_id: str | None, current_password: str, new_password: str) -> None:
        with self.state_lock:
            if self.get_session(session_id) is None:
                raise ApiError(HTTPStatus.UNAUTHORIZED, "登录状态已失效，请重新登录。")
            self.auth_store.change_password(current_password, new_password)
            self.sessions.clear()
            self.failed_logins.clear()

    def _purge_expired_sessions(self) -> None:
        now = time.monotonic()
        expired = [session_id for session_id, session in self.sessions.items() if session.expires_at <= now]
        for session_id in expired:
            self.sessions.pop(session_id, None)


class VaultWebHandler(BaseHTTPRequestHandler):
    server: VaultWebServer

    def do_GET(self) -> None:
        try:
            path = urlsplit(self.path).path
            if path == "/api/session":
                bearer = self._bearer_token()
                if bearer is not None:
                    api_key = self.server.api_keys.authenticate(bearer)
                    if api_key is None:
                        raise ApiError(HTTPStatus.UNAUTHORIZED, "API key 无效或已撤销。")
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "authenticated": True,
                            "auth_type": "api_key",
                            "permissions": api_key.get("permissions", ["admin"]),
                        },
                    )
                    return
                session = self.server.get_session(self._session_id_from_cookie())
                if session is None:
                    self._send_json(HTTPStatus.OK, {"authenticated": False})
                    return
                self._send_json(
                    HTTPStatus.OK,
                    {"authenticated": True, "username": session.username, "csrf_token": session.csrf_token},
                )
                return
            if path == "/api/snapshot":
                self._require_admin_session()
                self._send_json(HTTPStatus.OK, self._snapshot())
                return
            if path == "/api/v1/sync/pull":
                principal = self._require_principal()
                self._require_api_key_principal(principal)
                self._require_api_permission(principal, "read")
                cursor = parse_qs(urlsplit(self.path).query).get("cursor", [""])[0]
                self._send_json(HTTPStatus.OK, self._sync_pull(principal, cursor))
                return
            if path == "/api/api-keys":
                self._require_admin_session()
                self._send_json(HTTPStatus.OK, {"api_keys": self.server.api_keys.list()})
                return
            if path in ("/api/skills/categories", "/api/v1/skills/categories"):
                allowed = self._skill_access(path)
                self._send_json(HTTPStatus.OK, {"categories": self.server.skills.categories(allowed)})
                return
            if path in ("/api/skills", "/api/v1/skills"):
                allowed = self._skill_access(path)
                category = parse_qs(urlsplit(self.path).query).get("category", [None])[0]
                self._send_json(HTTPStatus.OK, {"skills": self.server.skills.list_skills(category, allowed)})
                return
            if path.startswith(("/api/skills/", "/api/v1/skills/")):
                allowed = self._skill_access(path)
                tail = path.split("/skills/", 1)[1]
                parts = [unquote(part) for part in tail.split("/")]
                if len(parts) == 4 and parts[1] == "versions" and parts[3] == "download":
                    archive, digest = self.server.skills.download(parts[0], parts[2], allowed)
                    self._send_skill_file(archive, digest)
                    return
                if len(parts) == 1 and parts[0]:
                    self._send_json(HTTPStatus.OK, {"skill": self.server.skills.detail(parts[0], allowed)})
                    return
                raise ApiError(HTTPStatus.NOT_FOUND, "接口不存在。")
            if path.startswith("/api/"):
                raise ApiError(HTTPStatus.NOT_FOUND, "接口不存在。")
            self._serve_static(path)
        except ApiError as exc:
            self._send_json(exc.status, {"error": exc.message})
        except SkillAccessError as exc:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": str(exc)})
        except VaultError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except BrokenPipeError:
            return
        except Exception as exc:  # Keep implementation details out of the browser response.
            print(f"web request failed: {type(exc).__name__}")
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "服务器暂时无法完成请求。"})

    def do_POST(self) -> None:
        try:
            path = urlsplit(self.path).path
            if path == "/api/login":
                self._handle_login()
                return

            principal = self._require_principal()
            if principal.kind == "session":
                assert principal.session is not None
                self._require_csrf(principal.session)
            if path == "/api/logout":
                if principal.session is None:
                    raise ApiError(HTTPStatus.FORBIDDEN, "API key 不能退出浏览器会话。")
                self.server.drop_session(self._session_id_from_cookie())
                self._send_json(
                    HTTPStatus.OK,
                    {"ok": True},
                    cookie=self._expired_session_cookie(),
                )
                return
            if path == "/api/settings/password":
                self._require_session_from_principal(principal)
                payload = self._read_json()
                passwords = [payload.get(name) for name in ("current_password", "new_password", "confirm_password")]
                if any(not isinstance(value, str) or not value or len(value) > 256 for value in passwords):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "请填写当前密码、新密码和确认密码，每项最多 256 个字符。")
                current_password, new_password, confirm_password = passwords
                if len(new_password) < MIN_PASSWORD_LENGTH:
                    raise ApiError(HTTPStatus.BAD_REQUEST, f"新密码至少需要 {MIN_PASSWORD_LENGTH} 个字符。")
                if new_password != confirm_password:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "两次输入的新密码不一致。")
                client_ip = self.client_address[0]
                if not self.server.login_allowed(client_ip):
                    raise ApiError(HTTPStatus.TOO_MANY_REQUESTS, "尝试次数过多，请稍后再试。")
                try:
                    self.server.change_password(self._session_id_from_cookie(), current_password, new_password)
                except ApiError as exc:
                    if exc.status == HTTPStatus.BAD_REQUEST:
                        self.server.record_failed_login(client_ip)
                    raise
                self._send_json(
                    HTTPStatus.OK,
                    {"ok": True, "requires_relogin": True},
                    cookie=self._expired_session_cookie(),
                )
                return
            if path == "/api/v1/sync/push":
                self._require_api_key_principal(principal)
                self._require_api_permission(principal, "add")
                self._send_json(HTTPStatus.OK, self._sync_push(principal, self._read_json()))
                return
            if path.startswith("/api/v1/entries/") and path.endswith("/push"):
                self._require_api_key_principal(principal)
                self._require_api_permission(principal, "add")
                entry_id = path[len("/api/v1/entries/") : -len("/push")].strip("/")
                payload = self._read_json()
                payload["id"] = entry_id
                self._send_json(HTTPStatus.OK, self._sync_push(principal, {"entries": [payload]}))
                return
            if path == "/api/api-keys":
                self._require_session_from_principal(principal)
                payload = self._read_json()
                name = self._required_string(payload, "name", max_length=80)
                note = self._optional_string(payload, "note", max_length=240)
                created = self.server.api_keys.create(name, note=note)
                self._send_json(HTTPStatus.CREATED, {"api_key": created})
                return
            if path.startswith("/api/api-keys/") and path.endswith("/revoke"):
                self._require_session_from_principal(principal)
                key_id = path[len("/api/api-keys/") : -len("/revoke")].strip("/")
                revoked = self.server.api_keys.revoke(key_id)
                self._send_json(HTTPStatus.OK, {"api_key": revoked})
                return
            if path.startswith("/api/api-keys/") and path.endswith("/restore"):
                self._require_session_from_principal(principal)
                key_id = path[len("/api/api-keys/") : -len("/restore")].strip("/")
                restored = self.server.api_keys.restore(key_id)
                self._send_json(HTTPStatus.OK, {"api_key": restored})
                return
            if path.startswith("/api/api-keys/") and path.endswith("/reveal"):
                self._require_session_from_principal(principal)
                key_id = path[len("/api/api-keys/") : -len("/reveal")].strip("/")
                self._send_json(HTTPStatus.OK, {"api_key": self.server.api_keys.reveal(key_id)})
                return
            if path.startswith("/api/api-keys/") and path.endswith("/permissions"):
                self._require_session_from_principal(principal)
                key_id = path[len("/api/api-keys/") : -len("/permissions")].strip("/")
                payload = self._read_json()
                valid_skill_categories = {category["id"] for category in self.server.skills.categories()}
                if any(category not in valid_skill_categories for category in payload.get("skill_categories", []) if isinstance(category, str)):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "包含不存在的 Skill 分类。")
                updated = self.server.api_keys.update_permissions(key_id, payload)
                self._send_json(HTTPStatus.OK, {"api_key": updated})
                return
            if path == "/api/skills/categories":
                self._require_session_from_principal(principal)
                payload = self._read_json()
                category = self.server.skills.add_category(
                    self._required_string(payload, "id", max_length=80),
                    self._required_string(payload, "name", max_length=40),
                )
                self._send_json(HTTPStatus.CREATED, {"category": category})
                return
            if path == "/api/skills/upload":
                self._require_session_from_principal(principal)
                if self.headers.get("Content-Type", "").split(";", 1)[0].lower() != "application/zip":
                    raise ApiError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "请上传 ZIP 压缩包。")
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError as exc:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "上传长度无效。") from exc
                if length <= 0 or length > MAX_PACKAGE_BYTES:
                    raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Skill 压缩包最大 25 MB。")
                query = parse_qs(urlsplit(self.path).query)
                value = lambda key, default="": query.get(key, [default])[0]
                environment = value("environment", "auto")
                if environment not in ("auto", "yes", "no"):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "环境依赖选项无效。")
                created = self.server.skills.upload(
                    self.rfile, length, name=value("name"), description=value("description"),
                    version=value("version"), category=value("category", "__other__"),
                    skill_id=value("skill_id") or None, environment_note=value("environment_note"),
                    requires_environment=None if environment == "auto" else environment == "yes",
                )
                self._send_json(HTTPStatus.CREATED, {"skill": created})
                return
            if path == "/api/entries":
                self._require_session_from_principal(principal)
                payload = self._read_json()
                entry_id = self._required_string(payload, "id", max_length=80)
                description = self._required_string(payload, "description", max_length=240)
                tags = self._tags(payload.get("tags"))
                category = self._optional_string(payload, "category", max_length=80) or None
                self._require_api_permission(principal, "add", category or "__other__")
                entry = self.server.vault.set_entry(entry_id, description, tags=tags, category=category)
                self._send_json(HTTPStatus.CREATED, {"entry": entry})
                return
            if path == "/api/categories":
                self._require_session_from_principal(principal)
                payload = self._read_json()
                category_id = self._required_string(payload, "id", max_length=80)
                name = self._required_string(payload, "name", max_length=40)
                color = self._optional_string(payload, "color", max_length=16) or "mint"
                if color not in CATEGORY_COLORS:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "分类颜色无效。")
                category = self.server.vault.set_category(category_id, name, color=color)
                self._send_json(HTTPStatus.CREATED, {"category": category})
                return
            if path == "/api/categories/assign":
                self._require_session_from_principal(principal)
                payload = self._read_json()
                category_value = payload.get("category")
                if category_value in (None, "", "__other__"):
                    category_id = None
                elif isinstance(category_value, str):
                    category_id = category_value.strip()
                else:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "category 必须是分类标识。")
                entry_ids = payload.get("entries")
                if not isinstance(entry_ids, list) or not entry_ids or not all(
                    isinstance(entry_id, str) for entry_id in entry_ids
                ):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "entries 必须是非空条目标识数组。")
                if len(entry_ids) > 200:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "一次最多移动 200 个资源。")
                assigned = self.server.vault.assign_category(category_id, entry_ids)
                self._send_json(HTTPStatus.OK, {"assigned": len(assigned)})
                return
            if path == "/api/secrets/reveal":
                self._require_session_from_principal(principal)
                payload = self._read_json()
                name = self._required_string(payload, "name", max_length=128)
                record = self.server.vault.get_secret(name)
                self._require_api_permission(principal, "read", self._record_category(record))
                self._send_json(HTTPStatus.OK, {"name": record["name"], "value": record["value"]})
                return
            if path == "/api/secrets":
                self._require_session_from_principal(principal)
                payload = self._read_json()
                name = self._required_string(payload, "name", max_length=128)
                value = payload.get("value")
                if not isinstance(value, str) or not value:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "秘密值不能为空。")
                if len(value) > 128 * 1024:
                    raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "秘密值过长。")
                note = self._optional_string(payload, "note", max_length=240)
                entry = self._optional_string(payload, "entry", max_length=80) or None
                tags = self._tags(payload.get("tags"))
                self._require_api_permission(principal, "add", self._entry_category(entry))
                record = self.server.vault.set_secret(name, value, note=note, tags=tags, entry=entry)
                self._send_json(HTTPStatus.CREATED, {"record": record})
                return
            raise ApiError(HTTPStatus.NOT_FOUND, "接口不存在。")
        except ApiError as exc:
            self._send_json(exc.status, {"error": exc.message})
        except VaultError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except BrokenPipeError:
            return
        except Exception as exc:  # Keep implementation details out of the browser response.
            print(f"web request failed: {type(exc).__name__}")
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "服务器暂时无法完成请求。"})

    def do_DELETE(self) -> None:
        try:
            path = urlsplit(self.path).path
            principal = self._require_principal()
            if path.startswith("/api/api-keys/"):
                self._require_session_from_principal(principal)
                key_id = path[len("/api/api-keys/") :].strip("/")
                self.server.api_keys.delete(key_id)
                self._send_json(HTTPStatus.OK, {"deleted": key_id})
                return
            if path.startswith("/api/secrets/"):
                self._require_session_from_principal(principal)
                name = path[len("/api/secrets/") :].strip("/")
                if not name:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "变量名不能为空。")
                record = self.server.vault.get_secret(name)
                self._require_api_permission(principal, "delete", self._record_category(record))
                self.server.vault.delete_secret(name)
                self._send_json(HTTPStatus.OK, {"deleted": name})
                return
            if path.startswith("/api/v1/secrets/"):
                self._require_api_key_principal(principal)
                name = path[len("/api/v1/secrets/") :].strip("/")
                if not name:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "变量名不能为空。")
                record = self.server.vault.get_secret(name)
                self._require_api_permission(principal, "delete", self._record_category(record))
                self.server.vault.delete_secret(name)
                self._send_json(HTTPStatus.OK, {"deleted": name})
                return
            raise ApiError(HTTPStatus.NOT_FOUND, "接口不存在。")
        except ApiError as exc:
            self._send_json(exc.status, {"error": exc.message})
        except VaultError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except BrokenPipeError:
            return
        except Exception as exc:
            print(f"web request failed: {type(exc).__name__}")
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "服务器暂时无法完成请求。"})

    def _handle_login(self) -> None:
        client_ip = self.client_address[0]
        if not self.server.login_allowed(client_ip):
            raise ApiError(HTTPStatus.TOO_MANY_REQUESTS, "尝试次数过多，请稍后再试。")

        payload = self._read_json()
        username = payload.get("username")
        password = payload.get("password")
        valid_username = isinstance(username, str) and hmac.compare_digest(
            username.encode("utf-8"), self.server.username.encode("utf-8")
        )
        with self.server.state_lock:
            valid_password = isinstance(password, str) and len(password) <= 256 and self.server.auth_store.verify(password)
            if not (valid_username and valid_password):
                self.server.record_failed_login(client_ip)
                raise ApiError(HTTPStatus.UNAUTHORIZED, "账号或密码不正确。")
            self.server.clear_failed_logins(client_ip)
            session_id, session = self.server.issue_session()
        self._send_json(
            HTTPStatus.OK,
            {"authenticated": True, "username": session.username, "csrf_token": session.csrf_token},
            cookie=self._session_cookie(session_id),
        )

    def _snapshot(self, principal: RequestPrincipal | None = None) -> dict[str, Any]:
        diagnostics = self.server.vault.diagnose()
        records = self.server.vault.list_records()
        entries = []
        for public_entry in self.server.vault.list_entries():
            detail = self.server.vault.get_entry(public_entry["id"])
            detail["secret_count"] = public_entry["secret_count"]
            detail["variables"] = detail.pop("records")
            entries.append(detail)
        categories = self.server.vault.list_categories()
        category_ids = {category["id"] for category in categories}
        other_count = sum(1 for entry in entries if entry.get("category") not in category_ids)
        categories.append(
            {
                "id": "__other__",
                "name": "其他",
                "color": "neutral",
                "entry_count": other_count,
                "built_in": True,
            }
        )
        unassigned = [record for record in records if not record.get("entry")]
        if principal is not None and principal.kind == "api_key":
            allowed = self._api_key_categories(principal)
            entries = [entry for entry in entries if self._entry_category_value(entry) in allowed]
            unassigned = unassigned if "__other__" in allowed else []
            allowed_entry_ids = {entry["id"] for entry in entries}
            records = [record for record in records if (record.get("entry") in allowed_entry_ids) or (not record.get("entry") and "__other__" in allowed)]
            categories = [category for category in categories if category["id"] in allowed or (category["id"] == "__other__" and "__other__" in allowed)]
        return {
            "status": {
                "ready": diagnostics.vault_exists and diagnostics.key_exists and diagnostics.decryptable,
                "vault_exists": diagnostics.vault_exists,
                "key_exists": diagnostics.key_exists,
                "decryptable": diagnostics.decryptable,
            },
            "metrics": {
                "entries": len(entries),
                "secrets": len(records),
                "unassigned": len(unassigned),
            },
            "entries": entries,
            "categories": categories,
            "unassigned": unassigned,
        }

    def _sync_pull(self, principal: RequestPrincipal, cursor: str) -> dict[str, Any]:
        allowed = self._api_key_categories(principal)
        try:
            after_revision = int(cursor or 0)
        except ValueError as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, "cursor 必须是整数 revision。") from exc
        changes = self.server.vault.list_sync_changes(after_revision)
        changed_entries = {change["entity_id"] for change in changes if change["entity_type"] == "entry"}
        changed_entries.update(change["parent_id"] for change in changes if change["entity_type"] == "record" and change.get("parent_id"))
        deleted_records = [change for change in changes if change["entity_type"] == "record" and change["operation"] == "delete"]
        full_pull = after_revision == 0
        entries: list[dict[str, Any]] = []
        for public_entry in self.server.vault.list_entries():
            if self._entry_category_value(public_entry) not in allowed and "__all__" not in allowed:
                continue
            if not full_pull and public_entry["id"] not in changed_entries:
                continue
            detail = self.server.vault.get_entry(public_entry["id"])
            variables = []
            newest = detail.get("updated_at", "")
            for public_record in detail.pop("records"):
                full_record = self.server.vault.get_secret(public_record["name"])
                newest = max(newest, full_record.get("updated_at", ""))
                variables.append(
                    {
                        "name": full_record["name"],
                        "value": full_record["value"],
                        "note": full_record.get("note", ""),
                        "tags": full_record.get("tags", []),
                        "created_at": full_record.get("created_at"),
                        "updated_at": full_record.get("updated_at"),
                    }
                )
            detail["variables"] = variables
            entries.append(detail)

        unassigned = []
        if "__other__" in allowed or "__all__" in allowed:
            for public_record in self.server.vault.list_records():
                if public_record.get("entry"):
                    continue
                full_record = self.server.vault.get_secret(public_record["name"])
                if full_pull or public_record["name"] in {change["entity_id"] for change in changes if change["entity_type"] == "record"}:
                    unassigned.append(
                        {
                            "name": full_record["name"],
                            "value": full_record["value"],
                            "note": full_record.get("note", ""),
                            "tags": full_record.get("tags", []),
                            "created_at": full_record.get("created_at"),
                            "updated_at": full_record.get("updated_at"),
                        }
                    )

        categories = [
            category
            for category in self.server.vault.list_categories()
            if category["id"] in allowed or "__all__" in allowed
        ]
        if "__other__" in allowed or "__all__" in allowed:
            categories.append({"id": "__other__", "name": "其他", "color": "neutral"})
        return {
            "schema_version": 1,
            "cursor": self.server.vault.sync_cursor(),
            "scope": {"categories": sorted(allowed)},
            "metrics": {"entries": len(entries), "unassigned": len(unassigned), "variables": sum(len(entry["variables"]) for entry in entries) + len(unassigned)},
            "categories": categories,
            "entries": entries,
            "unassigned": unassigned,
            "deleted_records": [
                {"name": change["entity_id"], "entry": change.get("parent_id"), "category": change["category"]}
                for change in deleted_records
                if change["category"] in allowed or "__all__" in allowed
            ],
        }

    def _sync_push(self, principal: RequestPrincipal, payload: dict[str, Any]) -> dict[str, Any]:
        items = payload.get("entries", [])
        if not isinstance(items, list):
            raise ApiError(HTTPStatus.BAD_REQUEST, "entries 必须是数组。")
        results: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                results.append({"ok": False, "code": "invalid_entry", "message": "条目格式无效。"})
                continue
            entry_id = str(item.get("id", "")).strip()
            try:
                category = str(item.get("category") or "__other__")
                self._require_api_permission(principal, "add", category)
                existing = self.server.vault.get_entry(entry_id)
                expected_revision = item.get("expected_revision")
                if expected_revision is not None and int(expected_revision) != int(existing.get("revision", 0)):
                    results.append({"ok": False, "code": "conflict", "message": "远端条目已发生变化，请先拉取再解决冲突。", "entry_id": entry_id})
                    continue
            except ApiError as exc:
                results.append({"ok": False, "code": "permission_denied", "message": exc.message, "entry_id": entry_id})
            except VaultError as exc:
                if "not found" not in str(exc).lower() and "not found" not in str(exc):
                    results.append({"ok": False, "code": "permission_or_validation", "message": str(exc), "entry_id": entry_id})
                    continue
                existing = None
            try:
                category_value = None if category == "__other__" else category
                saved = self.server.vault.set_entry(entry_id, str(item.get("description", "")), tags=item.get("tags", []), category=category_value)
                for variable in item.get("variables", []):
                    self.server.vault.set_secret(
                        variable["name"],
                        variable["value"],
                        note=variable.get("note", ""),
                        tags=variable.get("tags", []),
                        entry=entry_id,
                    )
                updated_entry = self.server.vault.get_entry(entry_id)
                results.append({"ok": True, "entry_id": entry_id, "updated_at": updated_entry["updated_at"], "revision": updated_entry.get("revision", 0)})
            except (KeyError, TypeError, ValueError) as exc:
                results.append({"ok": False, "code": "invalid_entry", "message": f"条目变量格式无效：{exc}", "entry_id": entry_id})
            except VaultError as exc:
                results.append({"ok": False, "code": "write_failed", "message": str(exc), "entry_id": entry_id})
        return {"schema_version": 1, "results": results}

    def _bearer_token(self) -> str | None:
        value = self.headers.get("Authorization", "")
        if not value.lower().startswith("bearer "):
            return None
        token = value[7:].strip()
        return token or None

    def _require_principal(self) -> RequestPrincipal:
        bearer = self._bearer_token()
        if bearer is not None:
            api_key = self.server.api_keys.authenticate(bearer)
            if api_key is None:
                raise ApiError(HTTPStatus.UNAUTHORIZED, "API key 无效或已撤销。")
            return RequestPrincipal(kind="api_key", subject=api_key["id"], api_key=api_key)

        session_id = self._session_id_from_cookie()
        session = self.server.get_session(session_id)
        if session is None or session_id is None:
            raise ApiError(HTTPStatus.UNAUTHORIZED, "登录状态已失效，请重新登录。")
        return RequestPrincipal(kind="session", subject=session.username, session=session)

    def _require_admin_session(self) -> WebSession:
        principal = self._require_principal()
        return self._require_session_from_principal(principal)

    def _skill_access(self, path: str) -> set[str] | None:
        principal = self._require_principal()
        if principal.kind == "session":
            return None
        if not path.startswith("/api/v1/skills"):
            raise ApiError(HTTPStatus.FORBIDDEN, "API Key 只能使用 Skill 查询接口。")
        permissions = (principal.api_key or {}).get("permissions", {})
        allowed = set(permissions.get("skill_categories", [])) if isinstance(permissions, dict) else set()
        if not allowed:
            raise ApiError(HTTPStatus.FORBIDDEN, "API Key 未授权任何 Skill 分类。")
        return allowed

    @staticmethod
    def _require_session_from_principal(principal: RequestPrincipal) -> WebSession:
        if principal.kind != "session" or principal.session is None:
            raise ApiError(HTTPStatus.FORBIDDEN, "API key 管理只能在管理员浏览器会话中执行。")
        return principal.session

    @staticmethod
    def _require_api_key_principal(principal: RequestPrincipal) -> None:
        if principal.kind != "api_key":
            raise ApiError(HTTPStatus.FORBIDDEN, "同步接口只接受 API Key。")

    @staticmethod
    def _api_key_categories(principal: RequestPrincipal) -> set[str]:
        permissions = (principal.api_key or {}).get("permissions", {})
        if not isinstance(permissions, dict):
            return set()
        return set(permissions.get("categories", []))

    def _require_api_permission(self, principal: RequestPrincipal, operation: str, category: str | None = None) -> None:
        if principal.kind != "api_key":
            return
        permissions = (principal.api_key or {}).get("permissions", {})
        if not isinstance(permissions, dict) or not permissions.get(operation, False):
            raise ApiError(HTTPStatus.FORBIDDEN, f"API key 没有{operation}权限。")
        allowed = self._api_key_categories(principal)
        if category is None:
            if not allowed:
                raise ApiError(HTTPStatus.FORBIDDEN, "API key 未授权任何分类。")
            return
        if "__all__" not in allowed and (category or "__other__") not in allowed:
            raise ApiError(HTTPStatus.FORBIDDEN, "API key 未授权访问该分类。")

    def _record_category(self, record: dict[str, Any]) -> str:
        return self._entry_category(record.get("entry"))

    def _entry_category(self, entry_id: str | None) -> str:
        if not entry_id:
            return "__other__"
        return self._entry_category_value(self.server.vault.get_entry(entry_id))

    @staticmethod
    def _entry_category_value(entry: dict[str, Any]) -> str:
        return entry.get("category") or "__other__"

    def _require_csrf(self, session: WebSession) -> None:
        supplied = self.headers.get("X-CSRF-Token", "")
        if not supplied or not hmac.compare_digest(supplied, session.csrf_token):
            raise ApiError(HTTPStatus.FORBIDDEN, "请求校验失败，请刷新页面后重试。")

    def _session_id_from_cookie(self) -> str | None:
        raw_cookie = self.headers.get("Cookie")
        if not raw_cookie:
            return None
        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookie)
        except Exception:
            return None
        morsel = cookie.get(SESSION_COOKIE)
        return morsel.value if morsel else None

    def _read_json(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("application/json"):
            raise ApiError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "请求必须使用 JSON。")
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, "请求长度无效。") from exc
        if content_length <= 0:
            raise ApiError(HTTPStatus.BAD_REQUEST, "请求内容不能为空。")
        if content_length > MAX_BODY_BYTES:
            raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "请求内容过大。")
        try:
            payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, "JSON 格式无效。") from exc
        if not isinstance(payload, dict):
            raise ApiError(HTTPStatus.BAD_REQUEST, "JSON 顶层必须是对象。")
        return payload

    @staticmethod
    def _required_string(payload: dict[str, Any], name: str, max_length: int) -> str:
        value = payload.get(name)
        if not isinstance(value, str) or not value.strip():
            raise ApiError(HTTPStatus.BAD_REQUEST, f"{name} 不能为空。")
        value = value.strip()
        if len(value) > max_length:
            raise ApiError(HTTPStatus.BAD_REQUEST, f"{name} 过长。")
        return value

    @staticmethod
    def _optional_string(payload: dict[str, Any], name: str, max_length: int) -> str:
        value = payload.get(name, "")
        if value is None:
            return ""
        if not isinstance(value, str):
            raise ApiError(HTTPStatus.BAD_REQUEST, f"{name} 必须是字符串。")
        value = value.strip()
        if len(value) > max_length:
            raise ApiError(HTTPStatus.BAD_REQUEST, f"{name} 过长。")
        return value

    @staticmethod
    def _tags(value: Any) -> list[str]:
        if value in (None, ""):
            return []
        raw_tags = value.split(",") if isinstance(value, str) else value
        if not isinstance(raw_tags, list):
            raise ApiError(HTTPStatus.BAD_REQUEST, "tags 必须是数组或逗号分隔文本。")
        tags: list[str] = []
        for item in raw_tags:
            if not isinstance(item, str):
                raise ApiError(HTTPStatus.BAD_REQUEST, "每个标签都必须是文本。")
            tag = " ".join(item.split())
            if tag and tag not in tags:
                if len(tag) > 32:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "单个标签不能超过 32 个字符。")
                tags.append(tag)
        if len(tags) > 12:
            raise ApiError(HTTPStatus.BAD_REQUEST, "标签不能超过 12 个。")
        return tags

    def _serve_static(self, path: str) -> None:
        assets = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/index.html": ("index.html", "text/html; charset=utf-8"),
            "/styles.css": ("styles.css", "text/css; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
        }
        asset = assets.get(path)
        if asset is None:
            self._send_bytes(HTTPStatus.NOT_FOUND, b"Not found", "text/plain; charset=utf-8")
            return
        name, content_type = asset
        data = files("agent_vault.web_static").joinpath(name).read_bytes()
        self._send_bytes(HTTPStatus.OK, data, content_type)

    def _send_skill_file(self, path: Path, digest: str) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(path.stat().st_size))
        self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
        self.send_header("X-Content-SHA256", digest)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        with path.open("rb") as archive:
            while block := archive.read(1024 * 1024):
                self.wfile.write(block)

    def _send_json(self, status: int, payload: dict[str, Any], cookie: str | None = None) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send_bytes(status, encoded, "application/json; charset=utf-8", cookie=cookie)

    def _send_bytes(
        self,
        status: int,
        body: bytes,
        content_type: str,
        cookie: str | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _session_cookie(session_id: str) -> str:
        return (
            f"{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; SameSite=Strict; "
            f"Max-Age={SESSION_TTL_SECONDS}"
        )

    @staticmethod
    def _expired_session_cookie() -> str:
        return f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"

    def log_message(self, message_format: str, *args: object) -> None:
        print(f"[agent-vault-web] {self.address_string()} {message_format % args}")


def build_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    *,
    vault: Vault | None = None,
    username: str | None = None,
    password: str | None = None,
) -> VaultWebServer:
    selected_vault = vault or Vault()
    selected_vault.init()
    selected_api_keys = ApiKeyStore(selected_vault.home)
    selected_api_keys.init()
    selected_username = username or os.environ.get("AGENT_VAULT_WEB_USERNAME", DEFAULT_USERNAME)
    selected_password = password or os.environ.get("AGENT_VAULT_WEB_PASSWORD", DEFAULT_PASSWORD)
    if not selected_username or not selected_password:
        raise VaultError("Web username and password cannot be empty.")
    return VaultWebServer((host, port), selected_vault, selected_api_keys, selected_username, selected_password)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the local Agent Vault web console.")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Bind address. Default: {DEFAULT_HOST}")
    parser.add_argument("--port", default=DEFAULT_PORT, type=int, help=f"Listen port. Default: {DEFAULT_PORT}")
    parser.add_argument("--open", action="store_true", help="Open the console in the default browser.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        server = build_server(args.host, args.port)
    except (OSError, VaultError) as exc:
        print(f"error: {exc}")
        return 1

    host, port = server.server_address[:2]
    browser_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    url = f"http://{browser_host}:{port}"
    print(f"Agent Vault web console: {url}")
    print("Press Ctrl+C to stop.")
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Agent Vault web console.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
