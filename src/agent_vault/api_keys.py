from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from pathlib import Path
from typing import Any

import keyring
from cryptography.fernet import Fernet, InvalidToken
from filelock import FileLock

from .storage import VaultError, default_vault_home, _is_windows, utc_now

API_KEY_PREFIX = "avk_"
API_KEY_ID_PREFIX = "key_"
API_KEY_DB_NAME = "api_keys.db"
API_KEYRING_SERVICE = "agent-vault-api-keys"
API_KEYRING_USERNAME = "api-key-data-key"


class ApiKeyStore:
    """Dedicated SQLite database for API keys, never stored in vault.db."""

    def __init__(self, vault_home: Path | None = None) -> None:
        base = Path(vault_home) if vault_home is not None else default_vault_home()
        self.home = base / "ApiKeys"
        self.path = self.home / API_KEY_DB_NAME
        self.lock_path = self.home / "api_keys.db.lock"
        self.key_path = self.home / "api_keys.key"

    def init(self) -> bool:
        self.home.mkdir(parents=True, exist_ok=True)
        created = not self.path.exists()
        with self._lock(), self._connect() as connection:
            if created:
                self._read_data_key(create=True)
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, note TEXT NOT NULL,
                    prefix TEXT NOT NULL, encrypted_value BLOB NOT NULL, key_hash TEXT NOT NULL,
                    permissions TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    last_used_at TEXT, revoked_at TEXT
                )
                """
            )
        return created

    def create(self, name: str, note: str = "") -> dict[str, Any]:
        name = " ".join(name.split())
        if not name:
            raise VaultError("API key name cannot be empty.")
        if len(name) > 80:
            raise VaultError("API key name cannot exceed 80 characters.")
        note = " ".join(note.split())
        if len(note) > 240:
            raise VaultError("API key note cannot exceed 240 characters.")
        raw_key = API_KEY_PREFIX + secrets.token_urlsafe(32)
        key_id = API_KEY_ID_PREFIX + secrets.token_hex(10)
        now = utc_now()
        with self._lock(), self._connect() as connection:
            connection.execute(
                "INSERT INTO api_keys(id,name,note,prefix,encrypted_value,key_hash,permissions,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (key_id, name, note, raw_key[:12], self._encrypt(raw_key), hashlib.sha256(raw_key.encode("utf-8")).hexdigest(), '{"categories":[],"read":false,"add":false,"delete":false,"skill_categories":[],"skill_upload_categories":[]}', now, now),
            )
            public = self._public(connection.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone())
        public["api_key"] = raw_key
        return public

    def list(self) -> list[dict[str, Any]]:
        with self._lock(), self._connect() as connection:
            return [self._public(row) for row in connection.execute("SELECT * FROM api_keys ORDER BY created_at DESC").fetchall()]

    def reveal(self, key_id: str) -> str:
        with self._lock(), self._connect() as connection:
            row = connection.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone()
            if row is None:
                raise VaultError(f"API key '{key_id}' not found.")
            if row["revoked_at"] is not None:
                raise VaultError("API key has been revoked.")
            try:
                return Fernet(self._read_data_key(create=False)).decrypt(row["encrypted_value"]).decode("utf-8")
            except (InvalidToken, UnicodeDecodeError) as exc:
                raise VaultError("API key cannot be decrypted with the current key.") from exc

    def revoke(self, key_id: str) -> dict[str, Any]:
        with self._lock(), self._connect() as connection:
            row = connection.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone()
            if row is None:
                raise VaultError(f"API key '{key_id}' not found.")
            now = utc_now()
            if row["revoked_at"] is None:
                connection.execute("UPDATE api_keys SET revoked_at = ?, updated_at = ? WHERE id = ?", (now, now, key_id))
            return self._public(connection.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone())

    def restore(self, key_id: str) -> dict[str, Any]:
        with self._lock(), self._connect() as connection:
            row = connection.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone()
            if row is None:
                raise VaultError(f"API key '{key_id}' not found.")
            now = utc_now()
            connection.execute("UPDATE api_keys SET revoked_at = NULL, updated_at = ? WHERE id = ?", (now, key_id))
            return self._public(connection.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone())

    def delete(self, key_id: str) -> None:
        with self._lock(), self._connect() as connection:
            row = connection.execute("SELECT 1 FROM api_keys WHERE id = ?", (key_id,)).fetchone()
            if row is None:
                raise VaultError(f"API key '{key_id}' not found.")
            connection.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))

    def update_permissions(self, key_id: str, permissions: dict[str, Any]) -> dict[str, Any]:
        categories = permissions.get("categories", [])
        if not isinstance(categories, list) or not all(isinstance(category, str) for category in categories):
            raise VaultError("Permission categories must be a string array.")
        skill_categories = permissions.get("skill_categories", [])
        if not isinstance(skill_categories, list) or not all(isinstance(category, str) for category in skill_categories):
            raise VaultError("Skill permission categories must be a string array.")
        skill_upload_categories = permissions.get("skill_upload_categories", [])
        if not isinstance(skill_upload_categories, list) or not all(isinstance(category, str) for category in skill_upload_categories):
            raise VaultError("Skill upload categories must be a string array.")
        normalized = {
            "categories": sorted(set(categories)),
            "read": bool(permissions.get("read", False)),
            "add": bool(permissions.get("add", False)),
            "delete": bool(permissions.get("delete", False)),
            "skill_categories": sorted(set(skill_categories) | set(skill_upload_categories)),
            "skill_upload_categories": sorted(set(skill_upload_categories)),
        }
        with self._lock(), self._connect() as connection:
            row = connection.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone()
            if row is None:
                raise VaultError(f"API key '{key_id}' not found.")
            if row["revoked_at"] is not None:
                raise VaultError("API key has been revoked.")
            connection.execute("UPDATE api_keys SET permissions = ?, updated_at = ? WHERE id = ?", (json.dumps(normalized, separators=(",", ":")), utc_now(), key_id))
            return self._public(connection.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone())

    def authenticate(self, raw_key: str) -> dict[str, Any] | None:
        if not isinstance(raw_key, str) or not raw_key.startswith(API_KEY_PREFIX):
            return None
        digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        with self._lock(), self._connect() as connection:
            for row in connection.execute("SELECT * FROM api_keys").fetchall():
                if not hmac.compare_digest(digest, row["key_hash"]):
                    continue
                if row["revoked_at"] is not None:
                    return None
                return self._public(row)
        return None

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _lock(self) -> FileLock:
        self.home.mkdir(parents=True, exist_ok=True)
        if not _is_windows():
            self.home.chmod(0o700)
        return FileLock(str(self.lock_path), timeout=10)

    def _encrypt(self, value: str) -> bytes:
        return Fernet(self._read_data_key(create=False)).encrypt(value.encode("utf-8"))

    def _read_data_key(self, create: bool) -> bytes:
        try:
            stored = keyring.get_password(API_KEYRING_SERVICE, API_KEYRING_USERNAME)
        except Exception as exc:
            stored = None
            keyring_error = exc
        else:
            keyring_error = None
        if stored is not None:
            return self._validate_key(stored)
        if not _is_windows() and self.key_path.exists():
            return self._validate_key(self.key_path.read_text(encoding="ascii").strip())
        if not create:
            if keyring_error is not None and _is_windows():
                raise VaultError(f"Unable to read API key Credential Manager entry: {keyring_error}") from keyring_error
            raise VaultError("API key encryption key not found.")
        generated = Fernet.generate_key().decode("ascii")
        try:
            keyring.set_password(API_KEYRING_SERVICE, API_KEYRING_USERNAME, generated)
        except Exception as exc:
            if _is_windows():
                raise VaultError(f"Unable to save API key encryption key: {exc}") from exc
            self.home.mkdir(parents=True, exist_ok=True)
            self.home.chmod(0o700)
            self.key_path.write_text(generated, encoding="ascii")
            self.key_path.chmod(0o600)
        return self._validate_key(generated)

    @staticmethod
    def _validate_key(stored: str) -> bytes:
        try:
            key = stored.encode("ascii")
            Fernet(key)
            return key
        except Exception as exc:
            raise VaultError("API key encryption key is invalid.") from exc

    @staticmethod
    def _public(row: sqlite3.Row) -> dict[str, Any]:
        try:
            permissions = json.loads(row["permissions"])
        except (TypeError, ValueError):
            permissions = {"categories": [], "read": False, "add": False, "delete": False, "skill_categories": [], "skill_upload_categories": []}
        if permissions == ["admin"]:
            permissions = {"categories": ["__all__"], "read": True, "add": True, "delete": True, "skill_categories": [], "skill_upload_categories": []}
        if isinstance(permissions, dict):
            permissions.setdefault("skill_categories", [])
            permissions.setdefault("skill_upload_categories", [])
        return {
            "id": row["id"], "name": row["name"], "note": row["note"], "prefix": row["prefix"],
            "permissions": permissions, "created_at": row["created_at"], "updated_at": row["updated_at"],
            "last_used_at": row["last_used_at"], "revoked_at": row["revoked_at"],
            "status": "revoked" if row["revoked_at"] else "active",
        }
