from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import keyring
from cryptography.fernet import Fernet, InvalidToken
from filelock import FileLock

from .storage import (
    KEYRING_SERVICE,
    KEYRING_USERNAME,
    KEY_FILE_NAME,
    VaultDiagnostics,
    VaultError,
    _is_windows,
    default_vault_home,
    validate_category_id,
    validate_entry_id,
    validate_name,
    utc_now,
)

SQLITE_VERSION = 1


class SQLiteVault:
    """SQLite-backed vault with Fernet encryption for every secret value."""

    def __init__(self, home: Path | None = None) -> None:
        self.home = Path(home) if home is not None else default_vault_home()
        self.path = self.home / "vault.db"
        self.legacy_path = self.home / "vault.enc"
        self.lock_path = self.home / "vault.db.lock"
        self.key_path = self.home / KEY_FILE_NAME

    def init(self) -> bool:
        self.home.mkdir(parents=True, exist_ok=True)
        created = not self.path.exists()
        with self._lock():
            if created:
                self._read_data_key(create=True)
            with self._connect() as connection:
                self._create_schema(connection)
                migration_marker = connection.execute("SELECT value FROM meta WHERE key = 'migrated_from_legacy'").fetchone()
                empty_database = all(
                    connection.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()["count"] == 0
                    for table in ("entries", "records", "categories")
                )
                if self.legacy_path.exists() and migration_marker is None and empty_database:
                    self._migrate_legacy(connection)
        return created

    def set_secret(
        self,
        name: str,
        value: str,
        note: str = "",
        tags: list[str] | None = None,
        entry: str | None = None,
    ) -> dict[str, Any]:
        name = validate_name(name)
        if entry is not None:
            entry = validate_entry_id(entry)
        with self._lock(), self._connect() as connection:
            self._create_schema(connection)
            if entry is not None and connection.execute("SELECT 1 FROM entries WHERE id = ?", (entry,)).fetchone() is None:
                raise VaultError(f"Entry '{entry}' not found. Run agent-vault entry set first.")
            conflict = connection.execute(
                "SELECT name FROM records WHERE lower(name) = lower(?) AND name <> ?", (name, name)
            ).fetchone()
            if conflict is not None:
                raise VaultError(
                    f"A secret named '{conflict['name']}' already exists with different case. "
                    "Windows environment variables are case-insensitive."
                )
            previous = connection.execute("SELECT entry, created_at FROM records WHERE name = ?", (name,)).fetchone()
            now = utc_now()
            encrypted = self._encrypt(value)
            effective_entry = entry if entry is not None else (previous["entry"] if previous else None)
            created_at = previous["created_at"] if previous else now
            connection.execute(
                """
                INSERT INTO records(name, encrypted_value, note, tags, entry, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    encrypted_value=excluded.encrypted_value, note=excluded.note, tags=excluded.tags,
                    entry=excluded.entry, updated_at=excluded.updated_at
                """,
                (name, encrypted, note, json.dumps(tags or [], ensure_ascii=False), effective_entry, created_at, now),
            )
            self._record_change(connection, "record", name, "upsert", effective_entry, self._category_for_entry(connection, effective_entry))
            return self._public_record_from_row(connection.execute("SELECT * FROM records WHERE name = ?", (name,)).fetchone())

    def list_records(self) -> list[dict[str, Any]]:
        with self._lock(), self._connect() as connection:
            self._create_schema(connection)
            rows = connection.execute("SELECT * FROM records ORDER BY lower(name)").fetchall()
            return [self._public_record_from_row(row) for row in rows]

    def get_secret(self, name: str) -> dict[str, Any]:
        name = validate_name(name)
        with self._lock(), self._connect() as connection:
            self._create_schema(connection)
            row = connection.execute("SELECT * FROM records WHERE name = ?", (name,)).fetchone()
            if row is None:
                raise VaultError(f"Secret '{name}' not found.")
            result = self._public_record_from_row(row)
            result["value"] = self._decrypt(row["encrypted_value"])
            return result

    def get_values(self, names: list[str]) -> dict[str, str]:
        if not names:
            raise VaultError("At least one secret name is required.")
        return {name: self.get_secret(name)["value"] for name in [validate_name(item) for item in names]}

    def delete_secret(self, name: str) -> None:
        name = validate_name(name)
        with self._lock(), self._connect() as connection:
            self._create_schema(connection)
            existing = connection.execute("SELECT entry FROM records WHERE name = ?", (name,)).fetchone()
            if existing is None:
                raise VaultError(f"Secret '{name}' not found.")
            entry_id = existing["entry"]
            category = self._category_for_entry(connection, entry_id)
            cursor = connection.execute("DELETE FROM records WHERE name = ?", (name,))
            if cursor.rowcount:
                self._record_change(connection, "record", name, "delete", entry_id, category)

    def set_entry(
        self,
        entry_id: str,
        description: str,
        tags: list[str] | None = None,
        category: str | None = None,
    ) -> dict[str, Any]:
        entry_id = validate_entry_id(entry_id)
        if category is not None:
            category = validate_category_id(category)
        description = description.strip()
        if not description:
            raise VaultError("Entry description cannot be empty.")
        with self._lock(), self._connect() as connection:
            self._create_schema(connection)
            if category is not None and connection.execute("SELECT 1 FROM categories WHERE id = ?", (category,)).fetchone() is None:
                raise VaultError(f"Category '{category}' not found.")
            previous = connection.execute("SELECT created_at, category FROM entries WHERE id = ?", (entry_id,)).fetchone()
            now = utc_now()
            effective_category = category if category is not None else (previous["category"] if previous else None)
            created_at = previous["created_at"] if previous else now
            connection.execute(
                """
                INSERT INTO entries(id, description, tags, category, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET description=excluded.description, tags=excluded.tags,
                    category=excluded.category, updated_at=excluded.updated_at
                """,
                (entry_id, description, json.dumps(tags or [], ensure_ascii=False), effective_category, created_at, now),
            )
            self._record_change(connection, "entry", entry_id, "upsert", None, effective_category or "__other__")
            return self._entry_from_row(connection.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone())

    def set_category(self, category_id: str, name: str, color: str = "mint") -> dict[str, Any]:
        category_id = validate_category_id(category_id)
        name = " ".join(name.split())
        if not name:
            raise VaultError("Category name cannot be empty.")
        with self._lock(), self._connect() as connection:
            self._create_schema(connection)
            previous = connection.execute("SELECT created_at FROM categories WHERE id = ?", (category_id,)).fetchone()
            now = utc_now()
            created_at = previous["created_at"] if previous else now
            connection.execute(
                """
                INSERT INTO categories(id, name, color, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET name=excluded.name, color=excluded.color, updated_at=excluded.updated_at
                """,
                (category_id, name, color, created_at, now),
            )
            self._record_change(connection, "category", category_id, "upsert", None, category_id)
            return self._category_from_row(connection.execute("SELECT * FROM categories WHERE id = ?", (category_id,)).fetchone())

    def list_categories(self) -> list[dict[str, Any]]:
        with self._lock(), self._connect() as connection:
            self._create_schema(connection)
            rows = connection.execute(
                "SELECT c.*, COUNT(e.id) AS entry_count FROM categories c LEFT JOIN entries e ON e.category = c.id "
                "GROUP BY c.id ORDER BY lower(c.name), lower(c.id)"
            ).fetchall()
            return [self._category_from_row(row) for row in rows]

    def assign_category(self, category_id: str | None, entry_ids: list[str]) -> list[dict[str, Any]]:
        if category_id is not None:
            category_id = validate_category_id(category_id)
        if not entry_ids:
            raise VaultError("At least one entry id is required.")
        validated = [validate_entry_id(entry_id) for entry_id in entry_ids]
        with self._lock(), self._connect() as connection:
            self._create_schema(connection)
            if category_id is not None and connection.execute("SELECT 1 FROM categories WHERE id = ?", (category_id,)).fetchone() is None:
                raise VaultError(f"Category '{category_id}' not found.")
            placeholders = ",".join("?" for _ in validated)
            rows = connection.execute(f"SELECT id FROM entries WHERE id IN ({placeholders})", validated).fetchall()
            found = {row["id"] for row in rows}
            missing = [entry_id for entry_id in validated if entry_id not in found]
            if missing:
                raise VaultError(f"Entry not found: {', '.join(missing)}")
            now = utc_now()
            connection.executemany("UPDATE entries SET category = ?, updated_at = ? WHERE id = ?", [(category_id, now, entry_id) for entry_id in validated])
            for entry_id in validated:
                self._record_change(connection, "entry", entry_id, "upsert", None, category_id or "__other__")
            return [self._entry_from_row(connection.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()) for entry_id in validated]

    def list_entries(self) -> list[dict[str, Any]]:
        with self._lock(), self._connect() as connection:
            self._create_schema(connection)
            rows = connection.execute(
                "SELECT e.*, COUNT(r.name) AS secret_count FROM entries e LEFT JOIN records r ON r.entry = e.id "
                "GROUP BY e.id ORDER BY lower(e.id)"
            ).fetchall()
            return [self._entry_from_row(row) for row in rows]

    def get_entry(self, entry_id: str) -> dict[str, Any]:
        entry_id = validate_entry_id(entry_id)
        with self._lock(), self._connect() as connection:
            self._create_schema(connection)
            row = connection.execute("SELECT e.*, COUNT(r.name) AS secret_count FROM entries e LEFT JOIN records r ON r.entry = e.id WHERE e.id = ? GROUP BY e.id", (entry_id,)).fetchone()
            if row is None:
                raise VaultError(f"Entry '{entry_id}' not found.")
            entry = self._entry_from_row(row)
            revision_row = connection.execute(
                "SELECT COALESCE(MAX(revision), 0) AS revision FROM sync_changes WHERE (entity_type = 'entry' AND entity_id = ?) OR (entity_type = 'record' AND parent_id = ?)",
                (entry_id, entry_id),
            ).fetchone()
            entry["revision"] = int(revision_row["revision"])
            entry["records"] = [self._public_record_from_row(record) for record in connection.execute("SELECT * FROM records WHERE entry = ? ORDER BY lower(name)", (entry_id,)).fetchall()]
            return entry

    def assign_entry(self, entry_id: str, names: list[str]) -> list[dict[str, Any]]:
        entry_id = validate_entry_id(entry_id)
        if not names:
            raise VaultError("At least one secret name is required.")
        validated = [validate_name(name) for name in names]
        with self._lock(), self._connect() as connection:
            self._create_schema(connection)
            if connection.execute("SELECT 1 FROM entries WHERE id = ?", (entry_id,)).fetchone() is None:
                raise VaultError(f"Entry '{entry_id}' not found. Run agent-vault entry set first.")
            placeholders = ",".join("?" for _ in validated)
            rows = connection.execute(f"SELECT name FROM records WHERE name IN ({placeholders})", validated).fetchall()
            found = {row["name"] for row in rows}
            missing = [name for name in validated if name not in found]
            if missing:
                raise VaultError(f"Secret not found: {', '.join(missing)}")
            now = utc_now()
            connection.executemany("UPDATE records SET entry = ?, updated_at = ? WHERE name = ?", [(entry_id, now, name) for name in validated])
            category = self._category_for_entry(connection, entry_id)
            for name in validated:
                self._record_change(connection, "record", name, "upsert", entry_id, category)
            return [self._public_record_from_row(connection.execute("SELECT * FROM records WHERE name = ?", (name,)).fetchone()) for name in validated]

    def diagnose(self) -> VaultDiagnostics:
        key_exists = False
        decryptable = False
        error: str | None = None
        try:
            key_exists = self._read_data_key(create=False) is not None
            if self.path.exists() and key_exists:
                with self._connect() as connection:
                    self._create_schema(connection)
                    row = connection.execute("SELECT encrypted_value FROM records LIMIT 1").fetchone()
                    if row is not None:
                        self._decrypt(row["encrypted_value"])
                decryptable = True
            elif self.path.exists():
                decryptable = False
        except VaultError as exc:
            error = str(exc)
        return VaultDiagnostics(self.home, self.path, self.path.exists(), key_exists, decryptable, error)

    def _migrate_legacy(self, connection: sqlite3.Connection) -> None:
        from .storage import LegacyVault

        legacy = LegacyVault(self.home)
        data = legacy._load_unlocked()
        categories = data.get("categories", {})
        for category in categories.values():
            connection.execute("INSERT OR REPLACE INTO categories(id, name, color, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", (category["id"], category.get("name", category["id"]), category.get("color", "mint"), category.get("created_at", utc_now()), category.get("updated_at", utc_now())))
        for entry in data.get("entries", {}).values():
            category = entry.get("category")
            if category not in categories:
                category = None
            connection.execute("INSERT OR REPLACE INTO entries(id, description, tags, category, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)", (entry["id"], entry.get("description", ""), json.dumps(entry.get("tags", []), ensure_ascii=False), category, entry.get("created_at", utc_now()), entry.get("updated_at", utc_now())))
        key = self._read_data_key(create=False)
        for record in data.get("records", {}).values():
            encrypted = Fernet(key).encrypt(str(record.get("value", "")).encode("utf-8"))
            connection.execute("INSERT OR REPLACE INTO records(name, encrypted_value, note, tags, entry, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (record["name"], encrypted, record.get("note", ""), json.dumps(record.get("tags", []), ensure_ascii=False), record.get("entry"), record.get("created_at", utc_now()), record.get("updated_at", utc_now())))
        connection.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('migrated_from_legacy', '1')")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS categories (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, color TEXT NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS entries (
                id TEXT PRIMARY KEY, description TEXT NOT NULL, tags TEXT NOT NULL,
                category TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                FOREIGN KEY(category) REFERENCES categories(id)
            );
            CREATE TABLE IF NOT EXISTS records (
                name TEXT PRIMARY KEY, encrypted_value BLOB NOT NULL, note TEXT NOT NULL,
                tags TEXT NOT NULL, entry TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                FOREIGN KEY(entry) REFERENCES entries(id)
            );
            CREATE INDEX IF NOT EXISTS idx_records_entry ON records(entry);
            CREATE INDEX IF NOT EXISTS idx_entries_category ON entries(category);
            CREATE TABLE IF NOT EXISTS sync_changes (
                revision INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                parent_id TEXT,
                category TEXT NOT NULL,
                changed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sync_changes_revision ON sync_changes(revision);
            CREATE INDEX IF NOT EXISTS idx_sync_changes_parent ON sync_changes(parent_id);
            """
        )

    @staticmethod
    def _record_change(
        connection: sqlite3.Connection,
        entity_type: str,
        entity_id: str,
        operation: str,
        parent_id: str | None,
        category: str,
    ) -> int:
        cursor = connection.execute(
            "INSERT INTO sync_changes(entity_type,entity_id,operation,parent_id,category,changed_at) VALUES (?,?,?,?,?,?)",
            (entity_type, entity_id, operation, parent_id, category, utc_now()),
        )
        return int(cursor.lastrowid)

    @staticmethod
    def _category_for_entry(connection: sqlite3.Connection, entry_id: str | None) -> str:
        if not entry_id:
            return "__other__"
        row = connection.execute("SELECT category FROM entries WHERE id = ?", (entry_id,)).fetchone()
        return row["category"] if row is not None and row["category"] else "__other__"

    def sync_cursor(self) -> int:
        with self._lock(), self._connect() as connection:
            self._create_schema(connection)
            row = connection.execute("SELECT COALESCE(MAX(revision), 0) AS revision FROM sync_changes").fetchone()
            return int(row["revision"])

    def list_sync_changes(self, after_revision: int) -> list[dict[str, Any]]:
        with self._lock(), self._connect() as connection:
            self._create_schema(connection)
            rows = connection.execute("SELECT * FROM sync_changes WHERE revision > ? ORDER BY revision", (after_revision,)).fetchall()
            return [dict(row) for row in rows]

    def entry_sync_revision(self, entry_id: str) -> int:
        with self._lock(), self._connect() as connection:
            self._create_schema(connection)
            row = connection.execute(
                "SELECT COALESCE(MAX(revision), 0) AS revision FROM sync_changes WHERE (entity_type = 'entry' AND entity_id = ?) OR (entity_type = 'record' AND parent_id = ?)",
                (entry_id, entry_id),
            ).fetchone()
            return int(row["revision"])

    def _lock(self) -> FileLock:
        self.home.mkdir(parents=True, exist_ok=True)
        if not _is_windows():
            self.home.chmod(0o700)
        return FileLock(str(self.lock_path), timeout=10)

    def _read_data_key(self, create: bool) -> bytes:
        try:
            stored = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
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
                raise VaultError(f"Unable to read Windows Credential Manager: {keyring_error}") from keyring_error
            raise VaultError("Vault key not found in the credential store or fallback key file. Run agent-vault init.")
        generated = Fernet.generate_key().decode("ascii")
        try:
            keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, generated)
        except Exception as exc:
            if _is_windows():
                raise VaultError(f"Unable to save key in Windows Credential Manager: {exc}") from exc
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
            raise VaultError("Vault key is invalid.") from exc

    def _encrypt(self, value: str) -> bytes:
        return Fernet(self._read_data_key(create=False)).encrypt(value.encode("utf-8"))

    def _decrypt(self, encrypted: bytes) -> str:
        try:
            return Fernet(self._read_data_key(create=False)).decrypt(encrypted).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError) as exc:
            raise VaultError("Vault value cannot be decrypted with the current vault key.") from exc

    @staticmethod
    def _json_tags(value: str) -> list[str]:
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return []
        return parsed if isinstance(parsed, list) else []

    @classmethod
    def _public_record_from_row(cls, row: sqlite3.Row) -> dict[str, Any]:
        result = {"name": row["name"], "note": row["note"], "tags": cls._json_tags(row["tags"]), "created_at": row["created_at"], "updated_at": row["updated_at"]}
        if row["entry"] is not None:
            result["entry"] = row["entry"]
        return result

    @classmethod
    def _entry_from_row(cls, row: sqlite3.Row) -> dict[str, Any]:
        keys = row.keys()
        result = {"id": row["id"], "description": row["description"], "tags": cls._json_tags(row["tags"]), "created_at": row["created_at"], "updated_at": row["updated_at"], "secret_count": row["secret_count"] if "secret_count" in keys else 0}
        result["category"] = row["category"]
        return result

    @staticmethod
    def _category_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {"id": row["id"], "name": row["name"], "color": row["color"], "created_at": row["created_at"], "updated_at": row["updated_at"], "entry_count": row["entry_count"] if "entry_count" in row.keys() else 0}
