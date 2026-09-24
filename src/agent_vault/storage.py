from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import keyring
from cryptography.fernet import Fernet, InvalidToken
from filelock import FileLock
from platformdirs import user_data_dir

APP_NAME = "AgentVault"
KEYRING_SERVICE = "agent-vault"
KEYRING_USERNAME = "vault-data-key"
VAULT_HOME_ENV = "AGENT_VAULT_HOME"
KEY_FILE_NAME = "vault.key"
VAULT_VERSION = 1
NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
ENTRY_ID_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_-]*\Z")
CATEGORY_ID_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_-]*\Z")


class VaultError(Exception):
    """Raised for expected vault failures that are safe to show to the user."""


@dataclass(frozen=True)
class VaultDiagnostics:
    home: Path
    path: Path
    vault_exists: bool
    key_exists: bool
    decryptable: bool
    error: str | None = None


def default_vault_home() -> Path:
    override = os.environ.get(VAULT_HOME_ENV)
    if override:
        return Path(override).expanduser()
    return Path(user_data_dir(APP_NAME, appauthor=False, roaming=False))


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def validate_name(name: str) -> str:
    if not NAME_PATTERN.fullmatch(name):
        raise VaultError("Invalid variable name. Use [A-Za-z_][A-Za-z0-9_]*.")
    return name


def validate_entry_id(entry_id: str) -> str:
    if not ENTRY_ID_PATTERN.fullmatch(entry_id):
        raise VaultError("Invalid entry id. Use [A-Za-z][A-Za-z0-9_-]*.")
    return entry_id


def validate_category_id(category_id: str) -> str:
    if not CATEGORY_ID_PATTERN.fullmatch(category_id):
        raise VaultError("Invalid category id. Use [A-Za-z][A-Za-z0-9_-]*.")
    return category_id


def _is_windows() -> bool:
    return os.name == "nt"


class LegacyVault:
    def __init__(self, home: Path | None = None) -> None:
        self.home = Path(home) if home is not None else default_vault_home()
        self.path = self.home / "vault.enc"
        self.lock_path = self.home / "vault.lock"
        self.key_path = self.home / KEY_FILE_NAME

    def init(self) -> bool:
        self.home.mkdir(parents=True, exist_ok=True)
        with self._lock():
            if self.path.exists():
                self._read_data_key(create=False)
                self._load_unlocked()
                return False

            self._read_data_key(create=True)
            self._save_unlocked(self._empty_vault())
            return True

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
        with self._lock():
            data = self._load_unlocked()
            records = data["records"]
            if entry is not None and entry not in data["entries"]:
                raise VaultError(f"Entry '{entry}' not found. Run agent-vault entry set first.")
            conflict = self._case_conflict(records, name)
            if conflict is not None:
                raise VaultError(
                    f"A secret named '{conflict}' already exists with different case. "
                    "Windows environment variables are case-insensitive."
                )

            now = utc_now()
            previous = records.get(name)
            records[name] = {
                "name": name,
                "value": value,
                "note": note,
                "tags": tags or [],
                "entry": entry if entry is not None else previous.get("entry") if previous else None,
                "created_at": previous.get("created_at", now) if previous else now,
                "updated_at": now,
            }
            self._save_unlocked(data)
            return self._public_record(records[name])

    def list_records(self) -> list[dict[str, Any]]:
        with self._lock():
            data = self._load_unlocked()
            records = data["records"].values()
            return [self._public_record(record) for record in sorted(records, key=lambda item: item["name"].lower())]

    def get_secret(self, name: str) -> dict[str, Any]:
        name = validate_name(name)
        with self._lock():
            data = self._load_unlocked()
            try:
                return dict(data["records"][name])
            except KeyError as exc:
                raise VaultError(f"Secret '{name}' not found.") from exc

    def get_values(self, names: list[str]) -> dict[str, str]:
        if not names:
            raise VaultError("At least one secret name is required.")
        validated = [validate_name(name) for name in names]
        with self._lock():
            data = self._load_unlocked()
            values: dict[str, str] = {}
            for name in validated:
                try:
                    values[name] = data["records"][name]["value"]
                except KeyError as exc:
                    raise VaultError(f"Secret '{name}' not found.") from exc
            return values

    def delete_secret(self, name: str) -> None:
        name = validate_name(name)
        with self._lock():
            data = self._load_unlocked()
            if name not in data["records"]:
                raise VaultError(f"Secret '{name}' not found.")
            del data["records"][name]
            self._save_unlocked(data)

    def delete_entry(self, entry_id: str, expected_category: str | None = None) -> dict[str, Any]:
        entry_id = validate_entry_id(entry_id)
        with self._lock():
            data = self._load_unlocked()
            if entry_id not in data["entries"]:
                raise VaultError(f"Entry '{entry_id}' not found.")
            category = data["entries"][entry_id].get("category") or "__other__"
            if expected_category is not None and category != expected_category:
                raise VaultError("Entry category changed; retry the deletion.")
            record_names = [
                name for name, record in data["records"].items()
                if record.get("entry") == entry_id
            ]
            for name in record_names:
                del data["records"][name]
            del data["entries"][entry_id]
            self._save_unlocked(data)
            return {"id": entry_id, "deleted_records": len(record_names)}

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
        with self._lock():
            data = self._load_unlocked()
            entries = data["entries"]
            if category is not None and category not in data["categories"]:
                raise VaultError(f"Category '{category}' not found.")
            now = utc_now()
            previous = entries.get(entry_id)
            entries[entry_id] = {
                "id": entry_id,
                "description": description,
                "tags": tags or [],
                "category": category if category is not None else previous.get("category") if previous else None,
                "created_at": previous.get("created_at", now) if previous else now,
                "updated_at": now,
            }
            self._save_unlocked(data)
            return dict(entries[entry_id])

    def set_category(self, category_id: str, name: str, color: str = "mint") -> dict[str, Any]:
        category_id = validate_category_id(category_id)
        name = " ".join(name.split())
        if not name:
            raise VaultError("Category name cannot be empty.")
        with self._lock():
            data = self._load_unlocked()
            categories = data["categories"]
            now = utc_now()
            previous = categories.get(category_id)
            categories[category_id] = {
                "id": category_id,
                "name": name,
                "color": color,
                "created_at": previous.get("created_at", now) if previous else now,
                "updated_at": now,
            }
            self._save_unlocked(data)
            return dict(categories[category_id])

    def list_categories(self) -> list[dict[str, Any]]:
        with self._lock():
            data = self._load_unlocked()
            counts: dict[str, int] = {}
            for entry in data["entries"].values():
                category = entry.get("category")
                if category:
                    counts[category] = counts.get(category, 0) + 1
            categories = []
            for category in data["categories"].values():
                public = dict(category)
                public["entry_count"] = counts.get(category["id"], 0)
                categories.append(public)
            return sorted(categories, key=lambda item: (item["name"].lower(), item["id"].lower()))

    def assign_category(self, category_id: str | None, entry_ids: list[str]) -> list[dict[str, Any]]:
        if category_id is not None:
            category_id = validate_category_id(category_id)
        if not entry_ids:
            raise VaultError("At least one entry id is required.")
        validated = [validate_entry_id(entry_id) for entry_id in entry_ids]
        with self._lock():
            data = self._load_unlocked()
            if category_id is not None and category_id not in data["categories"]:
                raise VaultError(f"Category '{category_id}' not found.")
            missing = [entry_id for entry_id in validated if entry_id not in data["entries"]]
            if missing:
                raise VaultError(f"Entry not found: {', '.join(missing)}")
            now = utc_now()
            assigned = []
            for entry_id in validated:
                data["entries"][entry_id]["category"] = category_id
                data["entries"][entry_id]["updated_at"] = now
                assigned.append(dict(data["entries"][entry_id]))
            self._save_unlocked(data)
            return assigned

    def list_entries(self) -> list[dict[str, Any]]:
        with self._lock():
            data = self._load_unlocked()
            counts = self._entry_counts(data["records"])
            entries = []
            for entry in data["entries"].values():
                public = dict(entry)
                public["secret_count"] = counts.get(entry["id"], 0)
                entries.append(public)
            return sorted(entries, key=lambda item: item["id"].lower())

    def get_entry(self, entry_id: str) -> dict[str, Any]:
        entry_id = validate_entry_id(entry_id)
        with self._lock():
            data = self._load_unlocked()
            if entry_id not in data["entries"]:
                raise VaultError(f"Entry '{entry_id}' not found.")
            entry = dict(data["entries"][entry_id])
            records = [
                self._public_record(record)
                for record in data["records"].values()
                if record.get("entry") == entry_id
            ]
            entry["records"] = sorted(records, key=lambda item: item["name"].lower())
            return entry

    def assign_entry(self, entry_id: str, names: list[str]) -> list[dict[str, Any]]:
        entry_id = validate_entry_id(entry_id)
        if not names:
            raise VaultError("At least one secret name is required.")
        validated = [validate_name(name) for name in names]
        with self._lock():
            data = self._load_unlocked()
            if entry_id not in data["entries"]:
                raise VaultError(f"Entry '{entry_id}' not found. Run agent-vault entry set first.")
            missing = [name for name in validated if name not in data["records"]]
            if missing:
                raise VaultError(f"Secret not found: {', '.join(missing)}")
            now = utc_now()
            assigned = []
            for name in validated:
                data["records"][name]["entry"] = entry_id
                data["records"][name]["updated_at"] = now
                assigned.append(self._public_record(data["records"][name]))
            self._save_unlocked(data)
            return assigned

    def diagnose(self) -> VaultDiagnostics:
        key_exists = False
        decryptable = False
        error: str | None = None
        try:
            key_exists = self._read_data_key(create=False) is not None
            if self.path.exists() and key_exists:
                self._load_unlocked()
                decryptable = True
        except VaultError as exc:
            error = str(exc)
        return VaultDiagnostics(
            home=self.home,
            path=self.path,
            vault_exists=self.path.exists(),
            key_exists=key_exists,
            decryptable=decryptable,
            error=error,
        )

    def _lock(self) -> FileLock:
        self.home.mkdir(parents=True, exist_ok=True)
        if not _is_windows():
            self.home.chmod(0o700)
        return FileLock(str(self.lock_path), timeout=10)

    def _read_data_key(self, create: bool) -> bytes | None:
        keyring_error: Exception | None = None
        try:
            stored = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
        except Exception as exc:  # keyring backend errors vary by platform/backend.
            keyring_error = exc
            stored = None

        if stored is not None:
            return self._validate_data_key(stored)

        if not _is_windows() and self.key_path.exists():
            try:
                self.key_path.chmod(0o600)
                return self._validate_data_key(self.key_path.read_text(encoding="ascii").strip())
            except OSError as exc:
                raise VaultError(f"Unable to read fallback key file: {exc}") from exc

        if not create:
            if _is_windows() and keyring_error is not None:
                raise VaultError(f"Unable to read Windows Credential Manager: {keyring_error}") from keyring_error
            raise VaultError("Vault key not found in the credential store or fallback key file. Run agent-vault init.")

        generated = Fernet.generate_key().decode("ascii")
        try:
            keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, generated)
            return self._validate_data_key(generated)
        except Exception as exc:
            keyring_error = exc

        if not _is_windows():
            try:
                self.home.mkdir(parents=True, exist_ok=True)
                self.home.chmod(0o700)
                self.key_path.write_text(generated, encoding="ascii")
                self.key_path.chmod(0o600)
                return self._validate_data_key(generated)
            except OSError as exc:
                raise VaultError(f"Unable to save fallback key file: {exc}") from exc

        raise VaultError(f"Unable to save key in Windows Credential Manager: {keyring_error}") from keyring_error

    @staticmethod
    def _validate_data_key(stored: str) -> bytes:
        try:
            key = stored.encode("ascii")
        except (AttributeError, UnicodeEncodeError) as exc:
            raise VaultError("Vault key is invalid.") from exc
        try:
            Fernet(key)
        except Exception as exc:
            raise VaultError("Vault key is invalid.") from exc
        return key

    def _load_unlocked(self) -> dict[str, Any]:
        if not self.path.exists():
            raise VaultError("Vault is not initialized. Run agent-vault init.")

        key = self._read_data_key(create=False)
        try:
            encrypted = self.path.read_bytes()
            raw = Fernet(key).decrypt(encrypted)
            data = json.loads(raw.decode("utf-8"))
        except InvalidToken as exc:
            raise VaultError("Vault cannot be decrypted with the current vault key.") from exc
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise VaultError(f"Vault file is unreadable: {exc}") from exc

        if data.get("version") != VAULT_VERSION or not isinstance(data.get("records"), dict):
            raise VaultError("Vault file has an unsupported format.")
        if not isinstance(data.get("entries", data.get("projects", {})), dict):
            raise VaultError("Vault file has an unsupported entry format.")
        if not isinstance(data.get("categories", {}), dict):
            raise VaultError("Vault file has an unsupported category format.")
        if "entries" not in data:
            data["entries"] = data.pop("projects", {})
        if "categories" not in data:
            data["categories"] = {}
        for record in data["records"].values():
            if "entry" not in record and "project" in record:
                record["entry"] = record.pop("project")
        return data

    def _save_unlocked(self, data: dict[str, Any]) -> None:
        key = self._read_data_key(create=False)
        data["updated_at"] = utc_now()
        encoded = json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
        encrypted = Fernet(key).encrypt(encoded)
        tmp_path = self.path.with_suffix(".enc.tmp")
        try:
            tmp_path.write_bytes(encrypted)
            tmp_path.replace(self.path)
        except OSError as exc:
            raise VaultError(f"Unable to write vault file: {exc}") from exc

    @staticmethod
    def _empty_vault() -> dict[str, Any]:
        now = utc_now()
        return {
            "version": VAULT_VERSION,
            "created_at": now,
            "updated_at": now,
            "records": {},
            "entries": {},
            "categories": {},
        }

    @staticmethod
    def _case_conflict(records: dict[str, Any], name: str) -> str | None:
        for existing in records:
            if existing.lower() == name.lower() and existing != name:
                return existing
        return None

    @staticmethod
    def _public_record(record: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in record.items() if key != "value" and value is not None}

    @staticmethod
    def _entry_counts(records: dict[str, Any]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for record in records.values():
            entry = record.get("entry")
            if entry:
                counts[entry] = counts.get(entry, 0) + 1
        return counts


# SQLite is the active backend. LegacyVault remains available only for
# migrating the pre-SQLite encrypted JSON file during first initialization.
from .sqlite_storage import SQLiteVault

Vault = SQLiteVault
