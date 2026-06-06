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
VAULT_VERSION = 1
NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


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


class Vault:
    def __init__(self, home: Path | None = None) -> None:
        self.home = Path(home) if home is not None else default_vault_home()
        self.path = self.home / "vault.enc"
        self.lock_path = self.home / "vault.lock"

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

    def set_secret(self, name: str, value: str, note: str = "", tags: list[str] | None = None) -> dict[str, Any]:
        name = validate_name(name)
        with self._lock():
            data = self._load_unlocked()
            records = data["records"]
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
        return FileLock(str(self.lock_path), timeout=10)

    def _read_data_key(self, create: bool) -> bytes | None:
        try:
            stored = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
        except Exception as exc:  # keyring backend errors vary by platform/backend.
            raise VaultError(f"Unable to read Windows credential: {exc}") from exc

        if stored is None:
            if not create:
                raise VaultError("Vault key not found in Windows Credential Manager. Run agent-vault init.")
            generated = Fernet.generate_key().decode("ascii")
            try:
                keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, generated)
            except Exception as exc:
                raise VaultError(f"Unable to save Windows credential: {exc}") from exc
            stored = generated

        key = stored.encode("ascii")
        try:
            Fernet(key)
        except Exception as exc:
            raise VaultError("Vault key in Windows Credential Manager is invalid.") from exc
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
            raise VaultError("Vault cannot be decrypted with the current Windows credential.") from exc
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise VaultError(f"Vault file is unreadable: {exc}") from exc

        if data.get("version") != VAULT_VERSION or not isinstance(data.get("records"), dict):
            raise VaultError("Vault file has an unsupported format.")
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
        return {"version": VAULT_VERSION, "created_at": now, "updated_at": now, "records": {}}

    @staticmethod
    def _case_conflict(records: dict[str, Any], name: str) -> str | None:
        for existing in records:
            if existing.lower() == name.lower() and existing != name:
                return existing
        return None

    @staticmethod
    def _public_record(record: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in record.items() if key != "value"}
