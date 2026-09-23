from __future__ import annotations

import os

import pytest

from agent_vault.api_keys import ApiKeyStore
from agent_vault.storage import LegacyVault, Vault, VaultError


def test_secret_file_is_encrypted(vault_home, fake_keyring) -> None:
    vault = Vault()
    assert vault.init() is True

    vault.set_secret("server_password", "super-secret-value")

    assert b"super-secret-value" not in vault.path.read_bytes()
    assert vault.get_secret("server_password")["value"] == "super-secret-value"


def test_default_record_listing_omits_value(vault_home, fake_keyring) -> None:
    vault = Vault()
    vault.init()
    vault.set_secret("server_password", "super-secret-value", note="ssh login", tags=["server"])

    records = vault.list_records()

    assert records == [
        {
            "name": "server_password",
            "note": "ssh login",
            "tags": ["server"],
            "created_at": records[0]["created_at"],
            "updated_at": records[0]["updated_at"],
        }
    ]
    assert "value" not in records[0]


def test_windows_environment_case_conflict_is_rejected(vault_home, fake_keyring) -> None:
    vault = Vault()
    vault.init()
    vault.set_secret("server_password", "one")

    with pytest.raises(VaultError, match="different case"):
        vault.set_secret("SERVER_PASSWORD", "two")


def test_invalid_variable_name_is_rejected(vault_home, fake_keyring) -> None:
    vault = Vault()
    vault.init()

    with pytest.raises(VaultError, match="Invalid variable name"):
        vault.set_secret("server-password", "value")


def test_entries_are_visible_metadata_without_values(vault_home, fake_keyring) -> None:
    vault = Vault()
    vault.init()
    vault.set_entry("japan_server", "日本三网优化服务器", tags=["server", "japan"])
    vault.set_secret("japan_server_password", "super-secret-value", entry="japan_server")

    entries = vault.list_entries()
    entry = vault.get_entry("japan_server")

    assert entries[0]["id"] == "japan_server"
    assert entries[0]["description"] == "日本三网优化服务器"
    assert entries[0]["secret_count"] == 1
    assert entry["records"][0]["name"] == "japan_server_password"
    assert "value" not in entry["records"][0]


def test_assign_entry_links_existing_records_without_reading_values(vault_home, fake_keyring) -> None:
    vault = Vault()
    vault.init()
    vault.set_entry("japan_server", "日本三网优化服务器")
    vault.set_secret("japan_server_password", "super-secret-value")

    assigned = vault.assign_entry("japan_server", ["japan_server_password"])

    assert assigned[0]["entry"] == "japan_server"
    assert "value" not in assigned[0]
    assert vault.get_secret("japan_server_password")["value"] == "super-secret-value"


def test_set_secret_rejects_missing_entry(vault_home, fake_keyring) -> None:
    vault = Vault()
    vault.init()

    with pytest.raises(VaultError, match="Entry 'missing' not found"):
        vault.set_secret("server_password", "value", entry="missing")


def test_categories_group_entries_and_uncategorized_remains_other(vault_home, fake_keyring) -> None:
    vault = Vault()
    vault.init()
    vault.set_category("servers", "服务器", color="blue")
    vault.set_entry("japan_server", "日本服务器")
    vault.set_entry("game_account", "游戏账号")

    assigned = vault.assign_category("servers", ["japan_server"])
    categories = vault.list_categories()
    entries = {entry["id"]: entry for entry in vault.list_entries()}

    assert assigned[0]["category"] == "servers"
    assert categories[0]["name"] == "服务器"
    assert categories[0]["entry_count"] == 1
    assert entries["japan_server"]["category"] == "servers"
    assert entries["game_account"]["category"] is None


def test_assign_category_is_atomic_for_missing_entries(vault_home, fake_keyring) -> None:
    vault = Vault()
    vault.init()
    vault.set_category("servers", "服务器")
    vault.set_entry("japan_server", "日本服务器")

    with pytest.raises(VaultError, match="Entry not found"):
        vault.assign_category("servers", ["japan_server", "missing"])

    assert vault.get_entry("japan_server")["category"] is None


def test_assigning_none_moves_entry_back_to_other(vault_home, fake_keyring) -> None:
    vault = Vault()
    vault.init()
    vault.set_category("servers", "服务器")
    vault.set_entry("japan_server", "日本服务器", category="servers")

    vault.assign_category(None, ["japan_server"])

    assert vault.get_entry("japan_server")["category"] is None


def test_sync_change_log_tracks_updates_and_tombstones(vault_home, fake_keyring) -> None:
    vault = Vault()
    vault.init()
    vault.set_entry("server_one", "server")
    cursor = vault.sync_cursor()
    vault.set_secret("server_one_password", "test-only", entry="server_one")
    vault.delete_secret("server_one_password")

    changes = vault.list_sync_changes(cursor)

    assert [change["operation"] for change in changes] == ["upsert", "delete"]
    assert changes[-1]["entity_id"] == "server_one_password"
    assert vault.entry_sync_revision("server_one") == changes[-1]["revision"]


def test_api_key_is_returned_once_and_only_hash_is_persisted(vault_home, fake_keyring) -> None:
    store = ApiKeyStore(vault_home)
    store.init()

    created = store.create("remote agent", note="trusted office agent")
    listed = store.list()

    assert created["api_key"].startswith("avk_")
    assert created["permissions"] == {"categories": [], "read": False, "add": False, "delete": False, "skill_categories": []}
    assert "api_key" not in listed[0]
    assert "key_hash" not in listed[0]
    assert listed[0]["status"] == "active"
    assert store.authenticate(created["api_key"])["id"] == created["id"]
    assert store.reveal(created["id"]) == created["api_key"]


def test_revoked_api_key_no_longer_authenticates(vault_home, fake_keyring) -> None:
    store = ApiKeyStore(vault_home)
    store.init()
    created = store.create("temporary agent")

    revoked = store.revoke(created["id"])

    assert revoked["status"] == "revoked"
    assert store.authenticate(created["api_key"]) is None
    restored = store.restore(created["id"])
    assert restored["status"] == "active"
    assert store.authenticate(created["api_key"])["id"] == created["id"]
    store.delete(created["id"])
    assert store.list() == []


def test_legacy_project_fields_are_mapped_to_entries(vault_home, fake_keyring) -> None:
    vault = LegacyVault()
    vault.init()
    data = vault._load_unlocked()
    data["projects"] = {
        "legacy_server": {
            "id": "legacy_server",
            "description": "legacy visible description",
            "tags": [],
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
    }
    data.pop("entries", None)
    data["records"]["legacy_password"] = {
        "name": "legacy_password",
        "value": "super-secret-value",
        "note": "",
        "tags": [],
        "project": "legacy_server",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }
    vault._save_unlocked(data)

    migrated = Vault()
    migrated.init()
    entry = migrated.get_entry("legacy_server")

    assert entry["description"] == "legacy visible description"
    assert entry["records"][0]["entry"] == "legacy_server"
    assert "value" not in entry["records"][0]


def test_non_windows_falls_back_to_restricted_key_file(
    vault_home, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(*_args, **_kwargs):
        raise RuntimeError("no system keyring")

    monkeypatch.setattr("agent_vault.sqlite_storage._is_windows", lambda: False)
    monkeypatch.setattr("agent_vault.storage.keyring.get_password", unavailable)
    monkeypatch.setattr("agent_vault.storage.keyring.set_password", unavailable)

    vault = Vault()
    assert vault.init() is True
    vault.set_secret("server_password", "super-secret-value")

    assert vault.key_path.exists()
    if os.name != "nt":
        assert vault.key_path.stat().st_mode & 0o777 == 0o600
        assert vault.home.stat().st_mode & 0o777 == 0o700
    assert b"super-secret-value" not in vault.path.read_bytes()
    assert vault.get_secret("server_password")["value"] == "super-secret-value"
