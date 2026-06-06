from __future__ import annotations

import pytest

from agent_vault.storage import Vault, VaultError


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
