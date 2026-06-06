from __future__ import annotations

from pathlib import Path

import pytest

from agent_vault import storage


@pytest.fixture
def vault_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "AgentVault"
    monkeypatch.setenv(storage.VAULT_HOME_ENV, str(home))
    return home


@pytest.fixture
def fake_keyring(monkeypatch: pytest.MonkeyPatch) -> dict[tuple[str, str], str]:
    values: dict[tuple[str, str], str] = {}

    def get_password(service: str, username: str) -> str | None:
        return values.get((service, username))

    def set_password(service: str, username: str, password: str) -> None:
        values[(service, username)] = password

    monkeypatch.setattr(storage.keyring, "get_password", get_password)
    monkeypatch.setattr(storage.keyring, "set_password", set_password)
    return values
