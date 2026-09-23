from __future__ import annotations

from agent_vault.client import SyncClient


def test_pull_encodes_numeric_cursor_from_server(vault_home, fake_keyring, monkeypatch) -> None:
    client = SyncClient(vault_home)
    client.configure("https://vault.example", "avk_test")
    requests: list[str] = []

    def fake_request(method: str, path: str, payload=None):
        requests.append(path)
        return {"entries": [], "unassigned": [], "deleted_records": [], "cursor": 1}

    monkeypatch.setattr(client, "_request", fake_request)

    client.pull()
    client.pull()

    assert requests == ["/api/v1/sync/pull", "/api/v1/sync/pull?cursor=1"]


def test_named_profile_keeps_agent_key_separate(vault_home, fake_keyring) -> None:
    default = SyncClient(vault_home)
    codex = SyncClient(vault_home, profile="codex")
    default.configure("https://other-agent.example", "avk_other")
    codex.configure("https://vault.example", "avk_codex")

    assert default.config_path != codex.config_path
    assert default.status()["base_url"] == "https://other-agent.example"
    assert codex.status()["base_url"] == "https://vault.example"
    assert fake_keyring[("agent-vault-sync-client", "remote-api-key")] == "avk_other"
    assert fake_keyring[("agent-vault-sync-client", "remote-api-key:codex")] == "avk_codex"
