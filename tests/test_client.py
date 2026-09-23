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
