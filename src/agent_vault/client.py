from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Sequence

import keyring

from .storage import Vault, VaultError, default_vault_home

CLIENT_DIR_NAME = "Client"
CLIENT_CONFIG_NAME = "sync.json"
CLIENT_KEYRING_SERVICE = "agent-vault-sync-client"
CLIENT_KEYRING_USERNAME = "remote-api-key"


class SyncClientError(Exception):
    pass


class SyncClient:
    def __init__(self, home: Path | None = None) -> None:
        self.vault = Vault(home)
        base = Path(home) if home is not None else default_vault_home()
        self.home = base / CLIENT_DIR_NAME
        self.config_path = self.home / CLIENT_CONFIG_NAME

    def configure(self, base_url: str, api_key: str) -> None:
        base_url = base_url.strip().rstrip("/")
        if not base_url.startswith(("http://", "https://")):
            raise SyncClientError("Base URL must start with http:// or https://.")
        if not api_key.strip():
            raise SyncClientError("API key cannot be empty.")
        self.home.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(json.dumps({"base_url": base_url, "cursor": 0, "entry_revisions": {}}, ensure_ascii=False, indent=2), encoding="utf-8")
        keyring.set_password(CLIENT_KEYRING_SERVICE, CLIENT_KEYRING_USERNAME, api_key.strip())

    def status(self) -> dict[str, Any]:
        config = self._config()
        return {
            "configured": bool(config.get("base_url") and self._api_key()),
            "base_url": config.get("base_url", ""),
            "cursor": config.get("cursor", ""),
            "local_vault": str(self.vault.home),
        }

    def pull(self) -> dict[str, Any]:
        config = self._config_required()
        cursor = config.get("cursor", "")
        query = f"?cursor={urllib.parse.quote(str(cursor))}" if cursor else ""
        payload = self._request("GET", f"/api/v1/sync/pull{query}")
        self.vault.init()
        for category in payload.get("categories", []):
            if category.get("id") == "__other__":
                continue
            self.vault.set_category(category["id"], category["name"], color=category.get("color", "mint"))
        pulled_entries = 0
        pulled_records = 0
        for entry in payload.get("entries", []):
            category = entry.get("category") or None
            self.vault.set_entry(entry["id"], entry.get("description", ""), tags=entry.get("tags", []), category=category)
            pulled_entries += 1
            for variable in entry.get("variables", []):
                self.vault.set_secret(variable["name"], variable["value"], note=variable.get("note", ""), tags=variable.get("tags", []), entry=entry["id"])
                pulled_records += 1
        for variable in payload.get("unassigned", []):
            self.vault.set_secret(variable["name"], variable["value"], note=variable.get("note", ""), tags=variable.get("tags", []), entry=None)
            pulled_records += 1
        for tombstone in payload.get("deleted_records", []):
            try:
                self.vault.delete_secret(tombstone["name"])
            except VaultError:
                pass
        revisions = config.setdefault("entry_revisions", {})
        for entry in payload.get("entries", []):
            if entry.get("revision") is not None:
                revisions[entry["id"]] = entry["revision"]
        config["cursor"] = payload.get("cursor", cursor)
        self._save_config(config)
        return {"entries": pulled_entries, "records": pulled_records, "cursor": config["cursor"]}

    def push_entry(self, entry_id: str) -> dict[str, Any]:
        config = self._config_required()
        local_entry = self.vault.get_entry(entry_id)
        variables = []
        for public_record in local_entry.get("records", []):
            full_record = self.vault.get_secret(public_record["name"])
            variables.append(
                {
                    "name": full_record["name"],
                    "value": full_record["value"],
                    "note": full_record.get("note", ""),
                    "tags": full_record.get("tags", []),
                }
            )
        category = local_entry.get("category") or "__other__"
        response = self._request(
            "POST",
            f"/api/v1/entries/{urllib.parse.quote(entry_id, safe='')}/push",
            {
                "description": local_entry["description"],
                "tags": local_entry.get("tags", []),
                "category": category,
                "expected_revision": config.get("entry_revisions", {}).get(entry_id),
                "variables": variables,
            },
        )
        for result in response.get("results", []):
            if result.get("ok") and result.get("revision") is not None:
                config.setdefault("entry_revisions", {})[entry_id] = result["revision"]
        self._save_config(config)
        return response

    def _config(self) -> dict[str, Any]:
        if not self.config_path.exists():
            return {}
        try:
            value = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SyncClientError(f"Client config is unreadable: {exc}") from exc
        return value if isinstance(value, dict) else {}

    def _config_required(self) -> dict[str, Any]:
        config = self._config()
        if not config.get("base_url") or not self._api_key():
            raise SyncClientError("Client is not configured. Run agent-vault-client configure first.")
        return config

    def _api_key(self) -> str | None:
        try:
            return keyring.get_password(CLIENT_KEYRING_SERVICE, CLIENT_KEYRING_USERNAME)
        except Exception:
            return None

    def _save_config(self, config: dict[str, Any]) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        config = self._config_required()
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(f"{config['base_url']}{path}", data=body, method=method)
        request.add_header("Authorization", f"Bearer {self._api_key()}")
        if body is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode("utf-8"))
            except (OSError, json.JSONDecodeError):
                payload = {}
            message = payload.get("error") or f"HTTP {exc.code}"
            raise SyncClientError(message) from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise SyncClientError(f"Remote sync failed: {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-vault-client", description="Offline-first Agent Vault sync client.")
    sub = parser.add_subparsers(dest="command", required=True)
    configure = sub.add_parser("configure", help="Save remote URL and API key for this client.")
    configure.add_argument("--base-url", required=True)
    configure.add_argument("--api-key-stdin", action="store_true", help="Read the API key from stdin.")
    sub.add_parser("status", help="Show sync client status without printing the API key.")
    sub.add_parser("pull", help="Pull permitted remote data into the local vault.")
    push = sub.add_parser("push-entry", help="Push one local entry to the remote vault.")
    push.add_argument("entry_id")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    client = SyncClient()
    try:
        if args.command == "configure":
            api_key = sys.stdin.read() if args.api_key_stdin else getpass.getpass("API key: ")
            client.configure(args.base_url, api_key)
            print("Sync client configured.")
        elif args.command == "status":
            print(json.dumps(client.status(), ensure_ascii=False, indent=2))
        elif args.command == "pull":
            print(json.dumps(client.pull(), ensure_ascii=False, indent=2))
        elif args.command == "push-entry":
            print(json.dumps(client.push_entry(args.entry_id), ensure_ascii=False, indent=2))
        return 0
    except (SyncClientError, VaultError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
