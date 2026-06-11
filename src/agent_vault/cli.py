from __future__ import annotations

import argparse
import os
import subprocess
import sys
from getpass import getpass
from typing import Sequence

from .storage import Vault, VaultError


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except VaultError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("aborted", file=sys.stderr)
        return 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-vault", description="Agent-safe local encrypted secret vault.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Initialize the encrypted vault.")
    init_parser.set_defaults(func=cmd_init)

    set_parser = subparsers.add_parser("set", help="Save or update a secret.")
    set_parser.add_argument("name", help="Variable name, for example server_password.")
    set_parser.add_argument("--note", default="", help="Optional non-secret note.")
    set_parser.add_argument("--tag", action="append", default=[], help="Optional tag. Can be passed multiple times.")
    set_parser.add_argument("--entry", help="Optional existing entry id.")
    set_parser.add_argument("--value-stdin", action="store_true", help="Read the secret value from stdin.")
    set_parser.set_defaults(func=cmd_set)

    list_parser = subparsers.add_parser("list", help="List stored secret names and metadata.")
    list_parser.set_defaults(func=cmd_list)

    get_parser = subparsers.add_parser("get", help="Show secret metadata, or reveal value with --reveal.")
    get_parser.add_argument("name", help="Secret variable name.")
    get_parser.add_argument("--reveal", action="store_true", help="Print the raw secret value to stdout.")
    get_parser.set_defaults(func=cmd_get)

    delete_parser = subparsers.add_parser("delete", help="Delete a secret.")
    delete_parser.add_argument("name", help="Secret variable name.")
    delete_parser.add_argument("--yes", action="store_true", help="Confirm deletion without an interactive prompt.")
    delete_parser.set_defaults(func=cmd_delete)

    run_parser = subparsers.add_parser("run", help="Inject secrets into a child process environment.")
    run_parser.add_argument("items", nargs=argparse.REMAINDER, help="NAME [NAME ...] -- COMMAND [ARG ...]")
    run_parser.set_defaults(func=cmd_run)

    doctor_parser = subparsers.add_parser("doctor", help="Check vault and credential status without printing secrets.")
    doctor_parser.set_defaults(func=cmd_doctor)

    entry_parser = subparsers.add_parser("entry", help="Manage visible entries and metadata.")
    entry_subparsers = entry_parser.add_subparsers(dest="entry_command", required=True)

    entry_set_parser = entry_subparsers.add_parser("set", help="Create or update an entry.")
    entry_set_parser.add_argument("entry_id", help="Stable entry id, for example japan_server.")
    entry_set_parser.add_argument("--description", required=True, help="Visible non-secret entry description.")
    entry_set_parser.add_argument("--tag", action="append", default=[], help="Visible tag. Can be passed multiple times.")
    entry_set_parser.set_defaults(func=cmd_entry_set)

    entry_list_parser = entry_subparsers.add_parser("list", help="List all entries and visible descriptions.")
    entry_list_parser.set_defaults(func=cmd_entry_list)

    entry_show_parser = entry_subparsers.add_parser("show", help="Show entry metadata and variable names.")
    entry_show_parser.add_argument("entry_id", help="Entry id.")
    entry_show_parser.set_defaults(func=cmd_entry_show)

    entry_assign_parser = entry_subparsers.add_parser("assign", help="Assign existing secrets to an entry.")
    entry_assign_parser.add_argument("entry_id", help="Entry id.")
    entry_assign_parser.add_argument("names", nargs="+", help="Existing secret variable names.")
    entry_assign_parser.set_defaults(func=cmd_entry_assign)

    return parser


def cmd_init(_args: argparse.Namespace) -> int:
    vault = Vault()
    created = vault.init()
    status = "initialized" if created else "ready"
    print(f"Vault {status}: {vault.path}")
    return 0


def cmd_set(args: argparse.Namespace) -> int:
    value = _read_secret(args.name, args.value_stdin)
    record = Vault().set_secret(args.name, value, note=args.note, tags=args.tag, entry=args.entry)
    print(f"Saved {record['name']}.")
    return 0


def cmd_list(_args: argparse.Namespace) -> int:
    records = Vault().list_records()
    if not records:
        print("No records.")
        return 0

    for record in records:
        tags = ",".join(record.get("tags", [])) or "-"
        note = _one_line(record.get("note", "")) or "-"
        print(f"{record['name']}\tupdated={record['updated_at']}\ttags={tags}\tnote={note}")
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    record = Vault().get_secret(args.name)
    if args.reveal:
        sys.stdout.write(record["value"])
        return 0

    tags = ",".join(record.get("tags", [])) or "-"
    note = _one_line(record.get("note", "")) or "-"
    print(f"name: {record['name']}")
    print(f"updated: {record['updated_at']}")
    print(f"tags: {tags}")
    print(f"note: {note}")
    print("value: <hidden; use --reveal to print>")
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    if not args.yes:
        raise VaultError("Refusing to delete without --yes.")
    Vault().delete_secret(args.name)
    print(f"Deleted {args.name}.")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    names, command = _split_run_items(args.items)
    values = Vault().get_values(names)
    env = os.environ.copy()
    env.update(values)
    result = subprocess.run(command, env=env, check=False)
    return result.returncode


def cmd_doctor(_args: argparse.Namespace) -> int:
    diagnostics = Vault().diagnose()
    print(f"home: {diagnostics.home}")
    print(f"vault: {diagnostics.path}")
    print(f"vault_exists: {diagnostics.vault_exists}")
    print(f"key_exists: {diagnostics.key_exists}")
    print(f"decryptable: {diagnostics.decryptable}")
    if diagnostics.error:
        print(f"error: {diagnostics.error}")
        return 1
    return 0


def cmd_entry_set(args: argparse.Namespace) -> int:
    entry = Vault().set_entry(args.entry_id, args.description, tags=args.tag)
    print(f"Saved entry {entry['id']}.")
    return 0


def cmd_entry_list(_args: argparse.Namespace) -> int:
    entries = Vault().list_entries()
    if not entries:
        print("No entries.")
        return 0

    for entry in entries:
        tags = ",".join(entry.get("tags", [])) or "-"
        description = _one_line(entry["description"])
        print(
            f"{entry['id']}\tsecrets={entry['secret_count']}\t"
            f"tags={tags}\tdescription={description}"
        )
    return 0


def cmd_entry_show(args: argparse.Namespace) -> int:
    entry = Vault().get_entry(args.entry_id)
    tags = ",".join(entry.get("tags", [])) or "-"
    print(f"id: {entry['id']}")
    print(f"description: {_one_line(entry['description'])}")
    print(f"tags: {tags}")
    print(f"updated: {entry['updated_at']}")
    print("variables:")
    if not entry["records"]:
        print("  (none)")
        return 0
    for record in entry["records"]:
        note = _one_line(record.get("note", "")) or "-"
        print(f"  {record['name']}\tnote={note}")
    return 0


def cmd_entry_assign(args: argparse.Namespace) -> int:
    records = Vault().assign_entry(args.entry_id, args.names)
    print(f"Assigned {len(records)} variable(s) to {args.entry_id}.")
    return 0


def _read_secret(name: str, value_stdin: bool) -> str:
    if value_stdin:
        return _strip_one_trailing_newline(sys.stdin.read())
    return getpass(f"Value for {name}: ")


def _strip_one_trailing_newline(value: str) -> str:
    if value.endswith("\r\n"):
        return value[:-2]
    if value.endswith("\n"):
        return value[:-1]
    return value


def _split_run_items(items: list[str]) -> tuple[list[str], list[str]]:
    if "--" not in items:
        raise VaultError("Use: agent-vault run NAME [NAME ...] -- COMMAND [ARG ...].")
    separator = items.index("--")
    names = items[:separator]
    command = items[separator + 1 :]
    if not names:
        raise VaultError("At least one secret name is required before --.")
    if not command:
        raise VaultError("A command is required after --.")
    return names, command


def _one_line(value: str) -> str:
    return " ".join(value.split())
