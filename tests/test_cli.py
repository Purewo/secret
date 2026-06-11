from __future__ import annotations

import io
import sys

import pytest

from agent_vault.cli import main


def test_get_hides_value_unless_reveal(vault_home, fake_keyring, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    assert main(["init"]) == 0
    monkeypatch.setattr(sys, "stdin", io.StringIO("super-secret-value\n"))
    assert main(["set", "server_password", "--value-stdin"]) == 0
    capsys.readouterr()

    assert main(["get", "server_password"]) == 0
    hidden = capsys.readouterr()
    assert "super-secret-value" not in hidden.out
    assert "value: <hidden" in hidden.out

    assert main(["get", "server_password", "--reveal"]) == 0
    revealed = capsys.readouterr()
    assert revealed.out == "super-secret-value"


def test_run_injects_secret_without_parent_output_leak(
    vault_home, fake_keyring, monkeypatch: pytest.MonkeyPatch, capfd
) -> None:
    assert main(["init"]) == 0
    monkeypatch.setattr(sys, "stdin", io.StringIO("super-secret-value\n"))
    assert main(["set", "server_password", "--value-stdin"]) == 0
    capfd.readouterr()

    code = "import os; print(os.environ.get('server_password') == 'super-secret-value')"
    assert main(["run", "server_password", "--", sys.executable, "-c", code]) == 0
    captured = capfd.readouterr()
    assert "True" in captured.out
    assert "super-secret-value" not in captured.out


def test_delete_requires_explicit_yes(vault_home, fake_keyring, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    assert main(["init"]) == 0
    monkeypatch.setattr(sys, "stdin", io.StringIO("super-secret-value\n"))
    assert main(["set", "server_password", "--value-stdin"]) == 0
    capsys.readouterr()

    assert main(["delete", "server_password"]) == 1
    error = capsys.readouterr()
    assert "without --yes" in error.err
    assert "super-secret-value" not in error.err


def test_entry_cli_lists_visible_metadata_without_secret_value(
    vault_home, fake_keyring, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    assert main(["init"]) == 0
    assert main(["entry", "set", "japan_server", "--description", "日本三网优化服务器", "--tag", "server"]) == 0
    monkeypatch.setattr(sys, "stdin", io.StringIO("super-secret-value\n"))
    assert main(["set", "japan_server_password", "--value-stdin", "--entry", "japan_server"]) == 0
    capsys.readouterr()

    assert main(["entry", "list"]) == 0
    listed = capsys.readouterr()
    assert "japan_server" in listed.out
    assert "日本三网优化服务器" in listed.out
    assert "super-secret-value" not in listed.out

    assert main(["entry", "show", "japan_server"]) == 0
    shown = capsys.readouterr()
    assert "japan_server_password" in shown.out
    assert "super-secret-value" not in shown.out
