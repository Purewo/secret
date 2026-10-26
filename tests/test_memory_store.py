from __future__ import annotations

import io
import tarfile
import zipfile

import pytest

from agent_vault.memory_store import MemoryBackupStore
from agent_vault.storage import VaultError


def zip_archive(filename: str = "memory.json", content: bytes = b'{"hello":"world"}') -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(filename, content)
    return buffer.getvalue()


def tar_archive() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        content = b"memory"
        info = tarfile.TarInfo("memory.json")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def test_memory_backup_uploads_versions_and_tracks_metadata(vault_home, fake_keyring) -> None:
    store = MemoryBackupStore(vault_home)
    store.init()

    first = zip_archive()
    created = store.upload(
        io.BytesIO(first), len(first), original_filename="agent-memory.zip",
        name="Codex memory", description="daily backup", version="1.0.0",
    )
    backup_id = created["id"]
    assert backup_id.startswith("memory_")
    assert created["latest_version"] == "1.0.0"
    assert created["versions"][0]["size_bytes"] == len(first)
    assert created["versions"][0]["archive_format"] == "zip"
    assert created["versions"][0]["sha256"]

    second = tar_archive()
    updated = store.upload(
        io.BytesIO(second), len(second), original_filename="agent-memory.tgz",
        version="1.1.0", backup_id=backup_id,
    )
    assert updated["name"] == "Codex memory"
    assert [item["version"] for item in updated["versions"]] == ["1.1.0", "1.0.0"]
    assert updated["versions"][0]["archive_format"] == "tar.gz"

    path, digest, filename = store.download(backup_id, "1.0.0")
    assert path.read_bytes() == first
    assert filename == "agent-memory.zip"
    assert len(digest) == 64
    assert store.detail(backup_id)["versions"][1]["download_count"] == 1


@pytest.mark.parametrize(
    ("filename", "payload", "expected"),
    [
        ("memory.7z", b"7z\xbc\xaf\x27\x1copaque", "7z"),
        ("memory.rar", b"Rar!\x1a\x07\x01\x00opaque", "rar"),
    ],
)
def test_memory_backup_accepts_common_opaque_archive_formats(vault_home, fake_keyring, filename, payload, expected) -> None:
    store = MemoryBackupStore(vault_home)
    store.init()
    result = store.upload(
        io.BytesIO(payload), len(payload), original_filename=filename,
        name="Opaque archive", version="1.0.0",
    )
    assert result["versions"][0]["archive_format"] == expected


def test_memory_backup_rejects_unsafe_zip_and_duplicate_version(vault_home, fake_keyring) -> None:
    store = MemoryBackupStore(vault_home)
    store.init()
    unsafe = zip_archive("../secrets.txt")
    with pytest.raises(VaultError, match="不安全"):
        store.upload(io.BytesIO(unsafe), len(unsafe), original_filename="memory.zip", name="Unsafe", version="1")

    payload = zip_archive()
    created = store.upload(io.BytesIO(payload), len(payload), original_filename="memory.zip", name="Memory", version="1")
    with pytest.raises(VaultError, match="版本已存在"):
        store.upload(io.BytesIO(payload), len(payload), original_filename="memory.zip", version="1", backup_id=created["id"])


def test_memory_backup_delete_removes_all_versions(vault_home, fake_keyring) -> None:
    store = MemoryBackupStore(vault_home)
    store.init()
    payload = zip_archive()
    created = store.upload(io.BytesIO(payload), len(payload), original_filename="memory.zip", name="Memory", version="1")
    store.upload(io.BytesIO(payload), len(payload), original_filename="memory.zip", version="2", backup_id=created["id"])
    store.delete(created["id"])
    assert store.list_backups() == []
    with pytest.raises(VaultError, match="不存在"):
        store.detail(created["id"])
