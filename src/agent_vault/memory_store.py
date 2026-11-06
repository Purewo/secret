"""Private, key-owned Agent backup archives, separate from vault data and shared Skills."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import sqlite3
import stat
import tempfile
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from filelock import FileLock

from .storage import VaultError, default_vault_home, utc_now


MAX_PACKAGE_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 20_000
MAX_UNPACKED_BYTES = 1024 * 1024 * 1024
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
BACKUP_ID_RE = re.compile(r"(?:memory|backup)_[A-Za-z0-9_-]{8,64}\Z")
OWNER_KEY_RE = re.compile(r"key_[A-Za-z0-9_-]{1,80}\Z")
PARTITIONS = {"memory": "记忆", "skills": "Skill", "other": "其他"}


class BackupNotFound(VaultError):
    """Missing and foreign-owned backups deliberately have the same result."""


class AgentBackupStore:
    """One private space per API key; each space contains three archive partitions."""

    def __init__(self, vault_home: Path | None = None) -> None:
        base = Path(vault_home) if vault_home is not None else default_vault_home()
        self.home = base / "MemoryBackups"
        self.path = self.home / "memory_backups.db"
        self.packages = self.home / "packages"
        self.lock_path = self.home / "memory_backups.lock"

    def init(self) -> None:
        self.packages.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self.home.chmod(0o700)
            self.packages.chmod(0o700)
        with self._lock(), self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS backups (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    owner_key_id TEXT,
                    partition TEXT NOT NULL DEFAULT 'memory'
                );
                CREATE TABLE IF NOT EXISTS versions (
                    backup_id TEXT NOT NULL,
                    version TEXT NOT NULL,
                    original_filename TEXT NOT NULL,
                    archive_format TEXT NOT NULL,
                    package_path TEXT NOT NULL,
                    bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    uploaded_at TEXT NOT NULL,
                    download_count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (backup_id, version),
                    FOREIGN KEY (backup_id) REFERENCES backups(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_memory_versions_uploaded
                    ON versions(uploaded_at);
                """
            )
            # Preserve old archives. Ownership cannot be inferred safely: legacy
            # NULL owners remain visible only to administrators until bound once.
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(backups)")}
            if "owner_key_id" not in columns:
                connection.execute("ALTER TABLE backups ADD COLUMN owner_key_id TEXT")
            if "partition" not in columns:
                connection.execute("ALTER TABLE backups ADD COLUMN partition TEXT NOT NULL DEFAULT 'memory'")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_backup_owner_partition ON backups(owner_key_id, partition)")

    def list_backups(self, *, owner_key_id: str | None = None, partition: str | None = None,
                     unbound_only: bool = False) -> list[dict[str, Any]]:
        filters, parameters = [], []
        if owner_key_id is not None:
            filters.append("b.owner_key_id = ?")
            parameters.append(self._validate_owner(owner_key_id))
        if unbound_only:
            filters.append("b.owner_key_id IS NULL")
        if partition is not None:
            filters.append("b.partition = ?")
            parameters.append(self._validate_partition(partition))
        with self._lock(), self._connect() as connection:
            rows = connection.execute(
                """
                SELECT b.*, v.version, v.original_filename, v.archive_format, v.bytes,
                       v.sha256, v.uploaded_at, v.download_count
                FROM backups b
                JOIN versions v ON v.backup_id = b.id
                WHERE v.rowid = (
                    SELECT MAX(rowid) FROM versions latest WHERE latest.backup_id = b.id
                )
                """ + (" AND " + " AND ".join(filters) if filters else "") +
                " ORDER BY b.updated_at DESC, b.name COLLATE NOCASE", parameters,
            ).fetchall()
        return [self._summary(row) for row in rows]

    def detail(self, backup_id: str, *, owner_key_id: str | None = None) -> dict[str, Any]:
        backup_id = self._validate_backup_id(backup_id)
        with self._lock(), self._connect() as connection:
            backup = self._owned_backup(connection, backup_id, owner_key_id)
            versions = connection.execute(
                "SELECT * FROM versions WHERE backup_id = ? ORDER BY uploaded_at DESC, rowid DESC",
                (backup_id,),
            ).fetchall()
        version_payload = [self._version(row) for row in versions]
        return {
            "id": backup["id"],
            "name": backup["name"],
            "description": backup["description"],
            "owner_key_id": backup["owner_key_id"],
            "partition": backup["partition"],
            "created_at": backup["created_at"],
            "updated_at": backup["updated_at"],
            "latest_version": version_payload[0]["version"] if version_payload else None,
            "versions": version_payload,
        }

    def upload(
        self,
        source: BinaryIO,
        length: int,
        *,
        original_filename: str,
        name: str = "",
        description: str = "",
        version: str,
        backup_id: str | None = None,
        owner_key_id: str,
        partition: str | None = None,
    ) -> dict[str, Any]:
        owner_key_id = self._validate_owner(owner_key_id)
        if partition is not None:
            partition = self._validate_partition(partition)
        if length <= 0 or length > MAX_PACKAGE_BYTES:
            raise VaultError("Agent 备份压缩包必须大于 0 且不超过 100 MB。")
        version = version.strip()
        if not VERSION_RE.fullmatch(version):
            raise VaultError("版本号格式无效。")
        original_filename = self._filename(original_filename)
        name = " ".join(name.split())
        description = " ".join(description.split())
        if len(name) > 120 or len(description) > 500:
            raise VaultError("Agent 备份名称最多 120 个字符，简介最多 500 个字符。")
        if not original_filename:
            raise VaultError("必须提供压缩包文件名。")

        with self._lock(), self._connect() as connection:
            is_new = backup_id is None
            if backup_id is not None:
                backup_id = self._validate_backup_id(backup_id)
                existing = self._owned_backup(connection, backup_id, owner_key_id)
                if partition is not None and partition != existing["partition"]:
                    raise VaultError("追加版本不能改变备份分区。")
                partition = existing["partition"]
                name = name or existing["name"]
                description = description or existing["description"]
            else:
                backup_id = "backup_" + secrets.token_hex(10)
                partition = partition or "memory"
            if not name:
                raise VaultError("新建Agent 备份时必须提供名称。")
            if connection.execute(
                "SELECT 1 FROM versions WHERE backup_id = ? AND version = ?",
                (backup_id, version),
            ).fetchone() is not None:
                raise VaultError("该Agent 备份版本已存在，请使用新的版本号。")

            fd, temp_name = tempfile.mkstemp(prefix="memory-upload-", suffix=".archive", dir=self.packages)
            temp_path = Path(temp_name)
            final_path: Path | None = None
            digest = hashlib.sha256()
            try:
                with os.fdopen(fd, "wb") as output:
                    remaining = length
                    while remaining:
                        block = source.read(min(1024 * 1024, remaining))
                        if not block:
                            raise VaultError("Agent 备份上传内容不完整。")
                        output.write(block)
                        digest.update(block)
                        remaining -= len(block)
                archive_format = self._validate_archive(temp_path, original_filename)
                final_path = self.packages / f"{backup_id}-{version}-{secrets.token_hex(6)}.archive"
                now = utc_now()
                os.replace(temp_path, final_path)
                if is_new:
                    connection.execute(
                        "INSERT INTO backups(id,name,description,created_at,updated_at,owner_key_id,partition) VALUES(?,?,?,?,?,?,?)",
                        (backup_id, name, description, now, now, owner_key_id, partition),
                    )
                else:
                    connection.execute(
                        "UPDATE backups SET name = ?, description = ?, updated_at = ? WHERE id = ?",
                        (name, description, now, backup_id),
                    )
                connection.execute(
                    """
                    INSERT INTO versions(
                        backup_id, version, original_filename, archive_format, package_path,
                        bytes, sha256, uploaded_at
                    ) VALUES(?,?,?,?,?,?,?,?)
                    """,
                    (
                        backup_id,
                        version,
                        original_filename,
                        archive_format,
                        final_path.name,
                        length,
                        digest.hexdigest(),
                        now,
                    ),
                )
            except Exception:
                temp_path.unlink(missing_ok=True)
                if final_path is not None:
                    final_path.unlink(missing_ok=True)
                raise
        return self.detail(backup_id, owner_key_id=owner_key_id)

    def download(self, backup_id: str, version: str, *, owner_key_id: str | None = None) -> tuple[Path, str, str]:
        backup_id = self._validate_backup_id(backup_id)
        with self._lock(), self._connect() as connection:
            self._owned_backup(connection, backup_id, owner_key_id)
            row = connection.execute(
                "SELECT package_path, sha256, original_filename FROM versions WHERE backup_id = ? AND version = ?",
                (backup_id, version),
            ).fetchone()
            if row is None:
                raise VaultError("Agent 备份版本不存在。")
            path = self.packages / row["package_path"]
            if not path.is_file():
                raise VaultError("Agent 备份文件已丢失。")
            connection.execute(
                "UPDATE versions SET download_count = download_count + 1 WHERE backup_id = ? AND version = ?",
                (backup_id, version),
            )
        return path, row["sha256"], row["original_filename"]

    def delete(self, backup_id: str, *, owner_key_id: str | None = None) -> None:
        backup_id = self._validate_backup_id(backup_id)
        with self._lock(), self._connect() as connection:
            self._owned_backup(connection, backup_id, owner_key_id)
            rows = connection.execute(
                "SELECT package_path FROM versions WHERE backup_id = ?", (backup_id,)
            ).fetchall()
            if not rows:
                raise VaultError("Agent 备份不存在。")
            connection.execute("DELETE FROM backups WHERE id = ?", (backup_id,))
        for row in rows:
            (self.packages / row["package_path"]).unlink(missing_ok=True)

    def update_metadata(self, backup_id: str, *, name: str | None = None,
                        description: str | None = None, owner_key_id: str | None = None) -> dict[str, Any]:
        backup_id = self._validate_backup_id(backup_id)
        with self._lock(), self._connect() as connection:
            backup = self._owned_backup(connection, backup_id, owner_key_id)
            if name is None and description is None:
                raise VaultError("请至少提供备份名称或备注。")
            name = backup["name"] if name is None else " ".join(name.split())
            description = backup["description"] if description is None else " ".join(description.split())
            if not name or len(name) > 120 or len(description) > 500:
                raise VaultError("备份名称必填且最多 120 个字符，备注最多 500 个字符。")
            connection.execute("UPDATE backups SET name = ?, description = ?, updated_at = ? WHERE id = ?",
                               (name, description, utc_now(), backup_id))
        return self.detail(backup_id, owner_key_id=owner_key_id)

    def bind_owner(self, backup_id: str, owner_key_id: str) -> dict[str, Any]:
        """Administrator-only migration operation; an existing owner is immutable."""
        backup_id = self._validate_backup_id(backup_id)
        owner_key_id = self._validate_owner(owner_key_id)
        with self._lock(), self._connect() as connection:
            backup = self._owned_backup(connection, backup_id, None)
            if backup["owner_key_id"] is not None:
                raise VaultError("备份已经绑定 Key，不能更换归属。")
            connection.execute("UPDATE backups SET owner_key_id = ?, updated_at = ? WHERE id = ?",
                               (owner_key_id, utc_now(), backup_id))
        return self.detail(backup_id)

    def has_backups(self, owner_key_id: str) -> bool:
        with self._lock(), self._connect() as connection:
            return connection.execute("SELECT 1 FROM backups WHERE owner_key_id = ? LIMIT 1",
                                      (owner_key_id,)).fetchone() is not None

    @classmethod
    def _owned_backup(cls, connection: sqlite3.Connection, backup_id: str,
                      owner_key_id: str | None) -> sqlite3.Row:
        query, parameters = "SELECT * FROM backups WHERE id = ?", [backup_id]
        if owner_key_id is not None:
            query += " AND owner_key_id = ?"
            parameters.append(cls._validate_owner(owner_key_id))
        backup = connection.execute(query, parameters).fetchone()
        if backup is None:
            raise BackupNotFound("Agent 备份不存在。")
        return backup

    @staticmethod
    def _validate_owner(owner_key_id: str) -> str:
        if not isinstance(owner_key_id, str) or not OWNER_KEY_RE.fullmatch(owner_key_id):
            raise VaultError("Agent 备份必须绑定一个有效的 API Key。")
        return owner_key_id

    @staticmethod
    def _validate_partition(partition: str) -> str:
        if partition not in PARTITIONS:
            raise VaultError("备份分区必须是 memory、skills 或 other。")
        return partition

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _lock(self) -> FileLock:
        self.home.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self.home.chmod(0o700)
        return FileLock(str(self.lock_path), timeout=10)

    @staticmethod
    def _filename(value: str) -> str:
        text = str(value or "").replace("\\", "/")
        name = PurePosixPath(text).name.strip()
        if name in {"", ".", ".."} or len(name) > 240:
            return ""
        return name

    @staticmethod
    def _validate_backup_id(backup_id: str) -> str:
        if not BACKUP_ID_RE.fullmatch(backup_id):
            raise VaultError("Agent 备份 ID 无效。")
        return backup_id

    @classmethod
    def _validate_archive(cls, path: Path, filename: str) -> str:
        lower = filename.lower()
        if lower.endswith(".zip"):
            try:
                with zipfile.ZipFile(path) as archive:
                    members = archive.infolist()
                    if not members or len(members) > MAX_ARCHIVE_ENTRIES:
                        raise VaultError("ZIP 文件数量无效或超过 20000 个。")
                    total_size = 0
                    for item in members:
                        cls._validate_member_path(item.filename)
                        if item.flag_bits & 1:
                            raise VaultError("不支持加密压缩包。")
                        if stat.S_ISLNK(item.external_attr >> 16):
                            raise VaultError("ZIP 不允许符号链接。")
                        total_size += item.file_size
                        if total_size > MAX_UNPACKED_BYTES:
                            raise VaultError("ZIP 解压后超过 1 GB。")
                    if archive.testzip() is not None:
                        raise VaultError("ZIP 文件校验失败。")
            except zipfile.BadZipFile as exc:
                raise VaultError("文件不是有效 ZIP 压缩包。") from exc
            return "zip"

        if lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")):
            try:
                with tarfile.open(path, mode="r:*") as archive:
                    members = archive.getmembers()
                    if not members or len(members) > MAX_ARCHIVE_ENTRIES:
                        raise VaultError("TAR 文件数量无效或超过 20000 个。")
                    total_size = 0
                    for item in members:
                        cls._validate_member_path(item.name)
                        if item.issym() or item.islnk():
                            raise VaultError("TAR 不允许符号链接或硬链接。")
                        total_size += item.size
                        if total_size > MAX_UNPACKED_BYTES:
                            raise VaultError("TAR 解压后超过 1 GB。")
            except (tarfile.ReadError, EOFError) as exc:
                raise VaultError("文件不是有效 TAR 压缩包。") from exc
            if lower.endswith((".tar.gz", ".tgz")):
                return "tar.gz"
            if lower.endswith((".tar.bz2", ".tbz2")):
                return "tar.bz2"
            if lower.endswith((".tar.xz", ".txz")):
                return "tar.xz"
            return "tar"

        with path.open("rb") as stream:
            header = stream.read(8)
        if lower.endswith(".7z") and header.startswith(b"7z\xbc\xaf\x27\x1c"):
            return "7z"
        if lower.endswith(".rar") and (header.startswith(b"Rar!\x1a\x07\x00") or header.startswith(b"Rar!\x1a\x07\x01")):
            return "rar"
        raise VaultError("不支持的Agent 备份格式，请使用 ZIP、TAR、7z 或 RAR。")

    @staticmethod
    def _validate_member_path(name: str) -> None:
        normalized = name.replace("\\", "/")
        parts = PurePosixPath(normalized).parts
        if not normalized or normalized.startswith("/") or ".." in parts or any(part.endswith(":") for part in parts):
            raise VaultError("压缩包包含不安全的文件路径。")

    @staticmethod
    def _summary(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "description": row["description"],
            "owner_key_id": row["owner_key_id"],
            "partition": row["partition"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "latest_version": row["version"],
            "latest": {
                "version": row["version"],
                "original_filename": row["original_filename"],
                "archive_format": row["archive_format"],
                "size_bytes": row["bytes"],
                "sha256": row["sha256"],
                "uploaded_at": row["uploaded_at"],
                "download_count": row["download_count"],
            },
        }

    @staticmethod
    def _version(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "version": row["version"],
            "original_filename": row["original_filename"],
            "archive_format": row["archive_format"],
            "size_bytes": row["bytes"],
            "sha256": row["sha256"],
            "uploaded_at": row["uploaded_at"],
            "download_count": row["download_count"],
            "download_url": f"/api/v1/agent-backups/{row['backup_id']}/versions/{row['version']}/download",
        }


# Keep the Python import and existing on-disk location compatible.
MemoryBackupStore = AgentBackupStore
