"""Versioned Skill packages kept outside the encrypted secret vault."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import sqlite3
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from filelock import FileLock

from .storage import VaultError, default_vault_home, utc_now


MAX_PACKAGE_BYTES = 25 * 1024 * 1024
MAX_UNPACKED_BYTES = 100 * 1024 * 1024
MAX_ZIP_FILES = 1000
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
CATEGORY_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,79}\Z")


class SkillAccessError(VaultError):
    """A key tried to cross its Skill category boundary."""


class SkillStore:
    def __init__(self, vault_home: Path | None = None) -> None:
        base = Path(vault_home) if vault_home is not None else default_vault_home()
        self.home = base / "Skills"
        self.path = self.home / "skills.db"
        self.packages = self.home / "packages"
        self.lock_path = self.home / "skills.lock"

    def init(self) -> None:
        self.packages.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self.home.chmod(0o700)
            self.packages.chmod(0o700)
        with self._lock(), self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS categories (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS skills (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL,
                    category TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS versions (
                    skill_id TEXT NOT NULL, version TEXT NOT NULL, package_path TEXT NOT NULL,
                    bytes INTEGER NOT NULL, sha256 TEXT NOT NULL, uploaded_at TEXT NOT NULL,
                    download_count INTEGER NOT NULL DEFAULT 0, requires_environment INTEGER NOT NULL,
                    environment_note TEXT NOT NULL, PRIMARY KEY(skill_id, version),
                    FOREIGN KEY(skill_id) REFERENCES skills(id)
                );
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _lock(self) -> FileLock:
        self.home.mkdir(parents=True, exist_ok=True)
        return FileLock(str(self.lock_path), timeout=10)

    def categories(self, allowed: set[str] | None = None) -> list[dict[str, Any]]:
        with self._lock(), self._connect() as connection:
            rows = connection.execute("SELECT id,name FROM categories ORDER BY name COLLATE NOCASE").fetchall()
            counts = {row["category"]: row["count"] for row in connection.execute("SELECT category,COUNT(*) AS count FROM skills GROUP BY category")}
        result = [{"id": row["id"], "name": row["name"], "skill_count": counts.get(row["id"], 0)} for row in rows]
        result.append({"id": "__other__", "name": "其他", "skill_count": counts.get("__other__", 0), "built_in": True})
        return [row for row in result if allowed is None or row["id"] in allowed or "__all__" in allowed]

    def add_category(self, category_id: str, name: str) -> dict[str, Any]:
        if not CATEGORY_RE.fullmatch(category_id) or category_id == "__other__":
            raise VaultError("Skill 分类标识无效。")
        name = " ".join(name.split())
        if not name or len(name) > 40:
            raise VaultError("Skill 分类名称必须为 1–40 个字符。")
        try:
            with self._lock(), self._connect() as connection:
                connection.execute("INSERT INTO categories(id,name,created_at) VALUES(?,?,?)", (category_id, name, utc_now()))
        except sqlite3.IntegrityError as exc:
            raise VaultError("Skill 分类已存在。") from exc
        return {"id": category_id, "name": name, "skill_count": 0}

    def list_skills(self, category: str | None = None, allowed: set[str] | None = None) -> list[dict[str, Any]]:
        if category and allowed is not None and category not in allowed and "__all__" not in allowed:
            raise SkillAccessError("API Key 无权访问该 Skill 分类。")
        with self._lock(), self._connect() as connection:
            sql = """SELECT s.*, v.version, v.bytes, v.uploaded_at, v.download_count,
                     v.requires_environment, v.environment_note
                     FROM skills s JOIN versions v ON v.skill_id=s.id
                     WHERE v.rowid=(SELECT MAX(rowid) FROM versions WHERE skill_id=s.id)"""
            params: list[Any] = []
            if category:
                sql += " AND s.category=?"
                params.append(category)
            sql += " ORDER BY s.updated_at DESC, s.name COLLATE NOCASE"
            rows = connection.execute(sql, params).fetchall()
        return [self._summary(row) for row in rows if allowed is None or row["category"] in allowed or "__all__" in allowed]

    def detail(self, skill_id: str, allowed: set[str] | None = None) -> dict[str, Any]:
        with self._lock(), self._connect() as connection:
            skill = connection.execute("SELECT * FROM skills WHERE id=?", (skill_id,)).fetchone()
            if skill is None:
                raise VaultError("Skill 不存在。")
            if allowed is not None and skill["category"] not in allowed and "__all__" not in allowed:
                raise SkillAccessError("API Key 无权访问该 Skill 分类。")
            rows = connection.execute("SELECT * FROM versions WHERE skill_id=? ORDER BY uploaded_at DESC, rowid DESC", (skill_id,)).fetchall()
        versions = [{
            "version": row["version"], "uploaded_at": row["uploaded_at"], "download_count": row["download_count"],
            "size_bytes": row["bytes"], "sha256": row["sha256"],
            "requires_environment": bool(row["requires_environment"]), "environment_note": row["environment_note"],
            "download_url": f"/api/v1/skills/{skill_id}/versions/{row['version']}/download",
        } for row in rows]
        return {"id": skill["id"], "name": skill["name"], "description": skill["description"],
                "category": skill["category"], "created_at": skill["created_at"], "updated_at": skill["updated_at"],
                "latest_version": versions[0]["version"] if versions else None, "versions": versions}

    def upload(self, source: BinaryIO, length: int, *, name: str, description: str, version: str,
               category: str = "__other__", skill_id: str | None = None,
               environment_note: str = "", requires_environment: bool | None = None) -> dict[str, Any]:
        name = " ".join(name.split())
        description = " ".join(description.split())
        environment_note = " ".join(environment_note.split())
        if not name or len(name) > 80 or not description or len(description) > 500:
            raise VaultError("Skill 名称和简介必填，分别最多 80 和 500 个字符。")
        if not VERSION_RE.fullmatch(version):
            raise VaultError("版本号格式无效。")
        if length <= 0 or length > MAX_PACKAGE_BYTES:
            raise VaultError("Skill 压缩包必须为 ZIP，最大 25 MB。")
        if len(environment_note) > 500:
            raise VaultError("环境依赖说明过长。")
        with self._lock(), self._connect() as connection:
            if category != "__other__" and connection.execute("SELECT 1 FROM categories WHERE id=?", (category,)).fetchone() is None:
                raise VaultError("Skill 分类不存在。")
            is_new = skill_id is None
            if skill_id:
                existing = connection.execute("SELECT * FROM skills WHERE id=?", (skill_id,)).fetchone()
                if existing is None:
                    raise VaultError("Skill 不存在。")
                if connection.execute("SELECT 1 FROM versions WHERE skill_id=? AND version=?", (skill_id, version)).fetchone():
                    raise VaultError("该 Skill 版本已存在，请使用新的版本号。")
            else:
                skill_id = "skill_" + secrets.token_hex(10)
            fd, temp_name = tempfile.mkstemp(prefix="upload-", suffix=".zip", dir=self.packages)
            temp_path = Path(temp_name)
            final_path: Path | None = None
            digest = hashlib.sha256()
            try:
                with os.fdopen(fd, "wb") as output:
                    remaining = length
                    while remaining:
                        block = source.read(min(1024 * 1024, remaining))
                        if not block:
                            raise VaultError("Skill 上传内容不完整。")
                        output.write(block)
                        digest.update(block)
                        remaining -= len(block)
                detected = self._validate_zip(temp_path)
                need_env = detected if requires_environment is None else requires_environment
                final_path = self.packages / f"{skill_id}-{version}.zip"
                now = utc_now()
                os.replace(temp_path, final_path)
                if is_new:
                    connection.execute("INSERT INTO skills(id,name,description,category,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                                       (skill_id, name, description, category, now, now))
                else:
                    connection.execute("UPDATE skills SET name=?,description=?,category=?,updated_at=? WHERE id=?",
                                       (name, description, category, now, skill_id))
                connection.execute("""INSERT INTO versions(skill_id,version,package_path,bytes,sha256,uploaded_at,requires_environment,environment_note)
                                      VALUES(?,?,?,?,?,?,?,?)""",
                                   (skill_id, version, final_path.name, length, digest.hexdigest(), now, int(need_env), environment_note))
            except Exception:
                temp_path.unlink(missing_ok=True)
                if final_path is not None:
                    final_path.unlink(missing_ok=True)
                raise
        return self.detail(skill_id)

    @staticmethod
    def _validate_zip(path: Path) -> bool:
        try:
            with zipfile.ZipFile(path) as archive:
                files = archive.infolist()
                if not files or len(files) > MAX_ZIP_FILES:
                    raise VaultError("ZIP 文件数量无效或超过 1000 个。")
                total = 0
                has_skill_md = False
                needs_environment = False
                for item in files:
                    name = item.filename.replace("\\", "/")
                    parts = PurePosixPath(name).parts
                    if not name or name.startswith("/") or ".." in parts or any(part.endswith(":") for part in parts):
                        raise VaultError("ZIP 包含不安全的文件路径。")
                    mode = (item.external_attr >> 16) & 0xFFFF
                    if stat.S_ISLNK(mode) or item.flag_bits & 1:
                        raise VaultError("ZIP 不允许符号链接或加密文件。")
                    total += item.file_size
                    if total > MAX_UNPACKED_BYTES:
                        raise VaultError("ZIP 解压后超过 100 MB。")
                    lower = name.lower()
                    if not item.is_dir() and item.file_size > 0 and len(parts) in (1, 2) and parts[-1].lower() == "skill.md":
                        has_skill_md = True
                    if lower.endswith((".py", ".js", ".ts", ".sh", ".ps1", "requirements.txt", "pyproject.toml", "package.json")):
                        needs_environment = True
                if not has_skill_md:
                    raise VaultError("ZIP 根目录或顶层目录必须包含 SKILL.md。")
                return needs_environment
        except zipfile.BadZipFile as exc:
            raise VaultError("文件不是有效 ZIP 压缩包。") from exc

    def download(self, skill_id: str, version: str, allowed: set[str] | None = None) -> tuple[Path, str]:
        with self._lock(), self._connect() as connection:
            row = connection.execute("""SELECT s.category,v.package_path,v.sha256 FROM skills s JOIN versions v ON v.skill_id=s.id
                                        WHERE s.id=? AND v.version=?""", (skill_id, version)).fetchone()
            if row is None:
                raise VaultError("Skill 版本不存在。")
            if allowed is not None and row["category"] not in allowed and "__all__" not in allowed:
                raise SkillAccessError("API Key 无权访问该 Skill 分类。")
            path = self.packages / row["package_path"]
            if not path.is_file():
                raise VaultError("Skill 压缩包已丢失。")
            connection.execute("UPDATE versions SET download_count=download_count+1 WHERE skill_id=? AND version=?", (skill_id, version))
            return path, row["sha256"]

    @staticmethod
    def _summary(row: sqlite3.Row) -> dict[str, Any]:
        return {"id": row["id"], "name": row["name"], "description": row["description"],
                "category": row["category"], "latest_version": row["version"],
                "uploaded_at": row["uploaded_at"], "download_count": row["download_count"],
                "size_bytes": row["bytes"], "requires_environment": bool(row["requires_environment"])}
