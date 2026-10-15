"""功能：离线准备、校验和安装漏洞库，维护上一有效版本及本次失败恢复。
实现：先在目标同目录准备候选，再备份和原子替换；GUI 可在准备后关闭旧句柄。
输入：OSV 原始 ZIP 或 PythonScan 全量 ZIP、目标路径；输出：全量库和可选 .bak。
依赖：Python 标准库；临时目录由 PreparedImport.close 或 import_db 的 finally 清理。
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import zipfile

from . import db
from .osv import OSVError, load_osv_zip, validate_record
from .versioning import normalize_name


def validate_full(path) -> dict:
    """检查全部索引数据及哈希覆盖，拒绝可被误当空库的损坏文件。"""
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise db.DBError("ZIP 含有重复文件名")
            manifest = json.loads(archive.read(db.MANIFEST_NAME).decode("utf-8"))
            if not isinstance(manifest, dict):
                raise db.DBError("manifest 必须为对象")
            if manifest.get("kind") == "delta":
                raise db.DBError("增量包请用 db update；此入口请选择 OSV 原始 ZIP 或全量库")
            if manifest.get("kind") != "full" or type(manifest.get("schema_version")) is not int or manifest["schema_version"] != db.SCHEMA_VERSION:
                raise db.DBError("全量库 kind/schema 版本不兼容")
            if not isinstance(manifest.get("snapshot"), str) or not manifest["snapshot"]:
                raise db.DBError("全量库缺少 snapshot")
            files = manifest.get("files")
            if not isinstance(files, dict) or db.INDEX_NAME not in files:
                raise db.DBError("manifest 缺少 index 哈希")
            for name, digest in files.items():
                if not isinstance(digest, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
                    raise db.DBError(f"无效 SHA256: {name}")
                if hashlib.sha256(archive.read(name)).hexdigest() != digest.lower():
                    raise db.DBError(f"文件校验失败: {name}")
            index = json.loads(archive.read(db.INDEX_NAME).decode("utf-8"))
            if not isinstance(index, dict) or not isinstance(index.get("packages"), dict) or not isinstance(index.get("latest", {}), dict):
                raise db.DBError("包索引结构无效")
            for package, version in index.get("latest", {}).items():
                if not _valid_package(package) or not isinstance(version, str):
                    raise db.DBError("latest 表结构无效")
            required = set()
            total = 0
            for package, info in index["packages"].items():
                if not _valid_package(package) or not isinstance(info, dict) or type(info.get("hits")) is not int:
                    raise db.DBError("包名或 hits 结构无效")
                name = f"data/{package}.json"
                required.add(name)
                if name not in files:
                    raise db.DBError(f"缺少包数据哈希: {name}")
                records = json.loads(archive.read(name).decode("utf-8"))
                if not isinstance(records, list) or len(records) != info["hits"]:
                    raise db.DBError(f"包记录数不符: {package}")
                for record in records:
                    validate_record(record)
                    if not any(entry.get("package", {}).get("ecosystem") == "PyPI"
                               and normalize_name(entry["package"]["name"]) == package
                               for entry in record.get("affected", [])):
                        raise db.DBError(f"公告 {record['id']} 与索引包 {package} 不对应")
                total += len(records)
            data_names = {n for n in names if n.startswith("data/") and not n.endswith("/")}
            if data_names != required:
                raise db.DBError("包索引和数据文件不一致")
            if type(manifest.get("record_count")) is not int or manifest["record_count"] != total or type(manifest.get("package_count")) is not int or manifest["package_count"] != len(required):
                raise db.DBError("manifest 记录数或包数不符")
            return manifest
    except (zipfile.BadZipFile, KeyError, ValueError, UnicodeError, TypeError) as exc:
        raise db.DBError(f"漏洞库格式损坏: {exc}") from exc


def _valid_package(name):
    return isinstance(name, str) and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", name)


@dataclass
class PreparedImport:
    target: Path
    candidate: Path
    manifest: dict
    temporary: object
    same_path: bool = False
    rollback: Path | None = None
    previous_valid: bool = False
    previous_invalid: bool = False
    installed: bool = False

    @property
    def backup(self):
        return self.target.with_name(self.target.name + ".bak")

    def close(self):
        """安装或取消后清理本次暂存文件，永不删除输入和管理库。"""
        self.temporary.cleanup()


def prepare_import(src_path, target=None) -> PreparedImport:
    """后台完成慢操作；此阶段不关闭或替换正在使用的库。"""
    src = Path(src_path).resolve()
    target = Path(target or db.default_db_path()).resolve()
    if not src.is_file():
        raise db.DBError(f"导入文件不存在: {src}")
    backup = target.with_name(target.name + ".bak")
    same = target.exists() and os.path.samefile(src, target)
    if not same and backup.exists() and os.path.samefile(src, backup):
        raise db.DBError("输入文件正是目标的 .bak 备份，请先复制到其他路径后导入，避免覆盖输入")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = tempfile.TemporaryDirectory(prefix=".pythonscan-import-", dir=target.parent)
    directory = Path(temporary.name)
    try:
        candidate = directory / "candidate.zip"
        shutil.copyfile(src, candidate)
        with zipfile.ZipFile(candidate) as archive:
            has_manifest = db.MANIFEST_NAME in archive.namelist()
        if not has_manifest:
            if same:
                raise db.DBError("原始 ZIP 与安装目标相同，请把原始文件放到其他位置后导入")
            records, snapshot = load_osv_zip(candidate)
            metadata = {"source_type": "osv-pypi-zip",
                        "source_sha256": hashlib.sha256(candidate.read_bytes()).hexdigest(),
                        "imported_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
            db.write_full_db(records, str(candidate), snapshot=snapshot, metadata=metadata)
        manifest = validate_full(candidate)
        prepared = PreparedImport(target, candidate, manifest, temporary, same_path=same)
        if target.exists() and not same:
            # 即便旧目标损坏，也保留本次恢复副本；只有有效库才更新公开 .bak。
            prepared.rollback = directory / "previous.zip"
            shutil.copyfile(target, prepared.rollback)
            try:
                validate_full(prepared.rollback)
                prepared.previous_valid = True
            except db.DBError:
                prepared.previous_invalid = True
        return prepared
    except (zipfile.BadZipFile, OSVError) as exc:
        temporary.cleanup()
        raise db.DBError(f"无法导入漏洞库: {exc}") from exc
    except BaseException:
        temporary.cleanup()
        raise


def install_import(prepared: PreparedImport) -> dict:
    """调用方关闭旧数据库句柄后安装；后置加载失败会恢复本次旧文件。"""
    if prepared.same_path:
        return dict(prepared.manifest)
    if prepared.installed:
        raise db.DBError("此导入任务已经安装")
    try:
        if prepared.previous_valid:
            backup_ready = Path(prepared.temporary.name) / "backup-ready.zip"
            shutil.copyfile(prepared.rollback, backup_ready)
            os.replace(backup_ready, prepared.backup)
        os.replace(prepared.candidate, prepared.target)
        prepared.installed = True
        with db.load(prepared.target):
            pass
    except Exception as original:
        if prepared.installed:
            try:
                restore_import(prepared)
            except Exception as recovery:
                raise db.DBError(f"导入失败: {original}；恢复旧库也失败: {recovery}") from original
        raise
    result = dict(prepared.manifest)
    if prepared.previous_invalid:
        result["backup_warning"] = "原目标损坏，未覆盖上一份有效备份"
    return result


def restore_import(prepared: PreparedImport):
    """仅撤销本次已经安装的库，恢复失败时保留 installed 状态供重试。"""
    if not prepared.installed:
        return
    if prepared.rollback is not None:
        ready = Path(prepared.temporary.name) / "restore-ready.zip"
        shutil.copyfile(prepared.rollback, ready)
        os.replace(ready, prepared.target)
    else:
        prepared.target.unlink()
    prepared.installed = False
