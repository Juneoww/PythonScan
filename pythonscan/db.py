"""本地漏洞库（zip 容器）的构建、加载、导入与增量更新。

库布局（docs/DESIGN.md §4）：
  manifest.json          元数据 + 除自身外各文件的 sha256
  index.json             包索引（包名 -> 记录数）与可选的最新版本表
  data/<规范包名>.json    该包全部漏洞记录（同步端已去重合并）

全量库 kind=full；增量包 kind=delta，以"包"为最小替换单元，
内部沿用 data/<包名>.json 路径，便于合并时按名覆盖。
"""

from __future__ import annotations

import hashlib
import json
import os
import zipfile
import tempfile
from datetime import date
from pathlib import Path

SCHEMA_VERSION = 1
MANIFEST_NAME = "manifest.json"
INDEX_NAME = "index.json"
DATA_PREFIX = "data/"
DELETIONS_NAME = "deletions.json"
INDEX_DELTA_NAME = "index_delta.json"
LATEST_DELTA_NAME = "latest.json"


class DBError(Exception):
    """漏洞库缺失、损坏、格式不符或增量版本不衔接。"""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _compact_json(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _pretty_json(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8")


def _read_manifest(zf: zipfile.ZipFile) -> dict:
    try:
        return json.loads(zf.read(MANIFEST_NAME).decode("utf-8"))
    except KeyError:
        raise DBError("缺少 manifest.json，文件不是有效的 PythonScan 漏洞库") from None


def _verify_files(zf: zipfile.ZipFile, manifest: dict, what: str) -> None:
    for name, expected in (manifest.get("files") or {}).items():
        try:
            actual = _sha256(zf.read(name))
        except KeyError:
            raise DBError(f"{what}缺少文件 {name}") from None
        if actual != expected:
            raise DBError(f"{what}文件校验失败: {name}（内容损坏或被篡改）")


# ---------------------------------------------------------------- 构建端（同步器/测试共用）

def write_full_db(records_by_package: dict, out_path: str, snapshot: str | None = None,
                  latest: dict | None = None, generator: str = "pythonscan",
                  metadata: dict | None = None) -> dict:
    """构建全量库 zip，返回 manifest。records: {规范包名: [记录, ...]}"""
    snapshot = snapshot or date.today().isoformat()
    entries: list[tuple[str, bytes]] = []
    packages: dict = {}
    total = 0
    for pkg, records in sorted((records_by_package or {}).items()):
        records = list(records)
        if not records:
            continue
        entries.append((f"{DATA_PREFIX}{pkg}.json", _compact_json(records)))
        packages[pkg] = {"hits": len(records)}
        total += len(records)
    index = {"packages": packages, "latest": dict(latest or {})}
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "full",
        "snapshot": snapshot,
        "generator": generator,
        "record_count": total,
        "package_count": len(packages),
    }
    manifest.update(metadata or {})
    manifest = _write_zip(out_path, entries, index, manifest, extra_files={})
    return manifest


def write_delta_db(prev_path: str, records_by_package: dict, out_path: str,
                   snapshot: str | None = None, latest: dict | None = None) -> dict:
    """对比上一版全量库生成增量包（以包为粒度，按内容哈希判定变更）。"""
    snapshot = snapshot or date.today().isoformat()
    with zipfile.ZipFile(prev_path) as zf:
        prev_manifest = _read_manifest(zf)
        if prev_manifest.get("kind") != "full":
            raise DBError("前一版本必须是全量库")
        prev_index = json.loads(zf.read(INDEX_NAME).decode("utf-8"))
        prev_files = prev_manifest.get("files") or {}
        prev_latest = prev_index.get("latest") or {}

    entries: list[tuple[str, bytes]] = []
    index_delta: dict = {"packages": {}, "latest": {}}
    stats_upsert = 0
    for pkg, records in sorted((records_by_package or {}).items()):
        records = list(records)
        blob = _compact_json(records)
        rel = f"{DATA_PREFIX}{pkg}.json"
        if prev_files.get(rel) != _sha256(blob):
            entries.append((rel, blob))
            index_delta["packages"][pkg] = {"hits": len(records)}
            stats_upsert += 1
    deletions = sorted(set(prev_index.get("packages") or {}) - set(records_by_package or {}))
    latest_delta = {k: v for k, v in (latest or {}).items() if prev_latest.get(k) != v}

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "delta",
        "base": prev_manifest["snapshot"],
        "target": snapshot,
        "generator": "pythonscan",
        "stats": {"upserts": stats_upsert, "deletions": len(deletions)},
    }
    extra = {INDEX_DELTA_NAME: _compact_json(index_delta)}
    if deletions:
        extra[DELETIONS_NAME] = _compact_json(deletions)
    if latest_delta:
        extra[LATEST_DELTA_NAME] = _compact_json(latest_delta)
    _write_delta_zip(out_path, entries, manifest, extra)
    return manifest


def _write_zip(out_path, entries, index, manifest, extra_files: dict) -> dict:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    index_blob = _pretty_json(index)
    files = {INDEX_NAME: _sha256(index_blob)}
    for name, blob in list(entries) + list(extra_files.items()):
        files[name] = _sha256(blob)
    manifest = dict(manifest, files=files)
    manifest_blob = _pretty_json(manifest)
    _atomic_write_zip(out_path, [(INDEX_NAME, index_blob)] + list(entries)
                      + list(extra_files.items()) + [(MANIFEST_NAME, manifest_blob)])
    return manifest


def _write_delta_zip(out_path, entries, manifest, extra_files: dict) -> None:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    files = {}
    for name, blob in list(entries) + list(extra_files.items()):
        files[name] = _sha256(blob)
    manifest = dict(manifest, files=files)
    manifest_blob = _pretty_json(manifest)
    _atomic_write_zip(out_path, list(entries) + list(extra_files.items())
                      + [(MANIFEST_NAME, manifest_blob)])


def _atomic_write_zip(out_path: Path, items: list[tuple[str, bytes]]) -> None:
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, blob in items:
            zf.writestr(name, blob)
    os.replace(tmp, out_path)


# ---------------------------------------------------------------- 使用端（内网）

def default_db_path() -> Path:
    env = os.environ.get("PYTHONSCAN_DB")
    if env:
        return Path(env)
    return Path.home() / ".pythonscan" / "vulndb.zip"


class VulnDB:
    """已加载的本地漏洞库。查询按包名读取 zip 内对应文件。"""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        if not self.path.exists():
            raise DBError(f"漏洞库不存在: {self.path}（请先执行 pythonscan db import 导入全量库）")
        try:
            self._zf = zipfile.ZipFile(self.path)
        except zipfile.BadZipFile:
            raise DBError(f"漏洞库文件损坏（非有效 zip）: {self.path}") from None
        try:
            self.manifest = _read_manifest(self._zf)
            if self.manifest.get("schema_version") != SCHEMA_VERSION:
                raise DBError(
                    f"漏洞库 schema 版本不兼容: 库 v{self.manifest.get('schema_version')}，"
                    f"程序 v{SCHEMA_VERSION}，请升级 PythonScan"
                )
            if self.manifest.get("kind") != "full":
                raise DBError("当前库不是全量库，请重新 db import")
            expected = (self.manifest.get("files") or {}).get(INDEX_NAME)
            index_blob = self._zf.read(INDEX_NAME)
            if expected and _sha256(index_blob) != expected:
                raise DBError("index.json 校验失败，漏洞库可能已损坏")
            self.index = json.loads(index_blob.decode("utf-8"))
            self._identity = None
        except Exception as exc:
            self._zf.close()
            if isinstance(exc, (ValueError, KeyError, UnicodeError, zipfile.BadZipFile, AttributeError, TypeError)):
                raise DBError(f"漏洞库格式损坏: {exc}") from exc
            raise

    @property
    def identity(self) -> dict:
        """从本实例打开的数据派生启用身份，不能信任输入声明的指纹。"""
        if self._identity is None:
            from .db_identity import identity
            self._identity = identity(self._zf, self.manifest)
        return dict(self._identity)

    @property
    def snapshot(self) -> str:
        return str(self.manifest.get("snapshot", ""))

    @property
    def record_count(self) -> int:
        return int(self.manifest.get("record_count") or 0)

    def get(self, package: str) -> list[dict]:
        try:
            blob = self._zf.read(f"{DATA_PREFIX}{package}.json")
        except KeyError:
            return []
        return json.loads(blob.decode("utf-8"))

    def latest(self, package: str) -> str | None:
        return (self.index.get("latest") or {}).get(package)

    def close(self) -> None:
        self._zf.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def load(path: str | Path | None = None) -> VulnDB:
    return VulnDB(path or default_db_path())


def db_info(path: str | Path | None = None) -> dict:
    path = Path(path or default_db_path())
    if not path.exists():
        raise DBError(f"漏洞库不存在: {path}")
    with load(path) as database:
        return dict(database.manifest, **database.identity,
                    path=str(path.resolve()), latest_count=len(database.index.get('latest') or {}))


def import_db(src_path: str, target: str | Path | None = None) -> dict:
    """导入 OSV 原始 ZIP 或全量库，持久化并保留上一有效库。"""
    from .db_import import prepare_import, install_import

    prepared = prepare_import(src_path, target)
    try:
        return install_import(prepared)
    finally:
        prepared.close()


def update_db(delta_path: str, target: str | Path | None = None) -> dict:
    """应用增量包：校验衔接与完整性 -> 与当前库合并 -> 原子替换。返回新 manifest。"""
    target = Path(target or default_db_path())
    if not target.exists():
        raise DBError(f"当前漏洞库不存在: {target}（请先 db import 全量库）")
    try:
        dz = zipfile.ZipFile(delta_path)
    except zipfile.BadZipFile:
        raise DBError(f"增量包损坏（非有效 zip）: {delta_path}") from None
    with dz:
        delta_manifest = _read_manifest(dz)
        if delta_manifest.get("kind") != "delta":
            raise DBError("该文件不是增量包（kind != delta），全量库请用 db import")
        _verify_files(dz, delta_manifest, "增量包")
        with zipfile.ZipFile(target) as old_zf:
            old_manifest = _read_manifest(old_zf)
            if delta_manifest.get("base") != old_manifest.get("snapshot"):
                raise DBError(
                    f"增量包基于快照 {delta_manifest.get('base')}，"
                    f"当前库快照为 {old_manifest.get('snapshot')}，版本不衔接；"
                    f"请按顺序应用中间增量，或直接导入新全量库"
                )
            old_index = json.loads(old_zf.read(INDEX_NAME).decode("utf-8"))
            index_delta = json.loads(dz.read(INDEX_DELTA_NAME).decode("utf-8"))
            namelist = set(dz.namelist())
            deletions = set(json.loads(dz.read(DELETIONS_NAME).decode("utf-8"))) \
                if DELETIONS_NAME in namelist else set()
            latest_delta = json.loads(dz.read(LATEST_DELTA_NAME).decode("utf-8")) \
                if LATEST_DELTA_NAME in namelist else {}
            upserts = {n for n in delta_manifest["files"] if n.startswith(DATA_PREFIX)}

            # 新索引：应用增量与删除
            packages = {k: v for k, v in (old_index.get("packages") or {}).items()
                        if k not in deletions}
            for pkg, info in (index_delta.get("packages") or {}).items():
                if info is None:
                    packages.pop(pkg, None)
                else:
                    packages[pkg] = info
            latest = dict(old_index.get("latest") or {})
            for k, v in latest_delta.items():
                if v is None:
                    latest.pop(k, None)
                else:
                    latest[k] = v

            items: list[tuple[str, bytes]] = []
            files: dict = {}
            # 保留未变更的数据文件（重算哈希写入新 manifest）
            for name in old_zf.namelist():
                if name in (MANIFEST_NAME, INDEX_NAME) or name in upserts:
                    continue
                pkg = name[len(DATA_PREFIX):]
                if name.startswith(DATA_PREFIX) and pkg[:-5] in deletions:
                    continue
                blob = old_zf.read(name)
                items.append((name, blob))
                files[name] = _sha256(blob)
            # 写入增量数据文件
            for name in sorted(upserts):
                blob = dz.read(name)
                items.append((name, blob))
                files[name] = _sha256(blob)

    index_blob = _pretty_json({"packages": packages, "latest": latest})
    files[INDEX_NAME] = _sha256(index_blob)
    record_count = sum(int(p.get("hits", 0)) for p in packages.values())
    new_manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "full",
        "snapshot": delta_manifest["target"],
        "base": delta_manifest.get("base"),
        "generator": f"pythonscan db update (base {delta_manifest['base']})",
        "record_count": record_count,
        "package_count": len(packages),
        "files": files,
    }
    items.append((INDEX_NAME, index_blob))
    items.append((MANIFEST_NAME, _pretty_json(new_manifest)))
    # 增量候选同样经过导入服务，身份与数据一起安装并保留旧版备份。
    with tempfile.TemporaryDirectory(prefix='.pythonscan-delta-', dir=target.parent) as directory:
        candidate = Path(directory) / 'candidate.zip'
        _atomic_write_zip(candidate, items)
        return import_db(str(candidate), target)
