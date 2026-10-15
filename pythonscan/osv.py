"""功能：离线读取、校验并合并 OSV PyPI 公告，供导入器和同步器共用。
实现：按包规范化和别名聚合，完整保留版本枚举与影响范围，无网络访问。
输入：OSV 格式 ZIP；输出：按包组织的公告和记录最近修改日，错误抛 OSVError。
依赖：Python 标准库；由应用模块调用，不作为独立命令入口。
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import json
import re
import zipfile

from .matching import affected_text
from .versioning import normalize_name

SEV_RANK = {"CRITICAL": 3, "HIGH": 2, "MODERATE": 1, "MEDIUM": 1, "LOW": 0}
ID_PRIORITY = ("CVE-", "GHSA-", "PYSEC-")
MAX_REFERENCES = 20

class OSVError(ValueError):
    """公告格式无效或不包含可用 PyPI 记录。"""


def modified_time(text):
    """读取带时区的 RFC3339 时间，统一转成 UTC。"""
    if not isinstance(text, str):
        raise OSVError("modified 必须为时间字符串")
    try:
        value = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if value.tzinfo is None:
            raise ValueError("missing timezone")
        return value.astimezone(timezone.utc)
    except ValueError as exc:
        raise OSVError(f"modified 时间无法解析: {text}") from exc


def validate_record(record, *, raw=False):
    """检查引擎实际读取的核心字段类型，允许省略可选公告字段。"""
    if not isinstance(record, dict) or not isinstance(record.get("id"), str) or not record["id"].strip():
        raise OSVError("公告必须为对象并包含非空 id")
    if raw:
        modified_time(record.get("modified"))
        if record.get("withdrawn"):
            modified_time(record["withdrawn"])
            # 已撤回公告不参与建库，历史 affected 字段不应阻止有效数据导入。
            return
    for key in ("aliases", "sources", "fixed_versions"):
        value = record.get(key, [])
        if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
            raise OSVError(f"{key} 必须为字符串数组")
    for key in ("summary", "details", "affected_text"):
        if key in record and not isinstance(record[key], str):
            raise OSVError(f"{key} 必须为字符串")
    for key in ("database_specific",):
        if key in record and not isinstance(record[key], dict):
            raise OSVError(f"{key} 必须为对象")
    for key in ("severity", "references"):
        if key in record and not isinstance(record[key], list):
            raise OSVError(f"{key} 必须为数组")
    if any(not isinstance(s, dict) for s in record.get("severity", [])):
        raise OSVError("severity 的条目必须为对象")
    refs = record.get("references", [])
    if any(not isinstance(v, dict if raw else str) for v in refs):
        raise OSVError("references 条目类型不正确")
    affected = record.get("affected", [])
    if not isinstance(affected, list):
        raise OSVError("affected 必须为数组")
    for entry in affected:
        if not isinstance(entry, dict) or not isinstance(entry.get("package", {}), dict):
            raise OSVError("affected 条目和 package 必须为对象")
        pkg = entry.get("package", {})
        if "package" in entry and any(not isinstance(pkg.get(key), str) for key in ("ecosystem", "name")):
            raise OSVError("package 必须包含字符串 ecosystem 和 name")
        if pkg.get("ecosystem") == "PyPI":
            name = pkg.get("name")
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", name):
                raise OSVError("PyPI 包名无效")
        versions = entry.get("versions", [])
        if not isinstance(versions, list) or any(not isinstance(v, str) for v in versions):
            raise OSVError("versions 必须为字符串数组")
        ranges = entry.get("ranges", [])
        if not isinstance(ranges, list):
            raise OSVError("ranges 必须为数组")
        for rng in ranges:
            if not isinstance(rng, dict) or not isinstance(rng.get("type"), str) or not isinstance(rng.get("events"), list):
                raise OSVError("range 必须包含 type 和 events 数组")
            for ev in rng["events"]:
                if not isinstance(ev, dict) or len(ev) != 1 or not any(k in ev for k in ("introduced", "fixed", "last_affected", "limit")) or any(not isinstance(v, str) for v in ev.values()):
                    raise OSVError("影响事件必须包含一个字符串版本字段")


def _fixed_versions(entry: dict) -> list[str]:
    fixed = []
    for rng in entry.get("ranges") or []:
        if str(rng.get("type") or "").upper() == "GIT":
            continue  # GIT 区间的 fixed 是 commit SHA，不是可比较的版本号
        for ev in rng.get("events") or []:
            if "fixed" in ev and ev["fixed"] not in fixed:
                fixed.append(str(ev["fixed"]))
    return fixed


def _slim(record: dict, entry: dict) -> dict:
    """按包裁剪 OSV 记录：只保留该 affected 条目与展示所需字段。"""
    level = str((record.get("database_specific") or {}).get("severity") or "").upper()
    if level == "MEDIUM":
        level = "MODERATE"
    vectors = [str(s["score"]) for s in record.get("severity") or []
               if str(s.get("type") or "").upper().startswith("CVSS") and s.get("score")]
    summary = record.get("summary") or (record.get("details") or "").strip().split("\n")[0]
    return {
        "id": record.get("id", ""),
        "aliases": list(record.get("aliases") or []),
        "summary": summary.strip(),
        "details": record.get("details") or "",
        "database_specific": {"severity": level},
        "severity": [{"type": "CVSS_V3", "score": v} for v in vectors],
        "published": record.get("published"),
        "modified": record.get("modified"),
        "affected": [entry],
        "fixed_versions": _fixed_versions(entry),
        "affected_text": affected_text(entry),
        "references": [r.get("url") for r in record.get("references") or [] if r.get("url")][:MAX_REFERENCES],
        "sources": [record.get("id", "")],
    }


def _id_priority(rid: str) -> int:
    for index, prefix in enumerate(ID_PRIORITY):
        if rid.startswith(prefix):
            return index
    return len(ID_PRIORITY)


def _merge_group(group: list[dict]) -> dict:
    """同一漏洞的多来源记录（GHSA/PYSEC/OSV）合并为一条：主 ID + 别名。"""
    primary = min((r["id"] for r in group), key=lambda rid: (_id_priority(rid), rid))
    base = next(r for r in group if r["id"] == primary)
    level = max((r["database_specific"]["severity"] for r in group),
                key=lambda s: SEV_RANK.get(s, -1), default="UNKNOWN")
    vector = next((v["score"] for r in group for v in r["severity"] if v.get("score")), None)

    aliases: set = set()
    affected_entries: list = []
    seen_texts: set = set()
    seen_entries: set = set()
    fixed: list = []
    refs: list = []
    sources: set = set()
    for rec in group:
        sources.add(rec["id"])
        aliases.update([rec["id"], *rec["aliases"]])
        fixed.extend(rec["fixed_versions"])
        for url in rec["references"]:
            if url not in refs:
                refs.append(url)
        for entry in rec["affected"]:
            key = json.dumps(entry, sort_keys=True, ensure_ascii=False)
            if key not in seen_entries:
                seen_entries.add(key)
                affected_entries.append(entry)
        text = rec["affected_text"]
        if text and text != "*":
            seen_texts.add(text)
    segments: list = []
    for text in sorted(seen_texts):
        segments.extend(seg for seg in text.split("; ") if seg)
    return {
        "id": primary,
        "aliases": sorted(aliases - {primary}),
        "summary": base["summary"],
        "details": base["details"],
        "database_specific": {"severity": level or "UNKNOWN"},
        "severity": [{"type": "CVSS_V3", "score": vector}] if vector else [],
        "published": min((r["published"] for r in group if r.get("published")), default=None),
        "modified": max((r["modified"] for r in group if r.get("modified")), default=None),
        "affected": affected_entries,
        "fixed_versions": sorted(set(fixed)),
        "affected_text": "; ".join(dict.fromkeys(segments)) or "*",
        "references": refs[:MAX_REFERENCES],
        "sources": sorted(sources),
    }


def merge_package(records: list[dict]) -> list[dict]:
    """按别名共享关系（并查集）把同包的多来源记录聚合去重。"""
    parent = list(range(len(records)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    key_owner: dict = {}
    for i, rec in enumerate(records):
        for key in {rec["id"], *rec["aliases"]}:
            if key in key_owner:
                root, other = find(i), find(key_owner[key])
                if root != other:
                    parent[root] = other
            else:
                key_owner[key] = i
    groups: dict = defaultdict(list)
    for i, rec in enumerate(records):
        groups[find(i)].append(rec)
    return [_merge_group(g) for g in groups.values()]


def load_osv_zip(src_zip):
    """严格读取原始导出；格式错误定位到文件，绝不静默丢失公告。"""
    by_package = defaultdict(list)
    newest = None
    try:
        with zipfile.ZipFile(src_zip) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise OSVError("ZIP 含有重复文件名")
            for name in names:
                if not name.endswith(".json"):
                    continue
                try:
                    record = json.loads(archive.read(name).decode("utf-8"))
                    validate_record(record, raw=True)
                    if record.get("withdrawn"):
                        continue
                    found = False
                    for entry in record.get("affected", []):
                        pkg = entry.get("package", {})
                        if pkg.get("ecosystem") != "PyPI":
                            continue
                        package = normalize_name(pkg["name"])
                        by_package[package].append(_slim(record, entry))
                        found = True
                    if found:
                        stamp = modified_time(record["modified"])
                        newest = max(newest, stamp) if newest else stamp
                except (ValueError, UnicodeDecodeError, KeyError, TypeError) as exc:
                    raise OSVError(f"{name}: {exc}") from exc
    except zipfile.BadZipFile as exc:
        raise OSVError("不是有效 ZIP 文件") from exc
    if not by_package:
        raise OSVError("ZIP 不包含有效的 PyPI 公告")
    return {pkg: merge_package(records) for pkg, records in by_package.items()}, newest.date().isoformat()
