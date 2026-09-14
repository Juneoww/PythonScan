"""扫描编排：输入依赖 -> 本地库匹配 -> 修复建议 -> ScanResult。

本模块是对外引擎 API（GUI 复用面），不感知 CLI / 终端细节。
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import date, datetime

from . import suggest as suggest_mod
from .inputspec import Dependency
from .matching import MatchOutcome, affected_text, match_record

SEVERITY_RANK = {"CRITICAL": 3, "HIGH": 2, "MODERATE": 1, "LOW": 0}


def detect_installed_version(package: str) -> str | None:
    """用 importlib.metadata 从当前 Python 环境探测已安装版本。"""
    import importlib.metadata as md

    candidates = [package, package.replace("-", "_"), package.replace("-", "")]
    for candidate in candidates:
        try:
            return md.version(candidate)
        except (md.PackageNotFoundError, ValueError):
            continue
    return None


def _severity_of(record: dict) -> tuple[str, str | None, float | None]:
    specific = record.get("database_specific") or {}
    level = str(specific.get("severity") or "").upper()
    vector = None
    for item in record.get("severity") or []:
        if str(item.get("type") or "").upper().startswith("CVSS") and item.get("score"):
            vector = str(item["score"])
            break
    if level == "MEDIUM":
        level = "MODERATE"
    return (level or "UNKNOWN"), vector, None


@dataclass
class VulnHit:
    id: str
    severity: str
    cvss_vector: str | None
    score: float | None
    summary: str
    affected: str
    fixed_versions: list[str]
    aliases: list[str]
    references: list[str]
    sources: list[str]

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, -1)

    @property
    def url(self) -> str:
        return f"https://osv.dev/vulnerability/{self.id}"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "aliases": self.aliases,
            "severity": {"level": self.severity, "cvss_v3": self.cvss_vector, "score": self.score},
            "summary": self.summary,
            "affected": self.affected,
            "fixed_versions": self.fixed_versions,
            "references": self.references,
            "url": self.url,
            "source": self.sources,
        }


@dataclass
class PackageResult:
    dependency: Dependency
    vulnerable: bool
    hits: list[VulnHit]
    fix: suggest_mod.FixSuggestion | None
    notes: list[str] = field(default_factory=list)
    manual_review: bool = False

    def to_dict(self) -> dict:
        return {
            "package": self.dependency.name,
            "version": self.dependency.version,
            "version_source": self.dependency.version_source,
            "unpinned": self.dependency.unpinned,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [h.to_dict() for h in self.hits],
            "fix_suggestion": self.fix.to_dict() if self.fix else None,
            "notes": self.notes,
        }


@dataclass
class ScanResult:
    source: str
    packages: list[PackageResult]
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    db_meta: dict = field(default_factory=dict)
    generated_at: str = ""

    @property
    def vulnerable(self) -> bool:
        return any(p.vulnerable for p in self.packages)

    def severity_counts(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0, "UNKNOWN": 0}
        for p in self.packages:
            if p.dependency.unpinned:
                continue  # 未固定版本的"全量历史漏洞"不计入风险统计
            for h in p.hits:
                counts[h.severity] = counts.get(h.severity, 0) + 1
        return counts

    def to_dict(self) -> dict:
        unpinned = sum(1 for p in self.packages if p.dependency.unpinned)
        return {
            "schema": "pythonscan-result/v1",
            "generated_at": self.generated_at,
            "db": self.db_meta,
            "scan": {
                "source": self.source,
                "total": len(self.packages),
                "vulnerable": sum(1 for p in self.packages if p.vulnerable),
                "unpinned": unpinned,
                "warnings": len(self.warnings),
                "errors": len(self.errors),
            },
            "results": [p.to_dict() for p in self.packages],
            "warnings": self.warnings,
            "errors": self.errors,
        }


def _hit_from_record(record: dict, outcome: MatchOutcome | None) -> VulnHit:
    level, vector, score = _severity_of(record)
    text = record.get("affected_text")
    if not text:
        texts = outcome.affected_texts if outcome else []
        if not texts:
            entries = [affected_text(a) for a in record.get("affected") or []]
            texts = [t for t in entries if t]
        text = "; ".join(texts) or "*"
    fixed = record.get("fixed_versions") or (outcome.fixed_versions if outcome else [])
    return VulnHit(
        id=str(record.get("id", "")),
        severity=level,
        cvss_vector=vector,
        score=score,
        summary=str(record.get("summary") or "").strip(),
        affected=text,
        fixed_versions=sorted(set(fixed)),
        aliases=list(record.get("aliases") or []),
        references=list(record.get("references") or []),
        sources=list(record.get("sources") or [record.get("id", "")]),
    )


def scan(deps: list[Dependency], database, *, source: str = "input",
         use_installed: bool = False, fail_fast: bool = False,
         stale_days: int = 90) -> ScanResult:
    result = ScanResult(source=source, packages=[], generated_at=datetime.now().astimezone().isoformat(timespec="seconds"))
    result.db_meta = {
        "snapshot": database.snapshot,
        "schema_version": database.manifest.get("schema_version"),
        "record_count": database.record_count,
    }
    _check_stale(result, database, stale_days)

    for index, dep in enumerate(deps):
        dep = _resolve_version(dep, use_installed, result.warnings)
        records = database.get(dep.name)
        hits: list[VulnHit] = []
        manual = False
        if dep.unpinned:
            hits = [_hit_from_record(rec, None) for rec in records]
        else:
            for rec in records:
                outcome = match_record(rec, dep.name, dep.version)
                manual = manual or outcome.manual_review
                if outcome.matched:
                    hits.append(_hit_from_record(rec, outcome))
        hits.sort(key=lambda h: (-h.rank, h.id))

        if dep.unpinned:
            fix = suggest_mod.suggest_unpinned(hits, database, dep.name, records)
        else:
            fix = suggest_mod.suggest_pinned(hits, dep.version) if hits else None

        notes: list[str] = []
        if dep.note:
            notes.append(dep.note)
        if dep.version_source == "environment":
            notes.append("__env__")
        if manual and not hits:
            notes.append("__manual__")
        package = PackageResult(dependency=dep, vulnerable=bool(hits), hits=hits, fix=fix,
                                notes=notes, manual_review=manual)
        result.packages.append(package)
        if fail_fast and package.vulnerable:
            remaining = len(deps) - index - 1
            if remaining:
                result.errors.append(f"--fail-fast: 已发现漏洞，剩余 {remaining} 项依赖未扫描")
            break
    return result


def _resolve_version(dep: Dependency, use_installed: bool, warnings: list[str]) -> Dependency:
    if not dep.unpinned or not use_installed:
        return dep
    found = detect_installed_version(dep.name)
    if found:
        return replace(dep, version=found, version_source="environment",
                       note=f"未提供版本，已从当前环境探测到 {found}")
    warnings.append(f"{dep.display_name}: 当前环境中未安装，按未固定版本处理")
    return dep


def _check_stale(result: ScanResult, database, stale_days: int) -> None:
    try:
        days = (date.today() - date.fromisoformat(database.snapshot)).days
    except (ValueError, TypeError):
        return
    if days > stale_days:
        result.warnings.append(f"__stale__:{days}")
