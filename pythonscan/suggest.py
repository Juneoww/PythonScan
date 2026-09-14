"""修复建议计算（PRD FR-3）。

有版本：目标 = 覆盖该版本全部命中漏洞的最低升级版本（各 fixed 中的最大可解析值）；
未固定版本：目标 = 库内最新版本，并核对最新版本是否仍存在已知漏洞。
无法可靠计算时 confidence=manual，绝不硬给结论。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .matching import match_record
from .versioning import InvalidVersion, Version


@dataclass
class FixSuggestion:
    upgrade_to: str | None = None
    covers: list[str] = field(default_factory=list)   # 该目标版本可修复的漏洞 ID
    latest: str | None = None
    latest_clean: bool | None = None
    confidence: str = "manual"                        # high | manual | info
    note: str | None = None

    def to_dict(self) -> dict:
        return {
            "upgrade_to": self.upgrade_to,
            "covers": self.covers,
            "latest": self.latest,
            "latest_clean": self.latest_clean,
            "confidence": self.confidence,
            "note": self.note,
        }


def suggest_pinned(hits, version: str) -> FixSuggestion:
    try:
        cur = Version(version)
    except InvalidVersion:
        return FixSuggestion(note="当前版本号无法解析，请人工确认")

    candidates: list[tuple[str, Version]] = []
    covers: list[str] = []
    unparseable = 0
    for hit in hits:
        best = None
        for fixed in hit.fixed_versions:
            try:
                fixed_v = Version(fixed)
            except InvalidVersion:
                unparseable += 1
                continue
            if fixed_v > cur and (best is None or fixed_v > best[1]):
                best = (fixed, fixed_v)
        if best is not None:
            candidates.append(best)
            covers.append(hit.id)
    if not candidates:
        return FixSuggestion(note="库中该漏洞未提供可用的修复版本，请人工核对 advisory")
    upgrade_to = max(candidates, key=lambda c: c[1])[0]
    confidence = "manual" if unparseable else "high"
    return FixSuggestion(upgrade_to=upgrade_to, covers=covers, confidence=confidence)


def suggest_unpinned(hits, database, package: str, records: list[dict]) -> FixSuggestion:
    latest = database.latest(package)
    if not latest:
        return FixSuggestion(
            confidence="info",
            note="库中无该包最新版本信息；请固定版本后重新扫描，以获得精确结论",
        )
    try:
        latest_clean = not any(match_record(r, package, latest).matched for r in records)
    except Exception:
        latest_clean = None
    if latest_clean:
        return FixSuggestion(upgrade_to=latest, latest=latest, latest_clean=True,
                             confidence="info",
                             note=f"未固定版本；库内最新版本 {latest} 无已知漏洞，建议固定到该版本")
    return FixSuggestion(latest=latest, latest_clean=False, confidence="manual",
                         note=f"库内最新版本 {latest} 仍存在已知漏洞，请关注漏洞库更新")
