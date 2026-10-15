"""OSV affected 区间与本地版本的匹配。

事件模型：introduced 开启区间段，fixed（开区间上界）/ last_affected（闭区间上界）闭合。
无法解析的版本一律标记 manual_review，交由上层提示人工核对，不做静默判定。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .inputspec import normalize_name
from .versioning import InvalidVersion, Version


@dataclass
class MatchOutcome:
    matched: bool = False
    fixed_versions: list[str] = field(default_factory=list)
    affected_texts: list[str] = field(default_factory=list)
    manual_review: bool = False
    skipped_ranges: int = 0


def match_record(record: dict, package: str, version_text: str) -> MatchOutcome:
    """判断 record 是否影响 package 的 version_text。"""
    package = normalize_name(package)
    try:
        ver = Version(version_text)
    except InvalidVersion:
        return MatchOutcome(manual_review=True)
    outcome = MatchOutcome()
    for affected in record.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") != "PyPI":
            continue
        if normalize_name(pkg.get("name", "")) != package:
            continue
        versions = affected.get("versions")
        if versions:
            if _in_explicit_versions(versions, ver, version_text):
                outcome.matched = True
        for rng in affected.get("ranges") or []:
            _match_range(rng, ver, outcome)
    return outcome


def _in_explicit_versions(versions, ver: Version, version_text: str) -> bool:
    for item in versions:
        text = str(item)
        if text == version_text:
            return True
        try:
            if Version(text) == ver:
                return True
        except InvalidVersion:
            continue
    return False


def _match_range(rng: dict, ver: Version, outcome: MatchOutcome) -> None:
    if str(rng.get("type") or "").upper() == "GIT":
        outcome.skipped_ranges += 1
        return
    try:
        segments, fixed = _segments(rng.get("events") or [])
    except InvalidVersion:
        outcome.manual_review = True
        return
    outcome.fixed_versions.extend(fixed)
    for lo, hi, hi_inclusive, text in segments:
        outcome.affected_texts.append(text)
        if lo is not None and ver < lo:
            continue
        if hi is None:
            outcome.matched = True
        elif hi_inclusive:
            outcome.matched = outcome.matched or ver <= hi
        else:
            outcome.matched = outcome.matched or ver < hi


def _segments(events: list[dict]):
    """事件序列 -> [(下界|None, 上界|None, 上界是否含, 展示文本)], [fixed 版本列表]"""
    segments = []
    fixed = []
    start = None        # (Version, 原文) 或 None（隐含 0）
    for ev in events:
        if "introduced" in ev:
            if start is not None:
                segments.append(_make_segment(start, None, False))
            start = (_parse(ev["introduced"]), str(ev["introduced"]))
        elif "fixed" in ev:
            hi = _parse(ev["fixed"])
            fixed.append(str(ev["fixed"]))
            segments.append(_make_segment(start, hi, False, hi_text=str(ev["fixed"])))
            start = None
        elif "last_affected" in ev:
            hi = _parse(ev["last_affected"])
            segments.append(_make_segment(start, hi, True, hi_text=str(ev["last_affected"])))
            start = None
        # "limit" 事件对精确匹配无意义，忽略
    if start is not None:
        segments.append(_make_segment(start, None, False))
    return segments, fixed


def _parse(text: str) -> Version:
    return Version(text)


def _make_segment(start, hi: Version | None, hi_inclusive: bool, hi_text: str = ""):
    lo, lo_text = start if start else (None, None)
    parts = []
    if lo is not None and not lo.is_zero():
        parts.append(f">={lo_text}")
    if hi is not None:
        parts.append(f"<={hi_text}" if hi_inclusive else f"<{hi_text}")
    text = ", ".join(parts) if parts else "*"
    return (lo, hi, hi_inclusive, text)


def affected_text(affected_entry: dict) -> str:
    """单个 affected 条目的区间展示文本（同步端预烘焙与未固定版本展示共用）。"""
    texts = []
    for rng in affected_entry.get("ranges") or []:
        if str(rng.get("type") or "").upper() == "GIT":
            continue
        try:
            segments, _ = _segments(rng.get("events") or [])
        except InvalidVersion:
            texts.append("(区间无法解析，需人工核对)")
            continue
        texts.extend(t for _, _, _, t in segments)
    return "; ".join(dict.fromkeys(texts)) if texts else "*"
