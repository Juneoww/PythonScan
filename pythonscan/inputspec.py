"""依赖输入行解析：支持 name==ver / name@ver / name ver / 裸 name 四种写法。

容错规则（PRD FR-1）：忽略空行、整行与行内注释、pip 选项行、环境标记；
extras 与通配符版本剥离处理；非法行抛 InvalidDependency 由调用方收集为告警。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .versioning import normalize_name


class InvalidDependency(ValueError):
    """无法解析出包名的依赖行。"""


@dataclass
class Dependency:
    raw: str
    name: str                       # PEP 503 规范化包名
    display_name: str               # 用户原始写法
    version: str | None
    version_source: str = "input"   # input | environment
    note: str | None = None

    @property
    def unpinned(self) -> bool:
        return self.version is None


@dataclass
class InputWarning:
    line_no: int
    raw: str
    reason: str


_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_V_PREFIX_RE = re.compile(r"^[vV](?=\d)")


def _clean_version(text: str, orig: str) -> tuple[str | None, str | None]:
    v = text.strip().strip("'\"").strip()
    if not v:
        raise InvalidDependency(orig)
    v = _V_PREFIX_RE.sub("", v)
    if v.endswith(".*"):
        return None, "通配符版本视为未固定版本"
    return v, None


def parse_line(line: str) -> Dependency | None:
    """解析单行依赖；空行/注释行返回 None；非法内容抛 InvalidDependency。"""
    text = line.split("#", 1)[0].strip()
    text = text.split(";", 1)[0].strip()
    if not text:
        return None
    m = _NAME_RE.match(text)
    if m is None:
        raise InvalidDependency(text)
    display = m.group(0)
    rest = text[m.end():].strip()
    if rest.startswith("["):                       # extras: requests[security]==1.0
        end = rest.find("]")
        if end < 0:
            raise InvalidDependency(text)
        rest = rest[end + 1:].strip()

    version = None
    note = None
    if rest:
        if rest.startswith("==="):
            version, note = _clean_version(rest[3:], text)
        elif rest.startswith("=="):
            version, note = _clean_version(rest[2:], text)
        elif rest.startswith("@"):
            version, note = _clean_version(rest[1:], text)
        elif rest[0] in "<>!~":
            note = "使用版本范围运算符，按未固定版本处理"
        else:
            version, note = _clean_version(rest.split()[0], text)

    dep = Dependency(raw=text, name=normalize_name(display), display_name=display,
                     version=version, note=note)
    if dep.unpinned and dep.note is None:
        dep.note = "未固定版本"
    return dep


def _finalize(dep: Dependency | None) -> Dependency | None:
    if dep is not None and dep.unpinned and dep.note is None:
        dep.note = "未固定版本"
    return dep


def load_deps_file(path: str) -> tuple[list[Dependency], list[InputWarning]]:
    """从清单文件读取依赖（每行一个），返回 (依赖列表, 告警列表)。"""
    deps: list[Dependency] = []
    warns: list[InputWarning] = []
    seen: set[tuple[str, str | None]] = set()
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        for line_no, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            try:
                dep = _finalize(parse_line(line))
            except InvalidDependency:
                warns.append(InputWarning(line_no, line, "无法解析出包名和版本"))
                continue
            if dep is None:
                continue
            key = (dep.name, dep.version)
            if key in seen:
                continue
            seen.add(key)
            deps.append(dep)
    return deps, warns


def read_interactive(prompt: str = "> ") -> tuple[list[Dependency], list[InputWarning]]:
    """交互式录入：逐行输入，空行或 EOF（Ctrl+Z/Ctrl+D）结束。"""
    deps: list[Dependency] = []
    warns: list[InputWarning] = []
    seen: set[tuple[str, str | None]] = set()
    while True:
        try:
            line = input(prompt)
        except EOFError:
            break
        if not line.strip():
            break
        try:
            dep = _finalize(parse_line(line))
        except InvalidDependency:
            warns.append(InputWarning(len(deps) + len(warns) + 1, line.strip(), "无法解析出包名和版本"))
            continue
        if dep is None:
            continue
        key = (dep.name, dep.version)
        if key in seen:
            continue
        seen.add(key)
        deps.append(dep)
    return deps, warns
