"""PEP 440 版本号解析与比较（子集实现，仅标准库）。

覆盖 epoch / release / pre(alpha,beta,rc) / post / dev；local 段解析但不参与比较。
无法解析时抛出 InvalidVersion，上层据此降级为"人工确认"，绝不猜测比较结果。
"""

from __future__ import annotations

import re
from functools import total_ordering


class InvalidVersion(ValueError):
    """无法按 PEP 440 解析的版本号。"""


_VERSION_RE = re.compile(
    r"""^\s*v?
    (?:(?P<epoch>\d+)!)?
    (?P<release>\d+(?:\.\d+)*)
    (?:[-_.]?(?P<pre_l>alpha|beta|preview|pre|a|b|c|rc)[-_.]?(?P<pre_n>\d+)?)?
    (?:
        -(?P<post_n1>\d+)
        |[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?
    )?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?
    (?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?
    \s*$""",
    re.VERBOSE | re.IGNORECASE,
)

_PRE_LETTER = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}


@total_ordering
class Version:
    __slots__ = ("text", "epoch", "release", "pre", "post", "dev", "_key")

    def __init__(self, text: str):
        m = _VERSION_RE.match(text)
        if m is None:
            raise InvalidVersion(f"无法解析版本号: {text!r}")
        self.text = text.strip()
        self.epoch = int(m.group("epoch") or "0")
        self.release = tuple(int(x) for x in m.group("release").split("."))
        if m.group("pre_l"):
            letter = _PRE_LETTER.get(m.group("pre_l").lower(), m.group("pre_l").lower())
            self.pre = (letter, int(m.group("pre_n") or "0"))
        else:
            self.pre = None
        if m.group("post_n1") is not None:
            self.post = int(m.group("post_n1"))
        elif m.group("post_l"):
            self.post = int(m.group("post_n2") or "0")
        else:
            self.post = None
        self.dev = int(m.group("dev_n") or "0") if m.group("dev_l") else None
        self._key = self._build_key()

    def _build_key(self):
        # release 末尾补零等价：2.3 == 2.3.0
        release = self.release
        while len(release) > 1 and release[-1] == 0:
            release = release[:-1]
        # 同一 release 内排序：dev-only < pre < 正式 < post
        if self.pre is None and self.post is None and self.dev is not None:
            pre_key = (0, "", 0)
        elif self.pre is not None:
            pre_key = (1,) + self.pre  # a < b < rc
        else:
            pre_key = (2, "", 0)
        post_key = (0, 0) if self.post is None else (1, self.post)
        dev_key = (1, 0) if self.dev is None else (0, self.dev)
        return (self.epoch, release, pre_key, post_key, dev_key)

    def __eq__(self, other):
        return isinstance(other, Version) and self._key == other._key

    def __lt__(self, other):
        return self._key < other._key

    def __hash__(self):
        return hash(self._key)

    def __repr__(self):
        return f"Version({self.text!r})"

    def is_zero(self) -> bool:
        """是否等价于 0（区间下界显示时省略）。"""
        return (
            self.epoch == 0
            and all(seg == 0 for seg in self.release)
            and self.pre is None
            and self.post is None
            and self.dev is None
        )


def normalize_name(name: str) -> str:
    """PEP 503 包名规范化：Django / django / Django_X 视为同一项目。"""
    return re.sub(r"[-_.]+", "-", str(name).strip()).lower()
