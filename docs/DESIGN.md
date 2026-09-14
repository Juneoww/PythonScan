# PythonScan 技术设计文档

| 文档版本 | 日期 | 依据 |
| --- | --- | --- |
| v0.1 | 2026-09-13 | docs/PRD.md v0.3 |

目标：把 PRD 落成可实现的最小设计。原则：**扫描器零第三方依赖**（Python ≥ 3.9 标准库）、引擎与界面分离、漏洞库与程序解耦。

---

## 1. 技术选型

| 关注点 | 选型 | 理由 |
| --- | --- | --- |
| 漏洞数据源 | OSV.dev PyPI 全量导出（zip/NDJSON，免 Key） | 单文件拉全量，天然聚合 GHSA/PYSEC/CVE 别名 |
| 包名规范化 | PEP 503：`re.sub(r"[-_.]+", "-", name).lower()` | 与 pip 行为一致 |
| 版本比较 | 自实现 PEP 440 子集（见 §5.1） | 免 `packaging` 依赖；解析失败降级"人工确认" |
| 库存储 | zip 内**每包一个 JSON 文件**（见 §4） | 查询按包读取、增量按包替换，实现最简 |
| 报告 | HTML 内置模板 → 浏览器无头打印出 PDF | 零第三方依赖出 PDF（`subprocess` 调 Edge/Chrome） |
| CLI | `argparse`；`importlib.metadata` 探测已装版本 | 均为标准库 |

---

## 2. 代码结构

```
PythonScan/
├── pythonscan/                # 内网扫描器（纯标准库，整个包可直接摆渡）
│   ├── __init__.py            #   __version__
│   ├── cli.py                 #   参数解析、交互式录入、终端渲染、退出码
│   ├── inputspec.py           #   依赖行解析（name==version 等 4 种写法）、requirements.txt 读取、告警收集
│   ├── engine.py              #   scan(deps, db, options) -> ScanResult（唯一编排入口，GUI 也调它）
│   ├── db.py                  #   漏洞库：加载/索引/manifest 校验/db import/db update
│   ├── versioning.py          #   PEP 440 子集解析与比较
│   ├── matching.py            #   受影响区间匹配
│   ├── suggest.py             #   修复建议计算
│   ├── report.py              #   JSON / HTML 渲染、PDF 无头打印
│   └── i18n.py                #   zh/en 文案字典
├── sync/
│   └── sync.py                # 外网同步器：抓取 OSV 导出 → 去重合并 → 生成全量库/增量包
└── tests/
    ├── test_versioning.py     #   版本比较边界用例
    ├── test_matching.py       #   区间匹配边界用例
    ├── test_inputspec.py      #   输入解析容错
    └── test_db_update.py      #   增量合并与校验
```

依赖方向：`cli → engine → {db, matching, suggest, inputspec, report, i18n}`；`matching/versioning` 不依赖其他业务模块。

---

## 3. 核心数据结构（引擎层）

```python
# inputspec.py
@dataclass
class Dependency:
    raw: str            # 原始行
    name: str           # 规范化包名；解析失败为 None（进 warnings）
    version: str|None   # 未给版本为 None
    version_source: str # "input" | "environment"（--use-installed 探测）

# engine.py
@dataclass
class VulnHit:      # 一条漏洞（已去重合并）
    id, aliases, severity, score, cvss_vector, summary, affected_text, fixed_versions, references, source

@dataclass
class PackageResult:
    dependency: Dependency
    vulnerable: bool
    hits: list[VulnHit]        # 未固定版本 = 该包全部历史漏洞
    fix: FixSuggestion|None    # {upgrade_to, covers, latest, confidence}
    notes: list[str]           # 未固定版本提示、探测失败原因等

@dataclass
class ScanResult:
    packages: list[PackageResult]
    warnings: list[str]; errors: list[str]
    db_meta: dict              # snapshot/schema_version/record_count（报告强制展示）
    def to_dict(self) -> dict  # PRD §7 JSON schema
```

---

## 4. 漏洞库文件格式

### 4.1 全量库（首次部署，摆渡一份即可）

```
pypi-advisories-YYYYMMDD.zip
├── manifest.json              # {schema_version:1, snapshot, source, generator, counts,
│                              #  files: {"<文件名>": "<sha256>"}}
├── index.json                 # {packages: {包名: {hits: n}}, latest: {包名: "x.y.z"}}
└── data/<规范包名>.json        # 每包一个文件，内容为该包全部记录数组（已去重合并）
```

- **为什么按包分文件**：扫描只读被查询的包（zip 支持按名随机读取，内存占用小）；增量更新按"包"整文件替换，无需记录级 diff；
- `index.json.latest` 由同步器从 PyPI JSON API 可选抓取（限速 + 缓存，失败留空），供修复建议用。

### 4.2 增量包（日常更新，最小化）

```
delta-20260913-to-20261001.zip
├── manifest.json              # {schema_version:1, base:"20260913", target:"20261001", stats}
├── upsert/<规范包名>.json      # 变更包的最终状态记录（整包替换）
└── deletions.json             # 记录被清空的包名列表
```

### 4.3 导入/更新流程（`db.py`）

```
db import 全量.zip   校验 manifest + files sha256 → 原子落盘（临时目录→改名）
db update 增量.zip   校验 sha256 → 校验 base == 当前 snapshot（不衔接则拒绝并提示补序）→
                     复制旧库条目 + 覆盖 upsert + 应用 deletions → 生成新库 → 原子替换
```

快照距今 > 90 天（可配置）时，扫描结果追加库过期警告（PRD Q6）。

---

## 5. 关键算法

### 5.1 版本比较（`versioning.py`，PEP 440 子集）

解析为可排序键 `(epoch, release, suffix_rank, …)`，比较规则：

| 规则 | 示例 |
| --- | --- |
| release 逐段数值比较，短段右侧补 0 | `2.3 == 2.3.0` |
| epoch 优先 | `1!1.0 > 2.0` |
| 后缀排序：`dev < pre/rc/alpha/beta < 正式 < post` | `1.0rc1 < 1.0 < 1.0.post1` |
| 解析失败抛 `InvalidVersion` | 上层标"需人工确认"，绝不给出错误结论 |

### 5.2 区间匹配（`matching.py`）

对记录的每条 `affected.ranges`（事件模型）判定 `v` 是否命中：

```
命中 ⇔ ∃ 区间段: v >= introduced
              且 (无 fixed      或 v <  fixed)
              且 (无 last_affected 或 v <= last_affected)
introduced 缺省视为 0；range type 仅处理 ECOSYSTEM/SEMVER（按 PEP440 解释），GIT 跳过并计数
```

### 5.3 去重合并（在**同步器**完成，扫描端不做）

同一漏洞多来源（GHSA/PYSEC/OSV）按别名聚合：主 ID 取 `CVE-* > GHSA-* > PYSEC-*`，severity/评分取各来源最高，references 取并集，`source` 保留来源列表。

### 5.4 修复建议（`suggest.py`）

- 有版本：`upgrade_to = max(该版本命中的各漏洞 fixed)`（无法比较则 `confidence=manual`）；
- 未固定版本：`upgrade_to = 库内 latest`，并注明 latest 是否仍有已知漏洞；
- 与 `index.latest` 比对，额外提示"可直接升到最新"。

---

## 6. 核心流程

### 6.1 扫描

```
输入(三种) → inputspec 解析规范化 ─┬─ 有版本 ──→ db.get(name) → matching → hits
                                  └─ 无版本 ──→ --use-installed? importlib.metadata 探测
                                                ├─ 成功: 同上, version_source=environment
                                                └─ 失败: hits = db.get(name) 全量, 标注未固定
→ suggest → ScanResult → 终端摘要 + JSON + HTML(→PDF 可选)
```

单库单进程即可满足性能目标（50 项依赖 ≤ 10s）：zip 按包读取，无并发需求。

### 6.2 同步器（外网机，`sync/sync.py`，同为标准库实现）

```
下载 OSV pypi/all.zip → 过滤 ecosystem=PyPI → 按 §5.3 去重合并 → 按 §5.2 解析 fixed_versions
→ 与本地上一快照 diff → 产出 全量库（无旧快照时）/ 增量包（有旧快照时）+ manifest(含 sha256)
支持 --proxy（外网机可能需代理访问 Google 存储）
```

### 6.3 PDF 导出（`report.py`）

```
生成 report.html → 探测浏览器（env PYTHONSCAN_BROWSER → Edge 路径 → Chrome 路径 → PATH）
→ subprocess: <浏览器> --headless --print-to-pdf="out.pdf" --no-pdf-header-footer "file:///…/report.html"
→ 探测失败: 保留 HTML，提示 Ctrl+P 手动另存 PDF（不报错中断）
```

---

## 7. 引擎 API（GUI 复用面）

```python
from pythonscan import engine, db

vdb = db.load("~/.pythonscan/db.zip")           # 校验 manifest，返回 VulnDB
result = engine.scan(
    deps=[Dependency("requests", "2.28.0", "input"), ...],
    database=vdb,
    use_installed=False, lang="zh",
)
result.to_dict()      # PRD §7 JSON
```

CLI 只是该 API 之上的一层壳；v2 GUI 直接复用，不再触达内部模块。

---

## 8. 错误处理与退出码

| 场景 | 行为 | 退出码 |
| --- | --- | --- |
| 扫描完成、无漏洞 | 正常输出 | 0 |
| 扫描完成、有漏洞 | 输出漏洞详情 | 1 |
| 库缺失/损坏（manifest 或 sha256 校验失败） | 报错 + 指引重新 `db import` | 2 |
| 增量包 base 与当前快照不衔接 | 拒绝应用，提示按序补齐 | 2 |
| 输入文件不存在/全部行非法 | 报错；部分非法则跳过并计入 warnings | 2 / 1 或 0 |
| PDF 浏览器未找到 | 降级为手动打印提示，不影响其他输出 | 不改变 |

---

## 9. 测试要点

1. `versioning`：`1.0rc1 < 1.0 < 1.0.post1`、`2.3 == 2.3.0`、`1!0.9 > 2.0`、非法串拒绝；
2. `matching`：`introduced`/`fixed`/`last_affected` 三类边界（恰等于边界值时的命中与否）；
3. `inputspec`：四种写法等价、extras/环境标记/行内注释剥离、非法行不中断；
4. `db.update`：base 衔接校验、upsert/deletions 合并结果、校验和失败拒绝、原子替换；
5. 端到端用例：`requests==2.28.0`（应命中 CVE-2023-32681，fixed 2.31.0）、`requests==2.32.x`（按库内容正确判定）、`flask==0.12.2`（包级建议 = 各 fixed 最大值）、裸 `requests`（全量列出 + 指引）。

---

## 10. 里程碑与模块对应

| 里程碑 | 涉及模块 |
| --- | --- |
| M1（v0.1.0 MVP） | `inputspec / db(仅 import/加载) / versioning / matching / engine / cli(交互+文件输入) / JSON 输出 / i18n(zh)` |
| M2（v0.2.0） | `sync(全量+增量) / db(update) / suggest / report(HTML+PDF) / i18n(en) / 库过期提醒` |
| M3（v1.0.0） | 全模块稳定化、tests 补齐、README/使用手册 |
