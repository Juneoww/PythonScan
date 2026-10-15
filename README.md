# PythonScan

内网离线检查 **pip 依赖包已知漏洞** 的工具：输入包名和版本号（或 requirements.txt），输出漏洞详情、严重级别、**修复建议**，并支持导出 JSON / HTML / PDF 报告。提供 **CLI 命令行** 与 **桌面图形界面** 两种使用方式。

- **离线可用**：扫描全程零网络请求，漏洞库在外网机生成后摆渡进内网
- **漏洞库与程序解耦**：升级漏洞库只需替换数据文件，支持增量更新（最小化更新）
- **零第三方依赖**：CLI 与 GUI 均纯 Python 标准库（Python ≥ 3.9，GUI 为 Tkinter），Windows / Linux 均可运行
- **数据来源**：[OSV.dev](https://osv.dev) PyPI 全量导出（聚合 GitHub Advisory / PYSEC / CVE）
- 双语界面（`--lang zh|en`）

[English](#english) | [PRD](docs/PRD.md) | [技术设计](docs/DESIGN.md) | **[新手操作手册](docs/操作手册.md)** | [漏洞库来源与准备说明](docs/漏洞库来源与准备说明.md)

## 架构一览

```
外网机（可联网）                         摆渡(U盘/网闸)        内网机（隔离）
┌──────────────────────────┐                              ┌──────────────────────────────┐
│ python -m sync.sync build │ ─── vulndb.zip / delta.zip ─→│ pythonscan db import/update  │
│ 生成全量库 / 增量包        │                              │ pythonscan scan -i deps.txt  │
└──────────────────────────┘                              └──────────────────────────────┘
```

## 快速开始（内网端）

**方式零：免安装 exe**（`release/` 目录已提供 Windows 可执行文件与预置漏洞库，无需 Python 环境）：

```bat
release\pythonscan-gui.exe                       :: 桌面图形界面（双击即可）
release\pythonscan.exe scan                      :: 命令行交互式扫描
release\pythonscan.exe db import release\pypi-advisories-20260920.zip   :: 首次先导入预置漏洞库
```

**方式一：桌面图形界面**（多行输入框 + 文件选择 + 一键导出报告）：

```bash
python -m pythonscan gui --db data/pypi-advisories.zip
# 或安装后直接运行: pythonscan-gui
# 不想显示控制台窗口可用: pythonw -m pythonscan gui
```

**方式二：命令行**。无需安装（仓库根目录执行）：

```bash
python -m pythonscan scan
```

或安装为命令：

```bash
pip install -e .
pythonscan scan
```

首次使用先导入漏洞库（在外网机生成，见下文）：

```bash
pythonscan db import pypi-advisories-20260913.zip
```

## 用法

```
pythonscan scan [-i 清单 | -r requirements.txt] [-o report.html] [--json out.json]
                [--pdf report.pdf] [--use-installed] [--fail-fast] [--lang zh|en]
pythonscan db import <全量库.zip> | db update <增量包.zip> | db info
```

### 三种输入方式

```bash
# ① 交互式录入：一行一个（支持 name==version / name@version / "name version" / 裸 name），空行结束
pythonscan scan

# ② 依赖清单文件（与交互式格式一致）
pythonscan scan -i deps.txt

# ③ requirements.txt 直接扫描
pythonscan scan -r requirements.txt
```

### 输出示例

```
$ pythonscan scan -i deps.txt
PythonScan v0.1.0   漏洞库快照: 2026-09-13 (18,342 条记录)
[危险] requests 2.28.0 — 1 个已知漏洞
  · CVE-2023-32681 [中危] (GHSA-j8r2-6x86-q33q)
      Requests 前向代理场景下 Proxy-Authorization 头泄露 …
      影响范围: >=2.0, <2.31.0    修复版本: 2.31.0
      详情: https://osv.dev/vulnerability/CVE-2023-32681
  修复建议: 升级到 2.31.0（覆盖 1 个漏洞）
[安全] flask 2.3.2 — 未发现已知漏洞
[警告] somepkg (未固定版本) — 该包共 12 个已知漏洞
  ……
--------------------------------------------------------
汇总: 3 项依赖 | 受影响 1 | 未固定版本 1 | 高危 0 中危 1 低危 0 | 未评级 0
```

### 只输入包名、不传版本？

该依赖会标注 **未固定版本** 并列出该包**全部已知漏洞**（含影响区间），供你对照实际使用的版本；可加 `--use-installed` 让工具从当前 Python 环境自动探测已装版本后精确扫描。报告同时给出固定版本指引与最新版本是否干净。

### 输出文件

| 参数 | 产物 |
| --- | --- |
| `--json out.json` | 结构化结果（schema: `pythonscan-result/v1`），供二次处理 |
| `-o report.html` | 成型 HTML 报告（单文件、内联样式、离线可开） |
| `--pdf report.pdf` | PDF 报告（调用本机 Edge/Chrome 无头打印；找不到浏览器自动降级为 HTML 手动打印） |

### 漏洞库管理

```bash
pythonscan db import pypi-advisories-20260913.zip   # 首次部署：导入全量库
pythonscan db update delta-20260913-to-20261001.zip # 日常更新：只应用增量
pythonscan db info                                  # 查看快照/记录数/校验信息
```

- 增量包与当前库版本不衔接时会拒绝并提示，按序应用或重新导入全量库即可；
- 库快照超过 90 天（`--stale-days` 可调）会在报告中给出醒目过期警告。

### 退出码

`0` 无已知漏洞 | `1` 发现已知漏洞 | `2` 运行出错（库缺失/损坏、文件不存在、参数错误）

## 漏洞库同步（外网机）

```bash
# 首次：生成全量库
python -m sync.sync build --out pypi-advisories-20260913.zip --proxy http://127.0.0.1:7890

# 之后：基于上一版生成增量包（通常只有几 KB~几 MB）
python -m sync.sync build --prev pypi-advisories-20260913.zip \
    --out delta-20260913-to-20261001.zip --proxy http://127.0.0.1:7890

# 可选：抓取各包最新版本写入索引（供修复建议展示"最新版本是否干净"）
python -m sync.sync build --src ... --out ... --fetch-latest --latest-cache latest.json
```

## 说明与局限

- 版本号请使用 PyPI 上的准确发布版本（`pip show <包>` / `pip freeze` 可查看）；
- 仅覆盖漏洞库快照内的已知漏洞，不构成完整安全保证；不做传递依赖解析、许可证扫描与恶意包检测；
- 结果数据（漏洞摘要等）保持来源原文，界面文案支持中英文（`--lang` 或 `PYTHONSCAN_LANG`）。

## 开发

```bash
python -m unittest discover -s tests   # 单元测试（45+ 用例）
```

## License

[MIT](LICENSE)
