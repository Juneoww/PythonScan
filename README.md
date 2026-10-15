# PythonScan

内网离线检查 **pip 依赖包已知漏洞** 的工具：输入包名和版本号（或 requirements.txt），输出漏洞详情、严重级别、**修复建议**，并支持导出 JSON / HTML / PDF 报告。提供 **CLI 命令行** 与 **桌面图形界面** 两种使用方式。

- **离线可用**：扫描全程零网络请求，漏洞库在外网机生成后摆渡进内网
- **漏洞库与程序解耦**：升级漏洞库只需替换数据文件，支持增量更新（最小化更新）
- **零第三方依赖**：CLI 与 GUI 均纯 Python 标准库（Python ≥ 3.9，GUI 为 Tkinter），Windows / Linux 均可运行
- **数据来源**：[OSV.dev](https://osv.dev) PyPI 全量导出（聚合 GitHub Advisory / PYSEC / CVE）
- 双语界面（`--lang zh|en`）

[English](#english) | [PRD](docs/PRD.md) | [技术设计](docs/DESIGN.md) | **[新手操作手册](docs/操作手册.md)** | [漏洞库来源与准备说明](docs/漏洞库来源与准备说明.md)

## 开发版：直接导入 OSV 漏洞库

当前开发版 `0.2.0.dev2` 支持原始 OSV ZIP、下载去重归档及启用版本追踪。每次更新只需：

1. 外网下载 [PyPI/all.zip](https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip)，将文件传入内网，无需解压或转换。
2. 打开开发版 GUI，点击 **导入/更新漏洞库**，选择该 ZIP。完成后立即使用新库，重启后自动加载。

导入完全离线，也兼容已有 PythonScan 全量库。默认安装到 `%USERPROFILE%\.pythonscan\vulndb.zip`；启动参数 `--db` 优先，其次是 `PYTHONSCAN_DB`。替换前把上一份有效库保存为目标文件旁的 `.bak`，输入 ZIP 保持不变。恢复时关闭程序，将 `.bak` 复制回目标路径后重启；若通过导入恢复，请先将 `.bak` 复制到其他路径再选择，以避免与新备份冲突。增量包继续使用 `db update`。

```powershell
python -m pythonscan db import C:\Transfer\all.zip
python -m pythonscan db info
```

仓库 `release/` 同步提供开发版，程序版本及 SHA256 见该目录的 `BUILD.json` 和 `SHA256SUMS.txt`。GitHub **v0.1.0 Release** 仍是历史版本，不包含直接导入原始 ZIP 的功能。下文的外网转换、增量流程仍可用于旧版及高级维护。

### 外网下载与版本管理

Windows 外网机双击 `release/download-db.cmd` 即可检查和归档，也可指定目录：

```powershell
release\pythonscan.exe db download --archive-dir ..\vulnerability-db
release\pythonscan.exe db info
```

联网只发生在显式 `db download`。管理器按 ETag、ZIP SHA256、规范 JSON 指纹和扫描内容依次去重，304 或内容相同不重复建版。归档在 `versions/<快照日期>_<内容指纹前12位>/`，包含原始 ZIP、可直接导入的 `vulndb.zip` 和元数据；`inventory.json` 列出批次，`checks.jsonl` 记录每次检查。无更新返回 0，网络/校验/写入失败返回 2。默认目录是 `PYTHONSCAN_ARCHIVE` 或 `~/.pythonscan/downloads`；启动脚本在本工作区使用 `vulnerability-db`，在便携包使用包旁同名目录。

**最新归档不等于实际启用。** 内网导入所需版本后，GUI 和 `db info` 显示实际路径、启用版本与完整内容指纹。身份取自实际数据；不维护可能脱节的外部 current.json。普通重复导入不改目标及备份；增量即使数据不变仍推进快照以维持基准链。历史手工归档保留原文件夹名，内容指纹仍可核对。

快照是公告最近修改的 UTC 日期，下载时间另存；日期、大小和记录数不能单独证明更新。上游暂无变化时不伪造新版本。遇 `.download.lock` 遗留锁，确认无任务运行后移除锁再重试，不要同时写同一归档目录。

## 架构一览

```
外网机（可联网）                         摆渡(U盘/网闸)        内网机（隔离）
┌──────────────────────────┐                              ┌──────────────────────────────┐
│ python -m sync.sync build │ ─── vulndb.zip / delta.zip ─→│ pythonscan db import/update  │
│ 生成全量库 / 增量包        │                              │ pythonscan scan -i deps.txt  │
└──────────────────────────┘                              └──────────────────────────────┘
```

## 快速开始（内网端）

**方式零：免安装 exe**（`release/` 目录提供 Windows 可执行文件，无需 Python 环境；漏洞库独立管理）：

```bat
release\pythonscan-gui.exe                       :: 桌面图形界面（双击即可）
release\pythonscan.exe scan                      :: 命令行交互式扫描
release\pythonscan.exe db import C:\Transfer\all.zip   :: 首次导入 OSV 原始 ZIP 或已有全量库
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

首次使用先导入漏洞库（可直接使用外网下载的 OSV 原始 ZIP）：

```bash
pythonscan db import all.zip
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
