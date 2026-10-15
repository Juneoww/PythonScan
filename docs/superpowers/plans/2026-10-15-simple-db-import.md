# 一步导入漏洞库 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** GUI 和 CLI 直接离线导入官方 OSV PyPI ZIP，持久化替换并自动使用，保留上一有效版本。

**Architecture:** 把 OSV 转换移入扫描器共享模块；导入服务分离准备、安装和恢复，在目标所在目录生成临时文件并完成替换。GUI 用队列向主线程交付后台结果，扫描和导入互斥。

**Tech Stack:** Python 3.9+ 标准库、unittest、Tkinter、PyInstaller。工作区 `.worktrees/simple-db-import`，最终快进合并至 `develop`。

## Task 1 OSV 转换与匹配

Files: create `pythonscan/osv.py`, `tests/test_osv.py`; modify `sync/sync.py`, `pythonscan/matching.py`.

- [x] 先写测试：枚举版本、枚举与 GIT 范围并存、同别名多来源枚举/范围、无上界条目保留、撤回排除、非 PyPI 排除、无效 JSON 与核心类型错误拒绝、modified UTC 快照、空库拒绝。
- [x] 运行 `python -m unittest discover -s tests -p test_osv.py -v`，确认缺少转换接口导致失败。
- [x] 实现 `load_osv_zip(path)` 返回 `(records_by_package, snapshot)`，抛 `OSVError(ValueError)`；OSV 根对象/id/modified/affected 及其 package/ranges/events/versions 的基本类型需显式检查，保留原始版本列表。合并以 affected 条目的规范 JSON 去重；别名并查集合并、来源及现有预计算字段维持兼容。无有效 PyPI 条目拒绝。同步器导入共享实现，继续输出原有构建参数和协议。
- [x] 修改匹配器对版本枚举与范围取并集，不跳过范围修复版本收集。运行新增测试与原有 matching/engine 测试。
- [x] 自审并提交本任务。

## Task 2 准备安装与备份

Files: create `pythonscan/db_import.py`, `tests/test_db_import.py`; modify `pythonscan/db.py`, `pythonscan/cli.py`.

- [x] 先写集成测试：两批原始 ZIP 的持久化导入与扫描变化、重启读取、备份还原、已有全量兼容、同路径只校验、增量拒绝、坏 ZIP/JSON/schema/hash/index/计数拒绝且不改旧库、损坏目标恢复且不覆盖良好备份。
- [x] 运行新增测试确认失败；然后实现 `prepare_import(src, target)` 返回持有临时目录的 `PreparedImport`，字段包含目标、manifest、候选路径、同路径标志，提供 `close()`。`install_import(prepared)` 返回 manifest；`restore_import(prepared)` 将本次保存的旧有效库恢复或删除本次首次安装产物（仅本次操作确已安装时）。`db.import_db` 包装准备和安装，保持既有 API 兼容。
- [x] 全量校验要求 manifest/index 为对象，schema=1/kind=full；files 必须覆盖 index 和所有索引包数据且每个声明哈希匹配；packages/latest 类型有效；数据为记录列表，id/affected 等核心字段类型有效；hits、package_count、record_count 与数据一致。禁止重复 ZIP 路径、非法包名、未索引的数据文件。允许既有测试/旧库中缺失可选 published/modified。已有零记录的合法全量可导入；原始 ZIP 不生成空库。
- [x] 准备阶段复制输入到目标同目录唯一临时目录，输入不变；原始 ZIP 转换后写出标准全量库并加入 imported_at、source_sha256、source_type。先校验候选再判定旧目标是否可作为有效备份。同路径必须是有效全量，作为无写操作处理。
- [x] 安装前准备本次专用恢复副本；备份写到目标名追加 `.bak`，只对有效旧库更新。先原子更新备份，再原子替换目标；失败清理候选并保持原目标。安装后重新完整校验/加载失败，调用恢复；恢复失败报告原错误与恢复错误，不声称成功。GUI 负责关闭现有句柄后调用安装。
- [x] 故障注入测试覆盖备份准备失败、备份替换失败、目标替换失败、安装后重载失败及恢复失败；临时目录清理并保留输入。CLI DBError/OSError 返回 2，帮助文案涵盖原始 ZIP。
- [x] 运行 `python -m unittest discover -s tests -v`，自审并提交本任务。

## Task 3 GUI 自动加载与生命周期

Files: modify `pythonscan/gui.py`, `pythonscan/i18n.py`; create `tests/test_gui_import.py`.

- [x] 在隐藏 Tk 根窗口/真实 mainloop 中先写测试：选择原始 ZIP 后后台导入，输入不变、旧结果清除、重启读取新库；导入失败旧句柄/结果恢复；扫描时按钮禁用；关闭窗口后准备结果清理。
- [x] 运行测试确认缺少导入行为失败。启动时固定 `db_path`；按钮调用后台 `prepare_import`，用 `queue.Queue` 交付结果，主线程周期 `after` 取队列，线程不调用 Tk。主线程关闭旧句柄后安装并重载；重载失败关闭新句柄并恢复本次旧库；错误保留输入/旧结果。
- [x] 用忙状态统一控制导入/扫描/导出；扫描启动时捕获 database 和 use_installed，工作线程只扫描并入队。关闭时置 threading.Event，关闭当前句柄；尚未交付的 PreparedImport 由工作线程清理，队列已有结果由关闭处理清理，取消轮询。
- [x] 新增中英文文案覆盖处理中、成功、失败、旧库无有效备份、增量误选指引。运行 GUI 测试与完整套件，自审并提交。

## Task 4 文档与打包验证

Files: modify `README.md`, `docs/操作手册.md`, `docs/漏洞库来源与准备说明.md`; generate binaries outside tracked `release/` until验证完成。

- [x] 文档突出两步流程，说明旧库备份路径、恢复、自定义目标和原始库快照含义。保留 v0.1.0 已知行为历史说明并明确开发版的新行为，不能保留“原始 ZIP 不能导入”的无版本限定结论。
- [x] 运行完整测试和 `git diff --check`；按 spec 先做合规评审，再做代码质量评审，修复实际问题。
- [x] `python -m PyInstaller --noconfirm --clean --distpath <workspace-root>/import-build/dist --workpath <workspace-root>/import-build/work-cli pythonscan.spec`；GUI 使用独立 work-gui 和 pythonscan-gui.spec。
- [ ] 发布 EXE 在移除 Python PATH 的临时目录中测试原始 ZIP 导入、第二批替换与备份、重启读取、扫描、错误退出码；验证 GUI EXE 启动，隐藏源 GUI 验证完整导入重扫流程。可读取最新 OSV 完整导出做真实数据导入验证；不修改用户默认库。
- [ ] 打包本地 Windows ZIP 和使用说明，SHA256 校验；不改动 GitHub v0.1.0 Release。验证通过后将工作区提交快进回 develop，保留既有文档，报告本地 EXE 路径。
