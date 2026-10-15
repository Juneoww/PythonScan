# 漏洞库下载归档与启用追踪 Implementation Plan

> **For agentic workers:** Use executing-plans sequentially: identity/import and downloader depend on shared interfaces. Independent spec/quality reviewers validate the completed work. Steps use checkbox syntax.

**Goal:** 外网低成本获得有效新库且不重复建版，内网准确显示实际启用版本，交付更新的 Windows EXE。

**Architecture:** `db_identity` 提供纯离线内容身份；原有导入服务将身份与数据一并安装。独立 `db_download` 负责显式 HTTP GET、条件请求、暂存、去重及归档提交。CLI/GUI 只展示服务结果，不把下载视为启用。

**Tech Stack:** Python 标准库、unittest、本地 HTTP 服务、Tkinter、PyInstaller。基线 `7798d48`；隔离工作区 `.worktrees/db-version-management`。

## Task 1 离线身份与启用事务

Files: create `pythonscan/db_identity.py`, `tests/test_db_identity.py`; modify `pythonscan/db_import.py`, `pythonscan/db.py`.

- [x] 先写测试并运行，确认身份接口缺失、重复导入会改备份、增量无新身份的失败。
- [x] `file_sha256(path)` 流式计算；`json_fingerprint(path, raw=False)` 按 JSON 文件名排序，对 `[name, parsed_json]` 使用 sort_keys=True/紧凑 UTF-8 并加8字节长度前缀。full 只取 index/data；raw 取所有 JSON，拒重复名/无效 JSON；输出64位十六进制。算法与既有手工归档一致。
- [x] `identity(path, manifest=None)` 总是按真实内容计算 `content_sha256` 和 `<安全快照>_<hash[:12]>`，不信任输入声明。安全快照仅保留 ASCII 字母数字和连字符，最多32字节，空值为 undated。
- [x] 准备阶段完整验证之后计算身份，重写候选 manifest 加入身份、导入时间；raw 另存 source_json_sha256。重写不改变数据哈希，使用唯一暂存/原子替换。
- [x] PreparedImport 增加 unchanged 标志。旧目标有效且内容相同时不替换、不更新 .bak，结果包含 unchanged=True；新旧不同仍沿用回滚。覆盖同路径、旧无身份库、伪造身份以及重载失败。
- [x] VulnDB 增加缓存的 identity 属性；所有库均按实际 index/data 派生，不能仅因 manifest 字段格式合法就信任它。增加直接加载伪造身份库的测试。db_info 用 load 返回 identity、实际 path；旧字段兼容。增量在目标同目录构建候选，然后走同一 import 服务生成身份及备份，不能留旧身份。
- [x] 跑身份、导入、增量与完整测试，自审并提交。

## Task 2 外网下载和版本归档

Files: create `pythonscan/db_download.py`, `tests/test_db_download.py`.

- [x] 先写本地 HTTP 服务测试：200/304、同字节、ZIP 重压、同日内容变化、无 ETag、失败、截断、损坏/丢失归档、原清单保护、日志及锁。运行确认缺少服务失败。
- [x] API `download(archive_dir=None)` 返回 dict：status(new/unchanged)、reason、version_id、directory、snapshot、content_sha256。固定 SOURCE_URL 官方 HTTPS；测试通过 patch SOURCE_URL 指向 loopback。
- [x] 默认路径 `PYTHONSCAN_ARCHIVE` 或 `~/.pythonscan/downloads`。独占 .download.lock，临时目录在同一根。读取 inventory 的 versions，兼容旧手工条目；路径严格解析限制于根。仅成功来源缓存并且相应文件哈希有效才携带 ETag。
- [x] urllib GET timeout=30，分块写入 raw.zip，核对可用 Content-Length；HTTP304 仅在发送有效条件请求且可用版本存在时接受。其他错误抛 DBError，失败日志不改 inventory 的成功状态。
- [x] 依次判定 raw SHA、raw JSON hash、转换 full 的 content_sha256；匹配前验证归档实际文件完整性。不存在可用旧文件时不能304短路；损坏已知版本报错或安全恢复，不能覆盖原有不可变目录。重复只刷新成功来源缓存/检查时间，记录对应已有版本。
- [x] 用 prepare_import 转换到本次暂存候选，保留原始输入；拷贝候选为 staged/vulndb.zip、写 metadata.json（使用本次响应 ETag/Last-Modified/generation/downloaded_at 等）。新目录版本ID来自候选 identity，旧手工ID可复用。路径碰撞拒绝覆盖。
- [x] os.replace 完成新目录和 inventory 提交。日志采用原内容加新行写唯一暂存后原子替换，避免部分追加；清单先提交，日志失败则恢复旧清单（原先不存在则撤销本次文件），并将本次新版本目录移回暂存。清单或补偿失败明确报告；失败日志不改成功缓存。测试日志提交失败后目录、inventory、成功缓存均恢复。checks.jsonl 写 new/unchanged/error，锁/暂存都 finally 清理。
- [x] 跑新增测试和完整测试，自审提交。

## Task 3 CLI、GUI、文档与打包

Files: modify `pythonscan/cli.py`, `pythonscan/gui.py`, `pythonscan/i18n.py`, `tests/test_gui_import.py`; create `tests/test_db_management_cli.py`, `release/download-db.cmd`; update README/manual/source material, version metadata.

- [x] 先加 CLI/GUI 测试：命令存在、download状态与启用区分、db info 身份/路径、GUI身份显示/重复/失败恢复。运行确认失败。
- [x] CLI db download 子命令只在显式调用时导入联网服务；支持 archive-dir/lang。db info 显示版本、完整内容指纹、路径。界面新增双语下载结果/重复导入文案。
- [x] GUI 顶栏显示快照、版本和完整指纹（换行），另显示绝对路径；扫描行为不联网。重复导入提示 unchanged，不改备份，成功/失败仍按原恢复规则。
- [x] 开发版版本 0.2.0.dev2。Windows cmd 启动器以脚本位置定位本工作区或便携包旁 vulnerability-db，调用 EXE db download，错误退出码保留，中文说明写在文件头。
- [x] 全套测试、diff check；独立 spec compliance 先过，再质量 review，修复并复审。
- [x] 构建 CLI/GUI 到 archive/builds/db-version-management-2026-10-15/dist。EXE 在不含 Python 的 PATH 下验证新命令、两次外网检查、原始/全量导入、重复导入备份稳定、重启 info 和扫描。隐藏 Tk 测试覆盖 GUI；不安装用户默认库。
- [x] 先归档既有 dev1，更新 source/release、dist/0.2.0.dev2 及包含当前有效快照的便携包，生成 BUILD/校验清单。文档明确两个日期、两种指纹和最新下载≠实际启用。GitHub v0.1.0 不变。
- [ ] 验证后快进合并本地 develop，在合并后运行完整测试，记录验收和迁移位置，清理本次工作树。
