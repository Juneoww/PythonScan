PythonScan 本地开发构建：0.2.0.dev1

此目录的 pythonscan.exe 与 pythonscan-gui.exe 已同步到开发版。
构建来源及文件哈希见 BUILD.json、SHA256SUMS.txt。
旧 v0.1.0 程序和预置库保存在工作区 archive\releases\v0.1.0。
GitHub v0.1.0 Release 保持历史版本。

首次使用：双击 pythonscan-gui.exe，点击“导入/更新漏洞库”。
选择 OSV PyPI all.zip 或 PythonScan 全量 ZIP。完成后立即扫描，重启自动加载。
程序扫描和导入均离线；当前版本没有自动联网下载或自动维护多版本目录的功能。

本工作区已归档的库位于：
D:\June\E\code\codex\PythonScan\vulnerability-db\versions\
归档索引是 vulnerability-db\inventory.json，下载归档不等于当前已启用。
从本目录运行命令行可查看当前实际加载位置和快照：
  .\pythonscan.exe db info

默认安装位置：%USERPROFILE%\.pythonscan\vulndb.zip
显式 --db 路径优先，其次 PYTHONSCAN_DB。
本次整理未自动安装或切换用户正在使用的库，请选择所需版本导入。
