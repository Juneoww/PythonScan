@echo off
rem 功能：在外网检查 OSV 更新、去重并归档，不启用内网扫描库。
rem 实现：调用同目录 EXE；仓库使用工作区 vulnerability-db，便携包使用包旁目录。
rem 输入：可选第一个参数指定归档目录；输出：版本目录、inventory.json、checks.jsonl。
rem 依赖：Windows CMD、同目录 pythonscan.exe 及外网连接。
setlocal
chcp 65001 >nul
set "archiveDir=%~1"
if not defined archiveDir set "archiveDir=%~dp0vulnerability-db"
if not defined PYTHONSCAN_ARCHIVE goto localDefault
if "%~1"=="" set "archiveDir=%PYTHONSCAN_ARCHIVE%"
goto runDownload
:localDefault
if "%~1"=="" if exist "%~dp0..\pyproject.toml" if exist "%~dp0..\..\source\pyproject.toml" set "archiveDir=%~dp0..\..\vulnerability-db"
:runDownload
"%~dp0pythonscan.exe" db download --archive-dir "%archiveDir%"
set "downloadExit=%ERRORLEVEL%"
if not "%downloadExit%"=="0" echo Download failed. Review the error above.
if not defined PYTHONSCAN_NO_PAUSE pause
exit /b %downloadExit%
