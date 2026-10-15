"""PythonScan 命令行入口。

用法:
  pythonscan scan [-i 清单 | -r requirements.txt] [-o report.html] [--json out.json]
                  [--pdf report.pdf] [--use-installed] [--fail-fast] [--lang zh|en]
  pythonscan db import <全量库.zip> | db update <增量包.zip> | db info
不带 -i/-r 时进入交互式录入（一行一个，空行结束）。
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, db, engine, report
from .db import DBError
from .i18n import localize_note, t
from .inputspec import InvalidDependency, load_deps_file, read_interactive

SEV_LABEL = {
    "zh": {"CRITICAL": "严重", "HIGH": "高危", "MODERATE": "中危", "LOW": "低危", "UNKNOWN": "未评级"},
    "en": {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MODERATE", "LOW": "LOW", "UNKNOWN": "UNRATED"},
}
SEV_COLOR = {"CRITICAL": "31", "HIGH": "31", "MODERATE": "33", "LOW": "36", "UNKNOWN": "90"}
MAX_TERMINAL_HITS = 10

EXIT_CLEAN = 0
EXIT_VULNERABLE = 1
EXIT_ERROR = 2


class Painter:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, code: str = "0") -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text


def _setup_console() -> None:
    if os.name == "nt":
        os.system("")  # 在部分 Windows 终端上启用 ANSI 颜色
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pythonscan",
        description="内网离线检查 pip 依赖包已知漏洞（数据源: 本地 OSV 漏洞库）",
        epilog=(
            "示例:\n"
            "  pythonscan scan                                   交互式录入（一行一个，空行结束）\n"
            "  pythonscan scan -i deps.txt                       扫描依赖清单\n"
            "  pythonscan scan -r requirements.txt -o report.html --json out.json\n"
            "  pythonscan scan -i deps.txt --pdf report.pdf      HTML + PDF 报告\n"
            "  pythonscan db import pypi-advisories-20260913.zip 导入全量漏洞库\n"
            "  pythonscan db update delta-20261001.zip           应用增量包\n"
            "  pythonscan db info                                查看当前漏洞库信息\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"PythonScan {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    scan_p = sub.add_parser("scan", help="扫描依赖漏洞")
    scan_p.add_argument("-i", "--input", help="依赖清单文件（一行一个: 包名==版本号）")
    scan_p.add_argument("-r", "--requirements", help="requirements.txt 路径")
    scan_p.add_argument("-o", "--output", help="HTML 报告输出路径")
    scan_p.add_argument("--json", dest="json_path", help="JSON 结果输出路径")
    scan_p.add_argument("--pdf", help="PDF 报告输出路径（本机浏览器无头打印）")
    scan_p.add_argument("--use-installed", action="store_true",
                        help="未固定版本的依赖从当前 Python 环境探测已装版本")
    scan_p.add_argument("--fail-fast", action="store_true", help="发现首个漏洞后停止扫描")
    scan_p.add_argument("--lang", default=os.environ.get("PYTHONSCAN_LANG", "zh"),
                        choices=["zh", "en"], help="界面语言（默认 zh，可用 PYTHONSCAN_LANG 配置）")
    scan_p.add_argument("--db", help="漏洞库路径（默认 ~/.pythonscan/vulndb.zip 或 PYTHONSCAN_DB）")
    scan_p.add_argument("--stale-days", type=int, default=90, help="库过期警告阈值天数（默认 90）")
    scan_p.add_argument("--no-color", action="store_true", help="禁用彩色输出")

    db_p = sub.add_parser("db", help="漏洞库管理（download/import/update/info）")
    db_sub = db_p.add_subparsers(dest="db_cmd", required=True)
    for name, help_text in (("import", "导入 OSV 原始 ZIP 或全量库"), ("update", "应用增量包")):
        p = db_sub.add_parser(name, help=help_text)
        p.add_argument("file", help="库文件路径")
        p.add_argument("--db", dest="target", help="目标库路径（默认 ~/.pythonscan/vulndb.zip）")
        p.add_argument("--lang", default=os.environ.get("PYTHONSCAN_LANG", "zh"), choices=["zh", "en"])
    info_p = db_sub.add_parser("info", help="查看当前漏洞库信息")
    info_p.add_argument("--db", help="库路径（默认 ~/.pythonscan/vulndb.zip）")
    info_p.add_argument("--lang", default=os.environ.get("PYTHONSCAN_LANG", "zh"), choices=["zh", "en"])

    download_p = db_sub.add_parser('download', help='外网检查、去重并归档 OSV PyPI（不启用）')
    download_p.add_argument('--archive-dir', help='归档目录（默认 PYTHONSCAN_ARCHIVE 或 ~/.pythonscan/downloads）')
    download_p.add_argument('--lang', default=os.environ.get('PYTHONSCAN_LANG', 'zh'), choices=['zh', 'en'])

    gui_p = sub.add_parser("gui", help="打开桌面图形界面（Tkinter）")
    gui_p.add_argument("--db", help="漏洞库路径（默认 ~/.pythonscan/vulndb.zip 或 PYTHONSCAN_DB）")
    gui_p.add_argument("--lang", default=os.environ.get("PYTHONSCAN_LANG", "zh"), choices=["zh", "en"])
    return parser


def main(argv=None) -> int:
    _setup_console()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.cmd == "scan":
            return _cmd_scan(args)
        if args.cmd == "db":
            return _cmd_db(args)
        if args.cmd == "gui":
            from .gui import run as run_gui
            run_gui(db_path=args.db, lang=args.lang)
            return EXIT_CLEAN
    except DBError as error:
        print(f"错误: {error}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as error:
        print(f"错误: {error}", file=sys.stderr)
        return EXIT_ERROR
    parser.print_help()
    return EXIT_ERROR


# ---------------------------------------------------------------- scan

def _cmd_scan(args) -> int:
    lang = args.lang
    paint = Painter(sys.stdout.isatty() and not getattr(args, "no_color", False))

    if args.input and args.requirements:
        print("错误: -i 与 -r 只能二选一。", file=sys.stderr)
        return EXIT_ERROR

    try:
        database = db.load(args.db)
    except DBError as error:
        print(paint(t(lang, "db_missing", error=error), "31"))
        return EXIT_ERROR

    try:
        if args.input or args.requirements:
            path = args.input or args.requirements
            try:
                deps, warns = load_deps_file(path)
            except OSError as error:
                print(f"错误: 无法读取 {path}: {error}", file=sys.stderr)
                return EXIT_ERROR
            source = path
        else:
            print(paint(t(lang, "scan_header", version=__version__,
                          snapshot=database.snapshot, records=database.record_count), "90"))
            print(t(lang, "interactive_hint"))
            deps, warns = read_interactive("> ")
            source = "interactive"

        if not deps:
            print(paint(t(lang, "no_deps"), "33"))
            return EXIT_ERROR

        result = engine.scan(deps, database, source=source,
                             use_installed=args.use_installed,
                             fail_fast=args.fail_fast,
                             stale_days=args.stale_days)
    finally:
        database.close()
    result.warnings = ([t(lang, "parse_warn", line_no=w.line_no, raw=w.raw, reason=w.reason)
                        for w in warns] + [localize_note(w, lang, args.stale_days)
                                           for w in result.warnings])
    if args.json_path:
        print(paint(t(lang, "saved", path=report.write_json(result, args.json_path)), "90"))
    if args.output:
        print(paint(t(lang, "saved", path=report.write_html(result, args.output, lang)), "90"))
    if args.pdf:
        html_path = args.output or str(Path(args.pdf).with_suffix(".html"))
        if not args.output:
            report.write_html(result, html_path, lang)
        ok, browser = report.write_pdf(html_path, args.pdf)
        if ok:
            print(paint(t(lang, "pdf_done", path=args.pdf), "32"))
        elif not browser:
            print(paint(t(lang, "pdf_no_browser"), "33"))
        else:
            print(paint(t(lang, "pdf_failed", browser=browser), "33"))

    _render_terminal(result, lang, paint)
    return EXIT_VULNERABLE if result.vulnerable else EXIT_CLEAN


def _sev(sev: str, lang: str) -> str:
    return SEV_LABEL.get(lang, SEV_LABEL["zh"]).get(sev, sev)


def _render_terminal(result, lang: str, paint: Painter) -> None:
    for pkg in result.packages:
        dep = pkg.dependency
        ver = dep.version or "-"
        if pkg.vulnerable and not dep.unpinned:
            print(paint(t(lang, "pkg_vuln", pkg=dep.display_name, ver=ver, count=len(pkg.hits)), "31"))
        elif pkg.vulnerable:
            print(paint(t(lang, "pkg_vuln_unpinned", pkg=dep.display_name, count=len(pkg.hits)), "33"))
        elif dep.unpinned:
            print(paint(t(lang, "pkg_clean_unpinned", pkg=dep.display_name), "32"))
        else:
            print(paint(t(lang, "pkg_clean", pkg=dep.display_name, ver=ver), "32"))

        for hit in pkg.hits[:MAX_TERMINAL_HITS]:
            alias = f" ({', '.join(hit.aliases)})" if hit.aliases else ""
            print(f"  {paint('·', '90')} {paint(hit.id, SEV_COLOR.get(hit.severity, '0'))} "
                  f"{paint('[' + _sev(hit.severity, lang) + ']', SEV_COLOR.get(hit.severity, '0'))}{alias}")
            if hit.summary:
                print(f"      {hit.summary}")
            print(f"      {t(lang, 'label_affected')}: {hit.affected or '*'}    "
                  f"{t(lang, 'label_fixed')}: {', '.join(hit.fixed_versions) or '-'}")
            print(f"      {t(lang, 'label_advisory')}: {hit.url}")
        if len(pkg.hits) > MAX_TERMINAL_HITS:
            print(paint(t(lang, "more_vulns", count=len(pkg.hits) - MAX_TERMINAL_HITS), "90"))
        if pkg.fix and (pkg.fix.upgrade_to or pkg.fix.note):
            if pkg.fix.upgrade_to:
                print(paint(t(lang, "fix_suggestion", to=pkg.fix.upgrade_to,
                              covers=len(pkg.fix.covers)), "32"))
            else:
                print(paint(t(lang, "fix_suggestion_info", note=pkg.fix.note), "33"))
        for note in pkg.notes:
            print(paint(f"  {localize_note(note, lang, 90)}", "90"))

    counts = result.severity_counts()
    print(paint("-" * 56, "90"))
    print(t(lang, "summary", total=len(result.packages),
            vulnerable=sum(1 for p in result.packages if p.vulnerable),
            unpinned=sum(1 for p in result.packages if p.dependency.unpinned),
            critical=counts.get("CRITICAL", 0), high=counts.get("HIGH", 0),
            moderate=counts.get("MODERATE", 0), low=counts.get("LOW", 0),
            unknown=counts.get("UNKNOWN", 0)))
    if result.warnings:
        print(paint(t(lang, "summary_warnings", warnings=len(result.warnings)), "33"))
        for warning in result.warnings:
            print(paint(f"  ! {warning}", "33"))
    for error in result.errors:
        print(paint(f"  ! {error}", "31"))


# ---------------------------------------------------------------- db

def _cmd_db(args) -> int:
    lang = args.lang
    if args.db_cmd == 'download':
        from .db_download import download
        result = download(args.archive_dir)
        reason = t(lang, 'download_reason_' + result['reason'])
        print(t(lang, 'download_result', status=t(lang, 'download_' + result['status']),
                reason=reason, version=result['version_id'], path=result['directory'],
                fingerprint=result['content_sha256']))
        return EXIT_CLEAN
    if args.db_cmd == "import":
        manifest = db.import_db(args.file, args.target)
        print(t(lang, 'db_unchanged' if manifest.get('unchanged') else "db_imported", path=args.target or db.default_db_path(),
                snapshot=manifest["snapshot"], records=manifest.get("record_count", 0),
                packages=manifest.get("package_count", 0)))
        if manifest.get("backup_warning"):
            print(manifest["backup_warning"], file=sys.stderr)
        return EXIT_CLEAN
    if args.db_cmd == "update":
        manifest = db.update_db(args.file, args.target)
        print(t(lang, "db_updated", base=manifest.get("base") or "-",
                target=manifest["snapshot"], records=manifest.get("record_count", 0)))
        return EXIT_CLEAN
    manifest = db.db_info(args.db)
    print(t(lang, "db_info", path=args.db or db.default_db_path(),
            snapshot=manifest.get("snapshot", "-"), schema=manifest.get("schema_version", "?"),
            records=manifest.get("record_count", 0), packages=manifest.get("package_count", 0),
            latests=manifest.get("latest_count", 0)))
    print(t(lang, 'db_identity_info', version=manifest['version_id'],
            fingerprint=manifest['content_sha256'], path=manifest['path']))
    return EXIT_CLEAN
