"""输出层：JSON 结果、HTML 成型报告、PDF 导出（浏览器无头打印）。

HTML 为单文件、内联 CSS、无任何外部资源引用（内网可离线打开/打印）。
PDF 不引入第三方库，复用本机 Edge/Chrome（PRD §8.2）。
"""

from __future__ import annotations

import html as _html
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import __version__
from .i18n import localize_note, t

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"]


def write_json(result, path: str) -> str:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2),
                    encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------- HTML

_CSS = """
:root{--bg:#f5f6f8;--card:#fff;--ink:#1f2430;--muted:#6b7280;--line:#e5e7eb;--red:#dc2626;--amber:#d97706;--blue:#2563eb;--green:#059669}
*{box-sizing:border-box}
body{font-family:"Segoe UI","Microsoft YaHei",Arial,sans-serif;background:var(--bg);color:var(--ink);margin:0;padding:32px 16px}
.wrap{max-width:980px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:16px;margin:26px 0 10px}
h3{margin:0 0 8px;font-size:15px}
.meta{color:var(--muted);font-size:13px;margin-bottom:16px}
.banner{background:#fef3c7;border:1px solid #f59e0b;color:#92400e;padding:10px 14px;border-radius:8px;margin:0 0 16px;font-size:14px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:6px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 18px;min-width:130px}
.card .num{font-size:26px;font-weight:700}
.card .lbl{font-size:12px;color:var(--muted)}
.c-red .num{color:var(--red)} .c-amber .num{color:var(--amber)} .c-blue .num{color:var(--blue)} .c-green .num{color:var(--green)}
.chips{font-size:12px;color:var(--muted);margin:6px 0 0}
.chip{display:inline-block;padding:2px 10px;border-radius:999px;color:#fff;margin-right:6px}
.pkg{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:14px}
.badge{display:inline-block;font-size:11px;padding:2px 8px;border-radius:999px;color:#fff;margin-left:6px;vertical-align:2px}
.b-gray{background:#6b7280} .b-blue{background:var(--blue)}
.sev-CRITICAL{background:#991b1b}.sev-HIGH{background:var(--red)}.sev-MODERATE{background:var(--amber)}.sev-LOW{background:var(--blue)}.sev-UNKNOWN{background:#6b7280}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;background:#fafafa}
a{color:var(--blue);text-decoration:none;word-break:break-all}
.fix{margin-top:10px;font-size:13px;background:#ecfdf5;border:1px solid #6ee7b7;color:#065f46;padding:6px 10px;border-radius:6px}
.fix.manual{background:#fef2f2;border-color:#fca5a5;color:#991b1b}
.note{color:var(--muted);font-size:12px;margin-top:6px}
details{margin:8px 0 20px} summary{cursor:pointer;color:var(--muted);font-size:14px}
details ul{margin:8px 0;padding-left:20px;font-size:13px}
.apx{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;font-size:13px}
.apx ul{margin:6px 0;padding-left:20px}
.foot{color:var(--muted);font-size:12px;margin-top:18px}
@media print{body{background:#fff;padding:0}.pkg,.card,.apx{border-color:#ddd}}
"""


def _esc(value) -> str:
    return _html.escape(str(value), quote=True)


def render_html(result, lang: str = "zh") -> str:
    counts = result.severity_counts()
    vuln_total = sum(counts.values())
    unpinned = sum(1 for p in result.packages if p.dependency.unpinned)
    stale = [w for w in result.warnings if w.startswith("__stale__:")]

    out: list[str] = []
    out.append(f"<!DOCTYPE html><html lang=\"{lang}\"><head><meta charset=\"utf-8\">")
    out.append(f"<title>{_esc(t(lang, 'report_title'))} - PythonScan</title>")
    out.append(f"<style>{_CSS}</style></head><body><div class=\"wrap\">")
    out.append(f"<h1>{_esc(t(lang, 'report_title'))}</h1>")
    out.append("<div class=\"meta\">{}</div>".format(_esc(
        f"PythonScan v{__version__} | {t(lang, 'report_generated')}: {result.generated_at} | "
        f"{t(lang, 'report_source')}: {result.source} | {t(lang, 'report_db')}: "
        f"{result.db_meta.get('snapshot', '-')} ({result.db_meta.get('record_count', 0):,})")))
    for w in stale:
        days = int(w.split(":", 1)[1])
        out.append(f"<div class=\"banner\">{_esc(t(lang, 'stale_warn', days=days, limit=90))}</div>")

    out.append("<div class=\"cards\">")
    out.append(_card(len(result.packages), t(lang, "card_total"), "c-blue"))
    out.append(_card(sum(1 for p in result.packages if p.vulnerable), t(lang, "card_vulnerable"), "c-red"))
    out.append(_card(vuln_total, t(lang, "card_vulns"), "c-amber"))
    out.append(_card(unpinned, t(lang, "card_unpinned"), "c-blue"))
    out.append("</div>")
    chips = " ".join(
        f"<span class=\"chip sev-{_esc(level)}\">{_esc(_sev_label(level, lang))} {counts[level]}</span>"
        for level in SEVERITY_ORDER if counts.get(level))
    out.append(f"<p class=\"chips\">{chips}</p>")

    vulnerable_pkgs = [p for p in result.packages if p.vulnerable]
    if vulnerable_pkgs:
        out.append(f"<h2>{_esc(t(lang, 'section_vulnerable'))}</h2>")
        for pkg in vulnerable_pkgs:
            out.append(_package_card(pkg, lang))

    clean = [p for p in result.packages if not p.vulnerable]
    out.append(f"<h2>{_esc(t(lang, 'section_clean'))} ({len(clean)})</h2>")
    if clean:
        out.append("<details><summary>" + _esc(t(lang, "section_clean")) + "</summary><ul>")
        for pkg in clean:
            badges = ""
            if pkg.dependency.unpinned:
                badges += f"<span class=\"badge b-gray\">{_esc(t(lang, 'badge_unpinned'))}</span>"
            if pkg.dependency.version_source == "environment":
                badges += f"<span class=\"badge b-blue\">{_esc(t(lang, 'badge_env'))}</span>"
            ver = _esc(pkg.dependency.version) if pkg.dependency.version else "-"
            out.append(f"<li>{_esc(pkg.dependency.display_name)} == {ver}{badges}</li>")
        out.append("</ul></details>")
    else:
        out.append(f"<p class=\"note\">{_esc(t(lang, 'report_clean_none'))}</p>")

    out.append(f"<h2>{_esc(t(lang, 'section_appendix'))}</h2>")
    out.append("<div class=\"apx\">")
    if result.warnings or result.errors:
        if result.warnings:
            out.append(f"<strong>{_esc(t(lang, 'report_warnings'))}</strong><ul>")
            for w in result.warnings:
                out.append(f"<li>{_esc(localize_note(w, lang, 90))}</li>")
            out.append("</ul>")
        if result.errors:
            out.append(f"<strong>{_esc(t(lang, 'report_errors'))}</strong><ul>")
            for e in result.errors:
                out.append(f"<li>{_esc(e)}</li>")
            out.append("</ul>")
    else:
        out.append(f"<p class=\"note\">{ _esc(t(lang, 'report_no_issues')) }</p>")
    out.append(f"<p class=\"foot\">{_esc(t(lang, 'disclaimer'))}</p>")
    out.append("</div>")
    out.append("</div></body></html>")
    return "\n".join(out)


def _card(num: int, label: str, cls: str) -> str:
    return f"<div class=\"card {cls}\"><div class=\"num\">{num}</div><div class=\"lbl\">{_esc(label)}</div></div>"


def _package_card(pkg, lang: str) -> str:
    dep = pkg.dependency
    badges = ""
    if dep.unpinned:
        badges += f"<span class=\"badge b-gray\">{_esc(t(lang, 'badge_unpinned'))}</span>"
    if dep.version_source == "environment":
        badges += f"<span class=\"badge b-blue\">{_esc(t(lang, 'badge_env'))}</span>"
    ver = _esc(dep.version) if dep.version else "-"
    out = [f"<div class=\"pkg\"><h3>{_esc(dep.display_name)} == {ver}{badges}"
           f"<span class=\"badge sev-{_esc(pkg.hits[0].severity)}\">{len(pkg.hits)} "
           f"{_esc(t(lang, 'card_vulns'))}</span></h3>"]
    if pkg.fix and (pkg.fix.upgrade_to or pkg.fix.note):
        manual = pkg.fix.confidence == "manual"
        out.append(f"<div class=\"fix{' manual' if manual else ''}\">{_esc(_fix_text(pkg, lang))}</div>")
    out.append("<table><tr>"
               f"<th style=\"width:24%\">{_esc(t(lang, 'col_id'))}</th>"
               f"<th style=\"width:12%\">{_esc(t(lang, 'col_severity'))}</th>"
               f"<th>{_esc(t(lang, 'col_summary'))}</th>"
               f"<th style=\"width:16%\">{_esc(t(lang, 'col_affected'))}</th>"
               f"<th style=\"width:12%\">{_esc(t(lang, 'col_fixed'))}</th></tr>")
    for hit in pkg.hits:
        aliases = f"<br><span style=\"color:#6b7280\">{_esc(', '.join(hit.aliases))}</span>" if hit.aliases else ""
        out.append(
            "<tr><td><a href=\"{}\" target=\"_blank\" rel=\"noopener\">{}</a>{}</td>"
            "<td><span class=\"chip sev-{}\">{}</span></td>"
            "<td>{}</td><td>{}</td><td>{}</td></tr>".format(
                _esc(hit.url), _esc(hit.id), aliases,
                _esc(hit.severity), _esc(_sev_label(hit.severity, lang)),
                _esc(hit.summary or "-"), _esc(hit.affected or "*"),
                _esc(", ".join(hit.fixed_versions) or "-")))
    out.append("</table>")
    for note in pkg.notes:
        out.append(f"<div class=\"note\">{_esc(localize_note(note, lang, 90))}</div>")
    out.append("</div>")
    return "".join(out)


def _fix_text(pkg, lang: str) -> str:
    fix = pkg.fix
    if fix.upgrade_to:
        return t(lang, "fix_upgrade", to=fix.upgrade_to, covers=len(fix.covers))
    return t(lang, "fix_suggestion_info", note=fix.note or "")


def _sev_label(level: str, lang: str) -> str:
    labels = {
        "zh": {"CRITICAL": "严重", "HIGH": "高危", "MODERATE": "中危", "LOW": "低危", "UNKNOWN": "未评级"},
        "en": {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MODERATE", "LOW": "LOW", "UNKNOWN": "UNRATED"},
    }
    return labels.get(lang, labels["zh"]).get(level, level)


def write_html(result, path: str, lang: str = "zh") -> str:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(result, lang), encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------- PDF

def find_browser() -> str | None:
    candidates: list[str] = []
    env = os.environ.get("PYTHONSCAN_BROWSER")
    if env:
        candidates.append(env)
    if os.name == "nt":
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        local = os.environ.get("LocalAppData", "")
        candidates += [
            rf"{pf86}\Microsoft\Edge\Application\msedge.exe",
            rf"{pf}\Microsoft\Edge\Application\msedge.exe",
            rf"{pf}\Google\Chrome\Application\chrome.exe",
            rf"{pf86}\Google\Chrome\Application\chrome.exe",
            rf"{local}\Google\Chrome\Application\chrome.exe",
        ]
    else:
        candidates += ["microsoft-edge", "google-chrome", "chromium", "chromium-browser"]
    for cand in candidates:
        path = cand if os.path.isabs(cand) else shutil.which(cand)
        if path and os.path.exists(path):
            return path
    return None


def write_pdf(html_path: str, pdf_path: str) -> tuple[bool, str]:
    """浏览器无头打印 HTML -> PDF。成功返回 (True, 浏览器路径)。"""
    browser = find_browser()
    if not browser:
        return False, ""
    # Edge/Chrome 启动后会切换自身工作目录，输出路径必须是绝对路径
    pdf_path = Path(pdf_path).resolve()
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    profile = tempfile.mkdtemp(prefix="pythonscan-pdf-")
    cmd = [
        browser, "--headless", "--disable-gpu",
        f"--user-data-dir={profile}",
        "--no-pdf-header-footer",
        f"--print-to-pdf={pdf_path}",
        Path(html_path).resolve().as_uri(),
    ]
    try:
        subprocess.run(cmd, capture_output=True, timeout=120, check=False)
    except (subprocess.TimeoutExpired, OSError):
        shutil.rmtree(profile, ignore_errors=True)
        return False, browser
    shutil.rmtree(profile, ignore_errors=True)
    if pdf_path.exists() and pdf_path.stat().st_size > 0:
        return True, browser
    return False, browser
