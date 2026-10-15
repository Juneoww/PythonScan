"""PythonScan 桌面端（Tkinter，仅标准库）。

复用引擎 API：输入框多行依赖 -> engine.scan -> 彩色结果区 -> 导出 JSON/HTML/PDF。
扫描在工作线程执行，界面不冻结；GUI 不触达引擎内部模块。
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import __version__, db, db_import, engine, report
from .db import DBError
from .i18n import localize_note, t
from .inputspec import Dependency, InvalidDependency, parse_line

SEV_COLORS = {
    "CRITICAL": "#991b1b",
    "HIGH": "#dc2626",
    "MODERATE": "#d97706",
    "LOW": "#2563eb",
    "UNKNOWN": "#6b7280",
}
INK = "#1f2430"
MUTED = "#6b7280"
SAFE = "#059669"
DANGER = "#dc2626"
WARN = "#b45309"


def _parse_text(text: str) -> tuple[list[Dependency], list[tuple[int, str]]]:
    """把输入框内容按行解析为依赖；返回 (依赖, [(行号, 原文) 告警])。"""
    deps: list[Dependency] = []
    warns: list[tuple[int, str]] = []
    seen: set[tuple[str, str | None]] = set()
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        try:
            dep = parse_line(line)
        except InvalidDependency:
            warns.append((line_no, line))
            continue
        if dep is None:
            continue
        if dep.unpinned and dep.note is None:
            dep.note = "未固定版本"
        key = (dep.name, dep.version)
        if key in seen:
            continue
        seen.add(key)
        deps.append(dep)
    return deps, warns


class ScanGUI:
    def __init__(self, root: tk.Tk, db_path: str | None = None, lang: str = "zh"):
        self.root = root
        self.lang = lang
        self.database = None
        self.result = None
        self._scanning = False
        self._importing = False
        self.db_path = Path(db_path or db.default_db_path()).resolve()
        self._closed = threading.Event()
        self._result_lock = threading.Lock()
        self._results = queue.Queue()
        self.use_installed_var = tk.BooleanVar(value=False)
        root.title(t(lang, "gui_title", version=__version__))
        root.geometry("900x700")
        root.minsize(760, 560)
        self._build_ui()
        self._load_db(str(self.db_path), quiet=True)
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll_id = root.after(40, self._poll_results)

    # ------------------------------------------------------------ UI 构建

    def _build_ui(self):
        lang = self.lang
        pad = {"padx": 10, "pady": 4}

        top = ttk.Frame(self.root)
        top.pack(fill="x", **pad)
        self.db_button = ttk.Button(top, text=t(lang, "gui_pick_db"),
                                    command=self._on_pick_db)
        self.db_button.pack(side="left")
        self.db_label = ttk.Label(top, text=t(lang, "gui_db_loading"), foreground=MUTED)
        self.db_label.pack(side="left", padx=8)

        input_label = ttk.Label(self.root, text=t(lang, "gui_input_label"))
        input_label.pack(fill="x", padx=10, pady=(8, 2))
        input_frame = ttk.Frame(self.root)
        input_frame.pack(fill="both", padx=10)
        self.input_text = tk.Text(input_frame, height=8, wrap="none",
                                  font=("Consolas", 10), undo=True,
                                  bg="#ffffff", fg=INK, relief="solid", bd=1)
        input_scroll = ttk.Scrollbar(input_frame, command=self.input_text.yview)
        self.input_text.configure(yscrollcommand=input_scroll.set)
        self.input_text.pack(side="left", fill="both", expand=True)
        input_scroll.pack(side="right", fill="y")
        self.input_text.insert("1.0", "# 一行一个，例如:\n# requests==2.28.0\n# flask 2.3.2\n")

        options = ttk.Frame(self.root)
        options.pack(fill="x", padx=10, pady=(4, 0))
        ttk.Checkbutton(options, text=t(lang, "gui_use_installed"),
                        variable=self.use_installed_var).pack(side="left")

        buttons = ttk.Frame(self.root)
        buttons.pack(fill="x", padx=10, pady=6)
        self.scan_button = ttk.Button(buttons, text=t(lang, "gui_scan_btn"),
                                      command=self._on_scan)
        self.scan_button.pack(side="left")
        ttk.Button(buttons, text=t(lang, "gui_import_btn"),
                   command=self._on_import_file).pack(side="left", padx=6)
        ttk.Button(buttons, text=t(lang, "gui_clear_btn"),
                   command=self._on_clear).pack(side="left")
        self.status_label = ttk.Label(buttons, text="", foreground=MUTED)
        self.status_label.pack(side="left", padx=10)

        self.output = tk.Text(self.root, wrap="word", font=("Consolas", 10),
                              state="disabled", bg="#fafafa", fg=INK,
                              relief="solid", bd=1)
        out_scroll = ttk.Scrollbar(self.root, command=self.output.yview)
        self.output.configure(yscrollcommand=out_scroll.set)
        self.output.pack(fill="both", expand=True, padx=10, pady=(2, 4))
        out_scroll.place(relx=0.99, rely=0.3, anchor="e")
        for sev, color in SEV_COLORS.items():
            self.output.tag_configure(f"sev-{sev}", foreground=color, font=("Consolas", 10, "bold"))
        self.output.tag_configure("danger", foreground=DANGER, font=("Consolas", 10, "bold"))
        self.output.tag_configure("safe", foreground=SAFE)
        self.output.tag_configure("warn", foreground=WARN)
        self.output.tag_configure("muted", foreground=MUTED)
        self.output.tag_configure("bold", font=("Consolas", 10, "bold"))

        export = ttk.Frame(self.root)
        export.pack(fill="x", padx=10, pady=(0, 8))
        ttk.Label(export, text=t(lang, "gui_export_label")).pack(side="left")
        self.export_buttons = []
        for key, cmd in (("gui_export_json", self._export_json),
                         ("gui_export_html", self._export_html),
                         ("gui_export_pdf", self._export_pdf)):
            btn = ttk.Button(export, text=t(lang, key), command=cmd, state="disabled")
            btn.pack(side="left", padx=4)
            self.export_buttons.append(btn)

    # ------------------------------------------------------------ 漏洞库

    def _on_pick_db(self):
        if self._scanning or self._importing:
            return
        path = filedialog.askopenfilename(
            title=t(self.lang, "gui_pick_db"),
            filetypes=[("OSV / PythonScan ZIP", "*.zip"), ("全部文件", "*.*")])
        if not path:
            return
        self._importing = True
        self._sync_controls()
        self._set_status(t(self.lang, "gui_db_importing"), WARN)
        # 关闭窗口后仍等待准备任务释放文件句柄并清理暂存目录。
        threading.Thread(target=ScanGUI._import_worker,
                         args=(path, self.db_path, self._results, self._result_lock, self._closed),
                         daemon=False).start()

    @staticmethod
    def _import_worker(path, target, results, result_lock, closed):
        try:
            prepared = db_import.prepare_import(path, target)
            ScanGUI._deliver(results, result_lock, closed, "import", (prepared, None))
        except Exception as exc:
            ScanGUI._deliver(results, result_lock, closed, "import", (None, exc))

    @staticmethod
    def _deliver(results, result_lock, closed, kind, payload):
        # 此锁使关闭事件和队列交付成为一个不可分割的操作，不在工作线程调用 Tk。
        with result_lock:
            if closed.is_set():
                if kind == "import" and payload[0] is not None:
                    payload[0].close()
            else:
                results.put((kind, payload))

    def _poll_results(self):
        if self._closed.is_set():
            return
        while True:
            try:
                kind, payload = self._results.get_nowait()
            except queue.Empty:
                break
            if kind == "import":
                self._import_done(*payload)
            else:
                self._scan_done(*payload)
        self._poll_id = self.root.after(40, self._poll_results)

    def _sync_controls(self):
        state = "disabled" if self._scanning or self._importing else "normal"
        self.db_button.configure(state=state)
        self.scan_button.configure(state=state)
        self._set_export_enabled(state == "normal" and self.result is not None)

    def _import_done(self, prepared, error):
        try:
            if error is not None:
                raise error
            if self.database is not None:
                self.database.close()
                self.database = None
            try:
                db_import.install_import(prepared)
                self.database = db.load(self.db_path)
            except Exception as original:
                try:
                    db_import.restore_import(prepared)
                    self.database = db.load(self.db_path)
                except Exception as recovery:
                    self.database = None
                    raise DBError(f"{original}; recovery failed: {recovery}") from original
                raise
            self.result = None
            self.output.configure(state="normal")
            self.output.delete("1.0", "end")
            self.output.configure(state="disabled")
            self._refresh_db_label()
            note = t(self.lang, "gui_db_imported")
            if prepared.previous_invalid:
                note += " " + t(self.lang, "gui_db_backup_skipped")
            self._set_status(note, SAFE)
        except Exception as exc:
            if self.database is None:
                self.db_label.configure(text=t(self.lang, "gui_db_missing"), foreground=DANGER)
            else:
                self._refresh_db_label()
            self._set_status(t(self.lang, "gui_db_import_failed", error=exc), DANGER)
            messagebox.showerror(t(self.lang, "gui_title"), str(exc))
        finally:
            if prepared is not None:
                prepared.close()
            self._importing = False
            self._sync_controls()

    def _refresh_db_label(self):
        self.db_label.configure(
            text=t(self.lang, "gui_db_loaded", snapshot=self.database.snapshot,
                   records=self.database.record_count), foreground=SAFE)

    def _on_close(self):
        with self._result_lock:
            if self._closed.is_set():
                return
            self._closed.set()
            while True:
                try:
                    kind, payload = self._results.get_nowait()
                except queue.Empty:
                    break
                if kind == "import" and payload[0] is not None:
                    payload[0].close()
        if self.database is not None:
            self.database.close()
            self.database = None
        self.root.after_cancel(self._poll_id)
        self.root.destroy()
        # 错误 traceback 可能暂存 GUI 实例；先在主线程释放 Tk 引用，避免后台 GC 终结 Tcl。
        for name, value in list(vars(self).items()):
            if isinstance(value, (tk.Misc, tk.Variable)):
                setattr(self, name, None)
        self.export_buttons = []

    def _load_db(self, path: str, quiet: bool):
        try:
            candidate = db.load(path)
        except (DBError, OSError) as error:
            self.db_label.configure(text=t(self.lang, "gui_db_missing"), foreground=DANGER)
            if not quiet:
                messagebox.showerror(t(self.lang, "gui_title"), str(error))
            return
        if self.database is not None:
            self.database.close()
        self.database = candidate
        self.db_label.configure(
            text=t(self.lang, "gui_db_loaded", snapshot=self.database.snapshot,
                   records=self.database.record_count),
            foreground=SAFE)

    # ------------------------------------------------------------ 扫描

    def _on_import_file(self):
        path = filedialog.askopenfilename(
            title=t(self.lang, "gui_import_btn"),
            filetypes=[("依赖清单", "*.txt"), ("全部文件", "*.*")])
        if not path:
            return
        try:
            content = Path(path).read_text(encoding="utf-8-sig", errors="replace")
        except OSError as error:
            messagebox.showerror(t(self.lang, "gui_title"), str(error))
            return
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", content)

    def _on_clear(self):
        if self._scanning or self._importing:
            return
        self.input_text.delete("1.0", "end")
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")
        self._set_status("")
        self.result = None
        self._set_export_enabled(False)

    def _on_scan(self):
        if self._scanning or self._importing:
            return
        if self.database is None:
            messagebox.showwarning(t(self.lang, "gui_title"), t(self.lang, "gui_db_missing"))
            return
        deps, warns = _parse_text(self.input_text.get("1.0", "end"))
        if not deps:
            messagebox.showinfo(t(self.lang, "gui_title"), t(self.lang, "no_deps"))
            return
        self._scanning = True
        self._sync_controls()
        self._set_status(t(self.lang, "gui_scanning"), WARN)
        thread = threading.Thread(target=ScanGUI._scan_worker,
                                  args=(deps, warns, self.database, self.use_installed_var.get(),
                                        self._results, self._result_lock, self._closed), daemon=True)
        thread.start()

    @staticmethod
    def _scan_worker(deps, warns, database, use_installed, results, result_lock, closed):
        try:
            result = engine.scan(deps, database, source="GUI", use_installed=use_installed)
            error = None
        except Exception as exc:  # 后台线程兜底，避免界面无响应假死
            result, error = None, exc
        ScanGUI._deliver(results, result_lock, closed, "scan", (result, warns, error))

    def _scan_done(self, result, warns, error):
        self._scanning = False
        self._sync_controls()
        if error is not None:
            self._set_status(t(self.lang, "gui_scan_failed", error=error), DANGER)
            return
        self.result = result
        for line_no, raw in warns:
            result.warnings.append(t(self.lang, "parse_warn",
                                     line_no=line_no, raw=raw, reason="无法解析出包名和版本"))
        self._render(result)
        vulnerable = sum(1 for p in result.packages if p.vulnerable)
        self._set_status(t(self.lang, "gui_scan_done",
                           total=len(result.packages), vulnerable=vulnerable),
                         DANGER if vulnerable else SAFE)
        self._set_export_enabled(True)

    # ------------------------------------------------------------ 结果渲染

    def _render(self, result):
        out = self.output
        lang = self.lang
        out.configure(state="normal")
        out.delete("1.0", "end")

        def ins(text: str, tag: str | None = None):
            out.insert("end", text, (tag,) if tag else ())

        for pkg in result.packages:
            dep = pkg.dependency
            ver = dep.version or "-"
            suffix = f" ({t(lang, 'badge_unpinned')})" if dep.unpinned else ""
            if pkg.vulnerable:
                ins(t(lang, "pkg_vuln" if not dep.unpinned else "pkg_vuln_unpinned",
                      pkg=dep.display_name, ver=ver, count=len(pkg.hits)), "danger\n")
            else:
                ins(t(lang, "pkg_clean" if not dep.unpinned else "pkg_clean_unpinned",
                      pkg=dep.display_name, ver=ver), "safe\n")
            for hit in pkg.hits[:20]:
                alias = f" ({', '.join(hit.aliases)})" if hit.aliases else ""
                ins(f"  · {hit.id} ", f"sev-{hit.severity}")
                ins(f"[{hit.severity}]{alias}\n", f"sev-{hit.severity}")
                if hit.summary:
                    ins(f"      {hit.summary}\n")
                ins(f"      {t(lang, 'label_affected')}: {hit.affected or '*'}    "
                    f"{t(lang, 'label_fixed')}: {', '.join(hit.fixed_versions) or '-'}\n", "muted")
                ins(f"      {t(lang, 'label_advisory')}: {hit.url}\n", "muted")
            if len(pkg.hits) > 20:
                ins(t(lang, "more_vulns", count=len(pkg.hits) - 20) + "\n", "muted")
            if pkg.fix and (pkg.fix.upgrade_to or pkg.fix.note):
                if pkg.fix.upgrade_to:
                    ins(t(lang, "fix_suggestion", to=pkg.fix.upgrade_to,
                          covers=len(pkg.fix.covers)) + "\n", "safe")
                else:
                    ins(t(lang, "fix_suggestion_info", note=pkg.fix.note) + "\n", "warn")
            for note in pkg.notes:
                ins(f"  {localize_note(note, lang, 90)}\n", "muted")
            ins("\n")

        counts = result.severity_counts()
        ins(t(lang, "summary", total=len(result.packages),
              vulnerable=sum(1 for p in result.packages if p.vulnerable),
              unpinned=sum(1 for p in result.packages if p.dependency.unpinned),
              critical=counts.get("CRITICAL", 0), high=counts.get("HIGH", 0),
              moderate=counts.get("MODERATE", 0), low=counts.get("LOW", 0),
              unknown=counts.get("UNKNOWN", 0)) + "\n", "bold")
        for warning in result.warnings:
            ins(f"  ! {warning}\n", "warn")
        for error in result.errors:
            ins(f"  ! {error}\n", "danger")
        ins(f"{t(lang, 'report_db')}: {result.db_meta.get('snapshot', '-')}"
            f" ({result.db_meta.get('record_count', 0):,})\n", "muted")
        out.configure(state="disabled")

    # ------------------------------------------------------------ 导出

    def _set_export_enabled(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        for btn in self.export_buttons:
            btn.configure(state=state)

    def _set_status(self, text: str, color: str = MUTED):
        self.status_label.configure(text=text, foreground=color)
        self.root.update_idletasks()

    def _require_result(self) -> bool:
        if self.result is None:
            messagebox.showinfo(t(self.lang, "gui_title"), t(self.lang, "gui_need_scan_first"))
            return False
        return True

    def _export_json(self):
        if not self._require_result():
            return
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                            initialfile="pythonscan-report.json",
                                            filetypes=[("JSON", "*.json")])
        if path:
            report.write_json(self.result, path)
            self._set_status(t(self.lang, "saved", path=path), SAFE)

    def _export_html(self):
        if not self._require_result():
            return
        path = filedialog.asksaveasfilename(defaultextension=".html",
                                            initialfile="pythonscan-report.html",
                                            filetypes=[("HTML", "*.html")])
        if path:
            report.write_html(self.result, path, self.lang)
            self._set_status(t(self.lang, "saved", path=path), SAFE)

    def _export_pdf(self):
        if not self._require_result():
            return
        path = filedialog.asksaveasfilename(defaultextension=".pdf",
                                            initialfile="pythonscan-report.pdf",
                                            filetypes=[("PDF", "*.pdf")])
        if not path:
            return
        self._set_status(t(self.lang, "gui_pdf_working"), WARN)
        html_path = str(Path(path).with_suffix(".html"))
        report.write_html(self.result, html_path, self.lang)
        ok, browser = report.write_pdf(html_path, path)
        if ok:
            self._set_status(t(self.lang, "pdf_done", path=path), SAFE)
        elif not browser:
            self._set_status(t(self.lang, "pdf_no_browser") + f" ({html_path})", WARN)
        else:
            self._set_status(t(self.lang, "pdf_failed", browser=browser) + f" ({html_path})", WARN)


def run(db_path: str | None = None, lang: str = "zh") -> None:
    root = tk.Tk()
    try:
        ttk.Style().theme_use("vista")
    except tk.TclError:
        pass
    ScanGUI(root, db_path=db_path, lang=lang)
    root.mainloop()


if __name__ == "__main__":
    run()
