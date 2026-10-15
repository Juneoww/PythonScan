"""功能：通过隐藏 Tk 窗口和真实事件循环验证导入、恢复与关闭行为。
实现：只模拟文件选择和错误弹窗，转换、安装、扫描均使用真实临时库。
输入：OSV 测试 ZIP；输出：unittest 断言；不访问用户默认漏洞库。
"""
from pathlib import Path
import json
import tempfile
import subprocess
import sys
import threading
import time
import tkinter as tk
import unittest
from unittest.mock import patch
import zipfile

from pythonscan import db, engine, gui
from pythonscan.inputspec import parse_line
from test_osv import advisory


class TestGUIImport(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.work = Path(temp.name)
        self.live = self.work / "managed.zip"
        self.raw = self.work / "all.zip"
        with zipfile.ZipFile(self.raw, "w") as archive:
            archive.writestr("demo.json", json.dumps(advisory(versions=["1.0"])))
        try:
            self.root = tk.Tk()
        except tk.TclError as error:
            self.skipTest(str(error))
        self.root.withdraw()
        self.app = gui.ScanGUI(self.root, str(self.live), lang="en")
        self.addCleanup(lambda: self.app._on_close() if not self.app._closed.is_set() else None)
        error_patch = patch.object(gui.messagebox, "showerror")
        self.errors = error_patch.start()
        self.addCleanup(error_patch.stop)
        self.app.input_text.delete("1.0", "end")
        self.app.input_text.insert("1.0", "demo==1.0")

    def wait_idle(self):
        deadline = time.monotonic() + 10

        def poll():
            if not getattr(self.app, "_importing", False) and not self.app._scanning:
                self.root.quit()
            elif time.monotonic() >= deadline:
                self.root.quit()
            else:
                self.root.after(20, poll)

        self.root.after(20, poll)
        self.root.mainloop()
        self.assertFalse(getattr(self.app, "_importing", False))
        self.assertFalse(self.app._scanning)

    def choose(self, path):
        with patch.object(gui.filedialog, "askopenfilename", return_value=str(path)):
            self.app._on_pick_db()
        self.wait_idle()

    def test_import_scan_and_restart_persistence(self):
        self.choose(self.raw)
        self.assertTrue(self.live.exists(), "选择原始 ZIP 应持久化到管理路径")
        self.assertIsNotNone(self.app.database)
        self.app._on_scan()
        self.wait_idle()
        self.assertTrue(self.app.result.vulnerable)
        self.assertEqual(self.app.input_text.get("1.0", "end").strip(), "demo==1.0")
        self.app.database.close()
        self.app.database = None
        with db.load(self.live) as restarted:
            self.assertEqual(restarted.snapshot, "2026-10-11")
            self.assertTrue(engine.scan([parse_line("demo==1.0")], restarted).vulnerable)

    def test_success_clears_old_result_and_failure_keeps_it(self):
        self.choose(self.raw)
        self.assertIsNotNone(self.app.database, "应支持导入原始 ZIP")
        self.app._on_scan()
        self.wait_idle()
        old_result = self.app.result
        bad = self.work / "bad.zip"
        bad.write_bytes(b"bad")
        self.choose(bad)
        self.assertIs(self.app.result, old_result)
        self.assertIsNotNone(self.app.database)
        self.assertTrue(self.errors.called)
        self.choose(self.raw)
        self.assertIsNone(self.app.result)
        self.assertEqual(str(self.app.export_buttons[0]["state"]), "disabled")

    def test_reload_failure_restores_old_db(self):
        self.choose(self.raw)
        self.assertIsNotNone(self.app.database, "应支持导入原始 ZIP")
        before = self.live.read_bytes()
        new = self.work / "new.zip"
        with zipfile.ZipFile(new, "w") as archive:
            archive.writestr("demo.json", json.dumps(advisory(versions=["2.0"])))
        original_load = db.load
        calls = []

        def load(path=None):
            calls.append(path)
            if len(calls) == 2:
                raise db.DBError("injected GUI reload failure")
            return original_load(path)

        with patch.object(db, "load", side_effect=load):
            self.choose(new)
        self.assertEqual(self.live.read_bytes(), before)
        self.assertIsNotNone(self.app.database)
        self.assertTrue(self.errors.called)

    def test_import_and_scan_are_mutually_exclusive(self):
        self.app._scanning = True
        with patch.object(gui.filedialog, "askopenfilename") as picker:
            self.app._on_pick_db()
        self.app._scanning = False
        self.assertFalse(picker.called, "扫描期间不能启动导入")

    def test_close_discards_late_preparation(self):
        from pythonscan import db_import
        started, release, cleaned = threading.Event(), threading.Event(), threading.Event()
        original = db_import.prepare_import

        def prepare(*args):
            prepared = original(*args)
            close = prepared.close

            def cleanup():
                close()
                cleaned.set()

            prepared.close = cleanup
            started.set()
            release.wait(5)
            return prepared

        with patch.object(db_import, "prepare_import", side_effect=prepare):
            with patch.object(gui.filedialog, "askopenfilename", return_value=str(self.raw)):
                self.app._on_pick_db()
            self.assertTrue(started.wait(5), "应在后台准备 OSV 导入")
            self.app._on_close()
            release.set()
            self.assertTrue(cleaned.wait(5), "关闭后应清理迟到的准备结果")
        self.assertFalse(self.live.exists())

    def test_process_exit_waits_for_import_cleanup(self):
        script = '''"""功能：在真实进程退出时验证导入文件句柄及临时目录清理。"""
import sys, threading, time, tkinter as tk
from pythonscan import gui, db_import
root=tk.Tk(); root.withdraw()
app=gui.ScanGUI(root, sys.argv[2])
started=threading.Event()
original=db_import.prepare_import
def prepare(*args):
    result=original(*args)
    with open(result.candidate, 'rb'):
        started.set()
        app._closed.wait(5)
        time.sleep(0.15)
    return result
db_import.prepare_import=prepare
gui.filedialog.askopenfilename=lambda **kw: sys.argv[1]
app._on_pick_db()
def poll():
    if started.is_set(): app._on_close()
    else: root.after(10,poll)
root.after(10,poll)
root.mainloop()
'''
        result = subprocess.run([sys.executable, "-c", script, str(self.raw),
                                 str(self.work / "child.zip")], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.work.glob(".pythonscan-import-*")), [])

    def test_closed_window_is_not_owned_by_background_worker(self):
        script = '''"""功能：复现窗口关闭后工作线程最后释放 Tk 对象的跨线程终结问题。"""
import sys, threading, tkinter as tk
from pythonscan import gui, db_import
root=tk.Tk(); root.withdraw()
app=gui.ScanGUI(root, sys.argv[2])
started=threading.Event(); release=threading.Event()
original=db_import.prepare_import
def prepare(*args):
    result=original(*args)
    started.set(); release.wait(5)
    return result
db_import.prepare_import=prepare
gui.filedialog.askopenfilename=lambda **kw:sys.argv[1]
app._on_pick_db()
assert started.wait(5)
app._on_close()
del app, root
release.set()
for thread in threading.enumerate():
    if thread is not threading.current_thread():thread.join(5)
'''
        result = subprocess.run([sys.executable, '-c', script, str(self.raw),
                                 str(self.work / 'child-owned.zip')], capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(b'main thread is not in main loop', result.stderr)


if __name__ == "__main__":
    unittest.main()
