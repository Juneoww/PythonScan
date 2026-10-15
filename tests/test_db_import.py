"""功能：验证持久化导入、完整性检查、备份和失败恢复，不使用用户默认库。
实现：临时全量库与原始 ZIP，真实磁盘替换加少量故障注入。
输入：测试公告；输出：unittest 结果，临时文件自动清理。
"""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from pythonscan import db, engine
from pythonscan.inputspec import parse_line
from test_osv import advisory


class TestImport(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.work = Path(temp.name)
        self.live = self.work / "managed.zip"
        self.backup = self.work / "managed.zip.bak"

    def raw(self, version="1.0"):
        path = self.work / (version + ".zip")
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("record.json", json.dumps(advisory(versions=[version])))
        return path

    def full(self, path=None, version="1.0"):
        path = path or self.work / "full.zip"
        db.write_full_db({"demo": [advisory(versions=[version])]}, str(path), snapshot="2026-10-11")
        return path

    def vulnerable(self, path=None):
        with db.load(path or self.live) as database:
            return engine.scan([parse_line("demo==1.0")], database).vulnerable

    def test_raw_import_persists_replacement_and_backup(self):
        first, second = self.raw(), self.raw("2.0")
        original = first.read_bytes()
        try:
            meta = db.import_db(str(first), self.live)
        except db.DBError as exc:
            self.fail(f"应支持原始 OSV ZIP 导入: {exc}")
        self.assertTrue(self.vulnerable())
        self.assertEqual(meta["snapshot"], "2026-10-11")
        self.assertEqual(meta["source_sha256"], hashlib.sha256(original).hexdigest())
        self.assertIn("imported_at", meta)
        self.assertFalse(self.backup.exists())
        db.import_db(str(second), self.live)
        self.assertFalse(self.vulnerable())
        self.assertTrue(self.vulnerable(self.backup))
        self.assertEqual(first.read_bytes(), original)

    def rewrite(self, source, change):
        with zipfile.ZipFile(source) as archive:
            entries = {n: archive.read(n) for n in archive.namelist()}
        change(entries)
        with zipfile.ZipFile(source, "w") as archive:
            for name, value in entries.items():
                archive.writestr(name, value)

    def test_declared_hash_and_index_coverage_and_counts_required(self):
        for problem in ["missing_hash", "missing_data", "count", "schema", "bad_json", "unindexed"]:
            with self.subTest(problem=problem):
                source = self.full()
                self.full(self.live, "2.0")
                before = self.live.read_bytes()

                def change(entries):
                    manifest = json.loads(entries["manifest.json"])
                    if problem == "missing_hash": manifest["files"].pop("data/demo.json")
                    if problem == "missing_data": entries.pop("data/demo.json")
                    if problem == "count": manifest["record_count"] = 999
                    if problem == "schema": manifest["schema_version"] = 99
                    if problem == "bad_json": entries["data/demo.json"] = b"{}"
                    if problem == "unindexed": entries["data/other.json"] = b"[]"
                    entries["manifest.json"] = json.dumps(manifest).encode()

                self.rewrite(source, change)
                with self.assertRaises(db.DBError):
                    db.import_db(str(source), self.live)
                self.assertEqual(self.live.read_bytes(), before)

    def test_same_path_only_validates_without_backup(self):
        self.full(self.live)
        before = self.live.read_bytes()
        db.import_db(str(self.live), self.live)
        self.assertEqual(self.live.read_bytes(), before)
        self.assertFalse(self.backup.exists())

    def test_repair_damaged_target_preserves_good_backup(self):
        self.full(self.backup)
        before = self.backup.read_bytes()
        self.live.write_bytes(b"broken")
        db.import_db(str(self.full(version="2.0")), self.live)
        self.assertFalse(self.vulnerable())
        self.assertEqual(self.backup.read_bytes(), before)

    def test_prepare_does_not_change_live_and_cleans_temp(self):
        from pythonscan import db_import
        self.full(self.live)
        before = self.live.read_bytes()
        prepared = db_import.prepare_import(self.raw("2.0"), self.live)
        candidate = prepared.candidate
        self.assertEqual(self.live.read_bytes(), before)
        self.assertTrue(candidate.exists())
        prepared.close()
        self.assertFalse(candidate.exists())

    def test_backup_and_live_replace_failures_leave_old_live(self):
        from pythonscan import db_import
        for phase in ["copy", "backup", "live"]:
            with self.subTest(phase=phase):
                self.full(self.live)
                before = self.live.read_bytes()
                prepared = db_import.prepare_import(self.raw("2.0"), self.live)
                try:
                    replace = db_import.os.replace

                    def fail_replace(src, dst):
                        if Path(dst) == (self.backup if phase == "backup" else self.live):
                            raise PermissionError("injected replacement failure")
                        return replace(src, dst)

                    if phase == "copy":
                        guard = patch.object(db_import.shutil, "copyfile", side_effect=OSError("copy failure"))
                    else:
                        guard = patch.object(db_import.os, "replace", side_effect=fail_replace)
                    with guard, self.assertRaises((OSError, db.DBError)):
                        db_import.install_import(prepared)
                    self.assertEqual(self.live.read_bytes(), before)
                finally:
                    prepared.close()

    def test_restore_and_restore_failure_report(self):
        from pythonscan import db_import
        self.full(self.live)
        before = self.live.read_bytes()
        prepared = db_import.prepare_import(self.raw("2.0"), self.live)
        try:
            db_import.install_import(prepared)
            self.assertFalse(self.vulnerable())
            with patch.object(db_import.os, "replace", side_effect=PermissionError("restore blocked")):
                with self.assertRaises((OSError, db.DBError)):
                    db_import.restore_import(prepared)
            db_import.restore_import(prepared)
            self.assertEqual(self.live.read_bytes(), before)
        finally:
            prepared.close()

    def test_invalid_raw_and_delta_leave_input_and_live_intact(self):
        self.full(self.live)
        before = self.live.read_bytes()
        broken = self.work / "bad.zip"
        broken.write_bytes(b"not zip")
        delta = self.work / "delta.zip"
        db.write_delta_db(str(self.live), {"demo": [advisory(versions=["2.0"])]}, str(delta))
        for source in [broken, delta]:
            original = source.read_bytes()
            with self.assertRaises(db.DBError):
                db.import_db(str(source), self.live)
            self.assertEqual(self.live.read_bytes(), before)
            self.assertEqual(source.read_bytes(), original)

    def test_indexed_record_must_affect_its_package(self):
        wrong = advisory(versions=["1.0"])
        wrong["affected"][0]["package"]["name"] = "other"
        source = self.work / "wrong-package.zip"
        db.write_full_db({"demo": [wrong]}, str(source))
        with self.assertRaises(db.DBError):
            db.import_db(str(source), self.live)


if __name__ == "__main__":
    unittest.main()
