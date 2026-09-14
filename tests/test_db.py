"""db 单测：全量库构建/加载/导入校验与增量合并。"""

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from pythonscan import db
from pythonscan.db import DBError, VulnDB, import_db, update_db, write_delta_db, write_full_db


def _record(rid, fixed="2.31.0", introduced="2.0"):
    return {
        "id": rid,
        "aliases": [],
        "summary": f"summary {rid}",
        "database_specific": {"severity": "HIGH"},
        "severity": [],
        "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": introduced}, {"fixed": fixed}]}]}],
        "fixed_versions": [fixed],
        "affected_text": f">={introduced}, <{fixed}",
        "references": [],
        "sources": [rid],
    }


class TestFullDb(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.db_path = self.dir / "vulndb.zip"
        self.manifest = write_full_db(
            {"requests": [_record("CVE-1"), _record("CVE-2", fixed="2.20.0")],
             "flask": [_record("GHSA-f1", fixed="1.0")]},
            out_path=str(self.db_path), snapshot="2026-09-13",
            latest={"requests": "2.32.5"})

    def tearDown(self):
        self.tmp.cleanup()

    def test_manifest_shape(self):
        self.assertEqual(self.manifest["kind"], "full")
        self.assertEqual(self.manifest["snapshot"], "2026-09-13")
        self.assertEqual(self.manifest["record_count"], 3)
        self.assertEqual(self.manifest["package_count"], 2)
        self.assertNotIn(db.MANIFEST_NAME, self.manifest["files"])

    def test_load_and_query(self):
        with VulnDB(self.db_path) as vdb:
            self.assertEqual(vdb.snapshot, "2026-09-13")
            self.assertEqual(len(vdb.get("requests")), 2)
            self.assertEqual(vdb.get("nope"), [])
            self.assertEqual(vdb.latest("requests"), "2.32.5")
            self.assertIsNone(vdb.latest("flask"))

    def test_import_then_load(self):
        target = self.dir / "sub" / "imported.zip"
        manifest = import_db(str(self.db_path), target)
        self.assertEqual(manifest["snapshot"], "2026-09-13")
        with VulnDB(target) as vdb:
            self.assertEqual(len(vdb.get("flask")), 1)

    def test_import_rejects_tampered_file(self):
        src = self.dir / "tampered.zip"
        with zipfile.ZipFile(self.db_path) as zin, zipfile.ZipFile(src, "w") as zout:
            for name in zin.namelist():
                blob = zin.read(name)
                if name.startswith("data/"):
                    blob = blob[:-1] + b"}"   # 破坏内容
                zout.writestr(name, blob)
        with self.assertRaises(DBError):
            import_db(str(src), self.dir / "x.zip")

    def test_load_missing_file(self):
        with self.assertRaises(DBError):
            VulnDB(self.dir / "nothing.zip")


class TestDelta(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.v1 = self.dir / "v1.zip"
        write_full_db({"requests": [_record("CVE-1")],
                       "flask": [_record("GHSA-f1")],
                       "oldpkg": [_record("CVE-old")]},
                      out_path=str(self.v1), snapshot="20260901")

    def tearDown(self):
        self.tmp.cleanup()

    def _apply(self, v2_records, snapshot="20260913"):
        delta = self.dir / "delta.zip"
        write_delta_db(self.v1, v2_records, out_path=str(delta), snapshot=snapshot)
        target = self.dir / "live.zip"
        import_db(str(self.v1), target)
        return update_db(str(delta), target)

    def test_add_update_delete(self):
        manifest = self._apply({"requests": [_record("CVE-1"), _record("CVE-2")],
                                "flask": [_record("GHSA-f1")]})
        self.assertEqual(manifest["snapshot"], "20260913")
        self.assertEqual(manifest["base"], "20260901")
        with VulnDB(self.dir / "live.zip") as vdb:
            self.assertEqual(len(vdb.get("requests")), 2)
            self.assertEqual(len(vdb.get("flask")), 1)
            self.assertEqual(vdb.get("oldpkg"), [])
            self.assertEqual(vdb.manifest["record_count"], 3)
            self.assertEqual(vdb.manifest["package_count"], 2)

    def test_unchanged_package_not_in_delta(self):
        delta = self.dir / "delta.zip"
        manifest = write_delta_db(self.v1, {"requests": [_record("CVE-1")],
                                            "flask": [_record("GHSA-f1")],
                                            "oldpkg": [_record("CVE-old")]},
                                  out_path=str(delta), snapshot="20260913")
        self.assertEqual(manifest["stats"]["upserts"], 0)
        with zipfile.ZipFile(delta) as zf:
            self.assertNotIn("data/requests.json", zf.namelist())

    def test_base_mismatch_rejected(self):
        delta = self.dir / "delta.zip"
        write_delta_db(self.v1, {"requests": [_record("CVE-1")]},
                       out_path=str(delta), snapshot="20260913")
        target = self.dir / "live.zip"
        import_db(str(self.v1), target)
        # 把当前库快照改成不衔接的日期
        with zipfile.ZipFile(target) as zf:
            manifest = json.loads(zf.read(db.MANIFEST_NAME).decode("utf-8"))
            manifest["snapshot"] = "20990101"
            items = [(n, zf.read(n)) for n in zf.namelist() if n != db.MANIFEST_NAME]
        with zipfile.ZipFile(target, "w") as zf:
            for name, blob in items:
                zf.writestr(name, blob)
            zf.writestr(db.MANIFEST_NAME, json.dumps(manifest))
        with self.assertRaises(DBError):
            update_db(str(delta), target)

    def test_delta_rejected_on_full_db_file(self):
        with self.assertRaises(DBError):
            update_db(str(self.v1), self.dir / "nonexistent-target.zip")


if __name__ == "__main__":
    unittest.main()
