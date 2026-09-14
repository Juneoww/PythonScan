"""engine 端到端单测：匹配、修复建议、未固定版本、fail-fast 与 JSON schema。"""

import json
import tempfile
import unittest
from pathlib import Path

from pythonscan import db, engine
from pythonscan.inputspec import Dependency


def _record(rid, fixed, introduced="2.0", level="HIGH", name="requests"):
    return {
        "id": rid,
        "aliases": [f"GHSA-{rid}" ] if not rid.startswith("GHSA") else [],
        "summary": f"vuln {rid}",
        "database_specific": {"severity": level},
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}] if level != "UNKNOWN" else [],
        "affected": [{"package": {"ecosystem": "PyPI", "name": name},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": introduced}, {"fixed": fixed}]}]}],
        "fixed_versions": [fixed],
        "affected_text": f">={introduced}, <{fixed}",
        "references": ["https://example.com"],
        "sources": [rid],
    }


class TestEngine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "db.zip"
        db.write_full_db(
            {
                "requests": [_record("CVE-2023-32681", "2.31.0", introduced="2.0", level="HIGH"),
                             _record("GHSA-old", "2.3.0", introduced="0", level="LOW")],
                "flask": [_record("GHSA-f1", "1.0", introduced="0", level="CRITICAL", name="flask")],
            },
            out_path=str(self.db_path), snapshot="2026-09-13", latest={"requests": "2.32.5"})
        self.vdb = db.VulnDB(self.db_path)

    def tearDown(self):
        self.vdb.close()
        self.tmp.cleanup()

    def _dep(self, name, version=None):
        return Dependency(raw=f"{name}=={version}" if version else name, name=name,
                          display_name=name, version=version)

    def test_vulnerable_package_with_fix(self):
        result = engine.scan([self._dep("requests", "2.28.0")], self.vdb)
        pkg = result.packages[0]
        self.assertTrue(pkg.vulnerable)
        self.assertEqual(len(pkg.hits), 1)  # 2.28.0 只命中 <2.31.0 那条
        self.assertEqual(pkg.hits[0].id, "CVE-2023-32681")
        self.assertEqual(pkg.fix.upgrade_to, "2.31.0")
        self.assertEqual(pkg.fix.covers, ["CVE-2023-32681"])
        self.assertEqual(pkg.fix.confidence, "high")

    def test_clean_version(self):
        result = engine.scan([self._dep("requests", "2.32.0")], self.vdb)
        pkg = result.packages[0]
        self.assertFalse(pkg.vulnerable)
        self.assertEqual(pkg.hits, [])
        self.assertIsNone(pkg.fix)

    def test_unpinned_lists_all_with_latest_suggestion(self):
        result = engine.scan([self._dep("requests")], self.vdb)
        pkg = result.packages[0]
        self.assertTrue(pkg.vulnerable)
        self.assertEqual(len(pkg.hits), 2)
        self.assertTrue(pkg.dependency.unpinned)
        self.assertEqual(pkg.fix.latest, "2.32.5")
        self.assertTrue(pkg.fix.latest_clean)
        self.assertEqual(pkg.fix.upgrade_to, "2.32.5")

    def test_unknown_package_is_clean(self):
        result = engine.scan([self._dep("no-such-pkg", "1.0")], self.vdb)
        self.assertFalse(result.packages[0].vulnerable)
        self.assertFalse(result.vulnerable)

    def test_fail_fast_stops_after_first_vuln(self):
        deps = [self._dep("flask", "0.12.2"), self._dep("requests", "2.28.0")]
        result = engine.scan(deps, self.vdb, fail_fast=True)
        self.assertEqual(len(result.packages), 1)
        self.assertTrue(result.errors)

    def test_severity_sorting(self):
        result = engine.scan([self._dep("requests")], self.vdb)
        ranks = [h.rank for h in result.packages[0].hits]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_json_schema(self):
        result = engine.scan([self._dep("requests", "2.28.0"), self._dep("nope", "1.0")], self.vdb,
                             source="requirements.txt")
        data = result.to_dict()
        self.assertEqual(data["schema"], "pythonscan-result/v1")
        self.assertEqual(data["scan"]["total"], 2)
        self.assertEqual(data["scan"]["vulnerable"], 1)
        self.assertEqual(data["scan"]["source"], "requirements.txt")
        entry = data["results"][0]
        for key in ("package", "version", "version_source", "unpinned", "vulnerable",
                    "vulnerabilities", "fix_suggestion", "notes"):
            self.assertIn(key, entry)
        vuln = entry["vulnerabilities"][0]
        for key in ("id", "aliases", "severity", "summary", "affected",
                    "fixed_versions", "references", "url", "source"):
            self.assertIn(key, vuln)
        self.assertIn("level", vuln["severity"])
        # JSON 可序列化
        json.dumps(data, ensure_ascii=False)


if __name__ == "__main__":
    unittest.main()
