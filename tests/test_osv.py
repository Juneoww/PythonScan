"""功能：验证离线 OSV 转换和版本匹配；使用临时 ZIP，不访问网络或真实库。
实现：用小规模公告覆盖版本枚举、多来源合并、撤回和错误数据。
输入：标准库构造的 OSV 记录；输出：unittest 断言，临时文件自动清理。
"""

import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from pythonscan.matching import match_record

try:
    from pythonscan.osv import OSVError, load_osv_zip
except ImportError:
    OSVError, load_osv_zip = ValueError, None


def advisory(rid="GHSA-demo", versions=None, events=None, **extra):
    entry = {"package": {"ecosystem": "PyPI", "name": "demo"}}
    if versions is not None:
        entry["versions"] = versions
    if events is not None:
        entry["ranges"] = [{"type": "ECOSYSTEM", "events": events}]
    return dict({"id": rid, "modified": "2026-10-10T23:00:00-03:00",
                 "affected": [entry]}, **extra)


class TestOSV(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "all.zip"

    def raw(self, *records):
        with zipfile.ZipFile(self.path, "w") as archive:
            for index, record in enumerate(records):
                archive.writestr(f"{index}.json", json.dumps(record))
        return self.path

    def load(self, path):
        self.assertIsNotNone(load_osv_zip, "缺少扫描器内置的离线 OSV 转换接口")
        return load_osv_zip(path)

    def test_versions_and_snapshot_survive_conversion(self):
        records, snapshot = self.load(self.raw(advisory(versions=["1.0"])))
        self.assertEqual(snapshot, "2026-10-11")
        self.assertTrue(match_record(records["demo"][0], "demo", "1.0").matched)
        self.assertFalse(match_record(records["demo"][0], "demo", "2.0").matched)

    def test_versions_with_git_range_are_matched(self):
        record = advisory(versions=["1.0"])
        record["affected"][0]["ranges"] = [{"type": "GIT", "repo": "https://example.com/repo",
                                             "events": [{"introduced": "0"}]}]
        records, _ = self.load(self.raw(record))
        self.assertTrue(match_record(records["demo"][0], "demo", "1.0").matched)

    def test_alias_merge_preserves_versions_and_open_range(self):
        first = advisory(versions=["1.0"], aliases=["CVE-2026-1"])
        second = advisory("PYSEC-demo", events=[{"introduced": "2.0"}], aliases=["CVE-2026-1"])
        third = advisory("GHSA-other", events=[{"introduced": "4.0"}, {"fixed": "5.0"}],
                         aliases=["CVE-2026-1"])
        records, _ = self.load(self.raw(first, second, third))
        self.assertEqual(len(records["demo"]), 1)
        record = records["demo"][0]
        for version in ["1.0", "3.0", "6.0"]:
            self.assertTrue(match_record(record, "demo", version).matched, version)
        self.assertEqual(len(record["sources"]), 3)

    def test_withdrawn_and_non_pypi_records_are_excluded(self):
        other = advisory("GHSA-other", versions=["1.0"])
        other["affected"][0]["package"]["ecosystem"] = "npm"
        records, _ = self.load(self.raw(advisory(versions=["1.0"]), other,
                                       advisory("GHSA-withdrawn", versions=["3.0"],
                                                withdrawn="2026-10-12T00:00:00Z")))
        self.assertEqual(len(records["demo"]), 1)
        self.assertEqual(records["demo"][0]["id"], "GHSA-demo")

    def test_invalid_core_types_and_dates_are_rejected(self):
        for record in [[], advisory(versions="1.0"), advisory(modified="yesterday"),
                       advisory(affected={}), advisory(aliases="CVE-1"),
                       advisory(events=[{"introduced": 1}]), advisory(id="")]:
            with self.subTest(record=record):
                with self.assertRaises(OSVError):
                    self.load(self.raw(record))

    def test_bad_json_names_the_problem_file(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("broken.json", "{")
        with self.assertRaisesRegex(OSVError, "broken.json"):
            self.load(self.path)

    def test_empty_or_withdrawn_only_archive_is_rejected(self):
        with self.assertRaises(OSVError):
            self.load(self.raw())
        with self.assertRaises(OSVError):
            self.load(self.raw(advisory(versions=["1.0"], withdrawn="2026-10-12T00:00:00Z")))

    def test_withdrawn_historical_package_does_not_block_live_data(self):
        withdrawn = advisory("MAL-historical", versions=["1.0"], withdrawn="2024-12-12T11:22:57Z")
        withdrawn["affected"][0]["package"]["name"] = "urlcon-"
        records, _ = self.load(self.raw(advisory(versions=["1.0"]), withdrawn))
        self.assertEqual(set(records), {"demo"})

    def test_malformed_ecosystem_is_not_silently_skipped(self):
        broken = advisory("GHSA-broken", versions=["1.0"])
        broken["affected"][0]["package"]["ecosystem"] = ["PyPI"]
        with self.assertRaisesRegex(OSVError, "1.json"):
            self.load(self.raw(advisory(versions=["1.0"]), broken))


if __name__ == "__main__":
    unittest.main()
