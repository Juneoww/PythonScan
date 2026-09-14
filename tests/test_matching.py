"""matching 单测：introduced/fixed/last_affected 边界与人工复核标记。"""

import unittest

from pythonscan.matching import affected_text, match_record


def _record(events, name="requests", rtype="ECOSYSTEM"):
    return {
        "id": "GHSA-test",
        "affected": [{"package": {"ecosystem": "PyPI", "name": name},
                      "ranges": [{"type": rtype, "events": events}]}],
    }


class TestMatchRecord(unittest.TestCase):
    def test_introduced_fixed(self):
        rec = _record([{"introduced": "2.0"}, {"fixed": "2.31.0"}])
        self.assertTrue(match_record(rec, "requests", "2.28.0").matched)
        self.assertFalse(match_record(rec, "requests", "1.9.9").matched)
        self.assertFalse(match_record(rec, "requests", "2.31.0").matched)
        self.assertTrue(match_record(rec, "Requests", "2.0").matched)  # 大小写归一

    def test_zero_introduced(self):
        rec = _record([{"introduced": "0"}, {"fixed": "2.3.0"}])
        self.assertTrue(match_record(rec, "requests", "0.5").matched)
        self.assertFalse(match_record(rec, "requests", "2.3.0").matched)

    def test_last_affected_inclusive(self):
        rec = _record([{"introduced": "1.0"}, {"last_affected": "2.0"}])
        self.assertTrue(match_record(rec, "requests", "2.0").matched)
        self.assertFalse(match_record(rec, "requests", "2.0.1").matched)

    def test_open_ended(self):
        rec = _record([{"introduced": "1.0"}])
        self.assertTrue(match_record(rec, "requests", "99.0").matched)

    def test_multiple_segments(self):
        rec = _record([{"introduced": "1.0"}, {"fixed": "1.5"},
                       {"introduced": "2.0"}, {"fixed": "2.3.0"}])
        self.assertTrue(match_record(rec, "requests", "1.2").matched)
        self.assertFalse(match_record(rec, "requests", "1.7").matched)
        self.assertTrue(match_record(rec, "requests", "2.2").matched)

    def test_pre_release_boundaries(self):
        rec = _record([{"introduced": "0"}, {"fixed": "2.3.0"}])
        self.assertTrue(match_record(rec, "requests", "2.3rc1").matched)
        self.assertFalse(match_record(rec, "requests", "2.3.post1").matched)

    def test_fixed_versions_collected_even_without_match(self):
        rec = _record([{"introduced": "2.0"}, {"fixed": "2.31.0"}])
        outcome = match_record(rec, "requests", "1.0")
        self.assertEqual(outcome.fixed_versions, ["2.31.0"])

    def test_unparseable_version_is_manual_review(self):
        rec = _record([{"introduced": "0"}, {"fixed": "2.3.0"}])
        outcome = match_record(rec, "requests", "????")
        self.assertFalse(outcome.matched)
        self.assertTrue(outcome.manual_review)

    def test_unparseable_bound_is_manual_review(self):
        rec = _record([{"introduced": "0"}, {"fixed": "not-a-version"}])
        outcome = match_record(rec, "requests", "1.0")
        self.assertFalse(outcome.matched)
        self.assertTrue(outcome.manual_review)

    def test_git_range_skipped(self):
        rec = _record([{"introduced": "0"}], rtype="GIT")
        outcome = match_record(rec, "requests", "1.0")
        self.assertFalse(outcome.matched)
        self.assertEqual(outcome.skipped_ranges, 1)

    def test_wrong_package_no_match(self):
        rec = _record([{"introduced": "0"}], name="flask")
        self.assertFalse(match_record(rec, "requests", "1.0").matched)

    def test_explicit_versions_list(self):
        rec = {"id": "X", "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                                        "versions": ["1.2.0", "1.3.0"]}]}
        self.assertTrue(match_record(rec, "requests", "1.3.0").matched)
        self.assertFalse(match_record(rec, "requests", "1.4.0").matched)

    def test_affected_text(self):
        entry = {"package": {"ecosystem": "PyPI", "name": "requests"},
                 "ranges": [{"type": "ECOSYSTEM",
                             "events": [{"introduced": "2.0"}, {"fixed": "2.31.0"}]}]}
        self.assertEqual(affected_text(entry), ">=2.0, <2.31.0")
        entry = {"package": {"ecosystem": "PyPI", "name": "requests"},
                 "ranges": [{"type": "ECOSYSTEM",
                             "events": [{"introduced": "0"}, {"fixed": "2.3.0"}]}]}
        self.assertEqual(affected_text(entry), "<2.3.0")


if __name__ == "__main__":
    unittest.main()
