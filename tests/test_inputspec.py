"""inputspec 单测：四种写法、容错与告警。"""

import unittest

from pythonscan.inputspec import (Dependency, InvalidDependency, parse_line)


class TestParseLine(unittest.TestCase):
    def test_four_syntaxes(self):
        for line in ["requests==2.28.0", "requests@2.28.0", "requests 2.28.0", "requests === 2.28.0"]:
            dep = parse_line(line)
            self.assertEqual(dep.name, "requests", msg=line)
            self.assertEqual(dep.version, "2.28.0", msg=line)
            self.assertFalse(dep.unpinned)

    def test_bare_name(self):
        dep = parse_line("requests")
        self.assertEqual(dep.name, "requests")
        self.assertIsNone(dep.version)
        self.assertEqual(dep.note, "未固定版本")

    def test_name_normalization(self):
        self.assertEqual(parse_line("Django").name, "django")
        self.assertEqual(parse_line("python_dateutil==2.8").name, "python-dateutil")

    def test_extras_and_markers(self):
        dep = parse_line("requests[security,socks]==2.28.0")
        self.assertEqual((dep.name, dep.version), ("requests", "2.28.0"))
        dep = parse_line("numpy>=1.21; python_version >= '3.10'")
        self.assertEqual(dep.name, "numpy")
        self.assertIsNone(dep.version)

    def test_comments_and_blank(self):
        self.assertIsNone(parse_line("# 全部注释"))
        self.assertIsNone(parse_line("   "))
        dep = parse_line("requests==2.28.0  # 内网基线")
        self.assertEqual(dep.version, "2.28.0")

    def test_range_operator_treated_unpinned(self):
        dep = parse_line("flask>=0.12")
        self.assertIsNone(dep.version)
        self.assertIn("未固定", dep.note)

    def test_wildcard_treated_unpinned(self):
        dep = parse_line("flask==1.0.*")
        self.assertIsNone(dep.version)
        self.assertIn("通配符", dep.note)

    def test_v_prefix(self):
        self.assertEqual(parse_line("requests==v2.28.0").version, "2.28.0")

    def test_invalid_raises(self):
        for line in ["==1.0", "requests==", "@2.0", "!!!"]:
            with self.assertRaises(InvalidDependency, msg=line):
                parse_line(line)


if __name__ == "__main__":
    unittest.main()
