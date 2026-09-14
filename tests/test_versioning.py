"""versioning 单测：版本排序规则与解析边界。"""

import unittest

from pythonscan.versioning import InvalidVersion, Version, normalize_name


class TestVersionOrdering(unittest.TestCase):
    def test_ascending_chain(self):
        chain = ["0.9", "1.0.dev1", "1.0a1.dev1", "1.0a1", "1.0b2", "1.0rc1",
                 "1.0", "1.0.post1.dev1", "1.0.post1", "1.1", "1.2.0", "2.0", "1!0.1"]
        versions = [Version(v) for v in chain]
        for low, high in zip(versions, versions[1:]):
            self.assertLess(low, high, f"{low} 应小于 {high}")

    def test_zero_padding_equivalence(self):
        self.assertEqual(Version("2.3"), Version("2.3.0"))
        self.assertEqual(Version("1.0.0"), Version("1"))

    def test_pre_aliases(self):
        self.assertEqual(Version("1.0c1"), Version("1.0rc1"))
        self.assertEqual(Version("1.0alpha2"), Version("1.0a2"))
        self.assertEqual(Version("1.0preview1"), Version("1.0rc1"))

    def test_v_prefix_and_whitespace(self):
        self.assertEqual(Version("v2.28.0"), Version("2.28.0"))
        self.assertEqual(Version(" 1.0 "), Version("1.0"))

    def test_invalid(self):
        for text in ["", "abc", "1.0.*", "1.0.x.y", ">=1.0", "1.0 beta!!"]:
            with self.assertRaises(InvalidVersion, msg=text):
                Version(text)

    def test_is_zero(self):
        self.assertTrue(Version("0.0.0").is_zero())
        self.assertTrue(Version("0").is_zero())
        self.assertFalse(Version("0.1").is_zero())
        self.assertFalse(Version("0.0.dev1").is_zero())


class TestNormalizeName(unittest.TestCase):
    def test_pep503(self):
        self.assertEqual(normalize_name("Django"), "django")
        self.assertEqual(normalize_name("python_dateutil"), "python-dateutil")
        self.assertEqual(normalize_name("Flask-_-.X"), "flask-x")


if __name__ == "__main__":
    unittest.main()
