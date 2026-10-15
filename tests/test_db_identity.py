"""功能：验证实际内容身份、重复导入和增量启用状态。
实现：使用真实临时库、同内容重打包及安装故障注入，不访问默认用户库。
输入：最小公告；输出：unittest 断言；仅依赖标准库。
"""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from pythonscan import db
from test_osv import advisory


class TestIdentity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.live = self.root / 'live.zip'

    def full(self, name, version='1.0', **metadata):
        path = self.root / name
        db.write_full_db({'demo': [advisory(versions=[version])]}, str(path),
                         snapshot='2026-10-15', metadata=metadata)
        return path

    def assert_identity(self, path):
        info = db.db_info(path)
        self.assertIn('version_id', info, '应追踪实际启用库版本')
        self.assertRegex(info['content_sha256'], r'^[a-f0-9]{64}$')
        self.assertTrue(info['version_id'].endswith(info['content_sha256'][:12]))
        self.assertEqual(info['path'], str(Path(path).resolve()))
        return info

    def test_legacy_full_derives_real_identity(self):
        self.assert_identity(self.full('old.zip'))

    def test_direct_load_and_import_ignore_forged_identity(self):
        source = self.full('forged.zip', content_sha256='0' * 64, version_id='fake')
        info = self.assert_identity(source)
        self.assertNotEqual(info['version_id'], 'fake')
        self.assertNotEqual(info['content_sha256'], '0' * 64)
        result = db.import_db(str(source), self.live)
        self.assertEqual(result['version_id'], info['version_id'])
        with zipfile.ZipFile(self.live) as z:
            installed = json.loads(z.read('manifest.json'))
        self.assertEqual(installed['content_sha256'], info['content_sha256'])

    def test_repeated_content_preserves_live_backup_and_enabled_identity(self):
        db.import_db(str(self.full('one.zip')), self.live)
        db.import_db(str(self.full('two.zip', '2.0')), self.live)
        backup = self.live.with_name('live.zip.bak')
        before, previous = self.live.read_bytes(), backup.read_bytes()
        info = db.db_info(self.live)
        same = self.full('repacked.zip', '2.0', imported_at='2099-01-01', version_id='fake')
        result = db.import_db(str(same), self.live)
        self.assertTrue(result.get('unchanged'), '同内容不应制造一次新启用')
        self.assertEqual(self.live.read_bytes(), before)
        self.assertEqual(backup.read_bytes(), previous)
        self.assertEqual(db.db_info(self.live)['version_id'], info['version_id'])

    def test_raw_records_source_content_fingerprint(self):
        raw = self.root / 'all.zip'
        with zipfile.ZipFile(raw, 'w') as z:
            z.writestr('demo.json', json.dumps(advisory(versions=['1.0'])))
        result = db.import_db(str(raw), self.live)
        self.assertIn('source_json_sha256', result)
        self.assert_identity(self.live)

    def test_delta_replaces_identity_and_preserves_previous_version(self):
        db.import_db(str(self.full('base.zip')), self.live)
        old = self.assert_identity(self.live)
        delta = self.root / 'delta.zip'
        db.write_delta_db(str(self.live), {'demo': [advisory(versions=['2.0'])]}, str(delta), snapshot='2026-10-16')
        result = db.update_db(str(delta), self.live)
        new = self.assert_identity(self.live)
        self.assertNotEqual(old['version_id'], new['version_id'])
        self.assertEqual(result['version_id'], new['version_id'])
        self.assertEqual(self.assert_identity(self.live.with_name('live.zip.bak'))['version_id'], old['version_id'])

    def test_failed_install_does_not_change_enabled_identity(self):
        from pythonscan import db_import
        db.import_db(str(self.full('old.zip')), self.live)
        before = self.live.read_bytes()
        prepared = db_import.prepare_import(self.full('new.zip', '2.0'), self.live)
        try:
            with patch.object(db, 'load', side_effect=db.DBError('injected reload')):
                with self.assertRaises(db.DBError):
                    db_import.install_import(prepared)
            self.assertEqual(self.live.read_bytes(), before)
        finally:
            prepared.close()

    def test_empty_delta_advances_snapshot_for_next_delta(self):
        db.import_db(str(self.full('base-chain.zip')), self.live)
        old = db.db_info(self.live)
        first = self.root / 'empty-delta.zip'
        records = {'demo': [advisory(versions=['1.0'])]}
        db.write_delta_db(str(self.live), records, str(first), snapshot='2026-10-16')
        db.update_db(str(first), self.live)
        self.assertEqual(db.db_info(self.live)['snapshot'], '2026-10-16')
        self.assertEqual(db.db_info(self.live)['content_sha256'], old['content_sha256'])
        second = self.root / 'next-delta.zip'
        db.write_delta_db(str(self.live), {'demo': [advisory(versions=['2.0'])]}, str(second), snapshot='2026-10-17')
        db.update_db(str(second), self.live)
        self.assertEqual(db.db_info(self.live)['snapshot'], '2026-10-17')

    def test_fingerprint_ignores_zip_layout_and_manifest_fields(self):
        self.assertIsNotNone(importlib.util.find_spec('pythonscan.db_identity'), '需要共享的离线身份模块')
        from pythonscan.db_identity import json_fingerprint
        first = self.full('first.zip')
        second = self.root / 'second.zip'
        with zipfile.ZipFile(first) as z, zipfile.ZipFile(second, 'w', compression=zipfile.ZIP_STORED) as out:
            for name in reversed(z.namelist()):
                value = json.loads(z.read(name))
                if name == 'manifest.json':
                    value['imported_at'] = '2099'
                out.writestr(name, json.dumps(value, sort_keys=True, indent=4))
        self.assertNotEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(json_fingerprint(first), json_fingerprint(second))
