"""功能：验证管理命令区分归档与启用，并显示真实库身份。
实现：真实本地库配合 CLI 输出断言；下载服务结果单独隔离，不访问外网。
输入：临时全量库；输出：退出码、状态和内容指纹断言。
"""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pythonscan import cli, db
from test_osv import advisory


class TestManagementCLI(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.full = self.root / 'full.zip'
        self.live = self.root / 'live.zip'
        db.write_full_db({'demo': [advisory(versions=['1.0'])]}, str(self.full), snapshot='2026-10-15')

    def run_cli(self, args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(args)
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_download_is_explicit_and_does_not_activate(self):
        result = dict(status='new', reason='content_changed', version_id='2026-10-15_123456789abc',
                      directory=str(self.root / 'archive'), snapshot='2026-10-15', content_sha256='1' * 64)
        with patch('pythonscan.db_download.download', return_value=result) as download:
            with patch.object(db, 'import_db', side_effect=AssertionError('download cannot activate')):
                code, out, err = self.run_cli(['db', 'download', '--archive-dir', str(self.root), '--lang', 'en'])
        self.assertEqual(code, 0, err)
        self.assertIn('not activated', out)
        self.assertIn(result['version_id'], out)
        self.assertEqual(Path(download.call_args.args[0]), self.root)
        self.assertFalse(self.live.exists())

    def test_info_shows_actual_identity_and_path(self):
        info = db.db_info(self.full)
        code, out, err = self.run_cli(['db', 'info', '--db', str(self.full), '--lang', 'en'])
        self.assertEqual(code, 0, err)
        self.assertIn(info['version_id'], out)
        self.assertIn(info['content_sha256'], out)
        self.assertIn(str(self.full.resolve()), out)

    def test_unchanged_import_is_reported(self):
        db.import_db(str(self.full), self.live)
        code, out, err = self.run_cli(['db', 'import', str(self.full), '--db', str(self.live), '--lang', 'en'])
        self.assertEqual(code, 0, err)
        self.assertIn('unchanged', out.lower())
        self.assertFalse(self.live.with_name('live.zip.bak').exists())

    def test_offline_import_and_info_do_not_access_network(self):
        with patch('urllib.request.urlopen', side_effect=AssertionError('offline operation')):
            self.assertEqual(self.run_cli(['db', 'import', str(self.full), '--db', str(self.live)])[0], 0)
            self.assertEqual(self.run_cli(['db', 'info', '--db', str(self.live)])[0], 0)

    def test_download_failure_returns_error_status(self):
        with patch('pythonscan.db_download.download', side_effect=db.DBError('network unavailable')):
            code, out, err = self.run_cli(['db', 'download', '--lang', 'en'])
        self.assertEqual(code, 2)
        self.assertIn('network unavailable', err)
        self.assertNotIn('unchanged', out.lower())
