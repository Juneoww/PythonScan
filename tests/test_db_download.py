"""功能：通过本地 HTTP 验证条件下载、内容去重、归档事务及失败日志。
实现：真实 HTTP/ZIP/磁盘操作，只对网络源和磁盘失败点做可控替换。
输入：两批最小 OSV 公告；输出：归档和清单断言；不访问外网或用户库。
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

from pythonscan.db import DBError
from test_osv import advisory


def raw_zip(version='1.0', compress=False):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED) as z:
        z.writestr('demo.json', json.dumps(advisory(versions=[version]), indent=2 if compress else None))
    return buffer.getvalue()


class TestDownload(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.archive = Path(self.temp.name) / 'archive'
        self.body, self.etag, self.status, self.extra_length = raw_zip(), '"one"', 200, 0
        self.requests = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                owner.requests.append(dict(self.headers))
                status = owner.status
                if owner.etag and self.headers.get('If-None-Match') == owner.etag:
                    status = 304
                self.send_response(status)
                if owner.etag:
                    self.send_header('ETag', owner.etag)
                self.send_header('Last-Modified', 'Thu, 15 Oct 2026 01:00:00 GMT')
                self.send_header('Content-Length', str(len(owner.body) + owner.extra_length))
                self.end_headers()
                if status == 200:
                    self.wfile.write(owner.body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def api(self):
        self.assertIsNotNone(importlib.util.find_spec('pythonscan.db_download'), '需要显式联网的下载归档服务')
        return importlib.import_module('pythonscan.db_download')

    def download(self):
        api = self.api()
        with patch.object(api, 'SOURCE_URL', f'http://127.0.0.1:{self.server.server_port}/all.zip'):
            return api.download(self.archive)

    def inventory(self):
        return json.loads((self.archive / 'inventory.json').read_text(encoding='utf-8'))

    def versions(self):
        path = self.archive / 'versions'
        return sorted(p for p in path.iterdir() if p.is_dir()) if path.exists() else []

    def checks(self):
        return [json.loads(line) for line in (self.archive / 'checks.jsonl').read_text(encoding='utf-8').splitlines()]

    def test_first_download_and_conditional_304(self):
        first = self.download()
        self.assertEqual(first['status'], 'new')
        self.assertTrue((Path(first['directory']) / 'vulndb.zip').exists())
        second = self.download()
        self.assertEqual(second['status'], 'unchanged')
        self.assertEqual(first['version_id'], second['version_id'])
        self.assertEqual(len(self.versions()), 1)
        self.assertEqual(self.requests[-1].get('If-None-Match'), '"one"')
        self.assertEqual([c['status'] for c in self.checks()], ['new', 'unchanged'])

    def test_same_bytes_without_etag(self):
        self.etag = None
        self.download()
        second = self.download()
        self.assertEqual(second['status'], 'unchanged')
        self.assertEqual(second['reason'], 'zip_same')
        self.assertNotIn('If-None-Match', self.requests[-1])
        self.assertEqual(len(self.versions()), 1)

    def test_repack_is_not_new_data(self):
        first = self.download()
        self.etag, self.body = '"two"', raw_zip(compress=True)
        second = self.download()
        self.assertEqual(second['reason'], 'json_same')
        self.assertEqual(second['version_id'], first['version_id'])
        self.assertEqual(len(self.versions()), 1)
        metadata = json.loads((self.versions()[0] / 'metadata.json').read_text(encoding='utf-8'))
        self.assertEqual(metadata['upstream_headers_at_download']['etag'], '"one"')

    def test_real_change_on_same_day_creates_distinct_version(self):
        first = self.download()
        self.etag, self.body = '"two"', raw_zip('2.0')
        second = self.download()
        self.assertEqual(second['status'], 'new')
        self.assertNotEqual(first['version_id'], second['version_id'])
        self.assertEqual(first['snapshot'], second['snapshot'])
        self.assertEqual(len(self.versions()), 2)

    def test_withdrawn_only_change_reuses_same_scan_content(self):
        first = self.download()
        withdrawn = advisory(versions=['9.0'])
        withdrawn.update(id='withdrawn', withdrawn='2026-10-15T00:00:00Z')
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as z:
            z.writestr('demo.json', json.dumps(advisory(versions=['1.0'])))
            z.writestr('withdrawn.json', json.dumps(withdrawn))
        self.body, self.etag = output.getvalue(), '"withdrawn"'
        result = self.download()
        self.assertEqual(result['reason'], 'scan_same')
        self.assertEqual(result['version_id'], first['version_id'])
        self.assertEqual(len(self.versions()), 1)

    def test_network_failure_does_not_change_success_cache(self):
        self.download()
        before = (self.archive / 'inventory.json').read_bytes()
        self.status, self.etag = 503, '"failure"'
        with self.assertRaises(DBError):
            self.download()
        self.assertEqual((self.archive / 'inventory.json').read_bytes(), before)
        self.assertEqual(self.checks()[-1]['status'], 'error')
        self.assertFalse((self.archive / '.download.lock').exists())

    def test_truncated_or_invalid_download_keeps_inventory(self):
        self.download()
        before = (self.archive / 'inventory.json').read_bytes()
        self.etag, self.extra_length = '"two"', 50
        with self.assertRaises(DBError):
            self.download()
        self.extra_length, self.body = 0, b'not a zip'
        with self.assertRaises(DBError):
            self.download()
        self.assertEqual((self.archive / 'inventory.json').read_bytes(), before)
        self.assertEqual(len(self.versions()), 1)

    def test_broken_cache_avoids_304_and_reports_archive(self):
        first = self.download()
        (Path(first['directory']) / 'vulndb.zip').write_bytes(b'damaged')
        before = (self.archive / 'inventory.json').read_bytes()
        with self.assertRaises(DBError):
            self.download()
        self.assertNotIn('If-None-Match', self.requests[-1])
        self.assertEqual((self.archive / 'inventory.json').read_bytes(), before)

    def test_inventory_failure_rolls_back_new_directory(self):
        api = self.api()
        replace = os.replace

        def fail(source, target):
            if Path(target).name == 'inventory.json':
                raise PermissionError('injected inventory failure')
            return replace(source, target)

        with patch.object(api.os, 'replace', side_effect=fail), self.assertRaises(DBError):
            self.download()
        self.assertEqual(self.versions(), [])
        self.assertFalse((self.archive / 'inventory.json').exists())
        self.assertEqual(self.checks()[-1]['status'], 'error')

    def test_log_failure_rolls_back_directory_inventory_and_cache(self):
        self.download()
        before = (self.archive / 'inventory.json').read_bytes()
        self.etag, self.body = '"two"', raw_zip('2.0')
        api = self.api()
        replace = os.replace

        def fail(source, target):
            if Path(target).name == 'checks.jsonl':
                raise PermissionError('injected log failure')
            return replace(source, target)

        with patch.object(api.os, 'replace', side_effect=fail), self.assertRaises(DBError):
            self.download()
        self.assertEqual((self.archive / 'inventory.json').read_bytes(), before)
        self.assertEqual(len(self.versions()), 1)
        self.assertFalse((self.archive / '.download.lock').exists())

    def test_lock_collision_makes_no_request(self):
        self.api()
        self.archive.mkdir()
        (self.archive / '.download.lock').write_text('another process', encoding='utf-8')
        with self.assertRaises(DBError):
            self.download()
        self.assertEqual(self.requests, [])
        self.assertTrue((self.archive / '.download.lock').exists())

    def test_failed_inventory_recovery_keeps_referenced_archive(self):
        self.download()
        self.etag, self.body = '"two"', raw_zip('2.0')
        api = self.api()
        replace = os.replace
        inventory_writes = 0

        def fail(source, target):
            nonlocal inventory_writes
            if Path(target).name == 'inventory.json':
                inventory_writes += 1
                if inventory_writes > 1:
                    raise PermissionError('injected recovery failure')
            if Path(target).name == 'checks.jsonl':
                raise PermissionError('injected log failure')
            return replace(source, target)

        with patch.object(api.os, 'replace', side_effect=fail), self.assertRaises(DBError):
            self.download()
        for entry in self.inventory()['versions']:
            self.assertTrue((self.archive / entry['directory'] / 'vulndb.zip').exists(),
                            '恢复清单失败时必须保留仍被引用的有效版本目录')

    def test_unexpected_304_is_error(self):
        self.status, self.etag = 304, None
        with self.assertRaises(DBError):
            self.download()
        self.assertFalse((self.archive / 'inventory.json').exists())

    def test_unsafe_existing_archive_path_is_rejected(self):
        self.api()
        self.archive.mkdir()
        (self.archive / 'inventory.json').write_text(json.dumps({'versions': [
            {'version_id': 'bad', 'directory': '../outside', 'files': {}}]}), encoding='utf-8')
        with self.assertRaises(DBError):
            self.download()
        self.assertEqual(self.requests, [])
