"""功能：显式联网下载 OSV PyPI，去重并归档有效漏洞库版本。
实现：条件 GET、文件/JSON/扫描内容摘要、同目录暂存和带补偿的清单提交。
输入：归档目录（参数、PYTHONSCAN_ARCHIVE 或用户目录）；输出：版本、检查日志。
依赖：Python 标准库；仅由 db download 调用，扫描与离线导入不引用网络服务。
"""
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import urllib.error
import urllib.request

from .db import DBError
from .db_identity import file_sha256, json_fingerprint
from .db_import import prepare_import, validate_full

SOURCE_URL = 'https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip'


class _CommitRecoveryError(DBError):
    """新清单可能仍在使用，不能清理它引用的本次版本目录。"""


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def _within(root, relative):
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise DBError('归档清单含无效相对路径')
    path = (root / relative.replace('\\', '/')).resolve()
    if not path.is_relative_to(root) or path == root:
        raise DBError(f'归档路径越界: {relative}')
    return path


def _entry_dir(root, entry):
    return _within(root, entry['directory'])


def _read_inventory(root):
    path = root / 'inventory.json'
    if not path.exists():
        return {'schema_version': 1, 'versions': []}
    try:
        value = json.loads(path.read_text(encoding='utf-8-sig'))
        if not isinstance(value, dict) or not isinstance(value.get('versions'), list):
            raise ValueError('versions 必须为数组')
        for entry in value['versions']:
            if not isinstance(entry, dict) or not isinstance(entry.get('version_id'), str):
                raise ValueError('无效版本条目')
            directory = _entry_dir(root, entry)
            files = entry.get('files')
            if not isinstance(files, dict) or 'vulndb.zip' not in files:
                raise ValueError('版本缺少全量库哈希')
            for name, digest in files.items():
                candidate = _within(root, str(directory.relative_to(root) / name))
                if not candidate.is_relative_to(directory) or not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest):
                    raise ValueError('版本文件哈希或路径无效')
        return value
    except (ValueError, KeyError, TypeError) as exc:
        raise DBError(f'归档清单损坏: {exc}') from exc


def _valid_entry(root, entry):
    directory = _entry_dir(root, entry)
    try:
        return all((directory / name).is_file() and file_sha256(directory / name) == digest
                   for name, digest in entry['files'].items())
    except OSError:
        return False


def _atomic_bytes(path, content):
    with tempfile.NamedTemporaryFile(prefix='.state-', dir=path.parent, delete=False) as stream:
        ready = Path(stream.name)
        try:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            stream.close()
            ready.unlink()
            raise
    try:
        os.replace(ready, path)
    finally:
        if ready.exists():
            ready.unlink()


def _append_check(root, record):
    path = root / 'checks.jsonl'
    previous = path.read_bytes() if path.exists() else b''
    row = (json.dumps(record, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
    _atomic_bytes(path, previous + row)


def _commit(root, inventory, event):
    """日志替换失败时恢复旧清单，避免错误结果却刷新了成功 ETag。"""
    path = root / 'inventory.json'
    old = path.read_bytes() if path.exists() else None
    content = (json.dumps(inventory, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    _atomic_bytes(path, content)
    try:
        _append_check(root, event)
    except Exception as original:
        try:
            if old is None:
                path.unlink()
            else:
                _atomic_bytes(path, old)
        except Exception as recovery:
            raise _CommitRecoveryError(f'检查日志写入失败: {original}；恢复旧清单失败: {recovery}') from original
        raise


def _result(root, entry, status, reason):
    return {'status': status, 'reason': reason, 'version_id': entry['version_id'],
            'directory': str(_entry_dir(root, entry)),
            'snapshot': entry['snapshot_utc_date'],
            'content_sha256': entry['scan_content_sha256']}


def _finish(root, inventory, entry, status, reason, headers):
    result = _result(root, entry, status, reason)
    updated = deepcopy(inventory)
    checked = _now()
    updated.update(schema_version=1, generated_at=checked,
                   latest_archived_version=entry['version_id'], automatic_download_history=True,
                   automatic_history_tracking=True,
                   last_successful_check={'checked_at': checked, **result},
                   source_cache={'url': SOURCE_URL, 'etag': headers.get('etag'),
                                 'version_id': entry['version_id'], 'checked_at': checked})
    _commit(root, updated, dict(checked_at=checked, **result))
    return result


def _reuse(root, inventory, entry, reason, headers):
    if not _valid_entry(root, entry):
        raise DBError(f'已有版本文件损坏或缺失，不能复用: {_entry_dir(root, entry)}')
    validate_full(_entry_dir(root, entry) / 'vulndb.zip')
    return _finish(root, inventory, entry, 'unchanged', reason, headers)


def _download_locked(root):
    inventory = _read_inventory(root)
    entries = inventory['versions']
    cached = inventory.get('source_cache') or {}
    cache_entry = next((entry for entry in entries if entry['version_id'] == cached.get('version_id')), None)
    request_headers = {'User-Agent': 'PythonScan-OSV-Downloader'}
    conditional = cached.get('url') == SOURCE_URL and isinstance(cached.get('etag'), str) and cache_entry is not None
    if conditional and _valid_entry(root, cache_entry):
        request_headers['If-None-Match'] = cached['etag']
    else:
        conditional = False
    request = urllib.request.Request(SOURCE_URL, headers=request_headers)
    with tempfile.TemporaryDirectory(prefix='.download-', dir=root) as temporary:
        work = Path(temporary)
        raw = work / 'raw.zip'
        try:
            response = urllib.request.urlopen(request, timeout=30)
        except urllib.error.HTTPError as exc:
            if exc.code != 304:
                exc.close()
                raise DBError(f'下载请求失败: HTTP {exc.code}') from exc
            exc.close()
            if not conditional:
                raise DBError('收到无有效本地缓存对应的 304，不能认定暂无更新') from exc
            return _reuse(root, inventory, cache_entry, 'not_modified', {'etag': cached['etag']})
        with response:
            if response.status != 200:
                raise DBError(f'下载响应状态无效: {response.status}')
            headers = {key: response.headers.get(key) for key in
                       ('etag', 'last-modified', 'x-goog-generation', 'content-length')}
            downloaded_at = _now()
            expected = headers['content-length']
            if expected is not None and (not expected.isdigit() or int(expected) < 1):
                raise DBError('下载响应 Content-Length 无效')
            count = 0
            with raw.open('wb') as stream:
                for block in iter(lambda: response.read(1024 * 1024), b''):
                    count += len(block)
                    stream.write(block)
            if expected is not None and count != int(expected):
                raise DBError(f'下载被截断: 预期 {expected} 字节，实际 {count}')
        source_hash = file_sha256(raw)
        for entry in entries:
            if entry.get('source_sha256') == source_hash or entry['files'].get('osv-PyPI-all.zip') == source_hash:
                return _reuse(root, inventory, entry, 'zip_same', headers)
        raw_content = json_fingerprint(raw, raw=True)
        for entry in entries:
            if entry.get('source_json_sha256') == raw_content:
                return _reuse(root, inventory, entry, 'json_same', headers)
        prepared = prepare_import(raw, work / 'unused-target.zip')
        try:
            content_hash = prepared.manifest['content_sha256']
            for entry in entries:
                if entry.get('scan_content_sha256') == content_hash:
                    return _reuse(root, inventory, entry, 'scan_same', headers)
            version_id = prepared.manifest['version_id']
            versions = _within(root, 'versions')
            versions.mkdir(exist_ok=True)
            destination = _within(root, 'versions/' + version_id)
            if destination.exists():
                raise DBError(f'版本目录已存在但未匹配到有效内容，拒绝覆盖: {destination}')
            staged = work / 'version'
            staged.mkdir()
            shutil.copyfile(raw, staged / 'osv-PyPI-all.zip')
            shutil.copyfile(prepared.candidate, staged / 'vulndb.zip')
            entry = {'version_id': version_id, 'snapshot_utc_date': prepared.manifest['snapshot'],
                     'directory': destination.relative_to(root).as_posix(), 'archived_at': _now(),
                     'downloaded_at': downloaded_at, 'source_url': SOURCE_URL,
                     'source_sha256': source_hash, 'source_json_sha256': raw_content,
                     'scan_content_sha256': content_hash,
                     'source_fingerprint_algorithm': 'osv-json-v1',
                     'scan_fingerprint_algorithm': 'pythonscan-json-v1',
                     'record_count': prepared.manifest['record_count'],
                     'package_count': prepared.manifest['package_count'],
                     'upstream_headers_at_download': headers,
                     'files': {'osv-PyPI-all.zip': source_hash, 'vulndb.zip': file_sha256(staged / 'vulndb.zip')}}
            (staged / 'metadata.json').write_text(json.dumps(entry, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        finally:
            prepared.close()
        updated = deepcopy(inventory)
        updated['versions'].append(entry)
        os.replace(staged, destination)
        try:
            return _finish(root, updated, entry, 'new', 'content_changed', headers)
        except Exception as original:
            if isinstance(original, _CommitRecoveryError):
                raise
            try:
                os.replace(destination, staged)
            except Exception as recovery:
                raise DBError(f'归档提交失败: {original}；撤销新目录失败: {recovery}') from original
            raise


def download(archive_dir=None):
    """一次显式检查；成功不启用任何库，失败不刷新成功缓存。"""
    root = Path(archive_dir or os.environ.get('PYTHONSCAN_ARCHIVE') or
                Path.home() / '.pythonscan' / 'downloads').resolve()
    root.mkdir(parents=True, exist_ok=True)
    lock = root / '.download.lock'
    try:
        stream = lock.open('x', encoding='utf-8')
    except FileExistsError as exc:
        raise DBError(f'已有下载任务或遗留锁: {lock}；确认无任务后移除此锁再重试') from exc
    try:
        with stream:
            stream.write(json.dumps({'pid': os.getpid(), 'started_at': _now()}))
        try:
            return _download_locked(root)
        except Exception as exc:
            try:
                _append_check(root, {'checked_at': _now(), 'status': 'error', 'error': str(exc)})
            except Exception as log_error:
                raise DBError(f'下载失败: {exc}；错误日志也无法写入: {log_error}') from exc
            if isinstance(exc, DBError):
                raise
            raise DBError(f'下载失败: {exc}') from exc
    finally:
        lock.unlink()
