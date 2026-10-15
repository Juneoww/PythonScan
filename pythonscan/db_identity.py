"""功能：离线计算漏洞库内容身份并更新候选库的 manifest。
实现：规范 JSON 后按文件名排序摘要，排除 ZIP 打包元数据和 manifest 时间。
输入：原始或全量 ZIP；输出：SHA256、版本 ID 或同数据的新 manifest。
依赖：标准库；不联网，身份始终由实际内容派生。
"""
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import zipfile

from .db import DBError


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def json_fingerprint(path, raw=False):
    """忽略压缩/时间戳/对象键顺序；数组顺序仍作为 JSON 内容保留。"""
    digest = hashlib.sha256()
    try:
        context = nullcontext(path) if isinstance(path, zipfile.ZipFile) else zipfile.ZipFile(path)
        with context as archive:
            all_names = archive.namelist()
            if len(all_names) != len(set(all_names)):
                raise DBError('ZIP 含重复文件名，无法确定身份')
            names = sorted(n for n in all_names if n.endswith('.json') and
                           (raw or n == 'index.json' or n.startswith('data/')))
            if not names or (not raw and 'index.json' not in names):
                raise DBError('ZIP 缺少可计算身份的 JSON 数据')
            for name in names:
                try:
                    data = json.loads(archive.read(name).decode('utf-8'))
                    encoded = json.dumps([name, data], sort_keys=True, ensure_ascii=False,
                                         separators=(',', ':'), allow_nan=False).encode('utf-8')
                except (ValueError, UnicodeError) as exc:
                    raise DBError(f'{name}: JSON 内容无效: {exc}') from exc
                digest.update(len(encoded).to_bytes(8, 'big'))
                digest.update(encoded)
    except (zipfile.BadZipFile, KeyError) as exc:
        raise DBError(f'无法读取漏洞库身份: {exc}') from exc
    return digest.hexdigest()


def identity(path, manifest=None):
    """即使 manifest 声明身份，也按实际 index/data 重算。"""
    if manifest is None:
        with zipfile.ZipFile(path) as archive:
            manifest = json.loads(archive.read('manifest.json'))
    content = json_fingerprint(path)
    snapshot = re.sub(r'[^A-Za-z0-9-]', '', str(manifest.get('snapshot', '')))[:32] or 'undated'
    return {'version_id': f'{snapshot}_{content[:12]}', 'content_sha256': content}


def stamp_manifest(path, updates):
    """仅在候选库中更新身份；复制数据成员时保留其字节和已声明哈希。"""
    path = Path(path)
    with tempfile.NamedTemporaryFile(prefix='.identity-', suffix='.zip', dir=path.parent, delete=False) as temp:
        ready = Path(temp.name)
    try:
        with zipfile.ZipFile(path) as source, zipfile.ZipFile(ready, 'w', compression=zipfile.ZIP_DEFLATED) as target:
            manifest = json.loads(source.read('manifest.json'))
            manifest.update(updates)
            for info in source.infolist():
                if info.filename != 'manifest.json':
                    with source.open(info) as reader, target.open(info, 'w') as writer:
                        shutil.copyfileobj(reader, writer)
            target.writestr('manifest.json', json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=1).encode('utf-8'))
        os.replace(ready, path)
        return manifest
    finally:
        if ready.exists():
            ready.unlink()
