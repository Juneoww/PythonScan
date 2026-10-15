"""漏洞库同步器：抓取 OSV PyPI 全量导出 -> 去重合并 -> 生成全量库/增量包。

用法（外网机，Python >= 3.9，仅标准库）:
  python -m sync.sync build --src https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip \
      --out vulndb.zip [--prev 上一版.zip] [--proxy http://127.0.0.1:7890] \
      [--fetch-latest] [--snapshot 2026-09-13]

- 无 --prev: 产出全量库；有 --prev: 与上一版按包内容哈希对比，产出增量包
- --fetch-latest: 从 PyPI JSON API 抓取各包最新版本（写入库 index，供修复建议）
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pythonscan.db import write_delta_db, write_full_db  # noqa: E402
from pythonscan.osv import load_osv_zip  # noqa: E402

OSV_PYPI_EXPORT_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"
UA = {"User-Agent": "pythonscan-sync/0.1"}



def _opener(proxy: str | None) -> urllib.request.OpenerDirector:
    if proxy:
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return urllib.request.build_opener()


def download(url: str, proxy: str | None) -> Path:
    print(f"下载: {url}")
    request = urllib.request.Request(url, headers=UA)
    tmp = Path(tempfile.gettempdir()) / f"pythonscan-osv-{date.today().isoformat()}.zip"
    done = 0
    with _opener(proxy).open(request, timeout=180) as resp, open(tmp, "wb") as fh:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            fh.write(chunk)
            done += len(chunk)
            if done % (50 << 20) < (1 << 20):
                print(f"  已下载 {done >> 20} MB ...")
    print(f"下载完成: {tmp} ({done >> 20} MB)")
    return tmp


def load_and_merge(src_zip: str) -> dict:
    """复用扫描器内置的离线转换，外网端只负责下载和构建。"""
    records, _ = load_osv_zip(src_zip)
    print(f"源数据: {len(records)} 个 PyPI 包")
    return records


def fetch_latest(packages, cache_path: str | None, proxy: str | None, workers: int = 6) -> dict:
    cache = {}
    if cache_path and Path(cache_path).exists():
        cache = json.loads(Path(cache_path).read_text(encoding="utf-8"))
    todo = [p for p in packages if p not in cache]
    print(f"抓取最新版本: {len(todo)} 个包 (缓存命中 {len(packages) - len(todo)})")

    def fetch(package: str):
        try:
            request = urllib.request.Request(PYPI_JSON_URL.format(name=package), headers=UA)
            with _opener(proxy).open(request, timeout=30) as resp:
                info = (json.loads(resp.read().decode("utf-8")) or {}).get("info") or {}
                return package, info.get("version")
        except OSError:
            return package, None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for package, version in pool.map(fetch, todo):
            if version:
                cache[package] = version
    if cache_path:
        Path(cache_path).write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    return {p: cache[p] for p in packages if p in cache}


def cmd_build(args) -> int:
    snapshot = args.snapshot or date.today().isoformat()
    src = args.src
    tmp_file = None
    if re.match(r"^https?://", src):
        tmp_file = download(src, args.proxy)
        src = str(tmp_file)
    if not Path(src).exists():
        print(f"错误: 源文件不存在: {src}", file=sys.stderr)
        return 2

    records_by_package = load_and_merge(src)
    record_total = sum(len(v) for v in records_by_package.values())
    print(f"去重合并后: {record_total} 条记录 / {len(records_by_package)} 个包")

    latest = fetch_latest(records_by_package, args.latest_cache, args.proxy) if args.fetch_latest else {}
    if args.prev:
        manifest = write_delta_db(args.prev, records_by_package, out_path=args.out,
                                  snapshot=snapshot, latest=latest or None)
        print(f"增量包已生成: {args.out}")
        print(f"  基于 {manifest['base']} -> 目标 {manifest['target']}  "
              f"变更 {manifest['stats']['upserts']} 个包, 删除 {manifest['stats']['deletions']} 个包")
    else:
        manifest = write_full_db(records_by_package, out_path=args.out,
                                 snapshot=snapshot, latest=latest or None)
        print(f"全量库已生成: {args.out}")
        print(f"  快照 {manifest['snapshot']}  {manifest['record_count']:,} 条记录 / "
              f"{manifest['package_count']:,} 个包")
    size_mb = Path(args.out).stat().st_size >> 20
    print(f"  文件大小: {size_mb} MB（内网端: pythonscan db {'update' if args.prev else 'import'} {args.out}）")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="pythonscan-sync",
                                     description="PythonScan 漏洞库同步器（外网机运行）")
    sub = parser.add_subparsers(dest="cmd", required=True)
    build = sub.add_parser("build", help="抓取并构建漏洞库")
    build.add_argument("--src", default=OSV_PYPI_EXPORT_URL,
                       help=f"OSV 导出 zip 的 URL 或本地路径（默认 {OSV_PYPI_EXPORT_URL}）")
    build.add_argument("--out", default="pypi-advisories.zip", help="输出库文件路径")
    build.add_argument("--prev", help="上一版全量库路径（提供则生成增量包）")
    build.add_argument("--proxy", help="HTTP(S) 代理，如 http://127.0.0.1:7890")
    build.add_argument("--snapshot", help="快照日期（默认今天）")
    build.add_argument("--fetch-latest", action="store_true",
                       help="从 PyPI 抓取各包最新版本（较耗时，写入修复建议所用索引）")
    build.add_argument("--latest-cache", help="最新版本缓存文件路径（复用上次抓取结果）")
    args = parser.parse_args(argv)
    return cmd_build(args)


if __name__ == "__main__":
    sys.exit(main())
