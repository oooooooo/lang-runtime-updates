"""HTTP downloads through curl, with an on-disk cache.

curl is used instead of urllib because it uses the OS trust store, which keeps
working behind corporate proxies that inject their own certificates.
"""

import hashlib
import os
import re
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "cache"

DAY = 24 * 3600
MONTH = 30 * DAY
FOREVER = None  # never expires, even with --refresh


class FetchError(Exception):
    pass


def cache_path(url: str) -> Path:
    u = urlparse(url)
    path = re.sub(r"[^A-Za-z0-9._/-]", "_", u.path.strip("/")) or "index"
    if u.query:
        path += "__" + hashlib.sha1(u.query.encode()).hexdigest()[:12]
    # A fixed suffix keeps files from colliding with directories of the same name.
    return CACHE / u.netloc / (path + ".body")


class Fetcher:
    def __init__(self, refresh: bool = False):
        self.refresh = refresh

    def _fresh(self, path: Path, max_age) -> bool:
        if not path.exists():
            return False
        if max_age is FOREVER:
            return True
        if self.refresh:
            return False
        return time.time() - path.stat().st_mtime < max_age

    def get(self, url: str, max_age=DAY, headers=None, missing_ok=False) -> bytes | None:
        """Return the body, or None for a 404 when missing_ok is set."""
        path = cache_path(url)
        miss = path.with_suffix(".404")
        if self._fresh(path, max_age):
            return path.read_bytes()
        if missing_ok and self._fresh(miss, max_age):
            return None
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent)
        os.close(fd)
        cmd = ["curl", "-sS", "-L", "--retry", "3", "--retry-delay", "2",
               "--max-time", "120", "-o", tmp, "-w", "%{http_code}"]
        for k, v in (headers or {}).items():
            cmd += ["-H", f"{k}: {v}"]
        cmd.append(url)
        try:
            out = subprocess.run(cmd, capture_output=True, text=True)
            code = out.stdout.strip()
            if code == "200":
                os.replace(tmp, path)
                return path.read_bytes()
            if code == "404" and missing_ok:
                miss.touch()
                return None
            raise FetchError(f"{url}: HTTP {code or '?'} {out.stderr.strip()}")
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def text(self, url: str, **kw) -> str | None:
        body = self.get(url, **kw)
        return None if body is None else body.decode("utf-8", "replace")

    def many(self, urls, workers: int = 16, progress=None, **kw) -> dict:
        """Fetch many URLs in parallel. Returns {url: text or None}."""
        urls = list(dict.fromkeys(urls))
        result = {}

        def one(u):
            try:
                return u, self.text(u, **kw)
            except FetchError as e:
                print(f"  warning: {e}")
                return u, None

        with ThreadPoolExecutor(workers) as pool:
            for i, (u, t) in enumerate(pool.map(one, urls), 1):
                result[u] = t
                if progress:
                    progress(i, len(urls))
        return result
