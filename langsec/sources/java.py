import json
import re
from datetime import date

from ..fetch import FOREVER, FetchError
from ..model import Release
from . import find_cves

ADVISORIES = "https://openjdk.org/groups/vulnerability/advisories/"
TEMURIN_LTS = (8, 11, 17, 21, 25)


def _temurin(f) -> list[tuple[str, str]]:
    """(date, release_name) of Temurin GA builds. The API caps page_size at 20."""
    out = []
    for feature in TEMURIN_LTS:
        for page in range(10):
            url = (f"https://api.adoptium.net/v3/assets/feature_releases/{feature}/ga"
                   f"?image_type=jdk&os=linux&architecture=x64&vendor=eclipse&page_size=20&page={page}")
            try:
                body = f.text(url, missing_ok=True)
            except FetchError:
                break
            if not body:
                break
            try:
                items = json.loads(body)
            except json.JSONDecodeError:
                break
            if not items:
                break
            for x in items:
                name = x["release_name"]
                if not re.fullmatch(r"jdk-?\d+\+\d+", name):
                    out.append((x["timestamp"][:10], name))
            if len(items) < 20:
                break
    return out


def collect(f, start: str) -> list[Release]:
    index = f.text(ADVISORIES)
    dates = sorted({f"{y}-{m}-{d}" for y, m, d in re.findall(r">(\d{4})/(\d\d)/(\d\d)<", index)})
    dates = [d for d in dates if d >= start]
    pages = f.many([ADVISORIES + d for d in dates], max_age=FOREVER, missing_ok=True)
    builds = _temurin(f)
    out = []
    for d in dates:
        near = sorted({n for t, n in builds
                       if 0 <= (date.fromisoformat(t) - date.fromisoformat(d)).days <= 10})
        out.append(Release("Java", ", ".join(near) or f"OpenJDK {d}", "all", d, True,
                           ADVISORIES + d, find_cves(pages.get(ADVISORIES + d) or "")))
    return out
