import json
import re
from datetime import datetime

from ..model import Release, branch_of, is_feature
from . import find_cves, split_sections


def _date(s: str) -> str:
    s = s.strip()
    for fmt in ("%d %b %Y", "%d %B %Y"):
        try:
            return datetime.strptime(s, fmt).strftime("%Y-%m-%d")
        except ValueError:
            pass
    raise ValueError(f"PHP: unknown date format {s!r}")


def collect(f, start: str) -> list[Release]:
    out = []
    for major in ("8", "7"):
        changelog = split_sections(
            f.text(f"https://www.php.net/ChangeLog-{major}.php"),
            r'<section class="version" id="(\d+\.\d+\.\d+)"')
        data = json.loads(f.text(f"https://www.php.net/releases/index.php?json&max=1000&version={major}"))
        for v, e in data.items():
            if not re.fullmatch(r"\d+\.\d+\.\d+", v) or is_feature(v):
                continue
            url = (f"https://www.php.net/releases/{v.replace('.', '_')}.php" if e.get("announcement")
                   else f"https://www.php.net/ChangeLog-{major}.php#{v}")
            out.append(Release("PHP", v, branch_of(v), _date(e["date"]),
                               "security" in e.get("tags", []), url,
                               find_cves(changelog.get(v, ""))))
    return out
