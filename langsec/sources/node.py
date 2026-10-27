import json

from ..fetch import FOREVER
from ..model import Release
from . import find_cves


def collect(f, start: str) -> list[Release]:
    rels = []
    for e in json.loads(f.text("https://nodejs.org/dist/index.json")):
        v = e["version"].lstrip("v")
        major, minor, patch = map(int, v.split("."))
        # Odd majors are short-lived and not used in production; X.0.0 is a feature release.
        if major % 2 or (minor == 0 and patch == 0):
            continue
        rels.append(Release("Node.js", v, str(major), e["date"], bool(e.get("security")),
                            f"https://nodejs.org/en/blog/release/v{v}"))
    pages = f.many([r.url for r in rels if r.security and r.date >= start],
                   max_age=FOREVER, missing_ok=True)
    for r in rels:
        if r.url in pages:
            r.cves = find_cves(pages[r.url] or "")
    return rels
