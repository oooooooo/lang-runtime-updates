import json
import re

from ..model import Release, branch_of, is_feature
from . import strip_tags

SECTION = r'<section id="python-\d+-\d+-\d+-[a-z0-9-]+">'


def collect(f, start: str) -> list[Release]:
    rels = []
    for e in json.loads(f.text("https://www.python.org/api/v2/downloads/release/?is_published=true")):
        v = e["name"].replace("Python ", "")
        if e["pre_release"] or not re.fullmatch(r"3\.\d+\.\d+", v):
            continue
        rels.append((v, e["release_date"][:10]))

    # The /3/ changelog only covers the newest line, so read each branch's own page.
    info = {}
    branches = sorted({branch_of(v) for v, _ in rels if int(v.split(".")[1]) >= 6},
                      key=lambda b: int(b.split(".")[1]))
    pages = f.many([f"https://docs.python.org/{b}/whatsnew/changelog.html" for b in branches],
                   workers=4, missing_ok=True)
    for html in pages.values():
        if not html:
            continue
        marks = [(m.start(), m.group(0)) for m in re.finditer(SECTION, html)]
        for i, (pos, tag) in enumerate(marks):
            m = re.match(r'<section id="python-(\d+)-(\d+)-(\d+)-final">', tag)
            if not m:
                continue
            v = ".".join(m.groups())
            end = marks[i + 1][0] if i + 1 < len(marks) else len(html)
            seg = html[pos:end]
            cves = {"CVE-" + x for x in re.findall(r"CVE[- ](\d{4}-\d{4,7})", strip_tags(seg))}
            sec = bool(re.search(r"<h3>Security<a", seg))
            old = info.get(v, (False, set()))
            info[v] = (old[0] or sec, old[1] | cves)

    out = []
    for v, d in rels:
        if is_feature(v):
            continue
        sec, cves = info.get(v, (False, set()))
        out.append(Release("Python", v, branch_of(v), d, sec,
                           f"https://www.python.org/downloads/release/python-{v.replace('.', '')}/",
                           sorted(cves)))
    return out
