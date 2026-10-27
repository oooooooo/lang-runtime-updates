import json
import re

from ..fetch import MONTH
from ..model import Release, branch_of, is_feature
from . import strip_tags


def _vulndb(f) -> dict[str, set[str]]:
    """Go release version (e.g. 1.21.8) -> CVE ids fixed in it, from vuln.go.dev."""
    modules = json.loads(f.text("https://vuln.go.dev/index/modules.json"))
    ids = sorted({v["id"] for m in modules if m["path"] in ("stdlib", "toolchain") for v in m["vulns"]})
    entries = f.many([f"https://vuln.go.dev/ID/{i}.json" for i in ids], max_age=MONTH, missing_ok=True)
    fixed = {}
    for body in entries.values():
        if not body:
            continue
        j = json.loads(body)
        cves = [a for a in j.get("aliases", []) if a.startswith("CVE-")]
        for a in j.get("affected", []):
            if a["package"]["name"] not in ("stdlib", "toolchain"):
                continue
            for r in a.get("ranges", []):
                for ev in r.get("events", []):
                    if "fixed" in ev:
                        fixed.setdefault(ev["fixed"], set()).update(cves)
    return fixed


def collect(f, start: str) -> list[Release]:
    html = f.text("https://go.dev/doc/devel/release")
    fixed = _vulndb(f)
    out = []
    for m in re.finditer(r'<p id="go(1\.\d+\.\d+)">(.*?)</p>', html, re.S):
        v = m.group(1)
        text = strip_tags(m.group(2))
        d = re.search(r"released (\d{4}-\d\d-\d\d)", text)
        if not d or is_feature(v):
            continue
        out.append(Release("Go", v, branch_of(v), d.group(1), "security" in text,
                           f"https://go.dev/doc/devel/release#go{v}", sorted(fixed.get(v, ()))))
    return out
