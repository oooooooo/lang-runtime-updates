import re

from ..model import Release
from . import find_cves


def collect(f, start: str) -> list[Release]:
    md = f.text("https://raw.githubusercontent.com/rust-lang/rust/master/RELEASES.md")
    blog = f.text("https://blog.rust-lang.org/")
    posts = sorted(set(re.findall(
        r'href="(https://blog\.rust-lang\.org/\d{4}/\d\d/\d\d/(?:cve-[^"]+|cargo-cves)/)"', blog)))
    out = []
    for sec in re.split(r"\n(?=Version \d+\.\d+\.\d+ \()", md):
        m = re.match(r"Version (\d+\.\d+\.\d+) \((\d{4}-\d\d-\d\d)\)", sec)
        if not m:
            continue
        v, d = m.groups()
        cves = find_cves(sec)
        url = next((p for p in posts for c in cves if c.lower() in p), None)
        url = url or (f"https://github.com/rust-lang/rust/blob/master/RELEASES.md"
                      f"#version-{v.replace('.', '')}-{d}")
        # Only the latest stable gets fixes, so feature releases count too.
        out.append(Release("Rust", v, "stable", d, bool(cves) or "INTEL-SA" in sec, url, cves))
    return out
