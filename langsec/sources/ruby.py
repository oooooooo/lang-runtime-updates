import re

from ..fetch import FOREVER
from ..model import Release, branch_of, is_feature
from . import find_cves, strip_tags


def _body(html: str) -> str:
    """Post body only: the sidebar lists recent security news and would cause false positives."""
    i = html.find('<div id="content"')
    text = strip_tags(html[i:] if i >= 0 else html)
    return text.split(" Download ")[0]


def collect(f, start: str) -> list[Release]:
    yml = f.text("https://raw.githubusercontent.com/ruby/www.ruby-lang.org/master/_data/releases.yml")
    entries = []
    for v, d, post in re.findall(r"- version: (\S+)\n\s+date: (\S+)\n\s+post: (\S+)", yml):
        if not re.fullmatch(r"\d+\.\d+\.\d+", v) or is_feature(v) or d < start:
            continue
        entries.append((v, d, "https://www.ruby-lang.org" + post.strip("\"'")))
    posts = f.many([u for _, _, u in entries], max_age=FOREVER, missing_ok=True)
    out = []
    for v, d, url in entries:
        body = _body(posts.get(url) or "")
        out.append(Release("Ruby", v, branch_of(v), d,
                           bool(re.search(r"CVE-|security|vulnerab", body, re.I)), url,
                           find_cves(body)))
    return out
