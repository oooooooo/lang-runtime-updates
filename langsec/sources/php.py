import json
import os
import re
from datetime import datetime

from ..fetch import FOREVER, FetchError, cache_path
from ..model import Release, branch_of, is_feature
from . import find_cves, split_sections

# Since late 2024 the changelog sometimes cites only the php-src GitHub advisory
# (e.g. PHP2Shell in 8.5.12). The repository advisory maps it to its CVE id.
# The API allows 60 requests/hour without GITHUB_TOKEN, so the HTML page is the fallback.
GHSA_RE = re.compile(r"GHSA(?:-[0-9a-z]{4}){3}")
GHSA_API = "https://api.github.com/repos/php/php-src/security-advisories/{id}"
GHSA_PAGE = "https://github.com/php/php-src/security/advisories/{id}"
GHSA_PAGE_CVE = re.compile(r">CVE ID</h3>\s*<div[^>]*>\s*(CVE-\d{4}-\d{4,7})")


def _date(s: str) -> str:
    s = s.strip()
    for fmt in ("%d %b %Y", "%d %B %Y"):
        try:
            return datetime.strptime(s, fmt).strftime("%Y-%m-%d")
        except ValueError:
            pass
    raise ValueError(f"PHP: unknown date format {s!r}")


def _ghsa_only(section: str) -> set[str]:
    """GHSA ids on changelog lines that name no CVE id."""
    return {g for item in re.findall(r"<li>(.*?)</li>", section, re.S)
            if not find_cves(item) for g in GHSA_RE.findall(item)}


def _ghsa_cve(f, ghsa: str, headers) -> str | None:
    url = GHSA_API.format(id=ghsa)
    try:
        cve = json.loads(f.text(url, max_age=FOREVER, headers=headers)).get("cve_id")
    except (FetchError, json.JSONDecodeError):
        cve = None
    if not cve:
        cache_path(url).unlink(missing_ok=True)  # retry next build; a CVE may be assigned later
        page = GHSA_PAGE.format(id=ghsa)
        try:
            m = GHSA_PAGE_CVE.search(f.text(page, max_age=FOREVER))
        except FetchError:
            m = None
        cve = m and m.group(1)
        if not cve:
            cache_path(page).unlink(missing_ok=True)
    return cve


def _ghsa_cves(f, ids) -> dict[str, str]:
    """GHSA id -> CVE id, for the ids that have one."""
    headers = {"Accept": "application/vnd.github+json"}
    if token := os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    out = {}
    for g in ids:
        if cve := _ghsa_cve(f, g, headers):
            out[g] = cve
        else:
            print(f"  warning: PHP: could not resolve {g} to a CVE id (severity stays unknown)")
    return out


def collect(f, start: str) -> list[Release]:
    out = []
    ghsas = {}  # Release -> GHSA ids in its changelog section
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
            section = changelog.get(v, "")
            r = Release("PHP", v, branch_of(v), _date(e["date"]),
                        "security" in e.get("tags", []), url, find_cves(section))
            out.append(r)
            if r.security and r.date >= start:
                ghsas[id(r)] = _ghsa_only(section)

    mapping = _ghsa_cves(f, sorted(set().union(*ghsas.values())))
    for r in out:
        extra = {mapping[g] for g in ghsas.get(id(r), ()) if g in mapping}
        if extra:
            r.cves = sorted(set(r.cves) | extra)
    return out
