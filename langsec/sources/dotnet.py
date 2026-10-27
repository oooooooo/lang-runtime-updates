import json
import re

from ..model import Release, branch_of, is_feature
from . import CVE_RE


def collect(f, start: str) -> list[Release]:
    index = json.loads(f.text(
        "https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/releases-index.json"))
    channels = [c for c in index["releases-index"] if c.get("latest-release-date", "9999") >= start]
    pages = f.many([c["releases.json"] for c in channels], workers=8)
    out = []
    for body in pages.values():
        if not body:
            continue
        for r in json.loads(body)["releases"]:
            v = r["release-version"]
            if not re.fullmatch(r"\d+\.\d+\.\d+", v) or is_feature(v):
                continue
            cves = sorted({c["cve-id"] for c in r.get("cve-list") or [] if CVE_RE.fullmatch(c.get("cve-id", ""))})
            out.append(Release(".NET", v, branch_of(v), r["release-date"][:10],
                               bool(r.get("security")), r.get("release-notes") or "", cves))
    return out
