"""CVE id -> CVSS base score.

Order: cvelistV5 CNA score, then CISA ADP score, then the NVD API.
"""

import json
import os
import time

from .fetch import FOREVER, FetchError, cache_path

CVELIST = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{y}/{d}xxx/{id}.json"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}"


def _cvelist_url(cve: str) -> str:
    _, y, n = cve.split("-")
    return CVELIST.format(y=y, d=int(n) // 1000, id=cve)


def _metric(metrics) -> float | None:
    found = {}
    for m in metrics or []:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
            if key in m and "baseScore" in m[key]:
                found.setdefault(key, m[key]["baseScore"])
    for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
        if key in found:
            return float(found[key])
    return None


def _from_cvelist(body: str):
    try:
        con = json.loads(body).get("containers", {})
    except json.JSONDecodeError:
        return None
    s = _metric(con.get("cna", {}).get("metrics"))
    if s is not None:
        return s, "CNA"
    for adp in con.get("adp") or []:
        s = _metric(adp.get("metrics"))
        if s is not None:
            return s, "ADP"
    return None


def _from_nvd(body: str):
    try:
        vulns = json.loads(body).get("vulnerabilities", [])
    except json.JSONDecodeError:
        return None
    for v in vulns:
        m = v["cve"].get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
            if m.get(key):
                return float(m[key][0]["cvssData"]["baseScore"]), "NVD"
    return None


def score_all(f, cves, progress) -> dict[str, tuple[float, str]]:
    cves = sorted(set(cves))
    scores = {}
    pages = f.many([_cvelist_url(c) for c in cves], max_age=FOREVER, missing_ok=True,
                   progress=lambda i, n: progress(f"cvelistV5 {i}/{n}"))
    for c in cves:
        body = pages.get(_cvelist_url(c))
        hit = body and _from_cvelist(body)
        if hit:
            scores[c] = hit

    rest = [c for c in cves if c not in scores]
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else None
    pause = 0.7 if key else 6.5  # NVD: 50 or 5 requests per 30 seconds
    for i, c in enumerate(rest, 1):
        progress(f"NVD {i}/{len(rest)}")
        url = NVD.format(id=c)
        cached = cache_path(url).exists()
        for attempt in range(3):
            try:
                body = f.text(url, max_age=FOREVER, headers=headers)
                break
            except FetchError as e:
                if attempt == 2:
                    print(f"  warning: {e}")
                    body = None
                else:
                    time.sleep(30)
        hit = body and _from_nvd(body)
        if hit:
            scores[c] = hit
        if not cached:
            time.sleep(pause)
    return scores

