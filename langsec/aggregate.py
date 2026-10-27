"""Per-branch yearly counts of security releases, by severity."""

from collections import defaultdict

from .model import LANGUAGES


def severity(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def max_score(cves, scores) -> float | None:
    found = [scores[c][0] for c in cves if c in scores]
    return max(found) if found else None


def yearly(releases, scores, years, current_year) -> list[dict]:
    rows = []
    for lang in LANGUAGES:
        for y in years:
            branches = defaultdict(lambda: defaultdict(int))
            for r in releases:
                if r.language != lang or not r.security or not r.date.startswith(str(y)):
                    continue
                s = max_score(r.cves, scores)
                b = branches[r.branch]
                b["all"] += 1
                b["high"] += s is not None and s >= 7
                b["crit"] += s is not None and s >= 9
                b["unk"] += s is None
            # A user on one supported branch: take the busiest branch of the year.
            top = lambda k: max((b[k] for b in branches.values()), default=0)
            rows.append({
                "language": lang, "year": y,
                "security_updates": top("all"), "high_or_above": top("high"),
                "critical": top("crit"), "unknown_severity": top("unk"),
                "partial_year": "yes" if y == current_year else "no",
            })
    return rows


def totals(rows, period) -> list[dict]:
    out = {}
    for r in rows:
        if r["year"] not in period:
            continue
        t = out.setdefault(r["language"], {"language": r["language"], "security_updates": 0,
                                           "high_or_above": 0, "critical": 0, "unknown_severity": 0})
        for k in ("security_updates", "high_or_above", "critical", "unknown_severity"):
            t[k] += r[k]
    return list(out.values())


def release_rows(releases, scores, years) -> list[dict]:
    """One row per language + date; versions released the same day are merged."""
    groups = defaultdict(list)
    for r in releases:
        if r.security and int(r.date[:4]) in years:
            groups[(r.language, r.date)].append(r)
    out = []
    for (lang, date), rs in groups.items():
        cves = sorted({c for r in rs for c in r.cves})
        s = max_score(cves, scores)
        rs.sort(key=lambda r: [int(p) if p.isdigit() else 0 for p in r.version.replace("-", ".").split(".")],
                reverse=True)
        out.append({
            "id": f"{lang}-{date}", "language": lang, "date": date,
            "versions": " / ".join(r.version for r in rs),
            "max_cvss": "" if s is None else s, "severity": severity(s),
            "cve_count": len(cves), "cves": " ".join(cves), "url": rs[0].url,
        })
    out.sort(key=lambda r: (r["date"], r["language"]), reverse=True)
    return out
