#!/usr/bin/env python3
"""Build the forced-update report: fetch, aggregate, render, open."""

import argparse
import csv
import shutil
import sys
import webbrowser
from datetime import date
from pathlib import Path

from langsec import aggregate, cves, overrides, render, validate
from langsec.fetch import Fetcher, FetchError
from langsec.sources import collectors

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
REPORT = ROOT / "dist" / "index.html"
STEPS = 6


def step(n: int, msg: str) -> None:
    print(f"[{n}/{STEPS}] {msg}", flush=True)


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def main() -> int:
    today = date.today()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--from", dest="start", type=int, default=today.year - 4, help="first year (default: 4 years before the current year)")
    p.add_argument("--to", dest="end", type=int, default=today.year, help="last year (default: the current year, counted as partial)")
    p.add_argument("--refresh", action="store_true", help="re-download release metadata instead of using the cache")
    p.add_argument("--no-open", action="store_true", help="don't open the report in a browser")
    args = p.parse_args()
    if shutil.which("curl") is None:
        print("error: curl is required but was not found on PATH", file=sys.stderr)
        return 1
    if args.start > args.end:
        print("error: --from must not be after --to", file=sys.stderr)
        return 1

    period = list(range(args.start, args.end + 1))
    years = period + ([today.year] if today.year > args.end else [])
    start = f"{args.start}-01-01"
    f = Fetcher(refresh=args.refresh)

    step(1, "Fetching release data")
    releases = []
    for lang, collect in collectors().items():
        try:
            found = collect(f, start)
        except (FetchError, KeyError, ValueError) as e:
            print(f"error: {lang}: {e}", file=sys.stderr)
            return 1
        releases += found
        n_sec = sum(r.security and r.date >= start for r in found)
        print(f"      {lang}: {n_sec} security releases since {args.start}")

    step(2, "Applying manual overrides")
    n_over = overrides.apply(ROOT / "overrides.csv", releases)
    print(f"      {n_over} applied")

    step(3, "Fetching CVSS scores")
    in_range = [r for r in releases if r.security and int(r.date[:4]) in years]
    ids = sorted({c for r in in_range for c in r.cves})
    def progress(msg):
        # Overwrite one line in a terminal; elsewhere print only every 100th item and the last.
        done, total = map(int, msg.split()[-1].split("/"))
        if sys.stdout.isatty():
            print(f"\r      {msg}   ", end="", flush=True)
        elif done % 100 == 0 or done == total:
            print(f"      {msg}", flush=True)

    scores = cves.score_all(f, ids, progress)
    print(f"\r      {len(scores)} of {len(ids)} CVEs scored          ")

    step(4, "Aggregating")
    previous = read_csv(DATA / "severity_yearly.csv")
    yearly = aggregate.yearly(releases, scores, years, today.year)
    totals = aggregate.totals(yearly, period)
    rows = aggregate.release_rows(releases, scores, years)
    sources = read_csv(ROOT / "official_sources.csv")
    write_csv(DATA / "severity_yearly.csv", yearly)
    write_csv(DATA / "security_releases.csv", rows)

    step(5, "Rendering report")
    score_sources = {}
    for c in ids:
        if c in scores:
            score_sources[scores[c][1]] = score_sources.get(scores[c][1], 0) + 1
    render.write(REPORT, {
        "generated": today.isoformat(), "from": args.start, "to": args.end, "current_year": today.year,
        "years": years, "yearly": yearly, "totals": totals, "releases": rows, "sources": sources,
        "overrides": n_over, "scored": sum(c in scores for c in ids), "total_cves": len(ids),
        "score_sources": score_sources,
    })

    step(6, "Validating")
    errors, warnings = validate.check(yearly, previous, sum(c in scores for c in ids), len(ids), rows)
    for w in warnings:
        print(f"      warning: {w}")
    for e in errors:
        print(f"      ERROR: {e}", file=sys.stderr)

    print(f"\nReport: {REPORT}")
    print("Validation: " + (f"{len(errors)} error(s), " if errors else "passed, ") + f"{len(warnings)} warning(s)")
    if not args.no_open:
        webbrowser.open(REPORT.as_uri())
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
