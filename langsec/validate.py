"""Sanity checks that catch upstream format changes."""

import random
import subprocess

from .model import LANGUAGES

# Rust 2025 legitimately had no security release.
ZERO_OK = {"Rust"}


def check(rows, previous, scored, total_cves, release_rows) -> tuple[list[str], list[str]]:
    errors, warnings = [], []
    full = [r for r in rows if r["partial_year"] == "no"]
    for r in full:
        if r["security_updates"] == 0 and r["language"] not in ZERO_OK:
            errors.append(f"{r['language']} {r['year']}: no security releases found (parser broken?)")
    prev = {(p["language"], int(p["year"])): int(p["security_updates"]) for p in previous
            if p.get("partial_year") == "no"}
    for r in full:
        before = prev.get((r["language"], r["year"]))
        if before and r["security_updates"] < before * 0.5:
            errors.append(f"{r['language']} {r['year']}: security releases dropped "
                          f"from {before} to {r['security_updates']}")
    if total_cves and scored / total_cves < 0.85:
        errors.append(f"only {scored}/{total_cves} CVEs have a CVSS score (expected 85%+)")

    rng = random.Random(0)
    for lang in LANGUAGES:
        urls = [r["url"] for r in release_rows if r["language"] == lang and r["url"]]
        for url in rng.sample(urls, min(2, len(urls))):
            code = subprocess.run(["curl", "-sS", "-L", "-o", "/dev/null", "--max-time", "30",
                                   "-w", "%{http_code}", url], capture_output=True, text=True).stdout
            if code != "200":
                warnings.append(f"source link returned HTTP {code or '?'}: {url}")
    return errors, warnings
