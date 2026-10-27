"""Manual corrections from overrides.csv."""

import csv
from pathlib import Path

from . import sources


def apply(path: Path, releases) -> int:
    if not path.exists():
        return 0
    index = {(r.language, r.version): r for r in releases}
    # Java versions are labels; let overrides address Java releases by date too.
    index.update({(r.language, r.date): r for r in releases if r.language == "Java"})
    n = 0
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            r = index.get((row["language"].strip(), row["version"].strip()))
            if not r:
                print(f"  warning: override for unknown release {row['language']} {row['version']}")
                continue
            field, value = row["field"].strip(), row["value"].strip()
            if field == "cves":
                r.cves = sources.find_cves(value)
            elif field == "security":
                r.security = value.lower() in ("1", "true", "yes")
            elif field == "url":
                r.url = value
            else:
                print(f"  warning: unknown override field {field!r}")
                continue
            n += 1
    return n
