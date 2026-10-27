# Language Runtime Forced-Update Report

Counts how often each language runtime (PHP, Python, Ruby, Node.js, Java, Go, Rust,
.NET) forced users to update because of security vulnerabilities, broken down by
severity (High / Critical), with an official source link for every update.
The output is a single local HTML report.

**Sample report:** https://oooooooo.github.io/lang-runtime-updates/sample-report.html
(built 2026-10-27, period 2022–2026). It is a snapshot of
[docs/sample-report.html](docs/sample-report.html), served by GitHub Pages from `docs/`,
and is not updated by the build.

## Requirements

- Python 3.11+ (standard library only)
- `curl`

## Usage

```sh
python3 build.py
```

That's it. The command downloads the data, builds `dist/index.html`, and opens it
in your browser.

The first run takes about 15 minutes, because the NVD API is rate limited.
Later runs reuse the `cache/` directory and finish in seconds to a few minutes.

### Options

| Option | What it does |
|---|---|
| `--refresh` | Re-download release metadata instead of using the cache |
| `--from 2021 --to 2025` | Change the period (default: the current year and the 4 years before it; the current year is partial) |
| `--no-open` | Build without opening the browser |

To speed up the first run, get a free NVD API key at
https://nvd.nist.gov/developers/request-an-api-key and set it before running:

```sh
NVD_API_KEY=your-key python3 build.py
```

PHP advisories that cite only a GitHub advisory id (GHSA) are looked up on GitHub.
Without a token GitHub allows 60 API requests per hour, after which the build falls back
to the advisory page. A token (no scopes needed) avoids that:

```sh
GITHUB_TOKEN=your-token python3 build.py
```

Tests: `python3 -m unittest discover -s tests -t .`

## Output

| Path | Contents |
|---|---|
| `dist/index.html` | The report. Works offline; open it directly from disk. |
| `data/severity_yearly.csv` | Yearly counts per language and severity |
| `data/security_releases.csv` | Every counted release with CVEs, max CVSS, and source URL |

## Fixing missing data

Some releases have no CVE ids in their official notes (mostly Python) and show as
"unknown" severity. Add the CVE ids to `overrides.csv` and run the command again:

```
language,version,field,value,note
Python,3.12.5,cves,CVE-2024-XXXX,from security-announce mailing list
```

## How it counts

See [AGENTS.md](AGENTS.md) for the counting rules, data sources, and known limitations.
