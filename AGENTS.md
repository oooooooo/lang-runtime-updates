# AGENTS.md — Language Runtime Forced-Update Report

This file is the full spec for building, from scratch, a local tool that measures
**how often each programming language runtime forced its users to update** because
of security vulnerabilities, and renders the result as a single local HTML report.

Everything runs locally. No server, no CI, no hosted page.

---

## 1. Goal

Help choose a language that **requires as few updates as possible**.

The report answers, per language and per year:

1. How many times did a user who stays on one supported version have to update
   because the update fixed a security vulnerability?
2. Of those, how many fixed at least one **High** (CVSS ≥ 7.0) or **Critical**
   (CVSS ≥ 9.0) vulnerability?
3. What is the official source (release announcement, release notes, advisory)
   for every counted update?

Out of scope:

- New-feature releases (x.y.0). The user does not need them.
- Framework and third-party package updates (npm, pip, Composer, gems, crates).
- Ordinary bug-fix-only patches. Nobody is forced to apply them unless they hit
  the bug, and no language flags "critical bug" releases officially.

## 2. Languages

PHP, Python, Ruby, Node.js, Java, Go, Rust, .NET (C#).

## 3. Commands

**One command does everything**: fetch (using cache), aggregate, render, and open
the report in the default browser.

```sh
python3 build.py              # the only command a user needs
python3 build.py --refresh    # ignore cached release metadata and re-download it
python3 build.py --from 2021 --to 2025
python3 build.py --no-open    # build without opening the browser
```

- Open the report with `webbrowser.open(dist/index.html as file:// URI)` unless
  `--no-open` is given.
- Print progress per step (`[3/6] Fetching CVE scores 412/1109`) so long runs
  (first run: NVD fallback can take ~15 minutes without an API key) don't look hung.
- Finish with the report path and a one-line summary of validation results.
- Python 3.11+ standard library only. No pip installs, no setup step, no virtualenv.
  Requires `curl` on PATH (preinstalled on macOS and most Linux).
- Default period: the five most recent full calendar years, plus the current year
  marked as partial.

## 4. Project layout

```
build.py                 # entry point: orchestrates fetch → extract → aggregate → render
langsec/
  fetch.py               # HTTP download with on-disk cache (see §7)
  sources/
    php.py  python.py  ruby.py  node.py  java.py  go.py  rust.py  dotnet.py
                         # each returns a list of Release records (see §5)
  cves.py                # CVE id → CVSS score (cvelistV5 + NVD fallback)
  model.py               # Release record and language list (see §5)
  aggregate.py           # per-branch yearly counts (see §6)
  overrides.py           # applies overrides.csv (see §10)
  validate.py            # end-of-build checks (see §12)
  render.py              # writes dist/index.html from template.html (see §9)
  template.html          # report page; data is injected at /*__DATA__*/
official_sources.csv     # the official sources table (see §11)
overrides.csv            # manual corrections (see §10)
cache/                   # raw downloads, gitignored
data/                    # generated CSV/JSON outputs
dist/index.html          # the report
```

## 5. Data model

Every language module returns `Release` records:

| field | type | meaning |
|---|---|---|
| `language` | str | one of the 8 names in §2 |
| `version` | str | e.g. `8.3.19`, `1.22.4`, `jdk-17.0.11+9` |
| `branch` | str | release line, e.g. `8.3`, `1.22`, `20` (Node major), `17` (Java feature) |
| `date` | str | `YYYY-MM-DD` |
| `security` | bool | the release officially contains a security fix (see §8) |
| `cves` | list[str] | CVE ids fixed by this release (may be empty even if `security`) |
| `url` | str | official page that announces or documents the release |

Exclude pre-releases and feature releases (`x.y.0`) **except** for Rust (see §8, Rust).

## 6. Counting rules

For each language and year:

1. Group that year's security releases by `branch`.
2. `security_updates` = the **maximum** count over branches. This approximates
   "a user who stays on one supported version".
3. A release's severity = the **highest CVSS base score** among its `cves`.
   - `critical`: ≥ 9.0, `high`: ≥ 7.0, `medium`: ≥ 4.0, `low`: < 4.0
   - `unknown`: security release with no scored CVE
4. `high_or_above`, `critical`, `unknown_severity` = per-branch maximum of each
   count, computed independently (they are not guaranteed to come from the same branch).

Special cases:

- **Node.js**: only even majors (LTS lines). Odd majors are short-lived and not
  used in production.
- **Rust**: only the latest stable is supported, so a security fix shipped in a
  feature release (e.g. 1.81.0 for CVE-2024-43402) still forces an update and counts.
  Branch = `stable` for every Rust release.
- **Java**: one security release per OpenJDK advisory date; branch = `all`.

Outputs in `data/`:

- `severity_yearly.csv`: `language,year,security_updates,high_or_above,critical,unknown_severity,partial_year`
- `security_releases.csv`: one row per language + date (merge versions released the
  same day): `id,language,date,versions,max_cvss,severity,cve_count,cves,url`
  where `id` = `<language>-<date>`, `versions` joined with ` / `.
- `official_sources.csv`: `id,language,label,url` (see §11).

## 7. Downloading

- Download with `curl` through `subprocess` (`curl -sS -f -L --retry 3`).
  Python's `urllib` failed on the original machine because a corporate proxy
  injects a self-signed certificate. curl uses the OS trust store and works.
- Cache every response under `cache/<host>/<path>`. Reuse it unless `--refresh`.
  CVE and NVD responses are cached permanently (they rarely change and NVD is slow).
- Run independent downloads in parallel (e.g. 16 workers) except NVD (§8, CVSS).
- Never execute downloaded content. Parse it as data only.

## 8. Sources and parsing, per language

All URLs below were verified working on 2026-10-27.

### PHP

- Releases: `https://www.php.net/releases/index.php?json&max=1000&version=8`
  and `...&version=7`. JSON object keyed by version.
  - `date` comes in two formats: `21 Oct 2026` and `11 June 2020`. Try
    `%d %b %Y`, then `%d %B %Y`.
  - `security` = `"security" in entry["tags"]`.
  - `url` = `https://www.php.net/releases/<8_3_19>.php` when `announcement` is true,
    otherwise `https://www.php.net/ChangeLog-<major>.php#<version>`.
- CVEs: `https://www.php.net/ChangeLog-8.php` and `ChangeLog-7.php`. Split on
  `<section class="version" id="X.Y.Z">` and regex `CVE-\d{4}-\d{4,7}` inside each section.

### Python

- Releases: `https://www.python.org/api/v2/downloads/release/?is_published=true`.
  Keep `3.x.y` where `pre_release` is false. `url` =
  `https://www.python.org/downloads/release/python-<3124>/`.
- Security flag and CVEs: per-branch changelogs
  `https://docs.python.org/<3.N>/whatsnew/changelog.html` for every 3.N from 3.6 to
  the newest. The main `/3/` page only covers the newest line, so fetch each branch.
  - Sections start with `<section id="python-3-12-4-final">`.
  - `security` = the section contains `<h3>Security<a`.
  - CVEs: regex `CVE[- ](\d{4}-\d{4,7})` on the section text (Python often writes
    `CVE 2024-4030` with a space).
- Known gap: Python frequently omits CVE ids, so many Python security releases end
  up `unknown`. Report this; do not guess.

### Ruby

- Releases: `https://raw.githubusercontent.com/ruby/www.ruby-lang.org/master/_data/releases.yml`.
  Parse entries with regex `- version: (\S+)\n\s+date: (\S+)\n\s+post: (\S+)`.
  **Strip quotes from `post`**: some values are quoted (`"/en/news/..."`).
- Security flag and CVEs: fetch each release post `https://www.ruby-lang.org<post>`.
  Use only the body: text from `<div id="content"` up to the `Download` heading.
  The sidebar lists recent security news and causes false positives otherwise.
  - `security` = body matches `CVE-|security|vulnerab` (case-insensitive).
- `url` = the post URL.

### Node.js

- Releases: `https://nodejs.org/dist/index.json`. It has `version`, `date`,
  and a boolean `security`. Skip `X.0.0` and odd majors.
- `url` = `https://nodejs.org/en/blog/release/v<version>`.
- CVEs: fetch that release page for security releases only, then regex CVE ids.

### Java (OpenJDK)

- Security releases: `https://openjdk.org/groups/vulnerability/advisories/`.
  Dates appear as `YYYY/MM/DD` links. Each date is one security release.
  Out-of-band advisories exist (2026 had 6).
- CVEs: `https://openjdk.org/groups/vulnerability/advisories/<YYYY-MM-DD>`.
  `url` = the same page.
- Version labels (optional): Eclipse Temurin API
  `https://api.adoptium.net/v3/assets/feature_releases/<8|11|17|21|25>/ga?image_type=jdk&os=linux&architecture=x64&vendor=eclipse&page_size=20&page=<n>`.
  **`page_size` is capped at 20**: paginate until an empty or error response. A Temurin
  build released 0–10 days after an advisory date belongs to that advisory.
  History starts mid-2021.

### Go

- Releases: `https://go.dev/doc/devel/release`. Each patch release is
  `<p id="go1.24.3"> ... (released 2025-05-06) includes security fixes to ...</p>`.
  - `security` = the paragraph text contains `security`.
  - `url` = `https://go.dev/doc/devel/release#go<version>`.
- CVEs: Go vulnerability database.
  - `https://vuln.go.dev/index/modules.json`: take vuln ids of modules `stdlib`
    and `toolchain`.
  - `https://vuln.go.dev/ID/<GO-YYYY-NNNN>.json` (OSV format): for affected packages
    `stdlib`/`toolchain`, every `ranges[].events[].fixed` version (e.g. `1.21.8`)
    maps that entry's `aliases` (CVE ids) to that Go release.

### Rust

- Releases and CVEs: `https://raw.githubusercontent.com/rust-lang/rust/master/RELEASES.md`.
  Split on lines `Version X.Y.Z (YYYY-MM-DD)`.
  - `security` = section contains a CVE id or `INTEL-SA` (1.62.1 shipped an
    Intel mitigation without a CVE id).
- `url`: the official blog post when one exists, otherwise the RELEASES.md anchor
  `https://github.com/rust-lang/rust/blob/master/RELEASES.md#version-<1621>-<date>`.
  Find blog posts by scraping `https://blog.rust-lang.org/` for links matching
  `/YYYY/MM/DD/cve-.../` or `/cargo-cves/`, and match them by CVE id.

### .NET

- Index: `https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/releases-index.json`.
  Follow each channel's `releases.json` (they now live under
  `https://builds.dotnet.microsoft.com/dotnet/release-metadata/<X.Y>/releases.json`).
- Each release has `release-date`, `release-version`, `security` (bool),
  `cve-list[].cve-id`, and `release-notes` (use it as `url`).

### CVSS scores (all languages)

Lookup order for each CVE id:

1. **cvelistV5** (fast, CDN-backed):
   `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/<YYYY>/<N//1000>xxx/<CVE-ID>.json`
   (e.g. `CVE-2024-24576` → `cves/2024/24xxx/CVE-2024-24576.json`).
   - Use the `containers.cna.metrics` score first: CVSS v3.1, then v3.0, then v4.0
     `baseScore`.
   - If the CNA has none, use `containers.adp[].metrics` (CISA Vulnrichment), same order.
   - Expect a few 404s for very recent or rejected ids.
2. **NVD API** for ids still unscored:
   `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id>`.
   - Without an API key the limit is 5 requests per 30 seconds. Sleep 6.5 s between
     calls. If `NVD_API_KEY` is set, send it as the `apiKey` header and sleep 0.7 s.
   - Use `metrics.cvssMetricV31`, then `V30`, then `V40` → `[0].cvssData.baseScore`.
     Ignore `cvssMetricV2`.
   - Do **not** download the NVD yearly feeds. They are tens of MB each and took
     minutes per file.

Record the score source (`CNA`, `ADP`, `NVD`) for transparency.

## 9. HTML report (`dist/index.html`)

A single self-contained file that works when opened from disk (`file://`):

- **Embed all data inline** as JSON in a `<script type="application/json">` block.
  `fetch()` of local files fails under `file://`.
- **No external dependencies.** Draw charts as hand-written SVG in inline JS.
  The report must work offline.
- Light and dark themes via CSS custom properties and `prefers-color-scheme`.
- Readable at phone width; no horizontal page scroll (wide tables scroll inside
  their own container).

Sections, in order:

1. **Title and takeaway.** One sentence generated from the data: the languages with
   the fewest and most High+ forced updates over the period, and the language with
   the most `unknown` severity, with a caveat that its real High+ count may be higher.
2. **Period totals** (horizontal bars, sorted by `high_or_above` ascending).
   Three nested bars per language: all security updates (muted) ⊃ High+ (accent) ⊃
   Critical (red). End label `all / high / critical`. Tooltip on hover.
3. **Per-year small multiples**: one mini bar chart per language, same y scale for
   all, same nesting, the partial current year marked with `*` and reduced opacity.
4. **How to read this**: High+ is the "apply now" signal. CVSS practice differs by
   scorer: Microsoft often rates DoS as 7.5, Oracle scores Java conservatively, and
   Go CVEs are scored by NVD/CISA. Go's standard library covers HTTP/TLS, which other
   languages leave to third-party packages. Rust fixes ship only in the latest
   version, which is backward-compatible.
5. **Source table**: every security release with language, date, versions, severity,
   max CVSS, CVE ids, and the official link. Filters: language, severity
   (incl. "High and above"), free-text search. Sorted newest first. Sticky header.
6. **Official sources table** (§11).
7. **Method**: the rules from §6 and §8 in plain words, the data date, and known gaps.

Use `textContent` for all data-derived text. Only render links whose URL starts
with `https://`.

## 10. Manual overrides

`overrides.csv` lets a person fix what automation cannot (mostly Python CVE ids):

```
language,version,field,value,note
Python,3.12.5,cves,CVE-2024-XXXX CVE-2024-YYYY,from security-announce mailing list
```

Apply overrides after extraction and before aggregation. Show the override count
in the Method section.

## 11. Official sources table (`official_sources.csv`)

| language | label | url |
|---|---|---|
| PHP | Release announcements (security tag) | https://www.php.net/releases/ |
| PHP | Supported versions | https://www.php.net/supported-versions.php |
| Python | Releases | https://www.python.org/downloads/ |
| Python | Security policy | https://www.python.org/dev/security/ |
| Python | security-announce list | https://mail.python.org/archives/list/security-announce@python.org/ |
| Node.js | Security release posts | https://nodejs.org/en/blog/vulnerability |
| Node.js | Release index JSON | https://nodejs.org/dist/index.json |
| .NET | Release notes with CVE lists | https://github.com/dotnet/core/tree/main/release-notes |
| .NET | Support policy | https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core |
| Go | Release history | https://go.dev/doc/devel/release |
| Go | Vulnerability database | https://pkg.go.dev/vuln/list |
| Go | golang-announce | https://groups.google.com/g/golang-announce |
| Rust | Blog (CVE posts) | https://blog.rust-lang.org/ |
| Rust | RELEASES.md | https://github.com/rust-lang/rust/blob/master/RELEASES.md |
| Rust | Security policy | https://www.rust-lang.org/policies/security |
| Ruby | Security announcements | https://www.ruby-lang.org/en/security/ |
| Ruby | Branch maintenance status | https://www.ruby-lang.org/en/downloads/branches/ |
| Java | OpenJDK vulnerability advisories | https://openjdk.org/groups/vulnerability/advisories/ |
| Java | Oracle Critical Patch Updates | https://www.oracle.com/security-alerts/ |
| All | Support end dates | https://endoflife.date/ |

## 12. Validation

Run these checks at the end of every build and fail loudly (non-zero exit, clear
message) when one breaks. Upstream page changes are the main risk.

1. Every language has at least one security release in every full year of the period
   (Rust 2025 legitimately had zero; allow zero only for Rust).
2. No language's yearly `security_updates` drops by more than 50% compared with the
   previous build's `data/severity_yearly.csv` for the same year.
3. Share of scored CVEs ≥ 85% overall.
4. Spot-check up to 2 random `url`s per language with an HTTP HEAD/GET. Warn
   (don't fail) on non-200.

### Reference results (built 2026-10-27, period 2021–2025)

Use these to sanity-check a fresh implementation. Small drift is expected as CVSS
scores and advisories are revised.

| language | security_updates | high_or_above | critical | unknown_severity |
|---|---|---|---|---|
| Rust | 7 | 5 | 1 | 1 |
| Ruby | 11 | 7 | 3 | 1 |
| Python | 25 | 7 | 2 | 16 |
| Java | 20 | 13 | 0 | 0 |
| PHP | 24 | 14 | 8 | 5 |
| Node.js | 24 | 21 | 5 | 2 |
| Go | 44 | 32 | 7 | 0 |
| .NET | 41 | 36 | 2 | 0 |

Per-year `security_updates`:

| language | 2021 | 2022 | 2023 | 2024 | 2025 |
|---|---|---|---|---|---|
| Rust | 1 | 2 | 2 | 2 | 0 |
| Ruby | 3 | 2 | 1 | 3 | 2 |
| Python | 4 | 4 | 3 | 7 | 7 |
| Java | 4 | 4 | 4 | 4 | 4 |
| PHP | 8 | 5 | 4 | 4 | 3 |
| Node.js | 9 | 5 | 3 | 4 | 3 |
| Go | 9 | 9 | 12 | 6 | 8 |
| .NET | 8 | 8 | 10 | 9 | 6 |

## 13. Known limitations (state them in the report)

- Severity depends on who scored the CVE. Cross-language comparisons of High+ are
  approximate.
- Python and PHP sometimes ship security fixes without CVE ids → `unknown`.
- "One user on one branch" is approximated by the busiest branch per year.
- Only the runtime is measured. Ecosystem package updates are often the larger burden.
- Support lifetimes matter for update burden too, but are not counted here:
  Java LTS 8+ years (vendor-dependent), Python 5, PHP 4, Ruby ~3–4, .NET LTS 3,
  Node.js LTS ~2.5, Go ~1 (strong compatibility promise), Rust latest-only
  (compatibility guaranteed).

## 14. Conventions for agents working on this repo

- Keep to the standard library. Ask before adding any dependency.
- Each source module is independent and testable with a cached fixture in
  `tests/fixtures/`. Add a fixture when you fix a parser.
- When an upstream format changes, fix the parser, update this file's §8, and
  note the date.
- Do not hand-edit generated files in `data/` or `dist/`. Change code or
  `overrides.csv` and rebuild.
