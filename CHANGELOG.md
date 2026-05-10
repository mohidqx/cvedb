# Changelog

All notable changes to **cvedb** are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [2.1.0] — 2026-05-10

### ✨ New Features
- **Offensive Addon Integration** — `cvedb-offensive.sh` now sourced by default in `cvedb.sh`, adds three new commands:
  - `cvedb scan <target>` — Port scan and enumerate CVEs for a target IP/domain
  - `cvedb nuclei <cve-id>` — Run Nuclei templates against a specific CVE
  - `cvedb poc <cve-id>` — Download and execute public POC for a CVE
- **Dual-mode addon** — Install as option A (source into cvedb.sh) or option B (run standalone)
- **Integrated help** — `cvedb help` now includes offensive commands

### 🔧 Changed
- **Default behaviour** — offensive addon is now auto-loaded when `cvedb-offensive.sh` is present in the same directory

### 📋 Requirements (Offensive)
- `nuclei` — Template-based vulnerability scanner
- `nmap` — Network scanning
- `curl` or `wget` — POC delivery

---

## [2.0.0] — 2026-05-09

### ✨ New Features
- **Self-update** — `cvedb update` pulls the latest release from `github.com/mohidqx/cvedb`, compares semver, and replaces the installed binary automatically (with `sudo` fallback)
- **Background update notification** — once per day, silently checks for newer versions and prints a one-line notice without blocking execution
- **`show` command** — `cvedb show CVE-XXXX-XXXXX` renders a full detail card: CVSS, EPSS, KEV status, ransomware flag, summary (reflowed), references, and CPEs
- **`search` command** — full-text search across summary, CVE ID, vendor names, and CPE strings with `cvedb search <term>`
- **`epss` command** — `cvedb epss [N]` ranks the top N CVEs by EPSS exploitation probability score
- **`kev` command** — filters the feed to CISA Known Exploited Vulnerabilities only
- **`watch` command** — `cvedb watch [seconds]` live-refreshes the terminal view on a configurable interval (default 60s)
- **`stats` command** — feed-level statistics: totals per severity, KEV count, ransomware count, avg CVSS/EPSS, top 5 vendors
- **`clear-cache` command** — delete the local feed cache on demand
- **Compiled binary** — distributed as a `shc`-compiled ELF binary alongside the `.sh` source; no source exposure at runtime
- **5 output formats** — `normal`, `wide`, `json`, `csv`, `minimal`; wide adds explicit KEV/RW columns; minimal is one-line-per-CVE for scripting
- **Severity filter** — `-s / --severity CRITICAL|HIGH|MEDIUM|LOW` applies at the jq layer before display
- **KEV & Ransomware badges** — `[KEV]` and `[RW]` inline badges in normal/wide table views
- **`severity` field in JSON export** — computed string field (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`) alongside raw CVSS score
- **`vendors` and `cpes` fields** — included in JSON export and indexed for `search`
- **Config file** — `~/.config/cvedb/config` for persisting `LIMIT`, `CACHE_TTL`, `SEVERITY_FILTER`, `NO_COLOR`
- **Environment variable overrides** — `CVEDB_LIMIT`, `CVEDB_SEVERITY`, `CVEDB_NO_COLOR`
- **`--no-cache` flag** — force a fresh API fetch, bypassing the TTL
- **`--stats` flag** — append statistics block after the table in a normal run
- **`--no-color` flag** — disable ANSI colours for piping or non-colour terminals
- **`-o / --output FILE`** — custom JSON export path
- **Feed cache** — responses cached at `~/.cache/cvedb/feed.json` for 5 minutes (configurable via `CACHE_TTL`) to avoid redundant API hits

### 🔧 Changed
- **Removed banner** — no ASCII art or decorative header on output; information only
- **jq filters externalised** to temp files — eliminates all shell-quoting edge cases and makes the jq code readable and maintainable
- **jq `def severity_level`** — shared helper function used consistently across filter and stats queries
- **Fallback behaviour** — when date filter returns 0 results, falls back to latest N overall with a clear warning (not a silent failure)
- **CVSS colouring** uses integer arithmetic via `bc` to avoid `awk`/`python` dependency
- **JSON export schema** now includes `cvedb_version` field

### 🐛 Fixed
- Shell quoting issues with `jq` inline filters containing `?//` operator (fixed by writing filters to temp files)
- `stat` portability: handles both GNU (`-c %Y`) and BSD (`-f %m`) variants for cache mtime check
- `--date` flag and positional date arg now both validate format with a regex guard

---

## [1.0.0] — 2026-05-08

### Added
- Initial release
- Fetch top 20 CVEs from `cvedb.shodan.io/cves`
- Filter by published/modified date
- CVSS severity colour coding (red/yellow/green/dim)
- Auto-export to `cve_YYYY-MM-DD.json`
- Basic `--help` and `--version` flags
- Dependency check for `curl` and `jq`
- Date format validation
- Fallback to latest 20 if no date matches

---

[2.0.0]: https://github.com/mohidqx/cvedb/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/mohidqx/cvedb/releases/tag/v1.0.0
