# cvedb Commands Reference

Complete command reference for **cvedb v2.1.0** including core CVE tracking and offensive addon capabilities.

---

## Table of Contents

1. [Core Commands](#core-commands)
2. [Offensive Commands](#offensive-commands)
3. [Flags & Options](#flags--options)
4. [Output Formats](#output-formats)
5. [Real-World Examples](#real-world-examples)
6. [Configuration](#configuration)

---

## Core Commands

### Basic Fetch

#### `cvedb` — Today's Top CVEs
Fetches and displays the top 20 CVEs published today.
```bash
cvedb
```
**Output:** Colour-coded table with CVSS, EPSS, KEV/RW badges

---

#### `cvedb [DATE]` — CVEs for Specific Date
Fetch top CVEs for a given date (YYYY-MM-DD format).
```bash
cvedb 2025-06-01           # top 20 for June 1st, 2025
cvedb 2026-05-09           # top 20 for May 9th, 2026
```
**Output:** Same table format, filtered by date

---

### Search & Filter

#### `cvedb search <term>` — Full-Text Search
Search across CVE ID, summary, vendors, and CPE strings.
```bash
cvedb search nginx              # find all nginx CVEs
cvedb search "remote code"      # multi-word search
cvedb search wordpress          # CMS vulnerabilities
cvedb search -s CRITICAL nginx  # filter by severity too
```
**Output:** Table of matching CVEs

---

#### `cvedb show CVE-XXXX-XXXXX` — Single CVE Detail
Display full information card for one CVE.
```bash
cvedb show CVE-2024-1234
cvedb show CVE-2026-10042
```
**Output:** 
- CVSS score & version
- EPSS exploitation probability
- KEV status
- Ransomware associations
- Full summary (reflowed)
- References list
- CPE strings
- Vendors affected

---

### Ranking & Analysis

#### `cvedb epss [N]` — Top N by Exploitation Probability
Rank CVEs by EPSS score (likelihood of being exploited in the wild).
```bash
cvedb epss                  # top 20 by EPSS
cvedb epss 10               # top 10 most exploitable
cvedb epss 50               # top 50
```
**Output:** Table sorted by EPSS descending

---

#### `cvedb kev` — CISA Known Exploited Vulnerabilities
Show only CVEs with active public exploits (CISA KEV feed).
```bash
cvedb kev
```
**Output:** All KEV entries with publication dates

---

#### `cvedb stats` — Feed Statistics
Display aggregate statistics and top vendor breakdown.
```bash
cvedb stats
```
**Output:**
- Total CVEs in feed
- Count by severity (CRITICAL / HIGH / MEDIUM / LOW)
- KEV count
- Ransomware-associated count
- Average CVSS/EPSS scores
- Top 5 affected vendors

---

### Monitoring

#### `cvedb watch [SECONDS]` — Live-Refresh Mode
Auto-refresh the table every N seconds (default: 60s).
```bash
cvedb watch                 # refresh every 60s
cvedb watch 30              # refresh every 30s
cvedb watch 5               # refresh every 5s
```
Press **Ctrl+C** to exit.

**Options with watch:**
```bash
cvedb watch 30 -d 2025-06-01          # watch for specific date
cvedb watch 30 -s CRITICAL            # watch critical only
cvedb watch 30 -f json -o results.json # continuous JSON export
```

---

### Maintenance

#### `cvedb update` — Self-Update
Check for new releases and auto-update the binary.
```bash
cvedb update
```
**Behaviour:**
- Compares local version with GitHub releases
- Downloads latest if newer
- Uses `sudo` if needed for `/usr/local/bin/cvedb`

---

#### `cvedb clear-cache` — Clear Feed Cache
Delete the cached CVE feed to force a fresh API fetch.
```bash
cvedb clear-cache
```
**Clears:** `~/.cache/cvedb/feed.json`

---

### Info

#### `cvedb --version` or `-v` — Show Version
```bash
cvedb --version
cvedb -v
```
**Output:** Version number (e.g., `2.1.0`)

---

#### `cvedb --help` or `-h` — Show Help
```bash
cvedb --help
cvedb -h
```
**Output:** Command summary and usage examples

---

## Offensive Commands

**Requires:** `cvedb-offensive.sh` sourced in `cvedb.sh` OR run standalone.

### Scanning

#### `cvedb scan <target>` — Target Recon & CVE Inventory
Port scan a target and cross-reference discovered services against known CVEs.
```bash
cvedb scan 192.168.1.100
cvedb scan example.com
cvedb scan -k YOUR_SHODAN_KEY --cvss 8.0 targets.txt
```
**Options:**
- `--shodan-key KEY` / `-k KEY` — Shodan API key (or set `SHODAN_API_KEY`)
- `--cvss N` — Minimum CVSS threshold (default: 7.0)
- `-s, --severity LEVEL` — Filter by severity
- `-o, --output FILE` — Export to JSON
- `-f, --format FMT` — Output format (normal/json/csv)

**Requires:** curl, jq, bc, nmap  
**Output:** Table of CVEs matching discovered services

---

### Template-Based Testing

#### `cvedb nuclei <cve-id>` — Run Nuclei Templates
Execute Nuclei templates against a target to verify if a CVE is present.
```bash
cvedb nuclei CVE-2024-1234 -u https://target.com
cvedb nuclei CVE-2026-10042 -l targets.txt
cvedb nuclei CVE-2024-1234 -s info  # info-level templates only
```
**Options:**
- `-u, --url URL` — Single target URL
- `-l, --list FILE` — List of targets (one per line)
- `-s, --severity LEVEL` — Filter templates by severity
- `-t, --timeout SECONDS` — Timeout per test (default: 30)
- `-o, --output FILE` — JSON/Markdown report
- `-r, --rate-limit N` — Max parallel requests
- `--no-interactsh` — Disable out-of-band interactions

**Requires:** nuclei (v3.0+), curl  
**Output:** Table of matches or detailed report

---

### POC Delivery

#### `cvedb poc <cve-id>` — Download & Execute POC
Find public POC for a CVE and optionally execute it.
```bash
cvedb poc CVE-2024-1234                     # list available POCs
cvedb poc CVE-2024-1234 -u https://target   # run POC against target
cvedb poc CVE-2026-10042 --download-only    # just download, don't run
```
**Options:**
- `-u, --url URL` — Target URL for POC execution
- `-p, --poc-id ID` — Select specific POC if multiple available
- `--download-only` — Download POC but don't execute
- `-o, --output DIR` — Save POC to directory
- `--dry-run` — Show what would be executed
- `--github-token TOKEN` — GitHub API token for rate limiting

**POC Sources:**
- ExploitDB
- GitHub repositories
- Metasploit modules
- Known public POCs

**Output:** POC results or execution log

---

## Flags & Options

### Global Flags

| Flag | Description | Default | Example |
|------|-------------|---------|---------|
| `-d, --date DATE` | Filter by date (YYYY-MM-DD) | today | `cvedb -d 2025-06-01` |
| `-l, --limit N` | Max results to show | 20 | `cvedb -l 50` |
| `-s, --severity LEVEL` | Filter: CRITICAL\|HIGH\|MEDIUM\|LOW | (all) | `cvedb -s CRITICAL` |
| `-f, --format FMT` | Output format (see below) | normal | `cvedb -f json` |
| `-o, --output FILE` | JSON export path | `cve_DATE.json` | `cvedb -o /tmp/out.json` |
| `--stats` | Append statistics after output | off | `cvedb --stats` |
| `--no-cache` | Bypass 5-min cache | off | `cvedb --no-cache` |
| `--no-color` | Disable ANSI colours | off | `cvedb --no-color` |
| `-v, --version` | Print version | — | `cvedb -v` |
| `-h, --help` | Show help | — | `cvedb -h` |

### Scan-Specific Options

| Flag | Description | Default |
|------|-------------|---------|
| `--shodan-key KEY` | Shodan API key | `$SHODAN_API_KEY` |
| `--cvss N` | Minimum CVSS (scan only) | 7.0 |
| `--max-threads N` | Parallel requests (scan) | 5 |

### Nuclei-Specific Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u, --url URL` | Single target | — |
| `-l, --list FILE` | Target file (one per line) | — |
| `-t, --timeout SEC` | Timeout per test | 30s |
| `-r, --rate-limit N` | Max parallel tests | 10 |
| `--no-interactsh` | Disable OOB interactions | off |

### POC-Specific Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u, --url URL` | Target for POC | — |
| `-p, --poc-id ID` | Specific POC to use | (auto) |
| `--download-only` | Don't execute | off |
| `--dry-run` | Preview without running | off |

---

## Output Formats

### `normal` (default)
Colour-coded terminal table with CVSS, EPSS, severity, KEV/RW badges inline.
```bash
cvedb
cvedb -f normal
```

### `wide`
Extended table with dedicated KEV and Ransomware columns.
```bash
cvedb -f wide
```

### `json`
Pretty-printed JSON to stdout (pipe-friendly).
```bash
cvedb -f json | jq '.[] | select(.cvss >= 9)'
```

### `csv`
Comma-separated values for spreadsheet import.
```bash
cvedb -f csv -o critical.csv -s CRITICAL
```

### `minimal`
One line per CVE: `CVE-ID CVSS SEVERITY` (ideal for scripting).
```bash
cvedb -f minimal | awk '$2 >= 9 {print $1}'
```

---

## Real-World Examples

### Example 1: Find Critical Nginx CVEs Published This Week
```bash
cvedb search nginx -s CRITICAL -l 20 -f json
```
**Use case:** Assess risk to nginx deployments

---

### Example 2: Monitor Active Exploits in Real-Time
```bash
cvedb kev --no-cache | tee -a exploitation-log.txt
```
**Use case:** Continuous threat monitoring

---

### Example 3: Scan an IP for Known Vulnerabilities
```bash
cvedb scan 192.168.1.50 \
  --shodan-key "YOUR_KEY" \
  --cvss 8.0 \
  -o /tmp/scan_report.json
```
**Use case:** Security assessment for a discovered host

---

### Example 4: Test Multiple Targets Against a Single CVE
```bash
cvedb nuclei CVE-2024-1234 \
  -l targets.txt \
  -o /tmp/nuclei_report.json \
  -r 20
```
**Use case:** Verify if your infrastructure is affected by a specific CVE

---

### Example 5: Download POC Without Executing
```bash
cvedb poc CVE-2024-1234 --download-only -o /tmp/pocs/
```
**Use case:** Pre-stage POCs for lab testing

---

### Example 6: Export Top 50 Critical CVEs as CSV
```bash
cvedb -s CRITICAL -l 50 -f csv -o critical_cves.csv
```
**Use case:** Import into risk management system

---

### Example 7: Continuous Feed Watch with Date Filter
```bash
cvedb watch 30 -d 2026-05-09 -f json -o /tmp/live_feed.json
```
**Use case:** Monitor live feed and export to logging system

---

### Example 8: Chain with jq for Custom Filtering
```bash
cvedb -f json --no-cache | jq '.cves[] | select(.epss > 0.9 and .kev == true)'
```
**Use case:** Find KEV entries with >90% exploitation likelihood

---

### Example 9: Multi-Step Security Response
```bash
# 1. Get top exploitable CVEs
cvedb epss 10 -o /tmp/top_epss.json

# 2. Run Nuclei against your infrastructure
cvedb nuclei CVE-2024-1234 -l /tmp/my_domains.txt -o /tmp/findings.json

# 3. Download POC for manual analysis
cvedb poc CVE-2024-1234 --download-only
```

---

### Example 10: Script to Alert on New CRITICAL CVEs
```bash
#!/bin/bash
cvedb -s CRITICAL -f minimal | while read cve cvss severity; do
  echo "🚨 ALERT: $cve ($severity) - https://cvedb.shodan.io/$cve"
done | mail -s "New Critical CVEs" security@company.com
```

---

## Configuration

### Config File
Create `~/.config/cvedb/config` to persist preferences:
```bash
# ~/.config/cvedb/config
LIMIT=50
CACHE_TTL=120              # seconds
SEVERITY_FILTER=""         # blank = all severities
NO_COLOR=0                 # 0 = colors on, 1 = colors off

# Offensive addon config
SHODAN_API_KEY="YOUR_KEY"
NUCLEI_TEMPLATE_DIR="${HOME}/.cvedb/templates"
GITHUB_TOKEN="YOUR_TOKEN"
```

### Environment Variables (Override Config)
```bash
CVEDB_LIMIT=10 \
CVEDB_SEVERITY=CRITICAL \
CVEDB_NO_COLOR=1 \
cvedb

# Offensive addon env vars
SHODAN_API_KEY="key" cvedb scan 192.168.1.1
GITHUB_TOKEN="token" cvedb poc CVE-2024-1234
```

### Cache Behaviour
- **Cache path:** `~/.cache/cvedb/feed.json`
- **Cache TTL:** 5 minutes (default, configurable via `CACHE_TTL`)
- **Bypass cache:** `cvedb --no-cache`
- **Clear cache:** `cvedb clear-cache`

---

## Severity Levels

| Level | CVSS Range | Example |
|-------|-----------|---------|
| CRITICAL | 9.0–10.0 | Remote code execution, unauthenticated |
| HIGH | 7.0–8.9 | Significant attack surface |
| MEDIUM | 4.0–6.9 | Moderate impact, requires interaction |
| LOW | 0.0–3.9 | Limited or no practical impact |

---

## Status Badges

| Badge | Meaning | Action |
|-------|---------|--------|
| `[KEV]` | CISA Known Exploited Vulnerability | **Patch ASAP** — active exploits exist |
| `[RW]` | Associated with ransomware campaigns | **High priority** — used in attacks |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error (missing deps, bad args, API fail) |
| `2` | Cache/config error |
| `3` | Authentication required (e.g., Shodan key) |

---

## Tips & Tricks

### Combine with GNU Tools
```bash
# Find CVEs affecting multiple vendors
cvedb -f json | jq '.cves[] | select(.vendors | length > 5)'

# Export all critical IDs to text file
cvedb -s CRITICAL -f minimal | cut -d' ' -f1 > critical_ids.txt

# Create a severity heatmap
cvedb --stats | grep severity
```

### Integration with Security Tools
```bash
# Pass to Metasploit
cvedb -f minimal | while read cve _; do msfconsole -x "search $cve"; done

# Send to Slack
cvedb -s CRITICAL -l 5 -f json | jq . | slackcli --channel security

# Ingest into Splunk
cvedb --no-cache -f json | curl -X POST http://splunk.local:8088 -d @-
```

### Scheduled Monitoring (Cron)
```bash
# Daily critical CVE report at 8am
0 8 * * * cvedb -s CRITICAL -f json -o /var/log/cvedb/daily_critical.json

# Hourly scan of internal IPs
0 * * * * cvedb scan /etc/cvedb/scope.txt --cvss 7.0 -o /var/log/cvedb/hourly_scan.json
```

---

## Troubleshooting

### "Required tool not found"
Install missing dependencies:
```bash
# Ubuntu/Debian
sudo apt install curl jq bc nmap nuclei

# macOS
brew install curl jq bc nmap nuclei

# Manually check
command -v curl jq bc nmap nuclei
```

### API Rate Limiting
The Shodan API has rate limits. To avoid hitting them:
```bash
# Use cache appropriately
cvedb -l 100 -f json  # uses cache by default

# Increase cache TTL
CACHE_TTL=3600 cvedb  # cache for 1 hour
```

### "Shodan API key required"
Set the key:
```bash
export SHODAN_API_KEY="your_key"
# or
cvedb scan 192.168.1.1 --shodan-key "your_key"
```

---

## Version History

- **v2.1.0** — Offensive addon integration (scan, nuclei, poc)
- **v2.0.0** — Core tracker launch (search, epss, kev, watch, stats)
- **v1.0.0** — Initial release (basic fetch)

---

**Last Updated:** 2026-05-10  
**Author:** mohidqx  
**Repo:** [github.com/mohidqx/cvedb](https://github.com/mohidqx/cvedb)
