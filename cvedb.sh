#!/usr/bin/env bash
# cvedb — Shodan CVE Tracker
# Version  : 2.0.0
# Author   : mohidqx
# Repo     : https://github.com/mohidqx/cvedb
# License  : MIT

set -euo pipefail

# ─── constants ────────────────────────────────────────────────────────────────
VERSION="2.0.0"
REPO="mohidqx/cvedb"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/main"
API_URL="https://cvedb.shodan.io/cves"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/cvedb"
CONFIG_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/cvedb/config"
INSTALL_PATH="${INSTALL_PATH:-/usr/local/bin/cvedb}"

# ─── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'    BRED='\033[1;31m'
YELLOW='\033[1;33m' GREEN='\033[0;32m'
CYAN='\033[0;36m'   BLUE='\033[0;34m'
MAGENTA='\033[0;35m' BOLD='\033[1m'
DIM='\033[2m'       RESET='\033[0m'

# ─── helpers ──────────────────────────────────────────────────────────────────
die()    { echo -e "${BRED}✗${RESET} $*" >&2; exit 1; }
info()   { echo -e "${CYAN}→${RESET} $*"; }
ok()     { echo -e "${GREEN}✔${RESET} $*"; }
warn()   { echo -e "${YELLOW}⚠${RESET}  $*"; }
section(){ echo -e "\n${BOLD}${BLUE}$*${RESET}"; }

need() {
  for dep in "$@"; do
    command -v "$dep" &>/dev/null || die "Required tool not found: '${dep}'. Install it and retry."
  done
}

# ─── version compare (major.minor.patch) ──────────────────────────────────────
ver_gt() {
  local IFS=.
  local a=($1) b=($2)
  for i in 0 1 2; do
    local av=${a[$i]:-0} bv=${b[$i]:-0}
    (( av > bv )) && return 0
    (( av < bv )) && return 1
  done
  return 1
}

# ─── auto-update ──────────────────────────────────────────────────────────────
cmd_update() {
  need curl
  info "Checking for updates  (current: v${VERSION})…"

  local remote_ver
  remote_ver=$(curl -fsSL --max-time 10 \
    "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
    | grep '"tag_name"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) \
    || { warn "Cannot reach GitHub. Skipping update check."; return; }

  if [[ -z "$remote_ver" ]]; then
    warn "Could not parse remote version. Skipping."; return
  fi

  if ver_gt "$remote_ver" "$VERSION"; then
    info "New version available: ${BOLD}v${remote_ver}${RESET}"
    info "Downloading from ${RAW_BASE}/cvedb.sh …"
    local tmp
    tmp=$(mktemp)
    curl -fsSL --max-time 30 "${RAW_BASE}/cvedb.sh" -o "$tmp" \
      || { rm -f "$tmp"; die "Download failed."; }
    chmod +x "$tmp"
    if [[ -w "$INSTALL_PATH" ]]; then
      mv "$tmp" "$INSTALL_PATH"
      ok "Updated to v${remote_ver}  →  ${INSTALL_PATH}"
    else
      warn "No write permission to ${INSTALL_PATH}. Trying sudo…"
      sudo mv "$tmp" "$INSTALL_PATH" \
        && ok "Updated to v${remote_ver}  →  ${INSTALL_PATH}" \
        || { rm -f "$tmp"; die "Update failed. Run: sudo cvedb update"; }
    fi
  else
    ok "Already up to date  (v${VERSION})"
  fi
}

# ─── silent background update check (on every run) ────────────────────────────
_bg_update_check() {
  local flag_file="${CACHE_DIR}/.update_checked"
  local today
  today=$(date +%Y-%m-%d)
  # only check once per day
  [[ -f "$flag_file" && "$(cat "$flag_file")" == "$today" ]] && return
  mkdir -p "$CACHE_DIR"
  (
    remote_ver=$(curl -fsSL --max-time 8 \
      "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
      | grep '"tag_name"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
    if [[ -n "$remote_ver" ]] && ver_gt "$remote_ver" "$VERSION"; then
      echo -e "\n${YELLOW}⚡ cvedb v${remote_ver} available → run: cvedb update${RESET}" >&2
    fi
    echo "$today" > "$flag_file"
  ) &
}

# ─── config load ──────────────────────────────────────────────────────────────
load_config() {
  LIMIT=20
  CACHE_TTL=300     # seconds
  NO_COLOR=0
  SEVERITY_FILTER=""

  if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
  fi

  # env overrides
  [[ -n "${CVEDB_LIMIT:-}"    ]] && LIMIT="$CVEDB_LIMIT"
  [[ -n "${CVEDB_NO_COLOR:-}" ]] && NO_COLOR="$CVEDB_NO_COLOR"
  [[ -n "${CVEDB_SEVERITY:-}" ]] && SEVERITY_FILTER="$CVEDB_SEVERITY"

  if [[ "$NO_COLOR" -eq 1 ]]; then
    RED='' BRED='' YELLOW='' GREEN='' CYAN='' BLUE='' MAGENTA='' BOLD='' DIM='' RESET=''
  fi
}

# ─── cache ────────────────────────────────────────────────────────────────────
_cache_key() { echo "${CACHE_DIR}/feed.json"; }

_fetch_with_cache() {
  mkdir -p "$CACHE_DIR"
  local cache_file
  cache_file=$(_cache_key)
  local now
  now=$(date +%s)

  if [[ -f "$cache_file" ]]; then
    local mtime
    mtime=$(stat -c %Y "$cache_file" 2>/dev/null || stat -f %m "$cache_file" 2>/dev/null || echo 0)
    local age=$(( now - mtime ))
    if (( age < CACHE_TTL )); then
      info "Using cached data  (${age}s old, TTL=${CACHE_TTL}s)"
      cat "$cache_file"
      return
    fi
  fi

  info "Fetching CVE feed from Shodan…"
  local raw
  raw=$(curl --silent --fail --max-time 20 "$API_URL") \
    || die "Cannot reach ${API_URL}. Check your connection."
  echo "$raw" > "$cache_file"
  echo "$raw"
}

# ─── jq filter files ──────────────────────────────────────────────────────────
_write_filters() {
  local dir="$1"

  cat > "${dir}/main.jq" << 'JQEOF'
def severity_level:
  if   . >= 9.0 then "CRITICAL"
  elif . >= 7.0 then "HIGH"
  elif . >= 4.0 then "MEDIUM"
  elif . >  0   then "LOW"
  else               "NONE"
  end;

[
  .cves[]? |
  select(
    ($date == "" or
      ((.published // "") | startswith($date)) or
      ((.modified  // "") | startswith($date)))
  ) |
  select(
    ($sev == "" or ((.cvss // 0) | severity_level) == ($sev | ascii_upcase))
  )
] |
sort_by(.published // .modified // "1970-01-01") |
reverse |
.[:($limit | tonumber)] |
map({
  cve_id,
  published:    (.published    // "N/A"),
  modified:     (.modified     // "N/A"),
  cvss:         (.cvss         // 0),
  cvss_version: (.cvss_version // "N/A"),
  epss:         (.epss         // 0),
  severity:     ((.cvss // 0) | severity_level),
  kev:          (.kev          // false),
  ransomware:   (.ransomware   // false),
  summary:      (.summary      // "No summary available."),
  references:   ([ (.references // [])[] | .url // . ] | .[:5]),
  cpes:         ([ (.cpes      // [])[]  ] | .[:5]),
  vendors:      ([ (.vendors   // [])[]  ] | .[:5])
})
JQEOF

  cat > "${dir}/stats.jq" << 'JQEOF'
def severity_level:
  if   . >= 9.0 then "CRITICAL"
  elif . >= 7.0 then "HIGH"
  elif . >= 4.0 then "MEDIUM"
  elif . >  0   then "LOW"
  else               "NONE"
  end;

. as $all |
{
  total:     ($all | length),
  critical:  ([ $all[] | select(.cvss >= 9.0)  ] | length),
  high:      ([ $all[] | select(.cvss >= 7.0 and .cvss < 9.0) ] | length),
  medium:    ([ $all[] | select(.cvss >= 4.0 and .cvss < 7.0) ] | length),
  low:       ([ $all[] | select(.cvss  > 0  and .cvss < 4.0)  ] | length),
  kev:       ([ $all[] | select(.kev == true) ] | length),
  ransomware:([ $all[] | select(.ransomware == true) ] | length),
  avg_cvss:  (if ($all | length) > 0 then ([ $all[].cvss ] | add / length) | . * 100 | round / 100 else 0 end),
  avg_epss:  (if ($all | length) > 0 then ([ $all[].epss ] | add / length) | . * 10000 | round / 10000 else 0 end),
  top_vendors: ([ $all[].vendors[]? ] | group_by(.) | map({vendor:.[0], count:(.|length)}) | sort_by(-.count) | .[:5])
}
JQEOF
}

# ─── CVSS colour ──────────────────────────────────────────────────────────────
cvss_color() {
  local v=$1
  local n
  n=$(printf '%s' "$v" | grep -oE '^[0-9]+(\.[0-9]+)?' || echo 0)
  local i
  i=$(echo "$n * 10 / 1" | bc 2>/dev/null || echo 0)
  if   (( i >= 90 )); then printf '%s' "${BRED}"
  elif (( i >= 70 )); then printf '%s' "${YELLOW}"
  elif (( i >= 40 )); then printf '%s' "${GREEN}"
  else                     printf '%s' "${DIM}"
  fi
}

kev_badge()        { [[ "$1" == "true" ]] && echo " ${BRED}[KEV]${RESET}" || echo ""; }
ransomware_badge() { [[ "$1" == "true" ]] && echo " ${MAGENTA}[RW]${RESET}" || echo ""; }

# ─── print table ──────────────────────────────────────────────────────────────
print_table() {
  local data="$1"
  local mode="${2:-normal}"   # normal | wide | json | csv | minimal

  case "$mode" in
    json)
      echo "$data" | jq .
      return ;;
    csv)
      echo "cve_id,published,cvss,severity,epss,kev,ransomware,summary"
      echo "$data" | jq -r '.[] | [.cve_id,.published[:10],.cvss,.severity,.epss,(.kev|tostring),(.ransomware|tostring),(.summary[:120]|gsub(",";";"))] | @csv'
      return ;;
    minimal)
      echo "$data" | jq -r '.[] | .cve_id + " " + (.cvss|tostring) + " " + .severity'
      return ;;
  esac

  # normal / wide table
  local sep
  if [[ "$mode" == "wide" ]]; then
    sep="${BOLD}$(printf '─%.0s' {1..110})${RESET}"
    printf "${BOLD}  %-20s  %-12s  %-8s  %-8s  %-5s  %-3s  %-3s  %s${RESET}\n" \
      "CVE ID" "Published" "CVSS" "Severity" "EPSS" "KEV" "RW " "Summary"
  else
    sep="${BOLD}$(printf '─%.0s' {1..88})${RESET}"
    printf "${BOLD}  %-20s  %-10s  %-8s  %-8s  %-5s  %s${RESET}\n" \
      "CVE ID" "Published" "CVSS" "Severity" "EPSS" "Summary"
  fi
  echo -e "$sep"

  echo "$data" | jq -r '.[] |
    [
      .cve_id,
      (.published[:10] // "N/A"),
      (.cvss|tostring),
      .severity,
      (.epss|tostring),
      (.kev|tostring),
      (.ransomware|tostring),
      (.summary[:80] + if (.summary|length) > 80 then "…" else "" end)
    ] | @tsv
  ' | while IFS=$'\t' read -r id pub cvss sev epss kev rw summ; do
    local cc
    cc=$(cvss_color "$cvss")
    local kb rb
    kb=$(kev_badge "$kev")
    rb=$(ransomware_badge "$rw")

    if [[ "$mode" == "wide" ]]; then
      printf "  ${CYAN}%-20s${RESET}  %-10s  ${cc}%-8s${RESET}  %-8s  %-5s  %-3s  %-3s  ${DIM}%s${RESET}\n" \
        "$id" "$pub" "$cvss" "$sev" "$epss" \
        "$([[ $kev == true ]] && echo "YES" || echo "-")" \
        "$([[ $rw  == true ]] && echo "YES" || echo "-")" \
        "$summ"
    else
      printf "  ${CYAN}%-20s${RESET}  %-10s  ${cc}%-8s${RESET}  %-8s  %-5s  ${DIM}%s${RESET}%s%s\n" \
        "$id" "$pub" "$cvss" "$sev" "$epss" "$summ" "$kb" "$rb"
    fi
  done

  echo -e "$sep"
  echo -e "  ${BRED}CRITICAL ≥9.0${RESET}  ${YELLOW}HIGH ≥7.0${RESET}  ${GREEN}MEDIUM ≥4.0${RESET}  ${DIM}LOW <4.0${RESET}   ${BRED}[KEV]${RESET}=Known Exploited  ${MAGENTA}[RW]${RESET}=Ransomware"
}

# ─── stats view ───────────────────────────────────────────────────────────────
print_stats() {
  local data="$1"
  local s
  s=$(echo "$data" | jq -f "${FILTER_DIR}/stats.jq")

  section "📊  Feed Statistics"
  echo -e "  Total CVEs     : ${BOLD}$(echo "$s" | jq .total)${RESET}"
  echo -e "  ${BRED}Critical${RESET}       : $(echo "$s" | jq .critical)"
  echo -e "  ${YELLOW}High${RESET}           : $(echo "$s" | jq .high)"
  echo -e "  ${GREEN}Medium${RESET}         : $(echo "$s" | jq .medium)"
  echo -e "  ${DIM}Low${RESET}            : $(echo "$s" | jq .low)"
  echo -e "  KEV (CISA)     : ${BOLD}$(echo "$s" | jq .kev)${RESET}"
  echo -e "  Ransomware     : ${BOLD}$(echo "$s" | jq .ransomware)${RESET}"
  echo -e "  Avg CVSS       : ${BOLD}$(echo "$s" | jq .avg_cvss)${RESET}"
  echo -e "  Avg EPSS       : ${BOLD}$(echo "$s" | jq .avg_epss)${RESET}"
  echo
  section "🏢  Top Vendors"
  echo "$s" | jq -r '.top_vendors[] | "  \(.count)x  \(.vendor)"'
}

# ─── CVE detail view ──────────────────────────────────────────────────────────
cmd_show() {
  local cve_id="${1:-}"
  [[ -z "$cve_id" ]] && die "Usage: cvedb show CVE-XXXX-XXXXX"
  cve_id=$(echo "$cve_id" | tr '[:lower:]' '[:upper:]')

  local raw
  raw=$(_fetch_with_cache)

  local rec
  rec=$(echo "$raw" | jq --arg id "$cve_id" '.cves[]? | select(.cve_id == $id)') \
    || die "CVE not found in current feed: $cve_id"

  [[ -z "$rec" ]] && die "CVE not found in current feed: $cve_id"

  section "🔍  $cve_id"
  echo -e "  Published    : $(echo "$rec" | jq -r '.published // "N/A"')"
  echo -e "  Modified     : $(echo "$rec" | jq -r '.modified  // "N/A"')"
  local cvss
  cvss=$(echo "$rec" | jq -r '.cvss // 0')
  local cc
  cc=$(cvss_color "$cvss")
  echo -e "  CVSS         : ${cc}${BOLD}${cvss}${RESET}  (v$(echo "$rec" | jq -r '.cvss_version // "N/A"'))"
  echo -e "  EPSS         : $(echo "$rec" | jq -r '.epss // 0')"
  echo -e "  KEV          : $(echo "$rec" | jq -r 'if .kev then "\033[1;31mYES — CISA Known Exploited\033[0m" else "No" end')"
  echo -e "  Ransomware   : $(echo "$rec" | jq -r 'if .ransomware then "\033[0;35mYES\033[0m" else "No" end')"
  echo
  echo -e "  ${BOLD}Summary${RESET}"
  echo "$rec" | jq -r '.summary // "N/A"' | fold -sw 78 | sed 's/^/    /'
  echo
  local refs
  refs=$(echo "$rec" | jq -r '(.references // [])[] | .url // .')
  if [[ -n "$refs" ]]; then
    echo -e "  ${BOLD}References${RESET}"
    echo "$refs" | head -5 | sed 's/^/    /'
  fi
  local cpes
  cpes=$(echo "$rec" | jq -r '(.cpes // [])[]' 2>/dev/null | head -5)
  if [[ -n "$cpes" ]]; then
    echo
    echo -e "  ${BOLD}CPEs${RESET}"
    echo "$cpes" | sed 's/^/    /'
  fi
  echo
}

# ─── watch mode ───────────────────────────────────────────────────────────────
cmd_watch() {
  local interval="${1:-60}"
  info "Watch mode — refreshing every ${interval}s  (Ctrl-C to stop)"
  while true; do
    clear
    # invalidate cache to force fresh fetch
    rm -f "$(_cache_key)"
    _run_fetch "$TARGET_DATE" "$OUTPUT_FORMAT" "$OUTPUT_FILE" "quiet"
    echo -e "\n${DIM}Last refresh: $(date)  |  Next in ${interval}s${RESET}"
    sleep "$interval"
  done
}

# ─── search mode ──────────────────────────────────────────────────────────────
cmd_search() {
  local term="${1:-}"
  [[ -z "$term" ]] && die "Usage: cvedb search <keyword>"
  local raw
  raw=$(_fetch_with_cache)

  local results
  results=$(echo "$raw" | jq --arg q "$term" '
    [
      .cves[]? |
      select(
        (.summary      // "" | ascii_downcase | contains($q | ascii_downcase)) or
        (.cve_id       // "" | ascii_downcase | contains($q | ascii_downcase)) or
        (.vendors      // [] | map(ascii_downcase) | any(contains($q | ascii_downcase))) or
        (.cpes         // [] | map(ascii_downcase) | any(contains($q | ascii_downcase)))
      )
    ] | sort_by(.cvss) | reverse | .[:20]
  ')

  local n
  n=$(echo "$results" | jq 'length')
  info "Found ${BOLD}${n}${RESET} results for: ${BOLD}\"${term}\"${RESET}"
  echo
  print_table "$results" "$OUTPUT_FORMAT"
}

# ─── EPSS top mode ────────────────────────────────────────────────────────────
cmd_epss() {
  local top="${1:-20}"
  local raw
  raw=$(_fetch_with_cache)

  local results
  results=$(echo "$raw" | jq --argjson n "$top" '
    [.cves[]? | select(.epss != null)]
    | sort_by(.epss) | reverse | .[:$n]
    | map({cve_id, published, cvss, severity:(
        if   .cvss >= 9.0 then "CRITICAL"
        elif .cvss >= 7.0 then "HIGH"
        elif .cvss >= 4.0 then "MEDIUM"
        else                   "LOW"
        end), epss, kev, ransomware, summary})
  ')

  info "Top ${top} CVEs by EPSS exploitation probability"
  echo
  print_table "$results" "$OUTPUT_FORMAT"
}

# ─── KEV-only mode ────────────────────────────────────────────────────────────
cmd_kev() {
  local raw
  raw=$(_fetch_with_cache)

  local results
  results=$(echo "$raw" | jq '
    [.cves[]? | select(.kev == true)]
    | sort_by(.published) | reverse | .[:20]
    | map({cve_id, published, cvss, severity:(
        if   .cvss >= 9.0 then "CRITICAL"
        elif .cvss >= 7.0 then "HIGH"
        elif .cvss >= 4.0 then "MEDIUM"
        else                   "LOW"
        end), epss, kev, ransomware, summary})
  ')

  local n
  n=$(echo "$results" | jq 'length')
  info "CISA Known Exploited Vulnerabilities — ${BOLD}${n}${RESET} in feed"
  echo
  print_table "$results" "$OUTPUT_FORMAT"
}

# ─── core fetch + display ─────────────────────────────────────────────────────
_run_fetch() {
  local date_filter="$1"
  local fmt="$2"
  local out_file="$3"
  local quiet="${4:-}"

  local raw
  raw=$(_fetch_with_cache)

  local total
  total=$(echo "$raw" | jq '.cves | length' 2>/dev/null || echo 0)
  [[ -z "$quiet" ]] && info "Feed size: ${BOLD}${total}${RESET} CVEs"

  local filtered
  filtered=$(echo "$raw" | jq \
    --arg date  "$date_filter" \
    --arg limit "$LIMIT" \
    --arg sev   "$SEVERITY_FILTER" \
    -f "${FILTER_DIR}/main.jq")

  local n
  n=$(echo "$filtered" | jq 'length')

  if [[ "$n" -eq 0 && -n "$date_filter" ]]; then
    warn "No matches for '${date_filter}'. Showing latest ${LIMIT} overall."
    filtered=$(echo "$raw" | jq \
      --arg date  "" \
      --arg limit "$LIMIT" \
      --arg sev   "$SEVERITY_FILTER" \
      -f "${FILTER_DIR}/main.jq")
    n=$(echo "$filtered" | jq 'length')
  fi

  # export
  local ts
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "$filtered" | jq \
    --arg date "$date_filter" \
    --arg ts   "$ts" \
    --arg ver  "$VERSION" \
    '{generated_at:$ts, cvedb_version:$ver, filter_date:$date, count:(.|length), cves:.}' \
    > "$out_file"

  if [[ -z "$quiet" ]]; then
    ok "Exported ${BOLD}${n}${RESET} CVEs  →  ${BOLD}${out_file}${RESET}"
    echo
    print_table "$filtered" "$fmt"
    echo

    if [[ "${SHOW_STATS:-0}" -eq 1 ]]; then
      print_stats "$filtered"
      echo
    fi
  else
    print_table "$filtered" "$fmt"
  fi
}

# ─── usage ────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
${BOLD}cvedb${RESET} v${VERSION} — Shodan CVE Tracker  |  github.com/${REPO}

${BOLD}USAGE${RESET}
  cvedb [OPTIONS] [YYYY-MM-DD]
  cvedb <command> [args]

${BOLD}COMMANDS${RESET}
  (default)              Fetch & display top CVEs
  show  <CVE-ID>         Full detail for one CVE
  search <keyword>       Full-text search across feed
  epss  [N]              Top N CVEs by EPSS score  (default 20)
  kev                    CISA Known Exploited Vulnerabilities only
  watch [seconds]        Live-refresh mode  (default 60s)
  update                 Self-update from github.com/${REPO}
  stats                  Feed statistics + vendor breakdown
  clear-cache            Delete cached feed

${BOLD}OPTIONS${RESET}
  -d, --date YYYY-MM-DD  Filter by published/modified date  (default: today)
  -l, --limit N          Max results  (default: 20)
  -s, --severity LEVEL   Filter: CRITICAL | HIGH | MEDIUM | LOW
  -f, --format FMT       Output: normal | wide | json | csv | minimal
  -o, --output FILE      JSON export path  (default: cve_DATE.json)
      --stats            Append statistics summary
      --no-cache         Skip cache, always fetch fresh
      --no-color         Disable colours
  -v, --version          Print version
  -h, --help             This help

${BOLD}ENV VARS${RESET}
  CVEDB_LIMIT     Max results
  CVEDB_SEVERITY  Severity filter
  CVEDB_NO_COLOR  Disable colour (set to 1)

${BOLD}EXAMPLES${RESET}
  cvedb                           # today, top 20
  cvedb 2025-06-01                # specific date
  cvedb -s CRITICAL -l 5          # top 5 critical
  cvedb -f csv -o report.csv      # export CSV
  cvedb search nginx               # keyword search
  cvedb epss 10                    # top 10 by EPSS
  cvedb kev                        # CISA KEV list
  cvedb show CVE-2024-1234         # full detail
  cvedb watch 30                   # refresh every 30s
  cvedb update                     # self-update
EOF
}

# ─── main ─────────────────────────────────────────────────────────────────────
main() {
  need curl jq

  load_config

  # temp dir for jq filter files
  FILTER_DIR=$(mktemp -d)
  trap 'rm -rf "$FILTER_DIR"' EXIT
  _write_filters "$FILTER_DIR"

  # ── defaults ────────────────────────────────────────────────
  TARGET_DATE=""
  OUTPUT_FORMAT="normal"
  OUTPUT_FILE=""
  SHOW_STATS=0
  NO_CACHE=0

  # ── parse args ──────────────────────────────────────────────
  POSITIONAL=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)      usage; exit 0 ;;
      -v|--version)   echo "cvedb v${VERSION}"; exit 0 ;;
      update)         cmd_update; exit 0 ;;
      clear-cache)    rm -rf "$CACHE_DIR"; ok "Cache cleared."; exit 0 ;;
      stats)
        raw=$(_fetch_with_cache)
        all=$(echo "$raw" | jq '[.cves[]?]')
        print_stats "$all"; exit 0 ;;
      show)           shift; cmd_show "${1:-}"; exit 0 ;;
      search)         shift; cmd_search "${1:-}"; exit 0 ;;
      epss)           shift; cmd_epss "${1:-20}"; exit 0 ;;
      kev)            cmd_kev; exit 0 ;;
      watch)          shift; cmd_watch "${1:-60}"; exit 0 ;;
      -d|--date)      TARGET_DATE="$2"; shift 2 ;;
      -l|--limit)     LIMIT="$2"; shift 2 ;;
      -s|--severity)  SEVERITY_FILTER="$2"; shift 2 ;;
      -f|--format)    OUTPUT_FORMAT="$2"; shift 2 ;;
      -o|--output)    OUTPUT_FILE="$2"; shift 2 ;;
      --stats)        SHOW_STATS=1; shift ;;
      --no-cache)     NO_CACHE=1; shift ;;
      --no-color)     NO_COLOR=1; load_config; shift ;;
      -*)             die "Unknown option: $1. Try --help." ;;
      *)              POSITIONAL+=("$1"); shift ;;
    esac
  done

  # positional → date
  if [[ ${#POSITIONAL[@]} -gt 0 ]]; then
    TARGET_DATE="${POSITIONAL[0]}"
    if ! [[ "$TARGET_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
      die "Bad date '${TARGET_DATE}'. Use YYYY-MM-DD."
    fi
  fi

  [[ -z "$TARGET_DATE" ]] && TARGET_DATE=$(date +%Y-%m-%d)
  [[ -z "$OUTPUT_FILE" ]] && OUTPUT_FILE="cve_${TARGET_DATE}.json"

  # invalidate cache if --no-cache
  [[ "$NO_CACHE" -eq 1 ]] && rm -f "$(_cache_key)"

  # background update notification
  _bg_update_check

  _run_fetch "$TARGET_DATE" "$OUTPUT_FORMAT" "$OUTPUT_FILE"
}

main "$@"
