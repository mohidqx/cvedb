#!/usr/bin/env bash
# cvedb — Shodan CVE Tracker
# Version  : 2.1.0
# Author   : mohidqx
# Repo     : https://github.com/mohidqx/cvedb
# License  : MIT

set -euo pipefail

# ─── constants ────────────────────────────────────────────────────────────────
readonly VERSION="2.1.0"
readonly REPO="mohidqx/cvedb"
readonly RAW_BASE="https://raw.githubusercontent.com/${REPO}/main"
readonly API_URL="https://cvedb.shodan.io/cves"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/cvedb"
CONFIG_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/cvedb/config"
INSTALL_PATH="${INSTALL_PATH:-/usr/local/bin/cvedb}"

# ─── colours (all written to stderr — never stdout) ───────────────────────────
RED="$(printf '\033[0;31m')"
BRED="$(printf '\033[1;31m')"
YELLOW="$(printf '\033[1;33m')"
GREEN="$(printf '\033[0;32m')"
CYAN="$(printf '\033[0;36m')"
BLUE="$(printf '\033[0;34m')"
MAGENTA="$(printf '\033[0;35m')"
BOLD="$(printf '\033[1m')"
DIM="$(printf '\033[2m')"
RESET="$(printf '\033[0m')"

# ─── helpers — all write to stderr so they never corrupt $() captures ─────────
die()     { echo -e "${BRED}✗${RESET} $*" >&2; exit 1; }
info()    { echo -e "${CYAN}→${RESET} $*" >&2; }
ok()      { echo -e "${GREEN}✔${RESET} $*" >&2; }
warn()    { echo -e "${YELLOW}⚠${RESET}  $*" >&2; }
section() { echo -e "\n${BOLD}${BLUE}$*${RESET}" >&2; }

need() {
  for dep in "$@"; do
    command -v "$dep" &>/dev/null || die "Required tool not found: '${dep}'. Install it and retry."
  done
}

# ─── version compare (semver major.minor.patch) ───────────────────────────────
ver_gt() {
  # returns 0 (true) if $1 > $2
  local i av bv
  local -a a b
  IFS='.' read -ra a <<< "$1"
  IFS='.' read -ra b <<< "$2"
  for i in 0 1 2; do
    av="${a[$i]:-0}"; bv="${b[$i]:-0}"
    (( av > bv )) && return 0
    (( av < bv )) && return 1
  done
  return 1
}

# ─── auto-update ──────────────────────────────────────────────────────────────
cmd_update() {
  need curl
  info "Checking for updates (current: v${VERSION})…"

  local remote_ver
  remote_ver=$(curl -fsSL --max-time 10 \
    "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
    | grep '"tag_name"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)

  if [[ -z "$remote_ver" ]]; then
    warn "Could not reach GitHub or parse version. Skipping update."; return 0
  fi

  if ver_gt "$remote_ver" "$VERSION"; then
    info "New version available: ${BOLD}v${remote_ver}${RESET}"
    info "Downloading from ${RAW_BASE}/cvedb.sh …"
    local tmp
    tmp=$(mktemp)
    if ! curl -fsSL --max-time 30 "${RAW_BASE}/cvedb.sh" -o "$tmp"; then
      rm -f "$tmp"; die "Download failed."
    fi
    chmod +x "$tmp"
    if [[ -w "$INSTALL_PATH" ]]; then
      mv "$tmp" "$INSTALL_PATH"
      ok "Updated to v${remote_ver}  →  ${INSTALL_PATH}"
    else
      warn "No write permission to ${INSTALL_PATH}. Trying sudo…"
      if sudo mv "$tmp" "$INSTALL_PATH"; then
        ok "Updated to v${remote_ver}  →  ${INSTALL_PATH}"
      else
        rm -f "$tmp"; die "Update failed. Try: sudo cvedb update"
      fi
    fi
  else
    ok "Already up to date (v${VERSION})"
  fi
}

# ─── silent background update check — once per day ────────────────────────────
_bg_update_check() {
  local flag_file="${CACHE_DIR}/.update_checked"
  local today
  today=$(date +%Y-%m-%d)
  [[ -f "$flag_file" && "$(cat "$flag_file" 2>/dev/null)" == "$today" ]] && return 0
  mkdir -p "$CACHE_DIR"
  (
    set +e  # don't let failures in background kill the subshell
    local rv
    rv=$(curl -fsSL --max-time 8 \
      "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
      | grep '"tag_name"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
    if [[ -n "$rv" ]] && ver_gt "$rv" "$VERSION"; then
      echo -e "\n${YELLOW}⚡ cvedb v${rv} available  →  run: cvedb update${RESET}" >&2
    fi
    echo "$today" > "$flag_file" 2>/dev/null || true
  ) &
}

# ─── config ───────────────────────────────────────────────────────────────────
load_config() {
  LIMIT=20
  CACHE_TTL=300
  NO_COLOR=0
  SEVERITY_FILTER=""

  if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
  fi

  [[ -n "${CVEDB_LIMIT:-}"    ]] && LIMIT="$CVEDB_LIMIT"
  [[ -n "${CVEDB_NO_COLOR:-}" ]] && NO_COLOR="$CVEDB_NO_COLOR"
  [[ -n "${CVEDB_SEVERITY:-}" ]] && SEVERITY_FILTER="$CVEDB_SEVERITY"

  if [[ "$NO_COLOR" -eq 1 ]]; then
    # shellcheck disable=SC2034
    RED='' BRED='' YELLOW='' GREEN='' CYAN='' BLUE='' MAGENTA='' BOLD='' DIM='' RESET=''
  fi
}

# ─── cache ────────────────────────────────────────────────────────────────────
_cache_path() { printf '%s/feed.json' "$CACHE_DIR"; }

_fetch_with_cache() {
  mkdir -p "$CACHE_DIR"
  local cache_file now mtime age
  cache_file=$(_cache_path)
  now=$(date +%s)

  if [[ -f "$cache_file" ]]; then
    mtime=$(stat -c %Y "$cache_file" 2>/dev/null \
         || stat -f %m "$cache_file" 2>/dev/null \
         || echo 0)
    age=$(( now - mtime ))
    if (( age < CACHE_TTL )); then
      info "Using cached data (${age}s old, TTL=${CACHE_TTL}s)"
      cat "$cache_file"
      return 0
    fi
  fi

  info "Fetching CVE feed from Shodan…"
  local raw
  raw=$(curl --silent --fail --max-time 20 "$API_URL") \
    || die "Cannot reach ${API_URL}. Check your connection."

  if [[ -z "$raw" ]]; then
    die "API returned an empty response."
  fi

  if ! printf '%s' "$raw" | jq empty 2>/dev/null; then
    die "API returned invalid JSON: $(printf '%s' "$raw" | head -c 120)"
  fi

  printf '%s' "$raw" > "$cache_file"
  printf '%s' "$raw"
}

# ─── jq filter files ──────────────────────────────────────────────────────────
_write_filters() {
  local dir="$1"

  # ── main filter: date + severity + limit + field reshape ──────────────────
  cat > "${dir}/main.jq" << 'JQEOF'
def severity_level:
  if   . >= 9.0 then "CRITICAL"
  elif . >= 7.0 then "HIGH"
  elif . >= 4.0 then "MEDIUM"
  elif . >  0   then "LOW"
  else               "NONE"
  end;

def safe_ref:
  if type == "object" then (.url // .href // null)
  elif type == "string" then .
  else null
  end;

[
  .cves[]? |
  select(
    $date == "" or
    ((.published // "") | startswith($date)) or
    ((.modified  // "") | startswith($date))
  ) |
  select(
    $sev == "" or
    ((.cvss // 0) | severity_level) == ($sev | ascii_upcase)
  )
] |
unique_by(.cve_id) |
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
  references:   ([ (.references // [])[] | safe_ref | select(. != null and (type == "string")) ] | .[:5]),
  cpes:         ([ (.cpes      // [])[] | select(type == "string") ] | .[:5]),
  vendors:      ([ (.vendors   // [])[] | select(type == "string") ] | .[:5])
})
JQEOF

  # ── stats filter: expects array of CVE objects ────────────────────────────
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
  total:      ($all | length),
  critical:   ([ $all[] | select((.cvss // 0) >= 9.0) ] | length),
  high:       ([ $all[] | select((.cvss // 0) >= 7.0 and (.cvss // 0) < 9.0) ] | length),
  medium:     ([ $all[] | select((.cvss // 0) >= 4.0 and (.cvss // 0) < 7.0) ] | length),
  low:        ([ $all[] | select((.cvss // 0)  > 0   and (.cvss // 0) < 4.0) ] | length),
  kev:        ([ $all[] | select(.kev == true)        ] | length),
  ransomware: ([ $all[] | select(.ransomware == true) ] | length),
  avg_cvss: (
    ($all | map(.cvss | select(. != null and type == "number")) ) as $vals |
    if ($vals | length) > 0
    then ($vals | add / length) * 100 | round / 100
    else 0
    end
  ),
  avg_epss: (
    ($all | map(.epss | select(. != null and type == "number")) ) as $vals |
    if ($vals | length) > 0
    then ($vals | add / length) * 10000 | round / 10000
    else 0
    end
  ),
  top_vendors: (
    [ $all[].vendors[]? | select(type == "string") ] |
    group_by(.) |
    map({ vendor: .[0], count: length }) |
    sort_by(-.count) |
    .[:5]
  )
}
JQEOF
}

# ─── CVSS colour ──────────────────────────────────────────────────────────────
cvss_color() {
  local v="${1:-0}"
  local n i
  n=$(printf '%s' "$v" | grep -oE '^[0-9]+(\.[0-9]+)?' || printf '0')
  i=$(printf 'scale=0; %s * 10 / 1\n' "$n" | bc 2>/dev/null || printf '0')
  if   (( i >= 90 )); then printf '%s' "$BRED"
  elif (( i >= 70 )); then printf '%s' "$YELLOW"
  elif (( i >= 40 )); then printf '%s' "$GREEN"
  else                     printf '%s' "$DIM"
  fi
}

# ─── print table ──────────────────────────────────────────────────────────────
print_table() {
  local data="$1"
  local mode="${2:-normal}"

  case "$mode" in
    json)
      printf '%s' "$data" | jq .; return ;;
    csv)
      printf 'cve_id,published,cvss,severity,epss,kev,ransomware,summary\n'
      printf '%s' "$data" | jq -r '
        .[] | [
          .cve_id,
          (.published[:10] // "N/A"),
          (.cvss | tostring),
          .severity,
          (.epss | tostring),
          (.kev | tostring),
          (.ransomware | tostring),
          (.summary[:120] | gsub(","; ";") | gsub("\t"; " "))
        ] | @csv'; return ;;
    minimal)
      printf '%s' "$data" | jq -r \
        '.[] | .cve_id + " " + (.cvss | tostring) + " " + .severity'
      return ;;
  esac

  # normal / wide table — use NUL-delimited records to survive tabs in summaries
  local sep
  if [[ "$mode" == "wide" ]]; then
    sep="$(printf '─%.0s' {1..112})"
    printf '%b  %-20s  %-10s  %-8s  %-8s  %-6s  %-3s  %-3s  %s%b\n' \
      "$BOLD" "CVE ID" "Published" "CVSS" "Severity" "EPSS" "KEV" "RW " "Summary" "$RESET"
  else
    sep="$(printf '─%.0s' {1..90})"
    printf '%b  %-20s  %-10s  %-8s  %-8s  %-6s  %s%b\n' \
      "$BOLD" "CVE ID" "Published" "CVSS" "Severity" "EPSS" "Summary" "$RESET"
  fi
  printf '%b%s%b\n' "$BOLD" "$sep" "$RESET"

  # NUL-separated fields via @base64 avoids ALL tab/newline issues in summary
  printf '%s' "$data" | jq -r '.[] |
    [
      .cve_id,
      (.published[:10] // "N/A"),
      (.cvss | tostring),
      .severity,
      (.epss | tostring),
      (.kev | tostring),
      (.ransomware | tostring),
      (.summary[:80] | gsub("\t";" ") | gsub("\n";" "))
      + if (.summary | length) > 80 then "…" else "" end
    ] | join("\u0000")
  ' | while IFS= read -r -d '' id \
              && IFS= read -r -d '' pub \
              && IFS= read -r -d '' cvss \
              && IFS= read -r -d '' sev \
              && IFS= read -r -d '' epss \
              && IFS= read -r -d '' kev \
              && IFS= read -r -d '' rw \
              && IFS= read -r -d $'\n' summ; do

    local cc kev_col rw_col
    cc=$(cvss_color "$cvss")
    kev_col="$( [[ "$kev" == "true" ]] && printf '%s' "${BRED}[KEV]${RESET}" || printf '' )"
    rw_col="$(  [[ "$rw"  == "true" ]] && printf '%s' " ${MAGENTA}[RW]${RESET}"  || printf '' )"

    if [[ "$mode" == "wide" ]]; then
      printf "  ${CYAN}%-20s${RESET}  %-10s  ${cc}%-8s${RESET}  %-8s  %-6s  %-3s  %-3s  ${DIM}%s${RESET}\n" \
        "$id" "$pub" "$cvss" "$sev" "$epss" \
        "$( [[ "$kev" == "true" ]] && printf 'YES' || printf '-' )" \
        "$( [[ "$rw"  == "true" ]] && printf 'YES' || printf '-' )" \
        "$summ"
    else
      printf "  ${CYAN}%-20s${RESET}  %-10s  ${cc}%-8s${RESET}  %-8s  %-6s  ${DIM}%s${RESET}%s%s\n" \
        "$id" "$pub" "$cvss" "$sev" "$epss" "$summ" \
        "${kev_col:+ ${kev_col}}" "${rw_col}"
    fi
  done

  printf '%b%s%b\n' "$BOLD" "$sep" "$RESET"
  printf "%b\n" "  ${BRED}CRITICAL ≥ 9.0${RESET}  ${YELLOW}HIGH ≥ 7.0${RESET}  ${GREEN}MEDIUM ≥ 4.0${RESET}  ${DIM}LOW < 4.0${RESET}   ${BRED}[KEV]${RESET} = Known Exploited  ${MAGENTA}[RW]${RESET} = Ransomware"
}

# ─── stats view ───────────────────────────────────────────────────────────────
print_stats() {
  local data="$1"
  local s
  s=$(printf '%s' "$data" | jq -f "${FILTER_DIR}/stats.jq")

  section "📊  Feed Statistics"
  printf "  Total CVEs     : ${BOLD}%s${RESET}\n"    "$(printf '%s' "$s" | jq -r '.total')"
  printf "  ${BRED}Critical${RESET}       : %s\n"    "$(printf '%s' "$s" | jq -r '.critical')"
  printf "  ${YELLOW}High${RESET}           : %s\n"  "$(printf '%s' "$s" | jq -r '.high')"
  printf "  ${GREEN}Medium${RESET}         : %s\n"   "$(printf '%s' "$s" | jq -r '.medium')"
  printf "  ${DIM}Low${RESET}            : %s\n"     "$(printf '%s' "$s" | jq -r '.low')"
  printf "  KEV (CISA)     : ${BOLD}%s${RESET}\n"   "$(printf '%s' "$s" | jq -r '.kev')"
  printf "  Ransomware     : ${BOLD}%s${RESET}\n"   "$(printf '%s' "$s" | jq -r '.ransomware')"
  printf "  Avg CVSS       : ${BOLD}%s${RESET}\n"   "$(printf '%s' "$s" | jq -r '.avg_cvss')"
  printf "  Avg EPSS       : ${BOLD}%s${RESET}\n"   "$(printf '%s' "$s" | jq -r '.avg_epss')"
  printf '\n' >&2
  section "🏢  Top Vendors"
  printf '%s' "$s" | jq -r '.top_vendors[] | "  \(.count)x  \(.vendor)"'
}

# ─── CVE detail ───────────────────────────────────────────────────────────────
cmd_show() {
  local cve_id="${1:-}"
  [[ -z "$cve_id" ]] && die "Usage: cvedb show CVE-XXXX-XXXXX"
  cve_id="${cve_id^^}"   # uppercase without subshell

  local raw rec
  raw=$(_fetch_with_cache)
  rec=$(printf '%s' "$raw" | jq --arg id "$cve_id" '.cves[]? | select(.cve_id == $id)')

  [[ -z "$rec" ]] && die "CVE not found in current feed: $cve_id"

  local cvss cc
  cvss=$(printf '%s' "$rec" | jq -r '.cvss // 0')
  cc=$(cvss_color "$cvss")

  section "🔍  $cve_id"
  printf "  Published    : %s\n"   "$(printf '%s' "$rec" | jq -r '.published // "N/A"')"
  printf "  Modified     : %s\n"   "$(printf '%s' "$rec" | jq -r '.modified  // "N/A"')"
  printf "  CVSS         : ${cc}${BOLD}%s${RESET}  (v%s)\n" \
    "$cvss" "$(printf '%s' "$rec" | jq -r '.cvss_version // "N/A"')"
  printf "  EPSS         : %s\n"   "$(printf '%s' "$rec" | jq -r '.epss // 0')"
  printf "  Severity     : %s\n"   "$(printf '%s' "$rec" | jq -r 'if (.cvss//0)>=9 then "CRITICAL" elif (.cvss//0)>=7 then "HIGH" elif (.cvss//0)>=4 then "MEDIUM" else "LOW" end')"
  printf "  KEV          : %s\n"   "$(printf '%s' "$rec" | jq -r 'if .kev then "YES — CISA Known Exploited" else "No" end')"
  printf "  Ransomware   : %s\n"   "$(printf '%s' "$rec" | jq -r 'if .ransomware then "YES" else "No" end')"
  printf '\n'
  printf "  ${BOLD}Summary${RESET}\n"
  printf '%s' "$rec" | jq -r '.summary // "N/A"' | fold -sw 78 | sed 's/^/    /'
  printf '\n'

  local refs
  refs=$(printf '%s' "$rec" | jq -r '
    (.references // [])[] |
    if type == "object" then (.url // .href // null)
    elif type == "string" then .
    else null end |
    select(. != null and type == "string")
  ' | head -5)
  if [[ -n "$refs" ]]; then
    printf "  ${BOLD}References${RESET}\n"
    printf '%s\n' "$refs" | sed 's/^/    /'
  fi

  local cpes
  cpes=$(printf '%s' "$rec" | jq -r '(.cpes // [])[] | select(type == "string")' | head -5)
  if [[ -n "$cpes" ]]; then
    printf '\n'
    printf "  ${BOLD}CPEs${RESET}\n"
    printf '%s\n' "$cpes" | sed 's/^/    /'
  fi
  printf '\n'
}

# ─── watch mode ───────────────────────────────────────────────────────────────
cmd_watch() {
  local interval="${1:-60}"
  local date_filter="${2:-}"
  local fmt="${3:-normal}"
  local out_file="${4:-}"

  # resolve defaults here, not from globals
  [[ -z "$date_filter" ]] && date_filter=$(date +%Y-%m-%d)
  [[ -z "$out_file"    ]] && out_file="cve_${date_filter}.json"

  info "Watch mode — refreshing every ${interval}s  (Ctrl-C to stop)"
  while true; do
    clear
    rm -f "$(_cache_path)"   # force fresh fetch each cycle
    _run_fetch "$date_filter" "$fmt" "$out_file" "quiet"
    printf "\n${DIM}Last refresh: %s  |  Next in %ss${RESET}\n" "$(date)" "$interval" >&2
    sleep "$interval"
  done
}

# ─── search ───────────────────────────────────────────────────────────────────
cmd_search() {
  local term="${1:-}"
  [[ -z "$term" ]] && die "Usage: cvedb search <keyword>"
  local raw results n
  raw=$(_fetch_with_cache)

  results=$(printf '%s' "$raw" | jq --arg q "$term" '
    [
      .cves[]? |
      select(
        ((.summary  // "") | ascii_downcase | contains($q | ascii_downcase)) or
        ((.cve_id   // "") | ascii_downcase | contains($q | ascii_downcase)) or
        ( (.vendors // []) | map(ascii_downcase) | any(contains($q | ascii_downcase))) or
        ( (.cpes    // []) | map(ascii_downcase) | any(contains($q | ascii_downcase)))
      )
    ] |
    sort_by(.cvss // 0) | reverse | .[:20] |
    map({
      cve_id,
      published: (.published // "N/A"),
      cvss:      (.cvss      // 0),
      severity:  (if (.cvss//0)>=9 then "CRITICAL" elif (.cvss//0)>=7 then "HIGH" elif (.cvss//0)>=4 then "MEDIUM" else "LOW" end),
      epss:      (.epss      // 0),
      kev:       (.kev       // false),
      ransomware:(.ransomware// false),
      summary:   (.summary   // "N/A")
    })
  ')

  n=$(printf '%s' "$results" | jq 'length')
  info "Found ${BOLD}${n}${RESET} results for: ${BOLD}\"${term}\"${RESET}"
  printf '\n'
  print_table "$results" "$OUTPUT_FORMAT"
}

# ─── epss top ─────────────────────────────────────────────────────────────────
cmd_epss() {
  local top="${1:-20}"
  local raw results
  raw=$(_fetch_with_cache)

  results=$(printf '%s' "$raw" | jq --argjson n "$top" '
    [ .cves[]? | select((.epss // -1) >= 0) ] |
    sort_by(.epss // 0) | reverse | .[:$n] |
    map({
      cve_id,
      published:  (.published  // "N/A"),
      cvss:       (.cvss       // 0),
      severity:   (if (.cvss//0)>=9 then "CRITICAL" elif (.cvss//0)>=7 then "HIGH" elif (.cvss//0)>=4 then "MEDIUM" else "LOW" end),
      epss:       (.epss       // 0),
      kev:        (.kev        // false),
      ransomware: (.ransomware // false),
      summary:    (.summary    // "N/A")
    })
  ')

  info "Top ${top} CVEs by EPSS exploitation probability"
  printf '\n'
  print_table "$results" "$OUTPUT_FORMAT"
}

# ─── kev ──────────────────────────────────────────────────────────────────────
cmd_kev() {
  local raw results n
  raw=$(_fetch_with_cache)

  results=$(printf '%s' "$raw" | jq '
    [ .cves[]? | select(.kev == true) ] |
    sort_by(.published // "1970-01-01") | reverse | .[:20] |
    map({
      cve_id,
      published:  (.published  // "N/A"),
      cvss:       (.cvss       // 0),
      severity:   (if (.cvss//0)>=9 then "CRITICAL" elif (.cvss//0)>=7 then "HIGH" elif (.cvss//0)>=4 then "MEDIUM" else "LOW" end),
      epss:       (.epss       // 0),
      kev:        (.kev        // false),
      ransomware: (.ransomware // false),
      summary:    (.summary    // "N/A")
    })
  ')

  n=$(printf '%s' "$results" | jq 'length')
  info "CISA Known Exploited Vulnerabilities — ${BOLD}${n}${RESET} in feed"
  printf '\n'
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
  [[ -z "$raw" ]] && die "Empty API/cache response. Try: cvedb clear-cache"

  local total filtered n ts
  total=$(printf '%s' "$raw" | jq '.cves | length' 2>/dev/null || printf '0')
  [[ -z "$quiet" ]] && info "Feed size: ${BOLD}${total}${RESET} CVEs"

  filtered=$(printf '%s' "$raw" | jq \
    --arg date  "$date_filter" \
    --arg limit "$LIMIT" \
    --arg sev   "$SEVERITY_FILTER" \
    -f "${FILTER_DIR}/main.jq")

  n=$(printf '%s' "$filtered" | jq 'length')

  # fallback: if date filter yields nothing, show latest N overall
  if [[ "$n" -eq 0 && -n "$date_filter" ]]; then
    warn "No matches for '${date_filter}'. Showing latest ${LIMIT} overall."
    filtered=$(printf '%s' "$raw" | jq \
      --arg date  "" \
      --arg limit "$LIMIT" \
      --arg sev   "$SEVERITY_FILTER" \
      -f "${FILTER_DIR}/main.jq")
    n=$(printf '%s' "$filtered" | jq 'length')
  fi

  # export JSON
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  printf '%s' "$filtered" | jq \
    --arg date "$date_filter" \
    --arg ts   "$ts" \
    --arg ver  "$VERSION" \
    '{ generated_at: $ts, cvedb_version: $ver, filter_date: $date, count: length, cves: . }' \
    > "$out_file"

  if [[ -z "$quiet" ]]; then
    ok "Exported ${BOLD}${n}${RESET} CVEs  →  ${BOLD}${out_file}${RESET}"
    printf '\n'
    print_table "$filtered" "$fmt"
    printf '\n'
    if [[ "${SHOW_STATS:-0}" -eq 1 ]]; then
      print_stats "$filtered"
      printf '\n'
    fi
  else
    print_table "$filtered" "$fmt"
  fi
}

# ─── usage ────────────────────────────────────────────────────────────────────
usage() {
  cat >&2 << EOF
${BOLD}cvedb${RESET} v${VERSION} — Shodan CVE Tracker  |  github.com/${REPO}

${BOLD}USAGE${RESET}
  cvedb [OPTIONS] [YYYY-MM-DD]
  cvedb <command> [args]

${BOLD}COMMANDS${RESET}
  (default)              Fetch & display top CVEs
  show  <CVE-ID>         Full detail for one CVE
  search <keyword>       Full-text search (summary/vendor/CPE/ID)
  epss  [N]              Top N CVEs by EPSS score  (default: 20)
  kev                    CISA Known Exploited Vulnerabilities only
  watch [sec] [date]     Live-refresh mode  (default: 60s)
  stats                  Feed-wide statistics + vendor breakdown
  update                 Self-update from github.com/${REPO}
  clear-cache            Delete local feed cache

${BOLD}OPTIONS${RESET}
  -d, --date YYYY-MM-DD  Filter by published/modified date  (default: today)
  -l, --limit N          Max results  (default: 20)
  -s, --severity LEVEL   CRITICAL | HIGH | MEDIUM | LOW
  -f, --format FMT       normal | wide | json | csv | minimal
  -o, --output FILE      JSON export path  (default: cve_DATE.json)
      --stats            Append statistics after table
      --no-cache         Skip cache, force fresh fetch
      --no-color         Disable colours
  -v, --version          Print version
  -h, --help             This help

${BOLD}ENV VARS${RESET}
  CVEDB_LIMIT     Max results
  CVEDB_SEVERITY  Severity filter
  CVEDB_NO_COLOR  Set to 1 to disable colour

${BOLD}EXAMPLES${RESET}
  cvedb                          # today, top 20
  cvedb 2025-06-01               # specific date
  cvedb -s CRITICAL -l 5         # top 5 critical
  cvedb -f csv -o out.csv        # export CSV
  cvedb search nginx             # keyword search
  cvedb epss 10                  # top 10 by EPSS
  cvedb kev                      # CISA KEV list
  cvedb show CVE-2024-1234       # full detail
  cvedb watch 30                 # refresh every 30s
  cvedb update                   # self-update
EOF
}

# ─── main ─────────────────────────────────────────────────────────────────────
main() {
  need curl jq bc

  load_config

  FILTER_DIR=$(mktemp -d)
  trap 'rm -rf "$FILTER_DIR"' EXIT
  _write_filters "$FILTER_DIR"

  # defaults
  TARGET_DATE=""
  OUTPUT_FORMAT="normal"
  OUTPUT_FILE=""
  SHOW_STATS=0
  NO_CACHE=0

  # arg parse
  local -a POSITIONAL=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)    usage; exit 0 ;;
      -v|--version) printf 'cvedb v%s\n' "$VERSION"; exit 0 ;;

      update)
        cmd_update; exit 0 ;;

      clear-cache)
        rm -rf "$CACHE_DIR"
        ok "Cache cleared."; exit 0 ;;

      stats)
        local _raw _all
        _raw=$(_fetch_with_cache)
        _all=$(printf '%s' "$_raw" | jq '[.cves[]?]')
        print_stats "$_all"; exit 0 ;;

      show)   shift; cmd_show   "${1:-}";    exit 0 ;;
      search) shift; cmd_search "${1:-}";    exit 0 ;;
      epss)   shift; cmd_epss   "${1:-20}";  exit 0 ;;
      kev)          cmd_kev;                 exit 0 ;;

      watch)
        shift
        local _wint="${1:-60}"; [[ $# -gt 0 ]] && shift || true
        # parse remaining options before launching watch
        local _wdate="" _wfmt="normal" _wout=""
        while [[ $# -gt 0 ]]; do
          case "$1" in
            -d|--date)   _wdate="$2"; shift 2 ;;
            -f|--format) _wfmt="$2";  shift 2 ;;
            -o|--output) _wout="$2";  shift 2 ;;
            *) shift ;;
          esac
        done
        cmd_watch "$_wint" "$_wdate" "$_wfmt" "$_wout"
        exit 0 ;;

      -d|--date)     TARGET_DATE="$2";     shift 2 ;;
      -l|--limit)    LIMIT="$2";           shift 2 ;;
      -s|--severity) SEVERITY_FILTER="$2"; shift 2 ;;
      -f|--format)   OUTPUT_FORMAT="$2";   shift 2 ;;
      -o|--output)   OUTPUT_FILE="$2";     shift 2 ;;
      --stats)       SHOW_STATS=1;         shift   ;;
      --no-cache)    NO_CACHE=1;           shift   ;;
      --no-color)    NO_COLOR=1; load_config; shift ;;
      -*)            die "Unknown option: $1. Try --help." ;;
      *)             POSITIONAL+=("$1");   shift   ;;
    esac
  done

  # positional arg = date
  if [[ ${#POSITIONAL[@]} -gt 0 ]]; then
    TARGET_DATE="${POSITIONAL[0]}"
    [[ "$TARGET_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] \
      || die "Bad date '${TARGET_DATE}'. Use YYYY-MM-DD."
  fi

  [[ -z "$TARGET_DATE" ]] && TARGET_DATE=$(date +%Y-%m-%d)
  [[ -z "$OUTPUT_FILE" ]] && OUTPUT_FILE="cve_${TARGET_DATE}.json"
  [[ "$NO_CACHE" -eq 1 ]] && rm -f "$(_cache_path)"

  _bg_update_check

  _run_fetch "$TARGET_DATE" "$OUTPUT_FORMAT" "$OUTPUT_FILE"
}

# ─── load offensive addon (optional) ───────────────────────────────────────────
if [[ -f "$(dirname "$0")/cvedb-offensive.sh" ]]; then
  # shellcheck disable=SC1090
  source "$(dirname "$0")/cvedb-offensive.sh"
fi

main "$@"