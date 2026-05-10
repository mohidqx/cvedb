#!/usr/bin/env bash
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  cvedb-offensive — Recon & Offensive addon for cvedb v2.1.0               ║
# ║  Author  : mohidqx  |  github.com/mohidqx/cvedb                           ║
# ║  Adds    : scan · nuclei · poc                                            ║
# ║                                                                           ║
# ║  INSTALL (two options):                                                   ║
# ║    A) Source into cvedb.sh — append this line before main "$@":           ║
# ║       source "$(dirname "$0")/cvedb-offensive.sh"                         ║
# ║    B) Standalone — run directly:                                          ║
# ║       ./cvedb-offensive.sh poc CVE-2024-1234                              ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ── Standalone bootstrap (only runs when NOT sourced from cvedb.sh) ───────────
_OFFENSIVE_STANDALONE=0
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  _OFFENSIVE_STANDALONE=1

  # Re-use cvedb helpers by sourcing the main script's functions
  CVEDB_BIN="${CVEDB_BIN:-$(command -v cvedb 2>/dev/null || echo '/usr/local/bin/cvedb')}"
  if [[ ! -f "$CVEDB_BIN" ]]; then
    echo "✗ cvedb not found. Set CVEDB_BIN=/path/to/cvedb.sh" >&2; exit 1
  fi

  # Source the main script to inherit all helpers/colours without running main()
  _SKIP_MAIN=1
  # shellcheck disable=SC1090
  source <(sed 's/^main "\$@"$//' "$CVEDB_BIN")

  load_config
  FILTER_DIR=$(mktemp -d)
  trap 'rm -rf "$FILTER_DIR"' EXIT
  _write_filters "$FILTER_DIR"
fi

# ── Shared offensive constants ────────────────────────────────────────────────
readonly OFFENSIVE_VERSION="1.0.0"
NUCLEI_TEMPLATE_DIR="${NUCLEI_TEMPLATE_DIR:-${HOME}/.cvedb/templates}"
SHODAN_API_KEY="${SHODAN_API_KEY:-}"
GITHUB_TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"

# ═════════════════════════════════════════════════════════════════════════════
#  1. TARGET SCOPE SCANNER
#     cvedb scan <scope_file> [--shodan-key KEY] [-s SEVERITY] [--cvss N]
#     Reads IPs/domains from a scope file, hits Shodan host API, cross-refs
#     against the live CVE feed, and prints a sorted hit table.
# ═════════════════════════════════════════════════════════════════════════════
cmd_scan() {
  local scope_file="${1:-}"
  shift || true

  # ── arg parse ──────────────────────────────────────────────────────────────
  local shodan_key="$SHODAN_API_KEY"
  local cvss_floor="7.0"
  local sev_filter=""
  local output_file=""
  local output_fmt="normal"
  local max_threads=5   # parallel Shodan requests

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --shodan-key|-k) shodan_key="$2";    shift 2 ;;
      --cvss)          cvss_floor="$2";    shift 2 ;;
      -s|--severity)   sev_filter="${2^^}"; shift 2 ;;
      -o|--output)     output_file="$2";   shift 2 ;;
      -f|--format)     output_fmt="$2";    shift 2 ;;
      *) shift ;;
    esac
  done

  [[ -z "$scope_file" ]] && die \
    "Usage: cvedb scan <scope_file> [--shodan-key KEY] [-s SEVERITY] [--cvss N] [-o FILE]"
  [[ ! -f "$scope_file" ]] && die "Scope file not found: $scope_file"
  [[ -z "$shodan_key"   ]] && die \
    "Shodan API key required. Set SHODAN_API_KEY env var or pass --shodan-key KEY"

  need curl jq bc

  # ── load scope ────────────────────────────────────────────────────────────
  local targets=()
  while IFS= read -r line; do
    line="${line%%#*}"          # strip inline comments
    line="${line//[[:space:]]/}" # strip whitespace
    [[ -z "$line" ]] && continue
    targets+=("$line")
  done < "$scope_file"

  local total_targets="${#targets[@]}"
  [[ "$total_targets" -eq 0 ]] && die "No targets found in: $scope_file"

  # ── fetch CVE feed once ───────────────────────────────────────────────────
  info "Loading CVE feed…"
  local feed
  feed=$(_fetch_with_cache)

  info "Scanning ${BOLD}${total_targets}${RESET} targets  (CVSS ≥ ${cvss_floor}${sev_filter:+, severity=${sev_filter}})"
  printf '\n'

  local sep
  sep="$(printf '─%.0s' {1..108})"
  printf '%b  %-22s  %-16s  %-18s  %-8s  %-8s  %-6s  %s%b\n' \
    "$BOLD" "Target" "CVE ID" "Vendor" "CVSS" "Severity" "EPSS" "Flags" "$RESET"
  printf '%b%s%b\n' "$BOLD" "$sep" "$RESET"

  local total_hits=0
  local json_hits='[]'

  for target in "${targets[@]}"; do

    # ── resolve hostname ───────────────────────────────────────────────────
    local ip="$target"
    if [[ ! "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      ip=$(dig +short "$target" 2>/dev/null \
           | grep -m1 -E '^[0-9]+\.[0-9.]+$' || printf '')
      if [[ -z "$ip" ]]; then
        warn "Cannot resolve: ${target} — skipping"
        continue
      fi
    fi

    # ── query Shodan host API ─────────────────────────────────────────────
    local resp http_code
    resp=$(curl -s -w '\n%{http_code}' --max-time 20 \
      "https://api.shodan.io/shodan/host/${ip}?key=${shodan_key}" 2>/dev/null || true)
    http_code=$(printf '%s' "$resp" | tail -1)
    resp=$(printf '%s' "$resp" | head -n -1)

    case "$http_code" in
      200) ;;
      404) printf "  ${DIM}%-22s  Not indexed by Shodan${RESET}\n" "${target:0:22}"; continue ;;
      401) die "Invalid Shodan API key." ;;
      *)   warn "${target} — Shodan API error ${http_code}"; continue ;;
    esac

    # ── extract Shodan-detected CVEs ──────────────────────────────────────
    local shodan_cves
    shodan_cves=$(printf '%s' "$resp" | jq -r \
      '[.vulns // {} | keys[]] | .[]' 2>/dev/null || true)

    if [[ -z "$shodan_cves" ]]; then
      printf "  ${DIM}%-22s  No CVEs detected by Shodan${RESET}\n" "${target:0:22}"
      continue
    fi

    local target_hit=0

    while IFS= read -r cve_id; do
      [[ -z "$cve_id" ]] && continue

      # look up in feed
      local rec
      rec=$(printf '%s' "$feed" | jq --arg id "$cve_id" \
        '.cves[]? | select(.cve_id == $id)' 2>/dev/null || true)
      [[ -z "$rec" ]] && continue

      local cvss epss severity kev rw vendor
      cvss=$(printf '%s' "$rec" | jq -r '.cvss // 0')
      epss=$(printf '%s' "$rec" | jq -r '.epss // 0')
      kev=$(printf '%s' "$rec"  | jq -r '.kev // false')
      rw=$(printf '%s' "$rec"   | jq -r '.ransomware // false')
      vendor=$(printf '%s' "$rec" | jq -r '(.vendors // []) | first // "unknown"')
      severity=$(printf '%s' "$rec" | jq -r '
        if (.cvss//0)>=9 then "CRITICAL"
        elif (.cvss//0)>=7 then "HIGH"
        elif (.cvss//0)>=4 then "MEDIUM"
        else "LOW" end')

      # ── apply filters ────────────────────────────────────────────────────
      local cvss_i floor_i
      cvss_i=$(printf 'scale=0; %s * 10 / 1\n' "$cvss" | bc 2>/dev/null || echo 0)
      floor_i=$(printf 'scale=0; %s * 10 / 1\n' "$cvss_floor" | bc 2>/dev/null || echo 70)
      (( cvss_i < floor_i )) && continue
      [[ -n "$sev_filter" && "$severity" != "$sev_filter" ]] && continue

      # ── build flag string ────────────────────────────────────────────────
      local flags=""
      [[ "$kev" == "true" ]] && flags+="${BRED}[KEV]${RESET} "
      [[ "$rw"  == "true" ]] && flags+="${MAGENTA}[RW]${RESET} "

      # ── print row ────────────────────────────────────────────────────────
      local cc
      cc=$(cvss_color "$cvss")
      printf "  ${CYAN}%-22s${RESET}  %-16s  %-18s  ${cc}%-8s${RESET}  %-8s  %-6s  %s\n" \
        "${target:0:22}" "$cve_id" "${vendor:0:18}" "$cvss" "$severity" \
        "$(printf '%.4f' "$epss")" "$flags"

      (( target_hit++ )); (( total_hits++ ))

      # ── accumulate JSON for export ───────────────────────────────────────
      if [[ -n "$output_file" ]]; then
        json_hits=$(printf '%s' "$json_hits" | jq \
          --arg t  "$target" \
          --arg ip "$ip" \
          --argjson r "$rec" \
          '. += [($r + {target: $t, resolved_ip: $ip})]')
      fi

    done <<< "$shodan_cves"

    [[ "$target_hit" -eq 0 ]] && \
      printf "  ${DIM}%-22s  CVEs present but below threshold (CVSS ≥ %s)${RESET}\n" \
        "${target:0:22}" "$cvss_floor"

  done

  printf '%b%s%b\n' "$BOLD" "$sep" "$RESET"
  printf '\n'
  ok "Scan complete — ${BOLD}${total_hits}${RESET} hits across ${BOLD}${total_targets}${RESET} targets"

  # ── JSON export ──────────────────────────────────────────────────────────
  if [[ -n "$output_file" ]]; then
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    printf '%s' "$json_hits" | jq \
      --arg ts    "$ts" \
      --arg scope "$scope_file" \
      --argjson   n "$total_hits" \
      '{ generated_at: $ts, scope_file: $scope, total_hits: $n, hits: . }' \
      > "$output_file"
    ok "Results exported → ${BOLD}${output_file}${RESET}"
  fi

  printf '\n'
  [[ "$total_hits" -gt 0 ]] && \
    info "Next step: ${BOLD}cvedb nuclei <CVE-ID>${RESET} to scaffold Nuclei templates"
}


# ═════════════════════════════════════════════════════════════════════════════
#  2. NUCLEI TEMPLATE GENERATOR
#     cvedb nuclei <CVE-ID> [-o output_dir]
#     Pulls CVE metadata from the feed, auto-detects vuln class from summary
#     keywords, and scaffolds a complete Nuclei v3 YAML template.
# ═════════════════════════════════════════════════════════════════════════════
cmd_nuclei() {
  local cve_id="${1:-}"
  shift || true

  local out_dir="$NUCLEI_TEMPLATE_DIR"
  local open_after=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o|--output) out_dir="$2"; shift 2 ;;
      --open)      open_after=1; shift   ;;
      *) shift ;;
    esac
  done

  [[ -z "$cve_id" ]] && die "Usage: cvedb nuclei <CVE-ID> [-o output_dir] [--open]"
  cve_id="${cve_id^^}"

  need curl jq

  mkdir -p "$out_dir"

  # ── fetch record ──────────────────────────────────────────────────────────
  info "Fetching metadata for ${BOLD}${cve_id}${RESET}…"
  local raw rec
  raw=$(_fetch_with_cache)
  rec=$(printf '%s' "$raw" | jq --arg id "$cve_id" \
    '.cves[]? | select(.cve_id == $id)' 2>/dev/null || true)

  [[ -z "$rec" ]] && die "CVE not found in current feed: ${cve_id}"

  # ── extract fields ────────────────────────────────────────────────────────
  local cvss epss kev rw summary published vendors cpes cvss_ver
  cvss=$(printf '%s' "$rec" | jq -r '.cvss // 0')
  epss=$(printf '%s' "$rec" | jq -r '.epss // 0')
  kev=$(printf '%s' "$rec"  | jq -r '.kev // false')
  rw=$(printf '%s' "$rec"   | jq -r '.ransomware // false')
  summary=$(printf '%s' "$rec" | jq -r '.summary // "No summary available"')
  published=$(printf '%s' "$rec" | jq -r '.published[:10] // "unknown"')
  vendors=$(printf '%s' "$rec" | jq -r '(.vendors // []) | join(", ")')
  cvss_ver=$(printf '%s' "$rec" | jq -r '.cvss_version // "3.1"')

  local severity
  severity=$(printf '%s' "$rec" | jq -r '
    if (.cvss//0) >= 9 then "critical"
    elif (.cvss//0) >= 7 then "high"
    elif (.cvss//0) >= 4 then "medium"
    else "low" end')

  # ── build references ──────────────────────────────────────────────────────
  local refs_yaml="  reference:\n"
  while IFS= read -r ref; do
    [[ -z "$ref" || "$ref" == "null" ]] && continue
    refs_yaml+="    - '${ref}'\n"
  done < <(printf '%s' "$rec" | jq -r '
    (.references // [])[] |
    if   type == "object" then (.url // .href // null)
    elif type == "string" then .
    else null end | select(. != null)' 2>/dev/null | head -5)

  refs_yaml+="    - 'https://nvd.nist.gov/vuln/detail/${cve_id}'\n"
  refs_yaml+="    - 'https://cvedb.shodan.io/cve/${cve_id}'\n"
  refs_yaml+="    - 'https://github.com/search?q=${cve_id}&type=repositories'\n"

  # ── CPE comments ──────────────────────────────────────────────────────────
  local cpe_block="  # No CPE data in feed\n"
  local cpe_list
  cpe_list=$(printf '%s' "$rec" | jq -r '(.cpes // []) | .[]' 2>/dev/null | head -5)
  if [[ -n "$cpe_list" ]]; then
    cpe_block="  # Affected CPEs:\n"
    while IFS= read -r cpe; do
      [[ -z "$cpe" ]] && continue
      cpe_block+="  #   ${cpe}\n"
    done <<< "$cpe_list"
  fi

  # ── Shodan dork ───────────────────────────────────────────────────────────
  local shodan_query="vuln:${cve_id}"
  [[ -n "$vendors" ]] && {
    local v1
    v1=$(printf '%s' "$vendors" | cut -d',' -f1 | xargs)
    [[ -n "$v1" ]] && shodan_query="vuln:${cve_id} org:\"${v1}\""
  }

  # ── Auto-detect vuln class from summary keywords ──────────────────────────
  local tags="cve,${cve_id,,},${published:0:4}"
  local vuln_class="detection"
  local http_method="GET"
  local http_path="/"
  local matcher_hint="# Look for version strings, error pages, or banner disclosures"
  local body_block=""
  local extra_matchers=""

  local sl="${summary,,}"   # lowercase summary for matching

  if   [[ "$sl" =~ "remote code execution"|"arbitrary code"|"rce" ]]; then
    tags+=",rce"; vuln_class="rce"
    matcher_hint="# RCE: look for command output echo, unique string in response"
    extra_matchers="      # - type: dsl\n      #   dsl:\n      #     - 'status_code == 200 && contains(body, \"uid=\")'"

  elif [[ "$sl" =~ "sql injection"|"sqli" ]]; then
    tags+=",sqli"; vuln_class="sqli"; http_method="GET"
    http_path="/?id=1'"
    matcher_hint="# SQLi: look for DB error strings"
    extra_matchers="      - type: word\n        words:\n          - \"You have an error in your SQL syntax\"\n          - \"mysql_fetch\"\n          - \"ORA-\"\n          - \"Microsoft OLE DB\"\n        condition: or"

  elif [[ "$sl" =~ "cross-site scripting"|" xss " ]]; then
    tags+=",xss"; vuln_class="xss"
    matcher_hint="# XSS: reflect a unique payload and look for unescaped output"
    http_path="/?q=<script>alert(1)</script>"

  elif [[ "$sl" =~ "path traversal"|"directory traversal"|"local file" ]]; then
    tags+=",lfi,traversal"; vuln_class="lfi"
    http_path="/../../../../etc/passwd"
    extra_matchers="      - type: regex\n        regex:\n          - \"root:[x*]:0:0\"\n          - \"\\\\[boot loader\\\\]\""

  elif [[ "$sl" =~ "server.side request"|"ssrf" ]]; then
    tags+=",ssrf"; vuln_class="ssrf"
    matcher_hint="# SSRF: use interactsh OOB or check for internal IP disclosure"
    extra_matchers="      # - type: word\n      #   words:\n      #     - \"169.254.169.254\"  # AWS metadata"

  elif [[ "$sl" =~ "xml external entity"|"xxe" ]]; then
    tags+=",xxe"; vuln_class="xxe"; http_method="POST"
    body_block="    body: |\n      <?xml version=\"1.0\"?>\n      <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n      <root>&xxe;</root>"
    extra_matchers="      - type: regex\n        regex:\n          - \"root:[x*]:0:0\""

  elif [[ "$sl" =~ "authentication bypass"|"auth bypass"|"unauthenticated" ]]; then
    tags+=",auth-bypass"; vuln_class="auth-bypass"
    matcher_hint="# Auth bypass: access admin/protected endpoints without creds"

  elif [[ "$sl" =~ "deserialization" ]]; then
    tags+=",deserialization"; vuln_class="deserialization"; http_method="POST"
    matcher_hint="# Deserialization: use ysoserial payloads with OOB callback"

  elif [[ "$sl" =~ "open redirect" ]]; then
    tags+=",redirect"; vuln_class="redirect"
    http_path="/?next=https://evil.com"
    extra_matchers="      - type: regex\n        part: header\n        regex:\n          - 'Location: https://evil\\.com'"

  elif [[ "$sl" =~ "command injection"|"os command" ]]; then
    tags+=",rce,cmdinject"; vuln_class="cmdinject"
    matcher_hint="# Cmd injection: use time-based OOB or echo unique string"

  elif [[ "$sl" =~ "buffer overflow"|"heap overflow"|"stack overflow" ]]; then
    tags+=",overflow"; vuln_class="overflow"
    matcher_hint="# Overflow: typically network-layer — consider a tcp template"

  elif [[ "$sl" =~ "information disclosure"|"sensitive information" ]]; then
    tags+=",exposure"; vuln_class="exposure"
    matcher_hint="# Info disclosure: look for credentials, keys, internal paths"
  fi

  # ── vendor tag ────────────────────────────────────────────────────────────
  [[ "$kev" == "true" ]] && tags+=",kev"
  [[ "$rw"  == "true" ]] && tags+=",ransomware"
  [[ -n "$vendors" ]] && {
    local vtag
    vtag=$(printf '%s' "$vendors" | cut -d',' -f1 | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -dc 'a-z0-9-')
    [[ -n "$vtag" ]] && tags+=",${vtag}"
  }

  # ── truncate summary for name ─────────────────────────────────────────────
  local short_name="${summary:0:80}"
  [[ "${#summary}" -gt 80 ]] && short_name+="…"

  # ── CVSS vector (approximated from score) ────────────────────────────────
  local cvss_vector="CVSS:${cvss_ver}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  local cvss_i
  cvss_i=$(printf 'scale=0; %s * 10 / 1\n' "$cvss" | bc 2>/dev/null || echo 0)
  (( cvss_i < 90 )) && cvss_vector="CVSS:${cvss_ver}/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
  (( cvss_i < 70 )) && cvss_vector="CVSS:${cvss_ver}/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N"

  # ── write template ────────────────────────────────────────────────────────
  local out_file="${out_dir}/${cve_id}.yaml"

  {
    printf 'id: %s\n\n' "${cve_id,,}"
    printf 'info:\n'
    printf '  name: "%s"\n' "$short_name"
    printf '  author: cvedb\n'
    printf '  severity: %s\n' "$severity"
    printf '  description: |\n'
    printf '    %s\n' "$summary"
    printf '  impact: |\n'
    printf '    CVSS %s: %s  |  EPSS: %s  |  KEV: %s  |  Ransomware: %s\n' \
      "$cvss_ver" "$cvss" "$epss" "$kev" "$rw"
    printf '    Published: %s  |  Vendors: %s\n' "$published" "${vendors:-unknown}"
    printf '  remediation: |\n'
    printf '    Apply vendor patches. Monitor advisories. Check affected CPEs below.\n'
    printf '%b' "${refs_yaml}\n"
    printf '  classification:\n'
    printf '    cvss-metrics: %s\n' "$cvss_vector"
    printf '    cvss-score: %s\n' "$cvss"
    printf '    cve-id: %s\n' "$cve_id"
    printf '    epss-score: %s\n' "$epss"
    printf '  metadata:\n'
    printf '    verified: false\n'
    printf '    max-request: 1\n'
    printf "    shodan-query: '%s'\n" "$shodan_query"
    printf '    fofa-query: "app=\"%s\""\n' "${vendors%% *}"
    printf '    vuln-type: %s\n' "$vuln_class"
    printf '  tags: %s\n\n' "$tags"

    printf '%b' "${cpe_block}\n"

    printf 'http:\n'
    printf '  - method: %s\n' "$http_method"
    printf '    path:\n'
    printf '      - "{{BaseURL}}%s"\n' "$http_path"
    printf '\n'

    [[ -n "$body_block" ]] && printf '    %b\n\n' "$body_block"

    printf '    headers:\n'
    printf '      User-Agent: "Mozilla/5.0 (compatible; Nuclei-cvedb/2.1)"\n'
    if [[ "$http_method" == "POST" ]]; then
      printf '      Content-Type: "application/xml"\n'
    fi
    printf '\n'

    printf '    redirects: true\n'
    printf '    max-redirects: 3\n\n'

    printf '    matchers-condition: and\n'
    printf '    matchers:\n\n'
    printf '      %s\n' "$matcher_hint"
    printf '      - type: status\n'
    printf '        status:\n'
    printf '          - 200\n'

    if [[ -n "$extra_matchers" ]]; then
      printf '\n'
      printf '%b' "      ${extra_matchers}\n"
    else
      printf '\n'
      printf '      - type: word\n'
      printf '        words:\n'
      printf '          - "TODO: Add response fingerprint for %s"\n' "$vuln_class"
      printf '        condition: or\n'
    fi

    printf '\n'
    printf '    # extractors:\n'
    printf '    #   - type: regex\n'
    printf '    #     name: version\n'
    printf '    #     regex:\n'
    printf '    #       - '"'"'(?i)version[\s:]+([0-9][0-9.]+)'"'"'\n'
    printf '\n'

    # Network template stub for overflow/binary vulns
    if [[ "$vuln_class" == "overflow" ]]; then
      printf '# ── Network template stub (overflow vulns are rarely HTTP) ──\n'
      printf '# network:\n'
      printf '#   - inputs:\n'
      printf '#       - data: "{{hex_decode(\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\")}}"\n'
      printf '#     host:\n'
      printf '#       - "{{Hostname}}"\n'
      printf '#       - "{{Hostname}}:{{Port}}"\n'
      printf '#     read-size: 1024\n'
      printf '#     matchers:\n'
      printf '#       - type: word\n'
      printf '#         words:\n'
      printf '#           - "TODO: banner or crash indicator"\n'
    fi

  } > "$out_file"

  ok "Template saved → ${BOLD}${out_file}${RESET}"
  printf '\n'

  # ── preview ───────────────────────────────────────────────────────────────
  section "📄  Template preview (first 35 lines)"
  printf '\n'
  head -35 "$out_file" | sed 's/^/    /'
  printf '    …\n\n'

  info "Validate : ${BOLD}nuclei -t ${out_file} -validate${RESET}"
  info "Single   : ${BOLD}nuclei -t ${out_file} -u https://target.com${RESET}"
  info "Mass scan: ${BOLD}nuclei -t ${out_file} -list targets.txt -o findings.json -je${RESET}"
  info "With dork: ${BOLD}shodan search '${shodan_query}' --fields ip_str,port | nuclei -t ${out_file}${RESET}"

  [[ "$open_after" -eq 1 ]] && {
    local editor="${EDITOR:-vim}"
    "$editor" "$out_file"
  }
}


# ═════════════════════════════════════════════════════════════════════════════
#  3. PoC AVAILABILITY CHECKER
#     cvedb poc <CVE-ID> [--json] [--open]
#     Queries GitHub repos + code search, Exploit-DB, PacketStorm, and
#     PoC-in-GitHub tracker. Outputs a risk-graded intelligence summary.
# ═════════════════════════════════════════════════════════════════════════════
cmd_poc() {
  local cve_id="${1:-}"
  shift || true

  local output_json=0
  local open_browser=0
  local top_n=8

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --json)  output_json=1;    shift ;;
      --open)  open_browser=1;   shift ;;
      -n)      top_n="$2";       shift 2 ;;
      *) shift ;;
    esac
  done

  [[ -z "$cve_id" ]] && die "Usage: cvedb poc <CVE-ID> [--json] [-n N] [--open]"
  cve_id="${cve_id^^}"

  need curl jq

  local auth_header=""
  [[ -n "$GITHUB_TOKEN" ]] && auth_header="Authorization: token ${GITHUB_TOKEN}"

  info "Hunting PoC material for ${BOLD}${cve_id}${RESET}…"
  printf '\n'

  # ── GitHub repo search ────────────────────────────────────────────────────
  local gh_repos gh_code
  gh_repos=$(curl -s -w '\n%{http_code}' --max-time 15 \
    -H "Accept: application/vnd.github.v3+json" \
    ${auth_header:+-H "$auth_header"} \
    "https://api.github.com/search/repositories?q=${cve_id}&sort=updated&order=desc&per_page=${top_n}" \
    2>/dev/null || printf '\n000')
  local gh_code
  gh_code=$(printf '%s' "$gh_repos" | tail -1)
  gh_repos=$(printf '%s' "$gh_repos" | head -n -1)

  local repo_count=0
  if [[ "$gh_code" == "200" ]]; then
    repo_count=$(printf '%s' "$gh_repos" | jq '.total_count // 0')
  elif [[ "$gh_code" == "403" ]]; then
    warn "GitHub rate limit hit. Set GITHUB_TOKEN for 5000 req/hr."
    gh_repos=""
  fi

  # ── GitHub code search (PoC files) ───────────────────────────────────────
  local gh_code_results code_count=0
  gh_code_results=$(curl -s --max-time 15 \
    -H "Accept: application/vnd.github.v3+json" \
    ${auth_header:+-H "$auth_header"} \
    "https://api.github.com/search/code?q=${cve_id}+filename:poc+extension:py+extension:rb+extension:sh&per_page=5" \
    2>/dev/null || true)
  [[ -n "$gh_code_results" ]] && \
    code_count=$(printf '%s' "$gh_code_results" | jq '.total_count // 0' 2>/dev/null || echo 0)

  # ── PoC-in-GitHub tracker (nomi-sec) ─────────────────────────────────────
  local year="${cve_id:4:4}"
  local num="${cve_id##*-}"
  local nomi_url="https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/${year}/${cve_id}.json"
  local nomi_data nomi_count=0
  nomi_data=$(curl -s --max-time 10 "$nomi_url" 2>/dev/null || true)
  if [[ -n "$nomi_data" ]] && printf '%s' "$nomi_data" | jq empty 2>/dev/null; then
    nomi_count=$(printf '%s' "$nomi_data" | jq 'length // 0')
  fi

  # ── Exploit-DB check ─────────────────────────────────────────────────────
  local edb_html edb_count=0
  edb_html=$(curl -s --max-time 10 \
    -H "User-Agent: Mozilla/5.0" \
    "https://www.exploit-db.com/search?cve=${cve_id#CVE-}" 2>/dev/null || true)
  [[ -n "$edb_html" ]] && \
    edb_count=$(printf '%s' "$edb_html" | grep -c 'exploits/[0-9]\+' 2>/dev/null || echo 0)

  # ── PacketStorm check ────────────────────────────────────────────────────
  local ps_code
  ps_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H "User-Agent: Mozilla/5.0" \
    "https://packetstormsecurity.com/search/?q=${cve_id}" 2>/dev/null || echo "000")

  # ── Compute risk score ────────────────────────────────────────────────────
  local risk_score=0
  (( repo_count  >  0 )) && (( risk_score += 2 ))
  (( repo_count  >  3 )) && (( risk_score += 2 ))
  (( repo_count  > 10 )) && (( risk_score += 2 ))
  (( nomi_count  >  0 )) && (( risk_score += 3 ))
  (( edb_count   >  0 )) && (( risk_score += 3 ))
  (( code_count  >  0 )) && (( risk_score += 1 ))
  [[ "$ps_code" == "200" ]] && (( risk_score += 1 ))

  local risk_label risk_color
  if   (( risk_score >= 8 )); then risk_label="CRITICAL"; risk_color="$BRED"
  elif (( risk_score >= 5 )); then risk_label="HIGH";     risk_color="$RED"
  elif (( risk_score >= 2 )); then risk_label="MEDIUM";   risk_color="$YELLOW"
  else                             risk_label="LOW";      risk_color="$DIM"
  fi

  # ── JSON output mode ──────────────────────────────────────────────────────
  if [[ "$output_json" -eq 1 ]]; then
    jq -n \
      --arg  cve        "$cve_id" \
      --argjson repos   "$repo_count" \
      --argjson code    "$code_count" \
      --argjson nomi    "$nomi_count" \
      --argjson edb     "$edb_count" \
      --arg  risk       "$risk_label" \
      --argjson score   "$risk_score" \
      '{cve_id: $cve, poc_risk: $risk, risk_score: $score,
        github_repos: $repos, github_code_files: $code,
        poc_in_github: $nomi, exploit_db: $edb}'
    return 0
  fi

  # ── Human output ──────────────────────────────────────────────────────────
  section "💀  PoC Intelligence: ${cve_id}"
  printf '\n'

  printf "  ${BOLD}%-30s${RESET} %s\n" "GitHub repos:" \
    "${BOLD}${repo_count}${RESET}"
  printf "  ${BOLD}%-30s${RESET} %s\n" "GitHub PoC code files:" \
    "${BOLD}${code_count}${RESET}"
  printf "  ${BOLD}%-30s${RESET} %s\n" "PoC-in-GitHub tracker:" \
    "$( (( nomi_count > 0 )) && \
        printf "${BRED}${BOLD}%s (tracked!)${RESET}" "$nomi_count" || \
        printf "${DIM}0${RESET}" )"
  printf "  ${BOLD}%-30s${RESET} %s\n" "Exploit-DB entries:" \
    "$( (( edb_count > 0 )) && \
        printf "${BRED}${BOLD}%s${RESET}" "$edb_count" || \
        printf "${DIM}0${RESET}" )"
  printf "  ${BOLD}%-30s${RESET} %s\n" "PacketStorm indexed:" \
    "$( [[ "$ps_code" == "200" ]] && \
        printf "${YELLOW}Possibly${RESET}" || \
        printf "${DIM}Unknown${RESET}" )"
  printf '\n'
  printf "  PoC Exploitation Risk  →  ${risk_color}${BOLD}  %s  ${RESET}\n\n" "$risk_label"

  # ── PoC-in-GitHub detail (most reliable source) ──────────────────────────
  if (( nomi_count > 0 )) && [[ -n "$nomi_data" ]]; then
    section "🎯  PoC-in-GitHub Tracked Repos"
    printf '\n'

    local now_ts
    now_ts=$(date +%s)

    printf '%s' "$nomi_data" | jq -r '
      .[:6][] |
      [
        .full_name,
        (.stargazers_count | tostring),
        (.forks_count | tostring),
        .pushed_at,
        (.description // "No description" | .[0:65]),
        .html_url
      ] | join("\u0001")
    ' 2>/dev/null | while IFS=$'\001' read -r name stars forks pushed desc url; do

      local push_ts days_ago freshness
      push_ts=$(date -d "$pushed" +%s 2>/dev/null || \
                date -j -f "%Y-%m-%dT%H:%M:%SZ" "$pushed" +%s 2>/dev/null || \
                echo "$now_ts")
      days_ago=$(( (now_ts - push_ts) / 86400 ))

      if   (( days_ago <=  7 )); then freshness="${BRED}[ ${days_ago}d — FRESH PoC ]${RESET}"
      elif (( days_ago <= 30 )); then freshness="${YELLOW}[ ${days_ago}d ago ]${RESET}"
      elif (( days_ago <= 90 )); then freshness="${GREEN}[ ${days_ago}d ago ]${RESET}"
      else                           freshness="${DIM}[ ${days_ago}d ago ]${RESET}"
      fi

      printf "  ${CYAN}${BOLD}%s${RESET}\n" "$name"
      printf "  ★ %-6s  Forks: %-6s  %s\n" "$stars" "$forks" "$freshness"
      printf "  ${DIM}%s${RESET}\n" "$desc"
      printf "  ${DIM}%s${RESET}\n\n" "$url"

    done
  fi

  # ── GitHub repo list ──────────────────────────────────────────────────────
  if [[ -n "$gh_repos" && "$repo_count" -gt 0 ]]; then
    section "📦  GitHub Repositories  (${repo_count} total)"
    printf '\n'

    local now_ts
    now_ts=$(date +%s)

    printf '%s' "$gh_repos" | jq -r --argjson n "$top_n" '
      .items[:($n)] [] |
      [
        .full_name,
        (.stargazers_count | tostring),
        (.forks_count | tostring),
        .pushed_at,
        (.description // "No description" | .[0:65]),
        .html_url,
        (.language // "Unknown")
      ] | join("\u0001")
    ' 2>/dev/null | while IFS=$'\001' read -r name stars forks pushed desc url lang; do

      local push_ts days_ago freshness
      push_ts=$(date -d "$pushed" +%s 2>/dev/null || \
                date -j -f "%Y-%m-%dT%H:%M:%SZ" "$pushed" +%s 2>/dev/null || \
                echo "$now_ts")
      days_ago=$(( (now_ts - push_ts) / 86400 ))

      if   (( days_ago <=  7 )); then freshness="${BRED}[ FRESH — ${days_ago}d ]${RESET}"
      elif (( days_ago <= 30 )); then freshness="${YELLOW}[ ${days_ago}d ago ]${RESET}"
      elif (( days_ago <= 90 )); then freshness="${GREEN}[ ${days_ago}d ago ]${RESET}"
      else                           freshness="${DIM}[ ${days_ago}d ]${RESET}"
      fi

      printf "  ${CYAN}${BOLD}%-45s${RESET}  ${DIM}%s${RESET}\n" "$name" "$lang"
      printf "  ★ %-6s  Forks: %-6s  %s\n" "$stars" "$forks" "$freshness"
      printf "  ${DIM}%s${RESET}\n"  "$desc"
      printf "  %s\n\n" "$url"

    done
  fi

  # ── PoC code files ────────────────────────────────────────────────────────
  if [[ -n "$gh_code_results" && "$code_count" -gt 0 ]]; then
    section "📄  PoC Code Files (${code_count} total)"
    printf '\n'
    printf '%s' "$gh_code_results" | jq -r '
      .items[:5][] |
      "  " + .repository.full_name + " / \033[0;36m" + .name + "\033[0m\n  " + .html_url
    ' 2>/dev/null
    printf '\n'
  fi

  # ── External sources ──────────────────────────────────────────────────────
  section "🔗  External Sources"
  printf '\n'
  printf "  %-18s %s\n" "PoC-in-GitHub:" "https://github.com/nomi-sec/PoC-in-GitHub/blob/master/${year}/${cve_id}.json"
  printf "  %-18s %s\n" "Exploit-DB:"    "https://www.exploit-db.com/search?cve=${cve_id#CVE-}"
  printf "  %-18s %s\n" "PacketStorm:"   "https://packetstormsecurity.com/search/?q=${cve_id}"
  printf "  %-18s %s\n" "GitHub search:" "https://github.com/search?q=${cve_id}&type=repositories&sort=updated"
  printf "  %-18s %s\n" "Vulhub:"        "https://github.com/vulhub/vulhub/search?q=${cve_id}"
  printf "  %-18s %s\n" "NVD:"           "https://nvd.nist.gov/vuln/detail/${cve_id}"
  printf "  %-18s %s\n" "Shodan CVE:"    "https://cvedb.shodan.io/cve/${cve_id}"
  printf '\n'

  # ── Triage recommendation ─────────────────────────────────────────────────
  if [[ "$risk_label" == "CRITICAL" || "$risk_label" == "HIGH" ]]; then
    warn "Active weaponized PoC material detected — prioritize triage if target is in scope"
    info "Scaffold Nuclei template : ${BOLD}cvedb nuclei ${cve_id}${RESET}"
    info "Shodan hunt              : ${BOLD}shodan search 'vuln:${cve_id}' --fields ip_str,port${RESET}"
  fi

  # ── Open in browser ───────────────────────────────────────────────────────
  if [[ "$open_browser" -eq 1 ]]; then
    local browser_url="https://github.com/search?q=${cve_id}&type=repositories&sort=updated"
    if command -v xdg-open &>/dev/null; then
      xdg-open "$browser_url" &>/dev/null &
    elif command -v open &>/dev/null; then
      open "$browser_url"
    fi
  fi
}


# ═════════════════════════════════════════════════════════════════════════════
#  INTEGRATION PATCH — add this block into cvedb.sh's main() arg parser
#  after the existing command cases (before the positional arg section):
#
#    scan)   shift; source /path/to/cvedb-offensive.sh; cmd_scan   "$@"; exit 0 ;;
#    nuclei) shift; source /path/to/cvedb-offensive.sh; cmd_nuclei "$@"; exit 0 ;;
#    poc)    shift; source /path/to/cvedb-offensive.sh; cmd_poc    "$@"; exit 0 ;;
#
#  OR: append "source /path/to/cvedb-offensive.sh" near the top of cvedb.sh
#  (after load_config) to bake all three commands in permanently.
# ═════════════════════════════════════════════════════════════════════════════

# ── Standalone entrypoint ─────────────────────────────────────────────────────
if [[ "${_OFFENSIVE_STANDALONE:-0}" -eq 1 ]]; then
  cmd="${1:-}"
  shift || true

  case "$cmd" in
    scan)   need curl jq bc; cmd_scan   "$@" ;;
    nuclei) need curl jq;    cmd_nuclei "$@" ;;
    poc)    need curl jq;    cmd_poc    "$@" ;;
    "")
      printf '%bcvedb-offensive%b v%s\n\n' "$BOLD" "$RESET" "$OFFENSIVE_VERSION"
      printf 'Commands:\n'
      printf '  scan   <scope_file> --shodan-key KEY [-s SEV] [--cvss N] [-o FILE]\n'
      printf '  nuclei <CVE-ID>     [-o output_dir] [--open]\n'
      printf '  poc    <CVE-ID>     [--json] [-n N] [--open]\n\n'
      printf 'Env vars:\n'
      printf '  SHODAN_API_KEY    Shodan API key (required for scan)\n'
      printf '  GITHUB_TOKEN      GitHub PAT for higher rate limits (poc)\n'
      printf '  NUCLEI_TEMPLATE_DIR  Template output dir (default: ~/.cvedb/templates)\n'
      ;;
    *) die "Unknown command: ${cmd}. Try: scan | nuclei | poc" ;;
  esac
fi
