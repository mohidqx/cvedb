#!/usr/bin/env bash
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  cvedb — Shodan CVE Tracker v2.1.0                                        ║
# ║  Installation Script                                                      ║
# ║                                                                           ║
# ║  Installs all dependencies and sets up cvedb for global use               ║
# ║  Usage: ./install.sh [--prefix /custom/path] [--skip-deps]                ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ─── colours ──────────────────────────────────────────────────────────────────
RED="$(printf '\033[0;31m')"
BRED="$(printf '\033[1;31m')"
YELLOW="$(printf '\033[1;33m')"
GREEN="$(printf '\033[0;32m')"
CYAN="$(printf '\033[0;36m')"
BLUE="$(printf '\033[0;34m')"
BOLD="$(printf '\033[1m')"
DIM="$(printf '\033[2m')"
RESET="$(printf '\033[0m')"

# ─── helpers ───────────────────────────────────────────────────────────────────
die()     { echo -e "${BRED}✗${RESET} $*" >&2; exit 1; }
info()    { echo -e "${CYAN}→${RESET} $*" >&2; }
ok()      { echo -e "${GREEN}✔${RESET} $*" >&2; }
warn()    { echo -e "${YELLOW}⚠${RESET}  $*" >&2; }
section() { echo -e "\n${BOLD}${BLUE}$*${RESET}" >&2; }

# ─── defaults ──────────────────────────────────────────────────────────────────
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local/bin}"
SKIP_DEPS=0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OS_TYPE="$(uname -s)"
PKG_MANAGER=""

# ─── parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)      INSTALL_PREFIX="$2"; shift 2 ;;
    --skip-deps)   SKIP_DEPS=1; shift ;;
    -h|--help)     show_help; exit 0 ;;
    *)             die "Unknown option: $1" ;;
  esac
done

# ─── detect OS & package manager ───────────────────────────────────────────────
detect_system() {
  case "$OS_TYPE" in
    Linux)
      if command -v apt-get &>/dev/null; then
        PKG_MANAGER="apt"
      elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
      elif command -v pacman &>/dev/null; then
        PKG_MANAGER="pacman"
      elif command -v apk &>/dev/null; then
        PKG_MANAGER="apk"
      else
        die "Could not detect package manager. Supported: apt, yum, pacman, apk"
      fi
      ;;
    Darwin)
      if command -v brew &>/dev/null; then
        PKG_MANAGER="brew"
      else
        die "Homebrew not found. Install from https://brew.sh"
      fi
      ;;
    MINGW*|CYGWIN*|MSYS*)
      die "Windows detected. Use WSL2 or Git Bash, then re-run this script."
      ;;
    *)
      die "Unsupported OS: $OS_TYPE"
      ;;
  esac
}

# ─── install core dependencies ─────────────────────────────────────────────────
install_deps() {
  section "Installing dependencies via ${PKG_MANAGER}…"

  local deps_core=("curl" "jq" "bc")
  local deps_optional=("nmap" "nuclei" "git")
  
  case "$PKG_MANAGER" in
    apt)
      sudo apt-get update >/dev/null 2>&1 || true
      info "Installing core tools…"
      sudo apt-get install -y "${deps_core[@]}" >/dev/null 2>&1
      info "Installing optional tools (scan, nuclei)…"
      sudo apt-get install -y "${deps_optional[@]}" >/dev/null 2>&1 || {
        warn "Some optional packages failed. Continue anyway."
      }
      ;;
    yum)
      info "Installing core tools…"
      sudo yum install -y "${deps_core[@]}" >/dev/null 2>&1
      info "Installing optional tools…"
      sudo yum install -y "${deps_optional[@]}" >/dev/null 2>&1 || {
        warn "Some optional packages failed. Continue anyway."
      }
      ;;
    pacman)
      info "Installing core tools…"
      sudo pacman -Sy --noconfirm "${deps_core[@]}" >/dev/null 2>&1
      info "Installing optional tools…"
      sudo pacman -Sy --noconfirm "${deps_optional[@]}" >/dev/null 2>&1 || {
        warn "Some optional packages failed. Continue anyway."
      }
      ;;
    apk)
      info "Installing core tools…"
      sudo apk add --no-cache "${deps_core[@]}" >/dev/null 2>&1
      info "Installing optional tools…"
      sudo apk add --no-cache "${deps_optional[@]}" >/dev/null 2>&1 || {
        warn "Some optional packages failed. Continue anyway."
      }
      ;;
    brew)
      info "Installing core tools…"
      brew install "${deps_core[@]}" >/dev/null 2>&1
      info "Installing optional tools…"
      brew install "${deps_optional[@]}" >/dev/null 2>&1 || {
        warn "Some optional packages failed. Continue anyway."
      }
      ;;
  esac

  ok "Dependencies installed"
}

# ─── verify dependencies ──────────────────────────────────────────────────────
verify_deps() {
  section "Verifying dependencies…"
  
  local required=("curl" "jq" "bc")
  local optional=("nmap" "nuclei")
  
  local all_ok=1
  
  for dep in "${required[@]}"; do
    if command -v "$dep" &>/dev/null; then
      ok "$dep: $(command -v "$dep")"
    else
      die "$dep: NOT FOUND (required)"
    fi
  done
  
  for dep in "${optional[@]}"; do
    if command -v "$dep" &>/dev/null; then
      ok "$dep: $(command -v "$dep")"
    else
      warn "$dep: NOT FOUND (optional - some features disabled)"
      all_ok=0
    fi
  done
  
  if [[ $all_ok -eq 0 ]]; then
    warn "Some optional tools missing. Install them manually if needed."
  fi
}

# ─── install cvedb binaries ────────────────────────────────────────────────────
install_binaries() {
  section "Installing cvedb binaries…"
  
  # Verify source files exist
  [[ -f "$SCRIPT_DIR/cvedb.sh" ]] || die "cvedb.sh not found in $SCRIPT_DIR"
  [[ -f "$SCRIPT_DIR/cvedb-offensive.sh" ]] || die "cvedb-offensive.sh not found in $SCRIPT_DIR"
  
  # Create install directory if needed
  if [[ ! -d "$INSTALL_PREFIX" ]]; then
    info "Creating install directory: $INSTALL_PREFIX"
    mkdir -p "$INSTALL_PREFIX" || {
      if [[ "$INSTALL_PREFIX" == /usr/local/bin ]]; then
        sudo mkdir -p "$INSTALL_PREFIX"
      else
        die "Cannot create $INSTALL_PREFIX"
      fi
    }
  fi
  
  # Copy and set permissions
  info "Installing cvedb → ${INSTALL_PREFIX}/cvedb"
  if [[ -w "$INSTALL_PREFIX" ]]; then
    cp "$SCRIPT_DIR/cvedb.sh" "${INSTALL_PREFIX}/cvedb"
    chmod +x "${INSTALL_PREFIX}/cvedb"
  else
    sudo cp "$SCRIPT_DIR/cvedb.sh" "${INSTALL_PREFIX}/cvedb"
    sudo chmod +x "${INSTALL_PREFIX}/cvedb"
  fi
  
  info "Installing cvedb-offensive → ${INSTALL_PREFIX}/cvedb-offensive"
  if [[ -w "$INSTALL_PREFIX" ]]; then
    cp "$SCRIPT_DIR/cvedb-offensive.sh" "${INSTALL_PREFIX}/cvedb-offensive"
    chmod +x "${INSTALL_PREFIX}/cvedb-offensive"
  else
    sudo cp "$SCRIPT_DIR/cvedb-offensive.sh" "${INSTALL_PREFIX}/cvedb-offensive"
    sudo chmod +x "${INSTALL_PREFIX}/cvedb-offensive"
  fi
  
  ok "Binaries installed to ${INSTALL_PREFIX}"
}

# ─── setup config & cache directories ──────────────────────────────────────────
setup_dirs() {
  section "Setting up config & cache directories…"
  
  local config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/cvedb"
  local cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}/cvedb"
  local template_dir="$HOME/.cvedb/templates"
  
  # Create directories
  mkdir -p "$config_dir"
  mkdir -p "$cache_dir"
  mkdir -p "$template_dir"
  
  info "Config dir:    $config_dir"
  info "Cache dir:     $cache_dir"
  info "Template dir:  $template_dir"
  
  # Create sample config if not exists
  if [[ ! -f "$config_dir/config" ]]; then
    info "Creating sample config…"
    cat > "$config_dir/config" << 'EOF'
# cvedb Configuration

# Output limit (default: 20)
LIMIT=20

# Cache TTL in seconds (default: 300 = 5 minutes)
CACHE_TTL=300

# Severity filter: leave blank for all, or set to CRITICAL|HIGH|MEDIUM|LOW
SEVERITY_FILTER=""

# Disable colors (0=on, 1=off)
NO_COLOR=0

# ─── Offensive Addon Configuration ─────────────────────────────────────────

# Shodan API Key (required for 'cvedb scan')
# Get from: https://account.shodan.io/
SHODAN_API_KEY=""

# GitHub Personal Access Token (for POC fetching)
# Get from: https://github.com/settings/tokens
GITHUB_TOKEN=""

# Nuclei template directory
NUCLEI_TEMPLATE_DIR="${HOME}/.cvedb/templates"

# Max parallel threads for scanning
MAX_SCAN_THREADS=5

# Default CVSS threshold for scans
SCAN_CVSS_FLOOR=7.0
EOF
    ok "Config file created: $config_dir/config"
    warn "Edit $config_dir/config to add Shodan API key and GitHub token"
  else
    ok "Config file already exists: $config_dir/config"
  fi
}

# ─── add to PATH (optional) ────────────────────────────────────────────────────
add_to_path() {
  if [[ "$INSTALL_PREFIX" == /usr/local/bin ]] || [[ "$INSTALL_PREFIX" == /usr/bin ]]; then
    ok "Install prefix is already in PATH"
    return
  fi
  
  section "Verifying PATH…"
  
  # Check if already in PATH
  if echo "$PATH" | grep -q "$INSTALL_PREFIX"; then
    ok "$INSTALL_PREFIX already in PATH"
    return
  fi
  
  local shell_rc=""
  case "$SHELL" in
    */bash)  shell_rc="$HOME/.bashrc" ;;
    */zsh)   shell_rc="$HOME/.zshrc" ;;
    */fish)  shell_rc="$HOME/.config/fish/config.fish" ;;
    *)       warn "Unknown shell. Add $INSTALL_PREFIX to PATH manually"; return ;;
  esac
  
  if [[ ! -f "$shell_rc" ]]; then
    info "Creating $shell_rc"
    touch "$shell_rc"
  fi
  
  # Add to PATH if not already there
  if ! grep -q "export PATH.*$INSTALL_PREFIX" "$shell_rc"; then
    echo "" >> "$shell_rc"
    echo "# cvedb installation" >> "$shell_rc"
    echo "export PATH=\"$INSTALL_PREFIX:\$PATH\"" >> "$shell_rc"
    ok "Added to $shell_rc"
    warn "Run: source $shell_rc  (or restart terminal)"
  fi
}

# ─── show help ─────────────────────────────────────────────────────────────────
show_help() {
  cat << 'EOF'
cvedb — Shodan CVE Tracker Installation

Usage: ./install.sh [OPTIONS]

OPTIONS:
  --prefix PATH        Install to custom location (default: /usr/local/bin)
  --skip-deps          Skip dependency installation (assume pre-installed)
  -h, --help           Show this help message

EXAMPLES:
  # Standard installation (system-wide)
  ./install.sh

  # Custom prefix (user-local)
  ./install.sh --prefix "$HOME/.local/bin"

  # Skip dependency install (deps already present)
  ./install.sh --skip-deps

WHAT THIS SCRIPT DOES:
  1. Detects OS (Linux/macOS) and package manager
  2. Installs dependencies: curl, jq, bc, nmap, nuclei, git
  3. Copies cvedb and cvedb-offensive to install prefix
  4. Creates ~/.config/cvedb/config (sample config)
  5. Creates ~/.cache/cvedb/ (cache directory)
  6. Creates ~/.cvedb/templates/ (Nuclei templates directory)
  7. Optionally adds install prefix to PATH

AFTER INSTALLATION:
  1. Run: cvedb --version
  2. Edit: ~/.config/cvedb/config (add Shodan API key if using scan)
  3. Try: cvedb -h

TROUBLESHOOTING:
  - "Command not found: cvedb" → Restart terminal or source ~/.bashrc
  - Missing dependencies → apt/yum/brew install [tool]
  - Shodan scan error → Add SHODAN_API_KEY to ~/.config/cvedb/config

EOF
}

# ─── main ──────────────────────────────────────────────────────────────────────
main() {
  section "cvedb v2.1.0 Installation"
  info "OS: $OS_TYPE"
  info "Install prefix: $INSTALL_PREFIX"
  info "Script directory: $SCRIPT_DIR"
  
  # Step 1: Detect system
  detect_system
  ok "Package manager detected: $PKG_MANAGER"
  
  # Step 2: Install dependencies
  if [[ $SKIP_DEPS -eq 0 ]]; then
    install_deps
  else
    info "Skipping dependency installation (--skip-deps)"
  fi
  
  # Step 3: Verify dependencies
  verify_deps
  
  # Step 4: Install binaries
  install_binaries
  
  # Step 5: Setup directories
  setup_dirs
  
  # Step 6: Update PATH
  add_to_path
  
  # Success summary
  section "Installation Complete! ✨"
  echo ""
  echo "${GREEN}cvedb is ready to use!${RESET}"
  echo ""
  echo "Quick start:"
  echo "  ${BOLD}cvedb${RESET}                          # fetch today's CVEs"
  echo "  ${BOLD}cvedb --help${RESET}                  # show help"
  echo "  ${BOLD}cvedb search nginx${RESET}            # search for nginx CVEs"
  echo "  ${BOLD}cvedb kev${RESET}                     # show CISA known exploited"
  echo ""
  echo "Offensive addon (requires setup):"
  echo "  ${BOLD}cvedb scan 192.168.1.1{{RESET}}       # scan target for CVEs"
  echo "  ${BOLD}cvedb nuclei CVE-2024-1234{{RESET}}   # run Nuclei templates"
  echo "  ${BOLD}cvedb poc CVE-2024-1234{{RESET}}      # download POC"
  echo ""
  echo "Next steps:"
  echo "  1. Edit ~/.config/cvedb/config"
  echo "  2. Add Shodan API key (for 'scan' command)"
  echo "  3. Run: cvedb --version"
  echo ""
}

# Run it
main "$@"
