#!/usr/bin/env bash
# scripts/functions.sh - Shared functions for ruleset conversion
# Usage: source scripts/functions.sh

# Prevent multiple sourcing
# - Use `${VARIABLE:-}` to avoid triggering bash -u error.
[[ -n "${_FUNCTIONS_LOADED:-}" ]] && return 0
_FUNCTIONS_LOADED=1

# # Source other scripts
# SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"      # Get absolute path
# source "$SCRIPT_DIR/download.sh"
# source "$SCRIPT_DIR/normalize.sh"
# source "$SCRIPT_DIR/convert.sh"

# Default values (can be overridden by ENV)
: "${DL_RETRY:=1}"
: "${DL_RETRY_DELAY:=3}"
: "${DL_TIMEOUT:=60}"

# ============================================================
# Download Function
# ============================================================
# [===DROPPED===]
# # Usage: dl <url> [output]
# # - If `output` is omitted, outputs to stdout
# # - Includes retry mechanism for reliability
# dl() {
#   local url="$1" out="${2:-}"
#   local args=(
#     -fsSL
#     --connect-timeout 10
#     --max-time 30
#     --retry 1
#     --retry-delay 3
#     --retry-all-errors
#   )
#   if [[ -n "$out" ]]; then
#     curl "${args[@]}" "$url" -o "$out"
#   else
#     curl "${args[@]}" "$url"
#   fi
# }

# Usage: dl [-r retry] [-d delay] [-t timeout] <url> [output]
# - Use GITHUB_TOKEN for authorization
# - Includes retry mechanism for reliability
# - Allows single overrides of named options
# - If `output` is omitted, outputs to stdout
dl() {
  local retry="$DL_RETRY"
  local retry_delay="$DL_RETRY_DELAY"
  local timeout="$DL_TIMEOUT"
  local OPTIND opt
  
  while getopts ":r:d:t:" opt; do
    case $opt in
      r) retry="$OPTARG" ;;
      d) retry_delay="$OPTARG" ;;
      t) timeout="$OPTARG" ;;
      :) echo "Option -$OPTARG requires an argument" >&2; return 1 ;;
      \?) echo "Unknown option -$OPTARG" >&2; return 1 ;;
    esac
  done
  shift $((OPTIND - 1))
  
  local url="$1" out="${2:-}"
  
  [[ -z "$url" ]] && { echo "Usage: dl [-r retry] [-d delay] [-t timeout] <url> [output]" >&2; return 1; }
  
  local args=(
    -fsSL
    --connect-timeout 10
    --max-time "$timeout"
    --retry "$retry"
    --retry-delay "$retry_delay"
    --retry-all-errors
    -H "User-Agent: GitHub-Actions"
  )
  
  # If GITHUB_TOKEN exists, add authorization header
  [[ -n "${GITHUB_TOKEN:-}" ]] && args+=(-H "Authorization: token $GITHUB_TOKEN")
  
  if [[ -n "$out" ]]; then
    curl "${args[@]}" "$url" -o "$out"
  else
    curl "${args[@]}" "$url"
  fi
}

# ============================================================
# Normalize Functions
# ============================================================
# Usage: norm_domain [separator]
# - Reads from stdin, writes to stdout
# - If separator is omitted, use " " by default
# - Preserves leading comments, skips mid-file comments
# - Extracts first column, removes port, adds "+." prefix
norm_domain() {
  local sep="${1:-[[:space:]]+}"
  awk -F"$sep" '
    BEGIN { ds = 0 }                                 # ds = data_started flag
    /^[[:space:]]*$/ { next }
    /^[[:space:]]*#/ { if (!ds) print; next }
    {
      ds = 1; h = $1                                 # End leading comments
      sub(/[[:space:]]*#.*$/, "", h)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", h)
      sub(/:[0-9]+$/, "", h)
      if (h ~ /^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+(:[0-9]{1,5})?$/) print "+." h      # Match domain / domain:port
    }
  '
}

# Usage: norm_ip [separator]
# - Reads from stdin, writes to stdout
# - If separator is omitted, use " " by default
# - Normalizes IPv4 addresses to CIDR notation
norm_ip() {
  local sep="${1:-[[:space:]]+}"
  awk -F"$sep" '
    BEGIN { ds = 0 }                                 # ds = data_started flag
    /^[[:space:]]*$/ { next }
    /^[[:space:]]*#/ { if (!ds) print; next }
    {
      ds = 1; h = $1
      sub(/[[:space:]]*#.*$/, "", h)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", h)
      if (match(h, /^[0-9]+(\.[0-9]+){3}/)) {
        ip = substr(h, 1, RLENGTH)
        rest = substr(h, RLENGTH + 1)
        cidr = 32
        if (rest ~ /^\/[0-9]+$/) cidr = substr(rest, 2) + 0
        else if (rest != "" && rest !~ /^:[0-9]+$/) next
        if (cidr >= 0 && cidr <= 32) print ip "/" cidr
      }
    }
  '
}

# ============================================================
# Process Functions
# ============================================================
# Usage: proc_domain <url> <output.mrs> [separator]
# - Downloads, normalizes, and converts domain list
# - If separator is omitted, use " " by default
proc_domain() {
  local url="$1" out="$2" sep="${3:-[[:space:]]+}"
  local txt="${out%.mrs}.txt"
  echo "  [D] ${out##*/}"
  dl "$url" | norm_domain "$sep" > "$txt"
  mihomo convert-ruleset domain text "$txt" "$out"
}

# Usage: proc_ip <url> <output.mrs> [separator]
# - Downloads, normalizes, and converts IP list
# - If separator is omitted, use " " by default
proc_ip() {
  local url="$1" out="$2" sep="${3:-[[:space:]]+}"
  local txt="${out%.mrs}.txt"
  echo "  [I] ${out##*/}"
  dl "$url" | norm_ip "$sep" > "$txt"
  mihomo convert-ruleset ipcidr text "$txt" "$out"
}

# Usage: proc_mixed <url> <domain_output.mrs> <ip_output.mrs> [separator]
# - Downloads once, splits into domain and IP lists
# - If separator is omitted, use " " by default
proc_mixed() {
  local url="$1" dom_out="$2" ip_out="$3" sep="${4:-[[:space:]]+}"
  local dom_txt="${dom_out%.mrs}.txt"
  local ip_txt="${ip_out%.mrs}.txt"
  local tmp="/tmp/mixed_raw_$$.txt"
  
  echo "  [D+I] ${dom_out##*/} + ${ip_out##*/}"
  dl "$url" > "$tmp"
  norm_domain "$sep" < "$tmp" > "$dom_txt"
  norm_ip "$sep" < "$tmp" > "$ip_txt"
  rm -f "$tmp"
  mihomo convert-ruleset domain text "$dom_txt" "$dom_out"
  mihomo convert-ruleset ipcidr text "$ip_txt" "$ip_out"
}

# ============================================================
# Utility Functions
# ============================================================
# Usage: switch_to_rules_branch
# - Switches to rules branch, creates if not exists
switch_to_rules_branch() {
  echo "[Git] Switching to rules branch"
  if git ls-remote --exit-code origin rules &>/dev/null; then
    git fetch origin rules && git switch rules
  else
    git switch -c rules
  fi
}

# Usage: install_mihomo
# - Download and install Mihomo from cached branch in this repository
# - ENV: GITHUB_REPOSITORY, GITHUB_TOKEN
install_mihomo() {
  echo "[Setup] Installing Mihomo from cache branch"
  
  local repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY not set}"
  local deb_url="https://raw.githubusercontent.com/${repo}/cache/mihomo.deb"
  
  dl "$deb_url" /tmp/mihomo.deb
  sudo dpkg -i /tmp/mihomo.deb 2>/dev/null || sudo apt-get install -f -y
  rm -f /tmp/mihomo.deb
  
  echo "[Setup] Mihomo installed: $(mihomo -v 2>&1 | head -1)"
}
