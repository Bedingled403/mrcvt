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
# - Supports: TLD (e.g. org, .org), DOMAIN (e.g. example.com, .example.com), DOMAIN+PORT (e.g. example.com:443 / .example.com:443 -> +.example.com)
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
      if (h ~ /^(\.)?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$/ && h !~ /^[0-9.]+$/) {           # Standard AWKs (such as POSIX awk or stock awk on macOS) do not support zero-width assertions
        if (h ~ /^\./) print "+" h
        else print "+." h
      }
    }
  '
}

# Usage: norm_ip [separator]
# - Reads from stdin, writes to stdout
# - If separator is omitted, use " " by default
# - Normalizes IPv4 and IPv6 addresses to CIDR notation
# - Supports: IPv4, IPv4+Port, IPv4+CIDR, IPv6, IPv6+Port (brackets), IPv6+CIDR
norm_ip() {
  local sep="${1:-[[:space:]]+}"
  awk -F"$sep" '
    BEGIN { ds = 0 }                                 # ds = data_started flag
    /^[[:space:]]*$/ { next }                        # Skip empty lines
    /^[[:space:]]*#/ { if (!ds) print; next }        # Print header comments
    {
      ds = 1; h = $1
      # Clean inline comments and whitespace
      sub(/[[:space:]]*#.*$/, "", h)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", h)

      ip = ""; rest = ""; max_cidr = 0
      
      # 1. Try matching IPv4 (e.g., 1.2.3.4)
      if (match(h, /^[0-9]{1,3}(\.[0-9]{1,3}){3}/)) {
        ip = substr(h, RSTART, RLENGTH)
        rest = substr(h, RSTART + RLENGTH)
        max_cidr = 32
      }
      # 2. Try matching IPv6 wrapped in brackets (e.g., [2001::1]:80)
      else if (match(h, /^\[[0-9a-fA-F:]+\]/)) {
        ip = substr(h, RSTART + 1, RLENGTH - 2) # Strip brackets
        rest = substr(h, RSTART + RLENGTH)
        max_cidr = 128
      }
      # 3. Try matching raw IPv6 (e.g., 2001::1)
      else if (match(h, /^[0-9a-fA-F:]+/)) {
        ip = substr(h, RSTART, RLENGTH)
        # Validate IPv6 must look like IPv6 (contain colon) to avoid matching pure numbers
        if (ip !~ /:/) next
        rest = substr(h, RSTART + RLENGTH)
        max_cidr = 128
      }
      else { next } # Not a recognized IP format

      # Handle Port in "rest" (e.g. :80 or :80/32)
      # If rest starts with colon followed by digits, strip it
      if (rest ~ /^:[0-9]+/) {
        sub(/^:[0-9]+/, "", rest)
      }

      # Handle CIDR in "rest" (e.g. /32 or empty)
      cidr = max_cidr
      if (rest ~ /^\/[0-9]+$/) {
        cidr = substr(rest, 2) + 0
      } else if (rest != "") {
        # If rest is not empty and not a valid CIDR (e.g. /7.rar), reject
        next
      }

      # Final Validation and Print
      if (cidr >= 0 && cidr <= max_cidr) {
        print ip "/" cidr
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
  local base="${out##*/}"
  local tmp="/tmp/domain_raw_${base%.mrs}.txt"

  echo "::group::  [D] $base"
  time -p ( dl "$url" > "$tmp")
  ls -lh $tmp
  
  time -p ( norm_domain "$sep" < "$tmp" > "$txt" )
  ls -lh "$txt"
  
  time -p ( mihomo convert-ruleset domain text "$txt" "$out" )
  ls -lh "$out"
  echo "::endgroup::"
}

# Usage: proc_ip <url> <output.mrs> [separator]
# - Downloads, normalizes, and converts IP list
# - If separator is omitted, use " " by default
proc_ip() {
  local url="$1" out="$2" sep="${3:-[[:space:]]+}"
  local txt="${out%.mrs}.txt"
  local base="${out##*/}"
  local tmp="/tmp/ip_raw_${base%.mrs}.txt"
  
  echo "::group::  [I] $base"
  time -p ( dl "$url" > "$tmp" )
  ls -lh $tmp
  
  time -p ( norm_ip "$sep" < "$tmp" > "$txt" )
  ls -lh "$txt"

  time -p ( mihomo convert-ruleset ipcidr text "$txt" "$out" )
  ls -lh "$out"
  echo "::endgroup::"
}

# Usage: proc_mixed <url> <domain_output.mrs> <ip_output.mrs> [separator]
# - Downloads once, splits into domain and IP lists
# - If separator is omitted, use " " by default
proc_mixed() {
  local url="$1" dom_out="$2" ip_out="$3" sep="${4:-[[:space:]]+}"
  local dom_txt="${dom_out%.mrs}.txt"
  local ip_txt="${ip_out%.mrs}.txt"
  local tmp="/tmp/mixed_raw_$$.txt"
  
  echo "::group::  [D+I] ${dom_out##*/} + ${ip_out##*/}"
  time -p ( dl "$url" > "$tmp" )
  ls -lh $tmp
  
  time -p ( norm_domain "$sep" < "$tmp" > "$dom_txt" )
  ls -lh $dom_txt
  time -p ( norm_ip "$sep" < "$tmp" > "$ip_txt" )
  ls -lh $ip_txt
  rm -f "$tmp"
  
  time -p ( mihomo convert-ruleset domain text "$dom_txt" "$dom_out" )
  ls -lh $dom_out
  time -p ( mihomo convert-ruleset ipcidr text "$ip_txt" "$ip_out" )
  ls -lh $ip_out
  echo "::endgroup::"
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
  
  local tmp_deb="/tmp/mihomo_$$.deb"                               # Prevent conflicts during concurrent execution
  dl "$deb_url" "$tmp_deb"
  if ! sudo dpkg -i "$tmp_deb"; then
    echo "[Setup] dpkg failed, attempting to fix dependencies..."  # Attempt to fix deps if dpkg failed
    sudo apt-get update && sudo apt-get install -f -y              # Add `apt-get update`: In a clean environment in GitHub Actions, running install -f directly sometimes fails because the local package index is missing.
  fi
  
  rm -f "$tmp_deb"
  echo "[Setup] Mihomo installed: $(mihomo -v 2>&1 | head -1)"
}
