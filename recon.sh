#!/usr/bin/env bash

# ============================================================================
# ADVANCED BUG BOUNTY RECONNAISSANCE FRAMEWORK v2.1 (STABLE)
# ============================================================================
# Features:
# - Full POSIX Compliance & Strict Mode
# - Bounded Concurrency (Prevents Fork Bombs)
# - Modular Architecture with Stream Isolation
# - Automatic Dependency Resolution & Fallbacks
# - Signal Trapping (No Zombie Processes)
#
# Usage:./recon.sh -d target.com [-t threads][-a]
# ============================================================================

# ----------------------------------------------------------------------------
# 1. DEFENSIVE CONFIGURATION & GLOBALS
# ----------------------------------------------------------------------------
set -euo pipefail
IFS=$'\n\t'

VERSION="2.1.0"
TARGET_DOMAIN=""
THREADS=20
AGGRESSIVE=false
DEEP_SCAN=false
OUTPUT_BASE="./recon_workspace"
LOG_FILE=""

# ANSI Color Codes
RED='\033${NC} ${TYPE} ${MSG}" >&2
    
    # Log to file if variable is set
    if [[ -n "$LOG_FILE" ]]; then
        echo " ${MSG}" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
    fi
}

check_dependency() {
    local tool="$1"
    if! command -v "$tool" &> /dev/null; then
        log "${YELLOW}${NC}" "Tool '$tool' not found. Some modules may fail."
    fi
}

cleanup() {
    # Only run if we have active jobs
    if [[ -n "$(jobs -p)" ]]; then
        log "${RED}[!]${NC}" "Interrupted. Killing child processes..."
        pkill -P $$ 2>/dev/null |

| true
    fi
    exit 1
}
trap cleanup SIGINT SIGTERM

usage() {
    cat << EOF
Usage: $0 -d <domain> [options]

Options:
  -d  Target domain (e.g., example.com)
  -t  Threads/Concurrency (default: 20)
  -a  Aggressive Mode (Enable active scans: nmap, nuclei active)
  -D  Deep Scan (Slower, more comprehensive)
  -h  Show this help

Example:
  $0 -d example.com -t 50 -a
EOF
    exit 1
}

# ----------------------------------------------------------------------------
# 3. SETUP & VALIDATION
# ----------------------------------------------------------------------------

# Parse Arguments
while getopts ":d:t:aDh" opt; do
  case ${opt} in
    d) TARGET_DOMAIN="$OPTARG" ;;
    t) THREADS="$OPTARG" ;;
    a) AGGRESSIVE=true ;;
    D) DEEP_SCAN=true ;;
    h) usage ;;
    \?) log "${RED}${NC}" "Invalid option: -$OPTARG"; usage ;;
    :) log "${RED}${NC}" "Option -$OPTARG requires an argument."; usage ;;
  esac
done

# Validation
if]; then
    log "${RED}${NC}" "Target domain is required."
    usage
fi

if[a-zA-Z0-9.-]{1,61}[a-zA-Z0-9]$ ]]; then
    log "${RED}${NC}" "Invalid domain format: $TARGET_DOMAIN"
    exit 1
fi

# Environment Setup
SESSION_ID=$(date +'%Y%m%d_%H%M')
SAFE_TARGET=$(echo "$TARGET_DOMAIN" | sed 's/[^a-zA-Z0-9.-]//g')
WORK_DIR="${OUTPUT_BASE}/${SAFE_TARGET}_${SESSION_ID}"
LOG_FILE="${WORK_DIR}/scan.log"

mkdir -p "$WORK_DIR"/{subdomains,live,scans,urls,params,vulns,report}

log "${GREEN}${NC}" "Target: $TARGET_DOMAIN | Threads: $THREADS | Aggressive: $AGGRESSIVE"

# ----------------------------------------------------------------------------
# 4. MODULES
# ----------------------------------------------------------------------------

module_subdomains() {
    log "${BLUE}[+]${NC}" "Phase 1: Subdomain Enumeration"
    local OUT_FILE="$WORK_DIR/subdomains/all_subs.txt"

    # Use 'anew' if available, else fallback to 'sort -u'
    local MERGE_CMD="sort -u"
    if command -v anew &>/dev/null; then MERGE_CMD="anew $OUT_FILE"; fi

    # 1. Subfinder
    if command -v subfinder &>/dev/null; then
        log "${CYAN}[*]${NC}" "Running Subfinder..."
        subfinder -d "$TARGET_DOMAIN" -silent -t "$THREADS" 2>>"$LOG_FILE" | $MERGE_CMD >> "$OUT_FILE" |

| true
    fi

    # 2. Assetfinder
    if command -v assetfinder &>/dev/null; then
        log "${CYAN}[*]${NC}" "Running Assetfinder..."
        assetfinder --subs-only "$TARGET_DOMAIN" 2>>"$LOG_FILE" | $MERGE_CMD >> "$OUT_FILE" |

| true
    fi

    # 3. Crt.sh (Passive)
    log "${CYAN}[*]${NC}" "Querying Crt.sh..."
    curl -s "https://crt.sh/?q=%25.$TARGET_DOMAIN&output=json" | \
        grep -oE "\"\S*${TARGET_DOMAIN}\"" | sed 's/"//g' | sed 's/\*\.//g' | \
        sort -u | $MERGE_CMD >> "$OUT_FILE" |

| true

    local count=$(wc -l < "$OUT_FILE" 2>/dev/null |

| echo 0)
    log "${GREEN}[OK]${NC}" "Found $count unique subdomains."
}

module_live_validation() {
    log "${BLUE}[+]${NC}" "Phase 2: Live Host Validation"
    local INPUT_SUBS="$WORK_DIR/subdomains/all_subs.txt"
    local OUT_HOSTS="$WORK_DIR/live/alive_hosts.txt"
    local OUT_URLS="$WORK_DIR/live/alive_urls.txt"

    if]; then
        log "${YELLOW}${NC}" "No subdomains to validate."
        return
    fi

    if command -v httpx &>/dev/null; then
        log "${CYAN}[*]${NC}" "Running HTTPX..."
        httpx -l "$INPUT_SUBS" \
            -silent -threads "$THREADS" \
            -status-code -title -tech-detect -follow-redirects \
            -json -o "$WORK_DIR/live/httpx_full.json" 2>>"$LOG_FILE" |

| true

        # Extract URLs
        if]; then
            if command -v jq &>/dev/null; then
                cat "$WORK_DIR/live/httpx_full.json" | jq -r '.url' | sort -u > "$OUT_URLS"
                cat "$WORK_DIR/live/httpx_full.json" | jq -r '.input' | sort -u > "$OUT_HOSTS"
            else
                grep -o '"url":"[^"]*"' "$WORK_DIR/live/httpx_full.json" | cut -d'"' -f4 | sort -u > "$OUT_URLS"
            fi
        fi
    else
        log "${RED}${NC}" "httpx missing. Skipping validation."
    fi
}

module_port_scan() {
    log "${BLUE}[+]${NC}" "Phase 3: Port Scanning"
    local INPUT_HOSTS="$WORK_DIR/live/alive_hosts.txt"
    local IP_LIST="$WORK_DIR/scans/ips.txt"

    if]; then return; fi

    # Resolve IPs first to avoid scanning the same LB 100 times
    log "${CYAN}[*]${NC}" "Resolving IPs..."
    if command -v dnsx &>/dev/null; then
        dnsx -l "$INPUT_HOSTS" -silent -a -resp-only | sort -u > "$IP_LIST" 2>>"$LOG_FILE" |

| true
    else
        # Fallback to dig/xargs
        cat "$INPUT_HOSTS" | xargs -P "$THREADS" -I {} bash -c "dig +short {} | grep -E '^[0-9.]+$'" | sort -u > "$IP_LIST" |

| true
    fi

    # Run Nmap on unique IPs
    if] && command -v nmap &>/dev/null; then
        local IP_COUNT=$(wc -l < "$IP_LIST")
        log "${CYAN}[*]${NC}" "Scanning $IP_COUNT unique IPs with Nmap..."
        nmap -iL "$IP_LIST" -n -sV -T4 --top-ports 1000 \
             -oN "$WORK_DIR/scans/nmap.txt" 2>>"$LOG_FILE" |

| true
    elif command -v naabu &>/dev/null; then
        log "${CYAN}[*]${NC}" "Scanning with Naabu..."
        naabu -list "$IP_LIST" -top-ports 1000 -silent -o "$WORK_DIR/scans/naabu.txt" |

| true
    else
        log "${YELLOW}${NC}" "Skipping active port scan (requires -a or naabu)."
    fi
}

module_url_discovery() {
    log "${BLUE}[+]${NC}" "Phase 4: URL Discovery"
    local INPUT_HOSTS="$WORK_DIR/live/alive_hosts.txt"
    local ALL_URLS="$WORK_DIR/urls/all_urls.txt"
    
    # 1. GAU (Get All Urls)
    if command -v gau &>/dev/null; then
        log "${CYAN}[*]${NC}" "Running GAU..."
        cat "$INPUT_HOSTS" | gau --threads "$THREADS" --blacklist ttf,woff,svg,png,jpg 2>>"$LOG_FILE" >> "$ALL_URLS" |

| true
    fi

    # 2. Waybackurls
    if command -v waybackurls &>/dev/null; then
        log "${CYAN}[*]${NC}" "Running Waybackurls..."
        cat "$INPUT_HOSTS" | waybackurls 2>>"$LOG_FILE" >> "$ALL_URLS" |

| true
    fi

    # 3. Katana (Active Crawling)
    if] && command -v katana &>/dev/null; then
        log "${CYAN}[*]${NC}" "Running Katana (Active Crawl)..."
        katana -list "$WORK_DIR/live/alive_urls.txt" -silent -jc -c "$THREADS" 2>>"$LOG_FILE" >> "$ALL_URLS" |

| true
    fi

    # Deduplicate
    sort -u "$ALL_URLS" -o "$ALL_URLS"
    local count=$(wc -l < "$ALL_URLS" 2>/dev/null |

| echo 0)
    log "${GREEN}[OK]${NC}" "Discovered $count unique URLs."
}

module_param_discovery() {
    log "${BLUE}[+]${NC}" "Phase 5: Parameter Discovery"
    local INPUT_URLS="$WORK_DIR/live/alive_urls.txt"
    local OUT_PARAMS="$WORK_DIR/params/arjun.json"

    if]; then return; fi

    # Arjun for bulk parameter scanning
    # Arjun supports '-i' for import. This is much faster than loops.
    if command -v arjun &>/dev/null; then
        log "${CYAN}[*]${NC}" "Running Arjun on live URLs..."
        arjun -i "$INPUT_URLS" -t "$THREADS" -oJ "$OUT_PARAMS" 2>>"$LOG_FILE" |

| true
    else
        log "${YELLOW}${NC}" "Arjun not found. Skipping parameter discovery."
    fi
}

module_vuln_scan() {
    log "${BLUE}[+]${NC}" "Phase 6: Vulnerability Scanning"
    local INPUT_URLS="$WORK_DIR/live/alive_urls.txt"
    local OUT_VULNS="$WORK_DIR/vulns/nuclei_results.txt"

    if]; then return; fi

    if command -v nuclei &>/dev/null; then
        log "${CYAN}[*]${NC}" "Running Nuclei..."
        
        # Tags to exclude for speed and safety
        local EXCLUDE_TAGS="dos,fuzz"
        
        if]; then
            nuclei -l "$INPUT_URLS" -t cves,vulnerabilities,misconfiguration \
                   -et "$EXCLUDE_TAGS" -c "$THREADS" -silent \
                   -o "$OUT_VULNS" 2>>"$LOG_FILE" |

| true
        else
            # Lighter scan for non-aggressive mode
            nuclei -l "$INPUT_URLS" -t technologies,misconfiguration \
                   -severity low,medium,high,critical \
                   -et "$EXCLUDE_TAGS" -c "$THREADS" -silent \
                   -o "$OUT_VULNS" 2>>"$LOG_FILE" |

| true
        fi
        
        local count=$(wc -l < "$OUT_VULNS" 2>/dev/null |

| echo 0)
        log "${GREEN}[OK]${NC}" "Nuclei finished. Found $count issues."
    else
        log "${YELLOW}${NC}" "Nuclei not found."
    fi
}

module_report() {
    log "${BLUE}[+]${NC}" "Generating Report"
    local REPORT_FILE="$WORK_DIR/report/summary.md"
    
    {
        echo "# Reconnaissance Report: $TARGET_DOMAIN"
        echo "**Date:** $(date)"
        echo "**Aggressive Mode:** $AGGRESSIVE"
        echo ""
        echo "## Statistics"
        echo "- Subdomains: $(wc -l < "$WORK_DIR/subdomains/all_subs.txt" 2>/dev/null |

| echo 0)"
        echo "- Live Hosts: $(wc -l < "$WORK_DIR/live/alive_hosts.txt" 2>/dev/null |

| echo 0)"
        echo "- URLs Discovered: $(wc -l < "$WORK_DIR/urls/all_urls.txt" 2>/dev/null |

| echo 0)"
        echo "- Vulnerabilities: $(wc -l < "$WORK_DIR/vulns/nuclei_results.txt" 2>/dev/null |

| echo 0)"
        echo ""
        echo "## Critical Findings"
        echo "\`\`\`"
        grep -i "critical" "$WORK_DIR/vulns/nuclei_results.txt" 2>/dev/null | head -n 10 |

| echo "No critical findings detected."
        echo "\`\`\`"
    } > "$REPORT_FILE"

    log "${GREEN}${NC}" "Report saved to $REPORT_FILE"
}

# ----------------------------------------------------------------------------
# 5. MAIN EXECUTION FLOW
# ----------------------------------------------------------------------------

main() {
    # Check dependencies before starting
    for tool in subfinder httpx dnsx gau nuclei; do
        check_dependency "$tool"
    done

    module_subdomains
    module_live_validation
    module_port_scan
    module_url_discovery
    module_param_discovery
    module_vuln_scan
    module_report
    
    log "${GREEN}${NC}" "All modules completed. Workspace: $WORK_DIR"
}

main
