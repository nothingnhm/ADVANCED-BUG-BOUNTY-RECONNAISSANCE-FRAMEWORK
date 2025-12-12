#!/usr/bin/env bash

# ============================================================================
# ADVANCED BUG BOUNTY RECONNAISSANCE FRAMEWORK v2.3 (SYNTAX FIX)
# ============================================================================
# Fixes:
# - Resolved "syntax error near unexpected token '?'" by ensuring multi-line 
#   pipelines are correctly terminated (replacing incorrect '|' continuation 
#   with robust '|| true' on a single logical line).
#
# Usage:./recon.sh -d target.com [-t threads][-a]
# ============================================================================

# ----------------------------------------------------------------------------
# 1. DEFENSIVE CONFIGURATION & GLOBALS
# ----------------------------------------------------------------------------
set -euo pipefail
IFS=$'\n\t'

VERSION="2.3.0"
TARGET_DOMAIN=""
THREADS=20
AGGRESSIVE=false
DEEP_SCAN=false
OUTPUT_BASE="./recon_workspace"
LOG_FILE=""

# ANSI Color Codes
RED='\033${NC} ${MSG}")

    # Print to console
    echo -e "${FORMATTED_MSG}"
    
    # Write to log file if variable is set
    if [[ -n "$LOG_FILE" ]]; then
        # Strip color codes for the log file
        echo "${FORMATTED_MSG}" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
    fi
}

# Function: check_dependency
# Description: Verifies tool existence.
check_dependency() {
    local tool="$1"
    if! command -v "$tool" &> /dev/null; then
        log "${RED}" "ERR" "Required tool '$tool' is not installed or not in PATH."
        exit 1
    fi
}

# Function: cleanup
# Description: Traps signals to kill child processes and remove temp files.
cleanup() {
    # Only run if we have active jobs
    if [[ -n "$(jobs -p)" ]]; then
        log "${RED}" "WARN" "Interrupted. Killing child processes..."
        # Kill child processes of this shell ($$)
        pkill -P $$ 2>/dev/null |

| true
    fi
    exit 1
}
# Set trap for graceful exit
trap cleanup SIGINT SIGTERM

usage() {
    cat << EOF
Usage: $0 -d <domain> [options]

Options:
  -d  Target domain (e.g., example.com)
  -t  Threads/Concurrency (default: 20)
  -a  Aggressive Mode (Enable active scans, e.g., full Nmap)
  -D  Deep Scan (Slower, comprehensive enumeration)
  -h  Show this help

Example:
  $0 -d example.com -t 50 -a -D
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
    \?) log "${RED}" "ERR" "Invalid option: -$OPTARG"; usage ;;
    :) log "${RED}" "ERR" "Option -$OPTARG requires an argument."; usage ;;
  esac
done

# Validation
if; then
    log "${RED}" "ERR" "Target domain is mandatory."
    usage
fi

# Regex for valid hostname (RFC 1123)
if([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
    log "${RED}" "ERR" "Invalid domain format: $TARGET_DOMAIN"
    exit 1
fi

# Environment Setup
SESSION_ID=$(date +'%Y%m%d_%H%M')
SAFE_TARGET=$(echo "$TARGET_DOMAIN" | sed 's/[^a-zA-Z0-9.-]//g')
WORK_DIR="${OUTPUT_BASE}/${SAFE_TARGET}_${SESSION_ID}"
LOG_FILE="${WORK_DIR}/scan.log"

mkdir -p "$WORK_DIR"/{subdomains,live,scans,urls,params,vulns,report}

log "${GREEN}" "INFO" "Scan initiated for: $TARGET_DOMAIN (v$VERSION)"
log "${GREEN}" "INFO" "Workspace created: $WORK_DIR"
log "${GREEN}" "INFO" "Threads: $THREADS | Aggressive: $AGGRESSIVE | Deep Scan: $DEEP_SCAN"

# Check Critical Dependencies
log "${YELLOW}" "INFO" "Verifying toolchain..."
DEPENDENCIES=("subfinder" "httpx" "curl" "jq")
for dep in "${DEPENDENCIES[@]}"; do
    # Only check if tool exists, do not exit if optional tools are missing
    command -v "$dep" &>/dev/null |

| log "${YELLOW}" "WARN" "Optional tool '$dep' not found."
done

# ----------------------------------------------------------------------------
# 4. MODULES
# ----------------------------------------------------------------------------

module_subdomains() {
    log "${BLUE}" "PHASE" "Phase 1: Subdomain Enumeration"
    local TEMP_FILE="$WORK_DIR/subdomains/temp_raw.txt"
    local OUT_FILE="$WORK_DIR/subdomains/all_subs.txt"

    # Use a temporary file to collect all raw results first.
    : > "$TEMP_FILE"

    # 1. Subfinder
    if command -v subfinder &>/dev/null; then
        log "${CYAN}" "STEP" "Running Subfinder (Passive)..."
        subfinder -d "$TARGET_DOMAIN" -silent -all -t "$THREADS" 2>>"$LOG_FILE" >> "$TEMP_FILE" |

| true
    fi

    # 2. Assetfinder
    if command -v assetfinder &>/dev/null; then
        log "${CYAN}" "STEP" "Running Assetfinder..."
        assetfinder --subs-only "$TARGET_DOMAIN" 2>>"$LOG_FILE" >> "$TEMP_FILE" |

| true
    fi

    # 3. Crt.sh (Passive)
    log "${CYAN}" "STEP" "Querying Crt.sh..."
    curl -s "https://crt.sh/?q=%25.$TARGET_DOMAIN&output=json" | \
        jq -r '..name_value' 2>/dev/null | \
        sed 's/\*\.//g' >> "$TEMP_FILE" |

| true # Corrected: Single logical line termination

    # Final Deduplication and Sanitization
    sort -u "$TEMP_FILE" | grep -E "^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$" | \
        grep "$SAFE_TARGET" > "$OUT_FILE" |

| true
    
    # Deep Scan: Optionally run Amass in passive mode
    if] && command -v amass &>/dev/null; then
        log "${CYAN}" "STEP" "Running Amass (Deep Passive)..."
        amass enum -passive -d "$TARGET_DOMAIN" -timeout 10 -o "$WORK_DIR/subdomains/amass.txt" 2>>"$LOG_FILE" |

| true
        # Merge Amass results if file is non-empty
        if; then
            cat "$WORK_DIR/subdomains/amass.txt" >> "$OUT_FILE"
            sort -u "$OUT_FILE" -o "$OUT_FILE"
        fi
    fi

    rm -f "$TEMP_FILE" # Clean up temp file
    local count=$(wc -l < "$OUT_FILE" 2>/dev/null |

| echo 0)
    log "${GREEN}" "OK" "Enumeration complete. Found $count unique subdomains."
}

module_live_validation() {
    log "${BLUE}" "PHASE" "Phase 2: Live Host Validation (HTTPX)"
    local INPUT_SUBS="$WORK_DIR/subdomains/all_subs.txt"
    local OUT_HOSTS="$WORK_DIR/live/alive_hosts.txt"
    local OUT_URLS="$WORK_DIR/live/alive_urls.txt"

    if; then
        log "${YELLOW}" "WARN" "No subdomains to validate."
        return
    fi

    if command -v httpx &>/dev/null; then
        log "${CYAN}" "STEP" "Running HTTPX..."
        httpx -l "$INPUT_SUBS" \
            -silent -threads "$THREADS" \
            -status-code -title -tech-detect -follow-redirects \
            -json -o "$WORK_DIR/live/httpx_full.json" 2>>"$LOG_FILE" |

| true

        # Extract URLs
        if; then
            if command -v jq &>/dev/null; then
                cat "$WORK_DIR/live/httpx_full.json" | jq -r '.url' | sort -u > "$OUT_URLS" |

| true
                # Extract hosts (domain names without protocol/path)
                cat "$WORK_DIR/live/httpx_full.json" | jq -r '.input' | sort -u > "$OUT_HOSTS" |

| true
            else
                log "${YELLOW}" "WARN" "jq missing. Extracting URLs/Hosts via grep (less reliable)."
                grep -o '"url":"[^"]*"' "$WORK_DIR/live/httpx_full.json" | cut -d'"' -f4 | sort -u > "$OUT_URLS" |

| true
                # Fallback extraction of hosts from URLs
                sed 's/.*:\/\///' "$OUT_URLS" | sed 's/\/.*//' | sort -u > "$OUT_HOSTS" |

| true
            fi
        fi
    else
        log "${RED}" "ERR" "httpx missing. Skipping validation."
        return
    fi
    
    local count=$(wc -l < "$OUT_URLS" 2>/dev/null |

| echo 0)
    log "${GREEN}" "OK" "Validation complete. Found $count live HTTP endpoints."
}

module_port_scan() {
    log "${BLUE}" "PHASE" "Phase 3: Port Scanning"
    local INPUT_HOSTS="$WORK_DIR/live/alive_hosts.txt"
    local IP_LIST="$WORK_DIR/scans/ips.txt"

    if; then log "${YELLOW}" "WARN" "No hosts to scan." ; return; fi

    # Resolve IPs first to avoid scanning the same LB 100 times
    log "${CYAN}" "STEP" "Resolving IPs for Port Scan..."
    
    if command -v dnsx &>/dev/null; then
        # Use dnsx (fast and Go-based)
        dnsx -l "$INPUT_HOSTS" -silent -a -resp-only | sort -u > "$IP_LIST" 2>>"$LOG_FILE" |

| true
    else
        # Fallback to dig/xargs
        cat "$INPUT_HOSTS" | xargs -P "$THREADS" -I {} bash -c "dig +short {} | grep -E '^[0-9.]+$'" | sort -u > "$IP_LIST" |

| true
    fi

    local IP_COUNT=$(wc -l < "$IP_LIST" 2>/dev/null |

| echo 0)
    
    if; then log "${YELLOW}" "WARN" "No resolvable IPs found. Skipping Port Scan." ; return; fi
    
    if command -v naabu &>/dev/null; then
        log "${CYAN}" "STEP" "Scanning $IP_COUNT unique IPs with Naabu..."
        
        local PORTS="-top-ports 1000"
        if; then
            PORTS="-p 1-65535" # Full port scan in aggressive mode
            log "${YELLOW}" "WARN" "Aggressive mode (full port scan) enabled. This may be time-consuming."
        fi
        
        naabu -list "$IP_LIST" $PORTS -silent -rate 3000 -c "$THREADS" \
              -o "$WORK_DIR/scans/naabu_ports.txt" 2>>"$LOG_FILE" |

| true
    elif && command -v masscan &>/dev/null; then
         log "${CYAN}" "STEP" "Scanning with Masscan (Full Scan)..."
         masscan -iL "$IP_LIST" -p1-65535 --rate=5000 \
                 -oL "$WORK_DIR/scans/masscan_ports.txt" 2>>"$LOG_FILE" |

| true
    else
        log "${YELLOW}" "WARN" "Naabu/Masscan not found. Skipping active port scan."
    fi
}

module_url_discovery() {
    log "${BLUE}" "PHASE" "Phase 4: URL Discovery & Crawling"
    local INPUT_HOSTS="$WORK_DIR/live/alive_hosts.txt"
    local LIVE_URLS="$WORK_DIR/live/alive_urls.txt"
    local ALL_URLS="$WORK_DIR/urls/all_urls.txt"
    
    : > "$ALL_URLS" # Clear file for fresh start

    if; then log "${YELLOW}" "WARN" "No hosts for URL discovery." ; return; fi

    # 1. GAU (Passive: Get All Urls)
    if command -v gau &>/dev/null; then
        log "${CYAN}" "STEP" "Running GAU (Wayback/CommonCrawl)..."
        # Using anew for safe merging and deduplication
        cat "$INPUT_HOSTS" | gau --threads "$THREADS" --blacklist ttf,woff,svg,png,jpg 2>>"$LOG_FILE" | anew "$ALL_URLS" |

| true
    fi

    # 2. Waybackurls (Passive Fallback)
    if command -v waybackurls &>/dev/null &&; then
        log "${CYAN}" "STEP" "Running Waybackurls (Fallback)..."
        cat "$INPUT_HOSTS" | waybackurls 2>>"$LOG_FILE" | anew "$ALL_URLS" |

| true
    fi

    # 3. Katana (Active Crawling on Live URLs)
    if] && command -v katana &>/dev/null &&; then
        log "${CYAN}" "STEP" "Running Katana (Active Crawl - Deep Scan)..."
        katana -list "$LIVE_URLS" -silent -jc -d 3 -c "$THREADS" 2>>"$LOG_FILE" | anew "$ALL_URLS" |

| true
    fi
    
    # Final Deduplicate
    sort -u "$ALL_URLS" -o "$ALL_URLS"
    local count=$(wc -l < "$ALL_URLS" 2>/dev/null |

| echo 0)
    log "${GREEN}" "OK" "Discovered $count unique URLs."
}

module_param_discovery() {
    log "${BLUE}" "PHASE" "Phase 5: Parameter Discovery"
    local INPUT_URLS="$WORK_DIR/live/alive_urls.txt"
    local OUT_PARAMS="$WORK_DIR/params/arjun_params.txt"
    local URLS_WITH_PARAMS="$WORK_DIR/urls/all_urls.txt"

    if; then log "${YELLOW}" "WARN" "No URLs for parameter discovery." ; return; fi

    # 1. Arjun (Active Parameter Fuzzing)
    # Arjun supports '-i' for import targets from a file.
    if command -v arjun &>/dev/null; then
        log "${CYAN}" "STEP" "Running Arjun (Active Fuzzing)..."
        arjun -i "$INPUT_URLS" -t "$THREADS" -oT "$OUT_PARAMS" 2>>"$LOG_FILE" |

| true # Fixed termination
    fi
    
    # 2. Extract Passive Parameters from URL list
    log "${CYAN}" "STEP" "Extracting passive parameters from discovered URLs..."
    # FIX: Corrected the pipeline termination to avoid syntax error near '?'
    # This also handles grep's non-zero exit when no lines match.
    grep -oP '(?<=\?|\&)[^=&]+(?==)' "$URLS_WITH_PARAMS" 2>/dev/null | sort -u >> "$WORK_DIR/params/passive_parameters.txt" |

| true

    local count=$(wc -l < "$WORK_DIR/params/passive_parameters.txt" 2>/dev/null |

| echo 0)
    log "${GREEN}" "OK" "Found $count unique parameters (Passive/Active)."
}

module_vuln_scan() {
    log "${BLUE}" "PHASE" "Phase 6: Vulnerability Scanning"
    local INPUT_URLS="$WORK_DIR/live/alive_urls.txt"
    local OUT_VULNS="$WORK_DIR/vulns/nuclei_results.txt"

    if; then log "${YELLOW}" "WARN" "No URLs for scanning." ; return; fi

    if command -v nuclei &>/dev/null; then
        log "${CYAN}" "STEP" "Running Nuclei (Updating Templates)..."
        nuclei -update-templates -silent 2>>"$LOG_FILE" |

| true
        
        local EXCLUDE_TAGS="dos,fuzz,cve"
        local TEMPLATE_TAGS="cves,vulnerabilities,misconfiguration,headless"

        if; then
            log "${CYAN}" "STEP" "Running Nuclei (Aggressive Mode: All Templates)..."
            nuclei -l "$INPUT_URLS" -severity critical,high,medium,low,info \
                   -et "$EXCLUDE_TAGS" -c "$THREADS" -silent \
                   -o "$OUT_VULNS" 2>>"$LOG_FILE" |

| true
        else
            log "${CYAN}" "STEP" "Running Nuclei (Standard Mode: CVE/Misconfig)..."
            nuclei -l "$INPUT_URLS" -t "$TEMPLATE_TAGS" \
                   -severity critical,high,medium \
                   -et "$EXCLUDE_TAGS" -c "$THREADS" -silent \
                   -o "$OUT_VULNS" 2>>"$LOG_FILE" |

| true
        fi
        
        local count=$(wc -l < "$OUT_VULNS" 2>/dev/null |

| echo 0)
        log "${GREEN}" "OK" "Vulnerability scan finished. Found $count potential issues."
    else
        log "${YELLOW}" "WARN" "Nuclei not found. Skipping vulnerability scan."
    fi
}

module_report() {
    log "${BLUE}" "PHASE" "Phase 7: Generating Report"
    local REPORT_FILE="$WORK_DIR/report/summary.md"
    
    # Gather Statistics
    local subs_count=$(wc -l < "$WORK_DIR/subdomains/all_subs.txt" 2>/dev/null |

| echo 0)
    local alive_count=$(wc -l < "$WORK_DIR/live/alive_urls.txt" 2>/dev/null |

| echo 0)
    # Find the output file from either naabu or masscan
    local ports_file=$(find "$WORK_DIR/scans" -name "*ports.txt" 2>/dev/null | head -n 1)
    local ports_count=$(wc -l < "${ports_file:-/dev/null}" 2>/dev/null |

| echo 0)
    local urls_count=$(wc -l < "$WORK_DIR/urls/all_urls.txt" 2>/dev/null |

| echo 0)
    local vulns_count=$(wc -l < "$WORK_DIR/vulns/nuclei_results.txt" 2>/dev/null |

| echo 0)
    local param_count=$(wc -l < "$WORK_DIR/params/passive_parameters.txt" 2>/dev/null |

| echo 0)


    # Write Report
    {
        echo "# Reconnaissance Report for $TARGET_DOMAIN"
        echo "**Date:** $(date)"
        echo "**Version:** $VERSION"
        echo ""
        echo "## 📊 Executive Summary"
        echo "| Category | Count |"
        echo "|---|---|"
        echo "| Unique Subdomains | $subs_count |"
        echo "| Live Web Services | $alive_count |"
        echo "| Open Ports | $ports_count |"
        echo "| Unique URLs Discovered | $urls_count |"
        echo "| Unique Parameters | $param_count |"
        echo "| Vulnerability Findings | $vulns_count |"
        echo ""
        echo "## 📂 Key Artifacts"
        echo "* **Subdomains (Unique):** \`$WORK_DIR/subdomains/all_subs.txt\`"
        echo "* **Live URLs (HTTP/S):** \`$WORK_DIR/live/alive_urls.txt\`"
        echo "* **Vulnerabilities (Nuclei):** \`$WORK_DIR/vulns/nuclei_results.txt\`"
        echo "* **Full Log:** \`$LOG_FILE\`"
        echo ""
        echo "## 🛡️ Critical Findings Preview (Top 10)"
        echo "\`\`\`text"
        grep -iE "critical|high" "$WORK_DIR/vulns/nuclei_results.txt" 2>/dev/null | head -n 10 |

| echo "No Critical/High findings detected."
        echo "\`\`\`"
        echo ""
        echo "---"
        echo "*Generated by Advanced Recon Framework v$VERSION*"
    } > "$REPORT_FILE"

    log "${GREEN}" "OK" "Report generated at: $REPORT_FILE"
    echo -e "${GREEN}Scan Completed Successfully! Output saved to: $WORK_DIR${NC}"
}

# ----------------------------------------------------------------------------
# 5. MAIN EXECUTION FLOW
# ----------------------------------------------------------------------------

main() {
    # Execution Pipeline
    module_subdomains
    module_live_validation
    module_port_scan
    module_url_discovery
    module_param_discovery
    module_vuln_scan
    module_report
}

# Start Main
main
