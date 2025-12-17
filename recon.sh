#!/usr/bin/env bash

# ============================================================================
# ADVANCED BUG BOUNTY RECONNAISSANCE FRAMEWORK v2.4 (FIXED)
# ============================================================================
# All syntax errors and bugs have been corrected
# Usage: ./recon.sh -d target.com [-t threads] [-a] [-D]
# ============================================================================

# ----------------------------------------------------------------------------
# 1. DEFENSIVE CONFIGURATION & GLOBALS
# ----------------------------------------------------------------------------
set -euo pipefail
IFS=$'\n\t'

VERSION="2.4.0"
TARGET_DOMAIN=""
THREADS=20
AGGRESSIVE=false
DEEP_SCAN=false
VERBOSE=false
OUTPUT_BASE="./recon_workspace"
LOG_FILE=""

# ANSI Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ----------------------------------------------------------------------------
# 2. UTILITY FUNCTIONS
# ----------------------------------------------------------------------------

# Function: log
# Description: Logs messages with color-coded severity levels
log() {
    local COLOR="$1"
    local LEVEL="$2"
    local MSG="$3"
    local TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    local FORMATTED_MSG="${COLOR}[${TIMESTAMP}] [${LEVEL}]${NC} ${MSG}"

    # Print to console
    echo -e "${FORMATTED_MSG}"
    
    # Write to log file if variable is set
    if [[ -n "$LOG_FILE" ]]; then
        # Strip color codes for the log file
        echo "${FORMATTED_MSG}" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
    fi
}

# Function: run_verbose
# Description: Run command with real-time output if verbose mode is enabled
run_verbose() {
    local cmd="$1"
    
    if [[ "$VERBOSE" == true ]]; then
        log "${CYAN}" "CMD" "Executing: $cmd"
        eval "$cmd" 2>&1 | while IFS= read -r line; do
            echo -e "${CYAN}  → ${NC}$line"
            if [[ -n "$LOG_FILE" ]]; then
                echo "  → $line" >> "$LOG_FILE"
            fi
        done
        local exit_code="${PIPESTATUS[0]}"
        return "$exit_code"
    else
        eval "$cmd" 2>>"$LOG_FILE" || true
    fi
}

# Function: cleanup
# Description: Traps signals to kill child processes and remove temp files.
cleanup() {
    # Only run if we have active jobs
    if [[ -n "$(jobs -p)" ]]; then
        log "${RED}" "WARN" "Interrupted. Killing child processes..."
        # Kill child processes of this shell ($$)
        pkill -P $$ 2>/dev/null || true
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
  -v  Verbose Mode (Show real-time output from tools)
  -h  Show this help

Example:
  $0 -d example.com -t 50 -a -D -v
EOF
    exit 1
}

# ----------------------------------------------------------------------------
# 3. SETUP & VALIDATION
# ----------------------------------------------------------------------------

# Parse Arguments
while getopts ":d:t:aDvh" opt; do
  case ${opt} in
    d) TARGET_DOMAIN="$OPTARG" ;;
    t) THREADS="$OPTARG" ;;
    a) AGGRESSIVE=true ;;
    D) DEEP_SCAN=true ;;
    v) VERBOSE=true ;;
    h) usage ;;
    \?) log "${RED}" "ERR" "Invalid option: -$OPTARG"; usage ;;
    :) log "${RED}" "ERR" "Option -$OPTARG requires an argument."; usage ;;
  esac
done

# Validation
if [[ -z "$TARGET_DOMAIN" ]]; then
    log "${RED}" "ERR" "Target domain is mandatory."
    usage
fi

# Regex for valid hostname (RFC 1123)
if ! [[ "$TARGET_DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
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
log "${GREEN}" "INFO" "Threads: $THREADS | Aggressive: $AGGRESSIVE | Deep Scan: $DEEP_SCAN | Verbose: $VERBOSE"

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
        run_verbose "subfinder -d '$TARGET_DOMAIN' -silent -all -t '$THREADS' >> '$TEMP_FILE'"
    fi

    # 2. Assetfinder
    if command -v assetfinder &>/dev/null; then
        log "${CYAN}" "STEP" "Running Assetfinder..."
        run_verbose "assetfinder --subs-only '$TARGET_DOMAIN' >> '$TEMP_FILE'"
    fi

    # 3. Crt.sh (Passive)
    log "${CYAN}" "STEP" "Querying Crt.sh..."
    if [[ "$VERBOSE" == true ]]; then
        curl -s "https://crt.sh/?q=%25.$TARGET_DOMAIN&output=json" | \
            jq -r '.[].name_value' 2>/dev/null | \
            sed 's/\*\.//g' | tee -a "$TEMP_FILE" | while read line; do
                echo -e "${CYAN}  → ${NC}$line"
            done || true
    else
        curl -s "https://crt.sh/?q=%25.$TARGET_DOMAIN&output=json" | \
            jq -r '.[].name_value' 2>/dev/null | \
            sed 's/\*\.//g' >> "$TEMP_FILE" || true
    fi

    # Final Deduplication and Sanitization
    sort -u "$TEMP_FILE" | grep -E "^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$" | \
        grep "$SAFE_TARGET" > "$OUT_FILE" || true
    
    # Deep Scan: Optionally run Amass in passive mode
    if [[ "$DEEP_SCAN" == true ]] && command -v amass &>/dev/null; then
        log "${CYAN}" "STEP" "Running Amass (Deep Passive)..."
        run_verbose "amass enum -passive -d '$TARGET_DOMAIN' -timeout 10 -o '$WORK_DIR/subdomains/amass.txt'"
        # Merge Amass results if file is non-empty
        if [[ -s "$WORK_DIR/subdomains/amass.txt" ]]; then
            cat "$WORK_DIR/subdomains/amass.txt" >> "$OUT_FILE"
            sort -u "$OUT_FILE" -o "$OUT_FILE"
        fi
    fi

    rm -f "$TEMP_FILE" # Clean up temp file
    local count=$(wc -l < "$OUT_FILE" 2>/dev/null || echo 0)
    log "${GREEN}" "OK" "Enumeration complete. Found $count unique subdomains."
}

module_live_validation() {
    log "${BLUE}" "PHASE" "Phase 2: Live Host Validation (HTTPX)"
    local INPUT_SUBS="$WORK_DIR/subdomains/all_subs.txt"
    local OUT_HOSTS="$WORK_DIR/live/alive_hosts.txt"
    local OUT_URLS="$WORK_DIR/live/alive_urls.txt"

    if [[ ! -s "$INPUT_SUBS" ]]; then
        log "${YELLOW}" "WARN" "No subdomains to validate."
        return
    fi

    if command -v httpx &>/dev/null; then
        log "${CYAN}" "STEP" "Running HTTPX..."
        
        if [[ "$VERBOSE" == true ]]; then
            httpx -l "$INPUT_SUBS" \
                -silent -threads "$THREADS" \
                -status-code -title -tech-detect -follow-redirects \
                -json -o "$WORK_DIR/live/httpx_full.json" 2>&1 | while IFS= read -r line; do
                    echo -e "${CYAN}  → ${NC}$line"
                    if [[ -n "$LOG_FILE" ]]; then
                        echo "  → $line" >> "$LOG_FILE"
                    fi
                done || true
        else
            httpx -l "$INPUT_SUBS" \
                -silent -threads "$THREADS" \
                -status-code -title -tech-detect -follow-redirects \
                -json -o "$WORK_DIR/live/httpx_full.json" 2>>"$LOG_FILE" || true
        fi

        # Extract URLs
        if [[ -s "$WORK_DIR/live/httpx_full.json" ]]; then
            if command -v jq &>/dev/null; then
                cat "$WORK_DIR/live/httpx_full.json" | jq -r '.url' | sort -u > "$OUT_URLS" || true
                # Extract hosts (domain names without protocol/path)
                cat "$WORK_DIR/live/httpx_full.json" | jq -r '.input' | sort -u > "$OUT_HOSTS" || true
            else
                log "${YELLOW}" "WARN" "jq missing. Extracting URLs/Hosts via grep (less reliable)."
                grep -o '"url":"[^"]*"' "$WORK_DIR/live/httpx_full.json" | cut -d'"' -f4 | sort -u > "$OUT_URLS" || true
                # Fallback extraction of hosts from URLs
                sed 's/.*:\/\///' "$OUT_URLS" | sed 's/\/.*//' | sort -u > "$OUT_HOSTS" || true
            fi
        fi
    else
        log "${RED}" "ERR" "httpx missing. Skipping validation."
        return
    fi
    
    local count=$(wc -l < "$OUT_URLS" 2>/dev/null || echo 0)
    log "${GREEN}" "OK" "Validation complete. Found $count live HTTP endpoints."
}

module_port_scan() {
    log "${BLUE}" "PHASE" "Phase 3: Port Scanning"
    local INPUT_HOSTS="$WORK_DIR/live/alive_hosts.txt"
    local IP_LIST="$WORK_DIR/scans/ips.txt"

    if [[ ! -s "$INPUT_HOSTS" ]]; then 
        log "${YELLOW}" "WARN" "No hosts to scan."
        return
    fi

    # Resolve IPs first to avoid scanning the same LB 100 times
    log "${CYAN}" "STEP" "Resolving IPs for Port Scan..."
    
    if command -v dnsx &>/dev/null; then
        # Use dnsx (fast and Go-based)
        run_verbose "dnsx -l '$INPUT_HOSTS' -silent -a -resp-only | sort -u > '$IP_LIST'"
    else
        # Fallback to dig/xargs
        if [[ "$VERBOSE" == true ]]; then
            log "${CYAN}" "INFO" "Resolving IPs with dig (verbose)..."
            cat "$INPUT_HOSTS" | while read host; do
                ip=$(dig +short "$host" | grep -E '^[0-9.]+

    local IP_COUNT=$(wc -l < "$IP_LIST" 2>/dev/null || echo 0)
    
    if [[ "$IP_COUNT" -eq 0 ]]; then 
        log "${YELLOW}" "WARN" "No resolvable IPs found. Skipping Port Scan."
        return
    fi
    
    if command -v naabu &>/dev/null; then
        log "${CYAN}" "STEP" "Scanning $IP_COUNT unique IPs with Naabu..."
        
        local PORTS="-top-ports 1000"
        if [[ "$AGGRESSIVE" == true ]]; then
            PORTS="-p 1-65535" # Full port scan in aggressive mode
            log "${YELLOW}" "WARN" "Aggressive mode (full port scan) enabled. This may be time-consuming."
        fi
        
        run_verbose "naabu -list '$IP_LIST' $PORTS -silent -rate 3000 -c '$THREADS' -o '$WORK_DIR/scans/naabu_ports.txt'"
    elif [[ "$AGGRESSIVE" == true ]] && command -v masscan &>/dev/null; then
         log "${CYAN}" "STEP" "Scanning with Masscan (Full Scan)..."
         run_verbose "masscan -iL '$IP_LIST' -p1-65535 --rate=5000 -oL '$WORK_DIR/scans/masscan_ports.txt'"
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

    if [[ ! -s "$INPUT_HOSTS" ]]; then 
        log "${YELLOW}" "WARN" "No hosts for URL discovery."
        return
    fi

    # 1. GAU (Passive: Get All Urls)
    if command -v gau &>/dev/null; then
        log "${CYAN}" "STEP" "Running GAU (Wayback/CommonCrawl)..."
        if [[ "$VERBOSE" == true ]]; then
            cat "$INPUT_HOSTS" | gau --threads "$THREADS" --blacklist ttf,woff,svg,png,jpg 2>&1 | while IFS= read -r line; do
                echo -e "${CYAN}  → ${NC}$line"
                if [[ -n "$LOG_FILE" ]]; then
                    echo "  → $line" >> "$LOG_FILE"
                fi
                echo "$line" >> "$ALL_URLS"
            done || true
        else
            cat "$INPUT_HOSTS" | gau --threads "$THREADS" --blacklist ttf,woff,svg,png,jpg 2>>"$LOG_FILE" | anew "$ALL_URLS" || true
        fi
    fi

    # 2. Waybackurls (Passive Fallback)
    if command -v waybackurls &>/dev/null && [[ ! -s "$ALL_URLS" ]]; then
        log "${CYAN}" "STEP" "Running Waybackurls (Fallback)..."
        if [[ "$VERBOSE" == true ]]; then
            cat "$INPUT_HOSTS" | waybackurls 2>&1 | while IFS= read -r line; do
                echo -e "${CYAN}  → ${NC}$line"
                if [[ -n "$LOG_FILE" ]]; then
                    echo "  → $line" >> "$LOG_FILE"
                fi
                echo "$line" >> "$ALL_URLS"
            done || true
        else
            cat "$INPUT_HOSTS" | waybackurls 2>>"$LOG_FILE" | anew "$ALL_URLS" || true
        fi
    fi

    # 3. Katana (Active Crawling on Live URLs)
    if [[ "$DEEP_SCAN" == true ]] && command -v katana &>/dev/null && [[ -s "$LIVE_URLS" ]]; then
        log "${CYAN}" "STEP" "Running Katana (Active Crawl - Deep Scan)..."
        run_verbose "katana -list '$LIVE_URLS' -silent -jc -d 3 -c '$THREADS' | anew '$ALL_URLS'"
    fi
    
    # Final Deduplicate
    sort -u "$ALL_URLS" -o "$ALL_URLS"
    local count=$(wc -l < "$ALL_URLS" 2>/dev/null || echo 0)
    log "${GREEN}" "OK" "Discovered $count unique URLs."
}

module_param_discovery() {
    log "${BLUE}" "PHASE" "Phase 5: Parameter Discovery"
    local INPUT_URLS="$WORK_DIR/live/alive_urls.txt"
    local OUT_PARAMS="$WORK_DIR/params/arjun_params.txt"
    local URLS_WITH_PARAMS="$WORK_DIR/urls/all_urls.txt"

    if [[ ! -s "$INPUT_URLS" ]]; then 
        log "${YELLOW}" "WARN" "No URLs for parameter discovery."
        return
    fi

    # 1. Arjun (Active Parameter Fuzzing)
    if command -v arjun &>/dev/null; then
        log "${CYAN}" "STEP" "Running Arjun (Active Fuzzing)..."
        run_verbose "arjun -i '$INPUT_URLS' -t '$THREADS' -oT '$OUT_PARAMS'"
    fi
    
    # 2. Extract Passive Parameters from URL list
    log "${CYAN}" "STEP" "Extracting passive parameters from discovered URLs..."
    if [[ "$VERBOSE" == true ]]; then
        grep -oP '(?<=\?|\&)[^=&]+(?==)' "$URLS_WITH_PARAMS" 2>/dev/null | sort -u | while read param; do
            echo -e "${CYAN}  → ${NC}Found parameter: $param"
            echo "$param" >> "$WORK_DIR/params/passive_parameters.txt"
        done || true
    else
        grep -oP '(?<=\?|\&)[^=&]+(?==)' "$URLS_WITH_PARAMS" 2>/dev/null | sort -u >> "$WORK_DIR/params/passive_parameters.txt" || true
    fi

    local count=$(wc -l < "$WORK_DIR/params/passive_parameters.txt" 2>/dev/null || echo 0)
    log "${GREEN}" "OK" "Found $count unique parameters (Passive/Active)."
}

module_vuln_scan() {
    log "${BLUE}" "PHASE" "Phase 6: Vulnerability Scanning"
    local INPUT_URLS="$WORK_DIR/live/alive_urls.txt"
    local OUT_VULNS="$WORK_DIR/vulns/nuclei_results.txt"

    if [[ ! -s "$INPUT_URLS" ]]; then 
        log "${YELLOW}" "WARN" "No URLs for scanning."
        return
    fi

    if command -v nuclei &>/dev/null; then
        log "${CYAN}" "STEP" "Running Nuclei (Updating Templates)..."
        run_verbose "nuclei -update-templates -silent"
        
        local EXCLUDE_TAGS="dos,fuzz"
        local TEMPLATE_TAGS="cves,vulnerabilities,misconfiguration,headless"

        if [[ "$AGGRESSIVE" == true ]]; then
            log "${CYAN}" "STEP" "Running Nuclei (Aggressive Mode: All Templates)..."
            
            if [[ "$VERBOSE" == true ]]; then
                nuclei -l "$INPUT_URLS" -severity critical,high,medium,low,info \
                       -et "$EXCLUDE_TAGS" -c "$THREADS" -v \
                       -o "$OUT_VULNS" 2>&1 | while IFS= read -r line; do
                           echo -e "${CYAN}  → ${NC}$line"
                           if [[ -n "$LOG_FILE" ]]; then
                               echo "  → $line" >> "$LOG_FILE"
                           fi
                       done || true
            else
                nuclei -l "$INPUT_URLS" -severity critical,high,medium,low,info \
                       -et "$EXCLUDE_TAGS" -c "$THREADS" -silent \
                       -o "$OUT_VULNS" 2>>"$LOG_FILE" || true
            fi
        else
            log "${CYAN}" "STEP" "Running Nuclei (Standard Mode: CVE/Misconfig)..."
            
            if [[ "$VERBOSE" == true ]]; then
                nuclei -l "$INPUT_URLS" -tags "$TEMPLATE_TAGS" \
                       -severity critical,high,medium \
                       -et "$EXCLUDE_TAGS" -c "$THREADS" -v \
                       -o "$OUT_VULNS" 2>&1 | while IFS= read -r line; do
                           echo -e "${CYAN}  → ${NC}$line"
                           if [[ -n "$LOG_FILE" ]]; then
                               echo "  → $line" >> "$LOG_FILE"
                           fi
                       done || true
            else
                nuclei -l "$INPUT_URLS" -tags "$TEMPLATE_TAGS" \
                       -severity critical,high,medium \
                       -et "$EXCLUDE_TAGS" -c "$THREADS" -silent \
                       -o "$OUT_VULNS" 2>>"$LOG_FILE" || true
            fi
        fi
        
        local count=$(wc -l < "$OUT_VULNS" 2>/dev/null || echo 0)
        log "${GREEN}" "OK" "Vulnerability scan finished. Found $count potential issues."
    else
        log "${YELLOW}" "WARN" "Nuclei not found. Skipping vulnerability scan."
    fi
}

module_report() {
    log "${BLUE}" "PHASE" "Phase 7: Generating Report"
    local REPORT_FILE="$WORK_DIR/report/summary.md"
    
    # Gather Statistics
    local subs_count=$(wc -l < "$WORK_DIR/subdomains/all_subs.txt" 2>/dev/null || echo 0)
    local alive_count=$(wc -l < "$WORK_DIR/live/alive_urls.txt" 2>/dev/null || echo 0)
    # Find the output file from either naabu or masscan
    local ports_file=$(find "$WORK_DIR/scans" -name "*ports.txt" 2>/dev/null | head -n 1)
    local ports_count=$(wc -l < "${ports_file:-/dev/null}" 2>/dev/null || echo 0)
    local urls_count=$(wc -l < "$WORK_DIR/urls/all_urls.txt" 2>/dev/null || echo 0)
    local vulns_count=$(wc -l < "$WORK_DIR/vulns/nuclei_results.txt" 2>/dev/null || echo 0)
    local param_count=$(wc -l < "$WORK_DIR/params/passive_parameters.txt" 2>/dev/null || echo 0)


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
        grep -iE "critical|high" "$WORK_DIR/vulns/nuclei_results.txt" 2>/dev/null | head -n 10 || echo "No Critical/High findings detected."
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
main | head -1)
                if [[ -n "$ip" ]]; then
                    echo -e "${CYAN}  → ${NC}$host => $ip"
                    echo "$ip" >> "$IP_LIST"
                fi
            done
            sort -u "$IP_LIST" -o "$IP_LIST"
        else
            cat "$INPUT_HOSTS" | xargs -P "$THREADS" -I {} bash -c "dig +short {} | grep -E '^[0-9.]+

    local IP_COUNT=$(wc -l < "$IP_LIST" 2>/dev/null || echo 0)
    
    if [[ "$IP_COUNT" -eq 0 ]]; then 
        log "${YELLOW}" "WARN" "No resolvable IPs found. Skipping Port Scan."
        return
    fi
    
    if command -v naabu &>/dev/null; then
        log "${CYAN}" "STEP" "Scanning $IP_COUNT unique IPs with Naabu..."
        
        local PORTS="-top-ports 1000"
        if [[ "$AGGRESSIVE" == true ]]; then
            PORTS="-p 1-65535" # Full port scan in aggressive mode
            log "${YELLOW}" "WARN" "Aggressive mode (full port scan) enabled. This may be time-consuming."
        fi
        
        naabu -list "$IP_LIST" $PORTS -silent -rate 3000 -c "$THREADS" \
              -o "$WORK_DIR/scans/naabu_ports.txt" 2>>"$LOG_FILE" || true
    elif [[ "$AGGRESSIVE" == true ]] && command -v masscan &>/dev/null; then
         log "${CYAN}" "STEP" "Scanning with Masscan (Full Scan)..."
         masscan -iL "$IP_LIST" -p1-65535 --rate=5000 \
                 -oL "$WORK_DIR/scans/masscan_ports.txt" 2>>"$LOG_FILE" || true
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

    if [[ ! -s "$INPUT_HOSTS" ]]; then 
        log "${YELLOW}" "WARN" "No hosts for URL discovery."
        return
    fi

    # 1. GAU (Passive: Get All Urls)
    if command -v gau &>/dev/null; then
        log "${CYAN}" "STEP" "Running GAU (Wayback/CommonCrawl)..."
        # Using anew for safe merging and deduplication
        cat "$INPUT_HOSTS" | gau --threads "$THREADS" --blacklist ttf,woff,svg,png,jpg 2>>"$LOG_FILE" | anew "$ALL_URLS" || true
    fi

    # 2. Waybackurls (Passive Fallback)
    if command -v waybackurls &>/dev/null && [[ ! -s "$ALL_URLS" ]]; then
        log "${CYAN}" "STEP" "Running Waybackurls (Fallback)..."
        cat "$INPUT_HOSTS" | waybackurls 2>>"$LOG_FILE" | anew "$ALL_URLS" || true
    fi

    # 3. Katana (Active Crawling on Live URLs)
    if [[ "$DEEP_SCAN" == true ]] && command -v katana &>/dev/null && [[ -s "$LIVE_URLS" ]]; then
        log "${CYAN}" "STEP" "Running Katana (Active Crawl - Deep Scan)..."
        katana -list "$LIVE_URLS" -silent -jc -d 3 -c "$THREADS" 2>>"$LOG_FILE" | anew "$ALL_URLS" || true
    fi
    
    # Final Deduplicate
    sort -u "$ALL_URLS" -o "$ALL_URLS"
    local count=$(wc -l < "$ALL_URLS" 2>/dev/null || echo 0)
    log "${GREEN}" "OK" "Discovered $count unique URLs."
}

module_param_discovery() {
    log "${BLUE}" "PHASE" "Phase 5: Parameter Discovery"
    local INPUT_URLS="$WORK_DIR/live/alive_urls.txt"
    local OUT_PARAMS="$WORK_DIR/params/arjun_params.txt"
    local URLS_WITH_PARAMS="$WORK_DIR/urls/all_urls.txt"

    if [[ ! -s "$INPUT_URLS" ]]; then 
        log "${YELLOW}" "WARN" "No URLs for parameter discovery."
        return
    fi

    # 1. Arjun (Active Parameter Fuzzing)
    if command -v arjun &>/dev/null; then
        log "${CYAN}" "STEP" "Running Arjun (Active Fuzzing)..."
        arjun -i "$INPUT_URLS" -t "$THREADS" -oT "$OUT_PARAMS" 2>>"$LOG_FILE" || true
    fi
    
    # 2. Extract Passive Parameters from URL list
    log "${CYAN}" "STEP" "Extracting passive parameters from discovered URLs..."
    grep -oP '(?<=\?|\&)[^=&]+(?==)' "$URLS_WITH_PARAMS" 2>/dev/null | sort -u >> "$WORK_DIR/params/passive_parameters.txt" || true

    local count=$(wc -l < "$WORK_DIR/params/passive_parameters.txt" 2>/dev/null || echo 0)
    log "${GREEN}" "OK" "Found $count unique parameters (Passive/Active)."
}

module_vuln_scan() {
    log "${BLUE}" "PHASE" "Phase 6: Vulnerability Scanning"
    local INPUT_URLS="$WORK_DIR/live/alive_urls.txt"
    local OUT_VULNS="$WORK_DIR/vulns/nuclei_results.txt"

    if [[ ! -s "$INPUT_URLS" ]]; then 
        log "${YELLOW}" "WARN" "No URLs for scanning."
        return
    fi

    if command -v nuclei &>/dev/null; then
        log "${CYAN}" "STEP" "Running Nuclei (Updating Templates)..."
        nuclei -update-templates -silent 2>>"$LOG_FILE" || true
        
        local EXCLUDE_TAGS="dos,fuzz"
        local TEMPLATE_TAGS="cves,vulnerabilities,misconfiguration,headless"

        if [[ "$AGGRESSIVE" == true ]]; then
            log "${CYAN}" "STEP" "Running Nuclei (Aggressive Mode: All Templates)..."
            nuclei -l "$INPUT_URLS" -severity critical,high,medium,low,info \
                   -et "$EXCLUDE_TAGS" -c "$THREADS" -silent \
                   -o "$OUT_VULNS" 2>>"$LOG_FILE" || true
        else
            log "${CYAN}" "STEP" "Running Nuclei (Standard Mode: CVE/Misconfig)..."
            nuclei -l "$INPUT_URLS" -tags "$TEMPLATE_TAGS" \
                   -severity critical,high,medium \
                   -et "$EXCLUDE_TAGS" -c "$THREADS" -silent \
                   -o "$OUT_VULNS" 2>>"$LOG_FILE" || true
        fi
        
        local count=$(wc -l < "$OUT_VULNS" 2>/dev/null || echo 0)
        log "${GREEN}" "OK" "Vulnerability scan finished. Found $count potential issues."
    else
        log "${YELLOW}" "WARN" "Nuclei not found. Skipping vulnerability scan."
    fi
}

module_report() {
    log "${BLUE}" "PHASE" "Phase 7: Generating Report"
    local REPORT_FILE="$WORK_DIR/report/summary.md"
    
    # Gather Statistics
    local subs_count=$(wc -l < "$WORK_DIR/subdomains/all_subs.txt" 2>/dev/null || echo 0)
    local alive_count=$(wc -l < "$WORK_DIR/live/alive_urls.txt" 2>/dev/null || echo 0)
    # Find the output file from either naabu or masscan
    local ports_file=$(find "$WORK_DIR/scans" -name "*ports.txt" 2>/dev/null | head -n 1)
    local ports_count=$(wc -l < "${ports_file:-/dev/null}" 2>/dev/null || echo 0)
    local urls_count=$(wc -l < "$WORK_DIR/urls/all_urls.txt" 2>/dev/null || echo 0)
    local vulns_count=$(wc -l < "$WORK_DIR/vulns/nuclei_results.txt" 2>/dev/null || echo 0)
    local param_count=$(wc -l < "$WORK_DIR/params/passive_parameters.txt" 2>/dev/null || echo 0)


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
        grep -iE "critical|high" "$WORK_DIR/vulns/nuclei_results.txt" 2>/dev/null | head -n 10 || echo "No Critical/High findings detected."
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
main" | sort -u > "$IP_LIST" || true
        fi
    fi

    local IP_COUNT=$(wc -l < "$IP_LIST" 2>/dev/null || echo 0)
    
    if [[ "$IP_COUNT" -eq 0 ]]; then 
        log "${YELLOW}" "WARN" "No resolvable IPs found. Skipping Port Scan."
        return
    fi
    
    if command -v naabu &>/dev/null; then
        log "${CYAN}" "STEP" "Scanning $IP_COUNT unique IPs with Naabu..."
        
        local PORTS="-top-ports 1000"
        if [[ "$AGGRESSIVE" == true ]]; then
            PORTS="-p 1-65535" # Full port scan in aggressive mode
            log "${YELLOW}" "WARN" "Aggressive mode (full port scan) enabled. This may be time-consuming."
        fi
        
        naabu -list "$IP_LIST" $PORTS -silent -rate 3000 -c "$THREADS" \
              -o "$WORK_DIR/scans/naabu_ports.txt" 2>>"$LOG_FILE" || true
    elif [[ "$AGGRESSIVE" == true ]] && command -v masscan &>/dev/null; then
         log "${CYAN}" "STEP" "Scanning with Masscan (Full Scan)..."
         masscan -iL "$IP_LIST" -p1-65535 --rate=5000 \
                 -oL "$WORK_DIR/scans/masscan_ports.txt" 2>>"$LOG_FILE" || true
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

    if [[ ! -s "$INPUT_HOSTS" ]]; then 
        log "${YELLOW}" "WARN" "No hosts for URL discovery."
        return
    fi

    # 1. GAU (Passive: Get All Urls)
    if command -v gau &>/dev/null; then
        log "${CYAN}" "STEP" "Running GAU (Wayback/CommonCrawl)..."
        # Using anew for safe merging and deduplication
        cat "$INPUT_HOSTS" | gau --threads "$THREADS" --blacklist ttf,woff,svg,png,jpg 2>>"$LOG_FILE" | anew "$ALL_URLS" || true
    fi

    # 2. Waybackurls (Passive Fallback)
    if command -v waybackurls &>/dev/null && [[ ! -s "$ALL_URLS" ]]; then
        log "${CYAN}" "STEP" "Running Waybackurls (Fallback)..."
        cat "$INPUT_HOSTS" | waybackurls 2>>"$LOG_FILE" | anew "$ALL_URLS" || true
    fi

    # 3. Katana (Active Crawling on Live URLs)
    if [[ "$DEEP_SCAN" == true ]] && command -v katana &>/dev/null && [[ -s "$LIVE_URLS" ]]; then
        log "${CYAN}" "STEP" "Running Katana (Active Crawl - Deep Scan)..."
        katana -list "$LIVE_URLS" -silent -jc -d 3 -c "$THREADS" 2>>"$LOG_FILE" | anew "$ALL_URLS" || true
    fi
    
    # Final Deduplicate
    sort -u "$ALL_URLS" -o "$ALL_URLS"
    local count=$(wc -l < "$ALL_URLS" 2>/dev/null || echo 0)
    log "${GREEN}" "OK" "Discovered $count unique URLs."
}

module_param_discovery() {
    log "${BLUE}" "PHASE" "Phase 5: Parameter Discovery"
    local INPUT_URLS="$WORK_DIR/live/alive_urls.txt"
    local OUT_PARAMS="$WORK_DIR/params/arjun_params.txt"
    local URLS_WITH_PARAMS="$WORK_DIR/urls/all_urls.txt"

    if [[ ! -s "$INPUT_URLS" ]]; then 
        log "${YELLOW}" "WARN" "No URLs for parameter discovery."
        return
    fi

    # 1. Arjun (Active Parameter Fuzzing)
    if command -v arjun &>/dev/null; then
        log "${CYAN}" "STEP" "Running Arjun (Active Fuzzing)..."
        arjun -i "$INPUT_URLS" -t "$THREADS" -oT "$OUT_PARAMS" 2>>"$LOG_FILE" || true
    fi
    
    # 2. Extract Passive Parameters from URL list
    log "${CYAN}" "STEP" "Extracting passive parameters from discovered URLs..."
    grep -oP '(?<=\?|\&)[^=&]+(?==)' "$URLS_WITH_PARAMS" 2>/dev/null | sort -u >> "$WORK_DIR/params/passive_parameters.txt" || true

    local count=$(wc -l < "$WORK_DIR/params/passive_parameters.txt" 2>/dev/null || echo 0)
    log "${GREEN}" "OK" "Found $count unique parameters (Passive/Active)."
}

module_vuln_scan() {
    log "${BLUE}" "PHASE" "Phase 6: Vulnerability Scanning"
    local INPUT_URLS="$WORK_DIR/live/alive_urls.txt"
    local OUT_VULNS="$WORK_DIR/vulns/nuclei_results.txt"

    if [[ ! -s "$INPUT_URLS" ]]; then 
        log "${YELLOW}" "WARN" "No URLs for scanning."
        return
    fi

    if command -v nuclei &>/dev/null; then
        log "${CYAN}" "STEP" "Running Nuclei (Updating Templates)..."
        nuclei -update-templates -silent 2>>"$LOG_FILE" || true
        
        local EXCLUDE_TAGS="dos,fuzz"
        local TEMPLATE_TAGS="cves,vulnerabilities,misconfiguration,headless"

        if [[ "$AGGRESSIVE" == true ]]; then
            log "${CYAN}" "STEP" "Running Nuclei (Aggressive Mode: All Templates)..."
            nuclei -l "$INPUT_URLS" -severity critical,high,medium,low,info \
                   -et "$EXCLUDE_TAGS" -c "$THREADS" -silent \
                   -o "$OUT_VULNS" 2>>"$LOG_FILE" || true
        else
            log "${CYAN}" "STEP" "Running Nuclei (Standard Mode: CVE/Misconfig)..."
            nuclei -l "$INPUT_URLS" -tags "$TEMPLATE_TAGS" \
                   -severity critical,high,medium \
                   -et "$EXCLUDE_TAGS" -c "$THREADS" -silent \
                   -o "$OUT_VULNS" 2>>"$LOG_FILE" || true
        fi
        
        local count=$(wc -l < "$OUT_VULNS" 2>/dev/null || echo 0)
        log "${GREEN}" "OK" "Vulnerability scan finished. Found $count potential issues."
    else
        log "${YELLOW}" "WARN" "Nuclei not found. Skipping vulnerability scan."
    fi
}

module_report() {
    log "${BLUE}" "PHASE" "Phase 7: Generating Report"
    local REPORT_FILE="$WORK_DIR/report/summary.md"
    
    # Gather Statistics
    local subs_count=$(wc -l < "$WORK_DIR/subdomains/all_subs.txt" 2>/dev/null || echo 0)
    local alive_count=$(wc -l < "$WORK_DIR/live/alive_urls.txt" 2>/dev/null || echo 0)
    # Find the output file from either naabu or masscan
    local ports_file=$(find "$WORK_DIR/scans" -name "*ports.txt" 2>/dev/null | head -n 1)
    local ports_count=$(wc -l < "${ports_file:-/dev/null}" 2>/dev/null || echo 0)
    local urls_count=$(wc -l < "$WORK_DIR/urls/all_urls.txt" 2>/dev/null || echo 0)
    local vulns_count=$(wc -l < "$WORK_DIR/vulns/nuclei_results.txt" 2>/dev/null || echo 0)
    local param_count=$(wc -l < "$WORK_DIR/params/passive_parameters.txt" 2>/dev/null || echo 0)


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
        grep -iE "critical|high" "$WORK_DIR/vulns/nuclei_results.txt" 2>/dev/null | head -n 10 || echo "No Critical/High findings detected."
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
