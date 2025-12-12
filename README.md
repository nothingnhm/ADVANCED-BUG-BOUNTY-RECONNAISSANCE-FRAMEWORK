I would be happy to expand the GitHub description to be more descriptive and provide clear instructions on how to use the tool.

Here is the revised and enhanced content, perfect for your `README.md`.

-----

# 🔎 Advanced Bug Bounty Reconnaissance Framework (`recon.sh`)

## 🌐 Overview

The **Advanced Bug Bounty Reconnaissance Framework** (`recon.sh`) is a robust, modular, and fully automated Bash script designed to execute a comprehensive, high-speed reconnaissance pipeline against a target domain. Built with stability and efficiency in mind, this tool is indispensable for security researchers, bug bounty hunters, and penetration testers who require reliable data collection with minimal manual intervention.

The script acts as an intelligent orchestrator, chaining together the most powerful command-line reconnaissance tools (Subfinder, httpx, Nuclei, etc.) into a single, multi-phased workflow. It ensures that output from one stage (e.g., subdomains) is seamlessly fed into the next (e.g., live host validation), concluding with a structured report and actionable findings.

## ✨ Core Features & Design Principles

  * **Robust Shell Scripting:** Full POSIX compliance and executed in **strict mode** (`set -euo pipefail`), ensuring predictable behavior and immediate error handling.
  * **Structured Workflow (The 6 Phases):** Progresses through discovery, validation, active scanning, and analysis to build a complete target profile.
  * **Safe Concurrency:** Implements **Bounded Concurrency** using Bash job control to manage multiple threads (`-t`), preventing resource exhaustion and "fork bombs."
  * **Modular Architecture:** Each stage is self-contained in a dedicated function, allowing for easy expansion, maintenance, and targeted execution.
  * **Intelligent Fallbacks:** Checks for the presence of required external tools (dependencies) and uses alternate methods (like `dig`/`xargs` or `sort -u` instead of `anew`) when primary tools are missing.
  * **Clean Workspace:** Creates a unique, timestamped directory (`recon_workspace/target_date/`) for every session, keeping results organized and reproducible.

## 🛠️ Prerequisites & Dependencies

This script is an **orchestrator** and requires several powerful community tools (mostly written in Go) to be installed on your system and available in your `$PATH`.

| Phase | Dependency Tool(s) | Primary Function |
| :--- | :--- | :--- |
| **Subdomain Enum** | `subfinder`, `assetfinder`, `curl` | Passive collection from multiple public sources. |
| **Live Host Check** | `httpx` (critical), `jq` (optional) | Probes for live HTTP/S services, extracts status codes, and detects technology. |
| **Port Scanning** | `dnsx`, `nmap` (Aggressive), `naabu` | Resolves IPs and actively scans for open ports. |
| **URL Discovery** | `gau`, `waybackurls`, `katana` (Aggressive) | Gathers historical and active URLs from archived snapshots and crawling. |
| **Parameter Mining** | `arjun` | Identifies hidden/potential request parameters in URLs. |
| **Vulnerability Scan** | `nuclei` | Scans live endpoints for common misconfigurations, CVEs, and security findings. |

> **Installation Note:** We strongly recommend installing these tools, especially the Project Discovery suite (`subfinder`, `httpx`, `dnsx`, `nuclei`), for full script functionality.

-----

## 🚀 How to Use the Tool

### 1\. Make the Script Executable

First, ensure the script has execution permissions:

```bash
chmod +x recon.sh
```

### 2\. Basic Usage and Options

Run the script from your terminal, always providing the target domain using the `-d` flag.

```bash
./recon.sh -d <domain> [options]
```

| Flag | Description | Example Value |
| :--- | :--- | :--- |
| `-d` | **Target domain** (required, e.g., `example.com`). | `nasa.gov` |
| `-t` | Concurrency limit / Number of **threads** for tools. | `50` |
| `-a` | **Aggressive Mode:** Enables active, network-intensive scans (`nmap`, active `nuclei` templates, deep `katana` crawling). | (No argument needed, just the flag) |
| `-D` | **Deep Scan Mode:** Slower, more comprehensive modules (currently a placeholder for future features). | (No argument needed, just the flag) |
| `-h` | Show the help message. | |

### 3\. Usage Examples

#### **Example 1: Safe and Fast Passive Recon**

This uses lower concurrency and avoids active network scanning, suitable for initial checks or shared network environments.

```bash
./recon.sh -d target.com -t 20
```

#### **Example 2: Full-Spectrum Aggressive Scan**

This increases concurrency and enables all active modules (`nmap` for port scanning and broader `nuclei` templates) for a deep inspection.

```bash
./recon.sh -d example.com -t 60 -a
```

### 4\. Reviewing Results

Upon completion, the script will output the location of your new workspace directory.

```
[OK] All modules completed. Workspace: ./recon_workspace/target.com_20251212_2230
```

Navigate to the workspace to find all your results organized into distinct folders:

```
cd ./recon_workspace/target.com_20251212_2230
ls

# subdomains/ live/ scans/ urls/ params/ vulns/ report/
```

The final output is the **summary report**:

```bash
cat report/summary.md
```

This report provides key statistics and highlights the top critical findings discovered by `nuclei`.

## 📂 Output Structure

All results are stored in a dedicated, unique directory under the base path `./recon_workspace/`. The name of the final workspace folder is based on the target domain and the execution time (e.g., `target.com_YYYYMMDD_HHMM`).

This organized structure ensures you can easily review the data for each phase of the reconnaissance.

### Directory Hierarchy

```
recon_workspace/
└── target.com_20251212_1800/  # Unique Workspace Directory
    ├── live/               # Live/Accessible hosts and URLs
    │   ├── alive_hosts.txt
    │   └── httpx_full.json
    ├── subdomains/         # Raw Subdomain Enumeration results
    │   └── all_subs.txt
    ├── urls/               # All historical and crawled URLs
    │   └── all_urls.txt
    ├── params/             # Discovered URL parameters
    │   └── arjun.json
    ├── scans/              # Network and Port Scanning results
    │   ├── ips.txt
    │   └── nmap.txt
    ├── vulns/              # Raw vulnerability findings
    │   └── nuclei_results.txt
    └── report/             # Final Summary Document
        └── summary.md
```

### Key Files Explained

| File Name | Content | Purpose |
| :--- | :--- | :--- |
| `summary.md` | Final Markdown report. | Provides a high-level summary of statistics and critical findings. |
| `alive_hosts.txt` | List of confirmed live domains/subdomains. | Input for subsequent URL and scanning phases. |
| `all_urls.txt` | Deduplicated list of all URLs found (GAU, Wayback, Katana). | The primary input for vulnerability scanning (`nuclei`). |
| `nuclei_results.txt` | Raw output from Nuclei. | Detailed, line-by-line list of all reported vulnerabilities and misconfigurations. |
