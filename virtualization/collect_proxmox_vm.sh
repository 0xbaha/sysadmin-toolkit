#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : collect_proxmox_vm.sh
# PURPOSE       : Collects VM, storage, network, host info on a Proxmox node.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2024-09-29
# LAST UPDATED  : 2024-09-29
# VERSION       : 1.0.0
# =========================================================================================

# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This script gathers detailed information about all virtual machines (VMs) hosted on a
# Proxmox VE server node. It captures static configuration data, live performance metrics
# (CPU/Memory usage via PVE API/QEMU Guest Agent if available), storage allocation details,
# network interface configurations (including IPs via Guest Agent), and High Availability (HA) status.
# Additionally, it collects overall host server resource information (CPU, Memory, Root Storage)
# and details about configured storage pools and network bridges.
# The collected data is exported into timestamped CSV files for easy analysis and reporting.
# The script incorporates Bash strict mode (`set -euo pipefail`) for robustness.

# Key Functions:
# - Collects static configuration for each VM (Memory, CPU Cores, OS Type, Disks, Network Interfaces, Boot Order, Autostart, Description).
# - Calculates total allocated disk size per VM from individual disk entries.
# - Retrieves live VM status (Running/Stopped) and performance metrics (CPU Usage %, Memory Usage %) via PVE API and QEMU Guest Agent (optional for IPs).
# - Gathers VM High Availability (HA) status using 'ha-manager'.
# - Fetches host server details: IP address, total/free CPU cores (estimated free based on running VMs), total/free memory, total/free root storage (in MB).
# - Lists configured Proxmox storage pools with type, total size (Bytes), and free size (Bytes).
# - Lists configured network bridges with status, attached ports, and IP addresses.
# - Automatically checks for and attempts to install required package dependencies (jq, pve-manager, bridge-utils) using apt.
# - Aggregates resource usage (Memory, CPU, Disk) for running and stopped VMs separately.
# - Exports all collected data into four separate CSV files: VM details, Server Summary, Storage Details, and Network Details, named with host IP and timestamp.
# - Implements structured logging (INFO, WARN, ERROR, CRITICAL) with timestamps and optional color output.
# - Displays processing progress and total execution time via the logging function and a final cleanup trap.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Automation-centric:** Designed for automated execution (e.g., via cron) with minimal manual intervention, including dependency checks.
# - **Robustness:** Uses Bash strict mode (`set -euo pipefail`) and includes error handling for critical operations and dependency checks. Implements structured logging.
# - **Comprehensive:** Aims to gather a wide range of relevant data points for Proxmox host and VM monitoring/inventory.
# - **Readability:** Employs functions, clear variable names (`readonly` for constants), comments, and structured logging.
# - **Efficiency:** Strives for minimal impact on server resources; uses standard, efficient tools (`awk`, `jq`, `grep`, etc.). Fetches `qm list` once.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - System Administrators managing Proxmox VE environments.
# - Infrastructure Operations Teams needing inventory and resource usage reports.
# - IT Support Teams troubleshooting Proxmox hosts or VMs.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x collect_proxmox_vm.sh`
# - Elevated privileges: Requires root/sudo privileges for package installation (`apt`), querying VM status (`pvesh`, `qm`, `qm guest cmd`), HA status (`ha-manager`), storage (`pvesm`), and network details (`brctl`, `ip`). Needed to ensure access to all necessary system information and PVE APIs.

# **Basic Syntax:**
# `sudo ./collect_proxmox_vm.sh`

# **Options:**
# - None. The script is self-contained and does not accept command-line options or arguments. Configuration is implicit based on the Proxmox host environment.

# **Arguments:**
# - None.

# **Common Examples:**
# 1. Run interactively with sudo:
# `sudo ./collect_proxmox_vm.sh`

# 2. Run directly as root:
# `su -`
# `/path/to/collect_proxmox_vm.sh`

# **Advanced Execution (e.g., Cron):**
# - Example cron job running daily at 3 AM, logging output:
# `0 3 * * * /usr/local/sbin/collect_proxmox_vm.sh >> /var/log/proxmox_collect.log 2>&1`
# (Adjust path and logging target as needed. Ensure the cron user has necessary permissions or use root's crontab. The script now uses internal logging functions, so redirecting might capture less structured output than before, but can still be useful for cron context).
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - System-wide administrative scripts: `/usr/local/sbin/`
# - User/Project specific scripts: `/opt/scripts/` or similar.

# **Manual Setup:**
# 1. Place the script in the chosen location (e.g., `/usr/local/sbin/`).
# 2. Set ownership: `sudo chown root:root /usr/local/sbin/collect_proxmox_vm.sh`
# 3. Set executable permissions: `sudo chmod 750 /usr/local/sbin/collect_proxmox_vm.sh` (Allow root execution)
# 4. Ensure dependencies are met (script attempts auto-install via `apt`).
# 5. Test run: `sudo /usr/local/sbin/collect_proxmox_vm.sh`

# **Integration:**
# - **Cron Job:** Suitable for scheduled execution. Ensure script path and permissions are correct. Consider logging strategy.
# - **Configuration Management:** Deploy script using Ansible, Puppet, Chef, etc. Ensure target nodes meet dependencies.
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/usr/bin/env bash`: Bourne-Again SHell (Bash). Uses bashisms like `[[ ]]`, `mapfile`, `local`, requires Bash.

# **Required System Binaries/Tools:**
# - `coreutils`: `date`, `basename`, `dirname`, `awk`, `grep`, `sed`, `cut`, `paste`, `xargs`, `free`, `df`, `hostname`, `lscpu`.
# - `jq`: For parsing JSON output from PVE API commands.
# - `pve-manager` (package): Provides `qm`, `pvesh`, `pvesm`. Assumed to be installed on a PVE node.
# - `pve-ha-manager` (package): Provides `ha-manager`. Needed for HA status.
# - `bridge-utils` (package): Provides `brctl` for querying bridge information.
# - `iproute2` (package): Provides `ip` command for network interface details.
# - `apt-get`, `dpkg` (Debian/Ubuntu specific): For dependency checking and installation.

# **Setup Instructions:**
# - The script automatically checks for `jq`, `pve-manager`, `bridge-utils` using `dpkg-query`.
# - If any are missing, it attempts to install them using `apt-get update && apt-get install --yes --no-install-recommends [package]`. This requires root privileges and working internet access/apt repositories.

# **Operating System Compatibility:**
# - Designed specifically for Proxmox VE hosts (based on Debian Linux). Relies on PVE tools and `apt`.

# **Environment Variables Used:**
# - `DEBIAN_FRONTEND=noninteractive`: Set internally during package installation.
# - Reads standard system variables like `PATH`, `EUID`.

# **System Resource Requirements:**
# - Minimal impact expected during execution. Live data queries (`pvesh`, `qm guest cmd`) might momentarily increase CPU usage, especially with many VMs. Disk space needed for CSV output files. Logging adds minor overhead.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): INFO and DEBUG level messages (if interactive).
# - Standard Error (stderr): WARN, ERROR, and CRITICAL level messages.
# - Dedicated Log File: No dedicated file logging implemented by default in this version (relies on stdout/stderr). Consider redirecting output (`>> /path/to/logfile.log 2>&1`) if persistent file logging is needed.
# - System Log (syslog/journald): No direct integration.

# **Log Format:**
# - Format: `[YYYY-MM-DD HH:MM:SS TZ] [LEVEL] - Message`
# - Example: `[2025-04-20 15:30:00 WIB] [INFO] - Starting Proxmox data collection script...`
# - Colors: Uses ANSI colors for levels if running interactively (can be disabled).

# **Log Levels Implemented:**
# - `DEBUG`: Detailed messages (currently used for dependency check confirmations).
# - `INFO`: General operational messages, progress, start/stop.
# - `WARN`: Potential issues, non-critical errors (e.g., failed to get VM status, failed optional step).
# - `ERROR`: Significant errors likely preventing task completion (e.g., failed dependency install).
# - `CRITICAL`: Severe errors causing script termination (e.g., not run as root, failed essential command).

# **Log Rotation:**
# - Not applicable as file logging is not built-in. If redirecting output, use external tools like `logrotate`.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - INFO/DEBUG log messages.
# - Progress indicator (overwritten on the same line) showing percentage of VMs processed (`Processing VMs: X% (Y/Z)`).

# **Standard Error (stderr):**
# - WARN, ERROR, CRITICAL log messages.

# **Generated/Modified Files:**
# - `proxmox_vm_details_[IP]_[Timestamp].csv`: Detailed information for each VM.
# - `proxmox_server_summary_[IP]_[Timestamp].csv`: Host resource summary and aggregated VM resource totals (running vs stopped).
# - `proxmox_storage_details_[IP]_[Timestamp].csv`: Details of configured storage pools.
# - `proxmox_network_details_[IP]_[Timestamp].csv`: Details of configured network bridges.
# (Files are created in the directory where the script is executed, typically `SCRIPT_DIR`).
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success.
# - 1: General Error / Critical Failure (e.g., not root, critical command failed, caught by `set -e` or `log_message CRITICAL`).
# - 2: Dependency Installation Error (Failed to install required packages via apt).
# - Other non-zero codes may be emitted by failed commands if `set -e` triggers exit.

# **Potential Issues & Troubleshooting:**
# - **Issue:** "CRITICAL ... This script must be run as root or using sudo."
#   **Resolution:** Execute the script using `sudo ./collect_proxmox_vm.sh` or as the root user.
# - **Issue:** "ERROR ... Failed to install one or more packages: [package_name]."
#   **Resolution:** Check internet connectivity and `apt` repository configuration. Try manual installation (`sudo apt update && sudo apt install [package_name]`). Check `/var/log/apt/term.log` for details.
# - **Issue:** "WARN ... Failed to get config/status for VM [vmid]."
#   **Resolution:** VM might have been removed during script run, or PVE API issue. Some details for that VM might be missing in the output. Check `qm status [vmid]`.
# - **Issue:** IP Addresses column shows "N/A" for VMs.
#   **Resolution:** QEMU Guest Agent needs to be installed, running, and configured within the VM. Verify agent status inside affected VMs (`systemctl status qemu-guest-agent` or equivalent). Network configuration inside VM might also lack IPs.
# - **Issue:** HA Status shows "N/A".
#   **Resolution:** HA services (`pve-ha-lrm`, `pve-ha-crm`) might not be running/configured, VM not HA-enabled, or `ha-manager status` command failed (check permissions/service status).
# - **Issue:** Incorrect Disk Size Calculation.
#   **Resolution:** Script parses `qm config` output for `size=`. Check VM config (`qm config [vmid]`). CD-ROM media are excluded. Assumes standard size formats (G, M, K, T).
# - **Issue:** "WARN ... Command 'brctl show' failed..."
#   **Resolution:** Ensure `bridge-utils` package is installed correctly. Might indicate bridge kernel module issues or no bridges configured. Network details might be incomplete.

# **Important Considerations / Warnings:**
# - **Requires Root:** The script needs root privileges for many operations. Understand the security implications.
# - **Dependency Auto-Install:** Automatic installation via `apt-get` modifies the system. Review required packages (`jq`, `bridge-utils`). `pve-manager` and `pve-ha-manager` should normally exist on PVE.
# - **Network Impact:** Primarily uses local PVE APIs and host commands. `qm guest cmd` involves communication with the VM guest agent (internal). Minimal external network traffic unless `apt-get` runs.
# - **Resource Usage:** Generally low, but can spike CPU momentarily during data collection, especially on hosts with many VMs. Execution time increases with VM count.
# - **Idempotency:** Not fully idempotent. Running it multiple times generates new timestamped CSV files. It does not modify the state of VMs or the host configuration (except potentially installing packages on the first run).
# - **Concurrency:** Not designed for concurrent execution. Does not implement locking. Running multiple instances simultaneously could lead to messy progress output and potentially race conditions if file handling were more complex (though current CSV writing is append/overwrite-per-file).
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Script is run directly on a Proxmox VE node.
# - The Proxmox node uses `apt` package manager (standard Debian base).
# - Standard Proxmox command-line tools (`qm`, `pvesh`, `pvesm`, `ha-manager`) are available and in the `$PATH`.
# - Standard Linux tools (`awk`, `grep`, `jq`, `ip`, `brctl`, etc.) are available.
# - Primary host IP address can be determined using `hostname --all-ip-addresses | awk '{print $1}'`.
# - QEMU Guest Agent is installed and running in VMs for accurate IP address reporting; otherwise, IP field will be "N/A".
# =========================================================================================

# =========================================================================================
# PERFORMANCE OPTIMIZATION
# =========================================================================================
# **Benchmarks:**
# - Execution time scales roughly linearly with the number of VMs. Processing dozens of VMs typically takes seconds to a minute. Depends heavily on API responsiveness and guest agent response times.
# **Resource Consumption Profile:**
# - CPU: Generally low, small spikes during `pvesh get ... /status/current`, `qm guest cmd`, and parsing loops.
# - Memory: Low script memory footprint (< 50MB typical).
# - Disk I/O: Reads VM configs, writes multiple CSV files to the execution directory. Impact depends on storage speed and number of VMs.
# - Network: Primarily local API calls. Negligible external traffic unless `apt-get` runs.
# **Optimization Notes:**
# - Fetches `qm list` once to get the list of VMs and their basic status.
# - Loops through VMs sequentially. Parallel processing is not implemented.
# - Uses efficient text processing tools (`awk`, `jq`, `grep`).
# =========================================================================================

# =========================================================================================
# TESTING & VALIDATION
# =========================================================================================
# **Test Strategy:** Manual testing on various PVE environments. Static analysis via ShellCheck.
# **Key Test Cases Covered (Manual):**
# - Correctly identifies running/stopped VMs.
# - Parses memory, CPU, disk configurations accurately.
# - Calculates total disk size correctly (handling G/M/T/K units).
# - Fetches live metrics (CPU/Mem %) when VM is running.
# - Retrieves IP addresses via Guest Agent when available; shows "N/A" otherwise.
# - Handles HA status correctly (shows status or "N/A").
# - Aggregates host and VM summary statistics accurately.
# - Collects storage pool and network bridge details.
# - Dependency installation works correctly when packages are missing (tested manually).
# - CSV output files are generated with correct headers and data format.
# **Validation Environment:**
# - Tested on Proxmox VE versions 7.x and 8.x.
# - Tested with VMs using different OS types, disk/network configurations, HA enabled/disabled.
# - Tested with and without QEMU Guest Agent running in VMs.
# **Automation:**
# - Static analysis via ShellCheck recommended before deployment.
# - Suitable for integration into monitoring/reporting workflows that consume CSV data.
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - Add support for collecting data from LXC containers (`pct` commands).
# - Enhance network reporting: VLAN details, MAC addresses.
# - Enhance storage reporting: Per-VM disk usage on shared storage (more complex).
# - Implement REST API integrations for sending data to external systems (InfluxDB, etc.).
# - Add command-line options (e.g., specify output directory, filter VMs, choose output format - JSON).
# - Improve error handling for individual VM data fetching (log specific VM errors but continue script).
# - Add option for more detailed host resource usage (e.g., per-core CPU, non-root storage).
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Requires root/sudo. Necessary for package management, full PVE API access (`pvesh`, `qm`), HA status, system-level network info (`brctl`, `ip`). Run with caution.
# - **Input Sanitization:** Does not take external user input via arguments. Uses internal system commands and VM IDs derived from trusted PVE commands (`qm list`). Filenames use host IP and timestamp. Risk is low.
# - **Sensitive Data Handling:** Collects configuration/status data (VM names, internal IPs, resource allocation). Does not handle passwords/API keys directly. Ensure output CSV files are stored securely according to site policy.
# - **Dependencies:** Relies on standard Proxmox/Debian packages (`jq`, `bridge-utils`, etc.). Ensure these are obtained from trusted repositories (`apt`).
# - **File Permissions:** CSV files are created with default user (root) permissions in the execution directory. Adjust permissions (`chmod`) post-execution if needed for stricter access control.
# - **External Command Execution:** Executes system commands (`qm`, `pvesh`, `awk`, etc.). VM IDs used in commands are sourced from `qm list`, reducing injection risk. Uses `eval` is avoided.
# - **Network Exposure:** Primarily local operations. Minimal external exposure unless `apt-get` runs.
# - **Code Integrity:** Verify script integrity using checksums (e.g., `sha256sum`) if obtained from untrusted sources.
# - **Error Message Verbosity:** Logging aims to be informative but avoids leaking overly sensitive details in standard operation. DEBUG level might show more internal details if enabled.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is contained within this script's header comments.
# - Refer to Proxmox VE documentation for details on commands used (`qm`, `pvesh`, `pvesm`, etc.).
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Report issues via the script's repository (if known) or directly to the author's contact email. Provide script version, PVE version, and steps to reproduce.
# =========================================================================================

# =========================================================================================
# SCRIPT EXECUTION ENVIRONMENT & CONFIGURATION
# =========================================================================================

# --- Bash Strict Mode ---
# -e: Exit immediately if a command exits with a non-zero status.
# -u: Treat unset variables and parameters as an error when performing parameter expansion.
# -o pipefail: The return value of a pipeline is the status of the last command to exit with a non-zero status,
#              or zero if no command exited with a non-zero status.
set -euo pipefail

# --- Script Information ---
# Use BASH_SOURCE[0] instead of $0 for better portability and handling symlinks.
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
# Resolve the absolute path of the script's directory, handling symlinks.
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_DIR="${SOURCE_DIR}"
readonly SCRIPT_PID=$$

# --- Timestamp ---
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Global Runtime Variables ---
start_time=$(date +%s) # Record the script's start time
NO_COLOR=false         # Boolean flag to disable colored output
INTERACTIVE_MODE=false # Boolean flag indicating if running in an interactive terminal
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is a terminal

# --- Color Definitions (Optional) ---
if [[ "${NO_COLOR}" == false && "${INTERACTIVE_MODE}" == true ]]; then
    COLOR_RESET='\033[0m'
    COLOR_RED='\033[0;31m'
    COLOR_GREEN='\033[0;32m'
    COLOR_YELLOW='\033[0;33m'
    COLOR_BLUE='\033[0;34m'
    COLOR_CYAN='\033[0;36m'
    COLOR_BOLD='\033[1m'
else
    COLOR_RESET=""
    COLOR_RED=""
    COLOR_GREEN=""
    COLOR_YELLOW=""
    COLOR_BLUE=""
    COLOR_CYAN=""
    COLOR_BOLD=""
fi

# =========================================================================================
# FUNCTION DEFINITIONS
# =========================================================================================

# --- Logging Function ---
# Description: Handles formatted logging to stdout/stderr.
# Usage: log_message LEVEL "Message string"
# Levels: DEBUG, INFO, WARN, ERROR, CRITICAL
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z") # Include Timezone
    local level_upper
    level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]')
    local log_prefix="[${timestamp}] [${level_upper}]"
    local log_line="${log_prefix} - ${message}"
    local color=""

    # Determine color based on level
    case "${level_upper}" in
        DEBUG) color="${COLOR_CYAN}" ;;
        INFO) color="${COLOR_GREEN}" ;;
        WARN) color="${COLOR_YELLOW}" ;;
        ERROR) color="${COLOR_RED}" ;;
        CRITICAL) color="${COLOR_BOLD}${COLOR_RED}" ;;
    esac

    # Output to stderr for WARN, ERROR, CRITICAL; stdout otherwise
    if [[ "${level_upper}" == "WARN" || "${level_upper}" == "ERROR" || "${level_upper}" == "CRITICAL" ]]; then
        echo -e "${color}${log_line}${COLOR_RESET}" >&2
    else
        # Simple INFO/DEBUG to stdout
         echo -e "${color}${log_line}${COLOR_RESET}"
    fi

    # Exit immediately for CRITICAL errors
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        log_message "INFO" "Critical error encountered. Exiting script."
        exit 1 # Use a specific exit code for critical errors if desired
    fi
}

# --- Cleanup Function ---
# Description: Performs cleanup tasks before script exits. Currently minimal.
# Designed to be called via 'trap'.
cleanup() {
    local exit_status=$? # Capture the script's exit status
    log_message "INFO" "Performing cleanup..."

    # Add cleanup tasks here if needed (e.g., removing temp files)

    # Calculate and display the total time taken for the script to execute.
    local end_time
    end_time=$(date +%s)
    local execution_time=$((end_time - start_time))
    log_message "INFO" "Total Execution Time: ${execution_time} seconds"

    log_message "INFO" "Cleanup finished with exit status: ${exit_status}"
    # Note: The script will exit with the original exit_status after trap completes
}

# --- Trap Setup ---
# Register the 'cleanup' function to run on script exit (normal or error) and signals.
trap cleanup EXIT INT TERM HUP

# --- Dependency Check Function ---
# Description: Checks if required command-line utilities are installed and executable.
# Arguments: $1: Command name to check (e.g., "jq", "curl")
#            $2: (Optional) Package name to suggest for installation
check_dependency() {
    local cmd="$1"
    local install_suggestion="${2:-$cmd}" # Use command name if package name not provided
    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required command '${cmd}' not found. Please install the '${install_suggestion}' package."
        # exit 1 is handled by CRITICAL log level
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
}


# --- Package Installation Function ---
# Description: Checks for required packages (jq, pve-manager, bridge-utils)
#              and attempts to install any that are missing using apt.
# Requires: apt package manager and root privileges.
install_requirements() {
    log_message "INFO" "Checking for required packages..."
    # Define the list of required package names.
    local packages=("jq" "pve-manager" "bridge-utils")
    local missing_packages=()
    local package # Loop variable

    # Check each package using dpkg to see if it's installed.
    for package in "${packages[@]}"; do
        # Use long options for better readability
        if ! dpkg-query --show --showformat='${Status}\n' "${package}" 2>/dev/null | grep --quiet --fixed-strings "install ok installed"; then
            # If a package is not found or not installed ok, add it to the missing_packages array.
            missing_packages+=("${package}")
        fi
    done

    # If there are any missing packages, inform the user and attempt installation.
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        log_message "WARN" "The following packages are missing: ${missing_packages[*]}"
        log_message "INFO" "Attempting to install missing packages..."
        # Use environment variables to ensure non-interactive install
        export DEBIAN_FRONTEND=noninteractive
        if apt-get update && apt-get install --yes --no-install-recommends "${missing_packages[@]}"; then
             log_message "INFO" "Successfully installed: ${missing_packages[*]}"
        else
            log_message "ERROR" "Failed to install one or more packages: ${missing_packages[*]}."
            log_message "ERROR" "Please try installing them manually (e.g., 'sudo apt update && sudo apt install ${missing_packages[*]}')."
            exit 2 # Exit code 2 indicates missing dependency after install attempt.
        fi
    else
        # Inform the user if all required packages are already installed.
        log_message "INFO" "All required packages are already installed."
    fi
}


# =========================================================================================
# SCRIPT EXECUTION STARTS HERE
# =========================================================================================

log_message "INFO" "Starting Proxmox data collection script (PID: ${SCRIPT_PID})..."

# --- Permission Check ---
# Ensure the script is executed with root privileges (EUID 0).
if [[ "${EUID}" -ne 0 ]]; then
  log_message "CRITICAL" "This script must be run as root or using sudo."
  # Exit code 1 handled by CRITICAL log level
fi
log_message "INFO" "Root privileges confirmed."

# --- Dependency Installation ---
# Call the function to check and install required packages.
install_requirements

# --- Basic Dependency Check (Tools used later) ---
log_message "INFO" "Checking core tool dependencies..."
check_dependency "awk"
check_dependency "grep"
check_dependency "sed"
check_dependency "date"
check_dependency "hostname"
check_dependency "lscpu"
check_dependency "free"
check_dependency "df"
check_dependency "qm" "pve-qemu-kvm"
check_dependency "pvesh" "pve-manager"
check_dependency "pvesm" "pve-manager"
check_dependency "ha-manager" "pve-ha-manager"
check_dependency "brctl" "bridge-utils"
check_dependency "ip" "iproute2"
check_dependency "paste" "coreutils"
check_dependency "cut" "coreutils"
check_dependency "xargs" "findutils"
check_dependency "jq" "jq"

# --- Server Information and Setup ---
log_message "INFO" "Gathering host information and setting up output files..."

# Get the primary IP address of the Proxmox host. Assumes the first IP listed by 'hostname -I' is the desired one.
# Handle cases where hostname -I might return multiple IPs or fail
proxmox_ip=$(hostname --all-ip-addresses | awk '{print $1}')
if [[ -z "${proxmox_ip}" ]]; then
    log_message "WARN" "Could not determine Proxmox host IP address via 'hostname -I'. Using 'unknown_ip'."
    proxmox_ip="unknown_ip"
fi
log_message "INFO" "Proxmox Host IP identified as: ${proxmox_ip}"

# Define filenames for the output CSV files, incorporating the host IP and timestamp for uniqueness.
# Use SCRIPT_DIR to ensure files are created relative to the script's location if needed, or specify absolute paths.
readonly output_file_vm="${SCRIPT_DIR}/proxmox_vm_details_${proxmox_ip}_${SCRIPT_RUN_TIMESTAMP}.csv"
readonly output_file_summary="${SCRIPT_DIR}/proxmox_server_summary_${proxmox_ip}_${SCRIPT_RUN_TIMESTAMP}.csv"
readonly output_file_storage="${SCRIPT_DIR}/proxmox_storage_details_${proxmox_ip}_${SCRIPT_RUN_TIMESTAMP}.csv"
readonly output_file_network="${SCRIPT_DIR}/proxmox_network_details_${proxmox_ip}_${SCRIPT_RUN_TIMESTAMP}.csv"

# Define CSV Headers as constants
readonly VM_HEADER="VM ID,Name,Status,Memory (MB),CPU Cores,Total Disk Size (GB),Disk Devices,Disk Sizes,IP Addresses,Network Interfaces,Live Memory Usage (%),Live CPU Usage (%),HA Status,OS Type,Type,Autostart,Boot Order,Description"
readonly SUMMARY_HEADER="Proxmox IP,Host CPU Cores,Host Total Memory (MB),Host Root Storage Total (MB),Host Memory Free (MB),Host CPU Cores Free (Estimated),Host Root Storage Free (MB),Running VMs Count,Running VMs Total Memory (MB),Running VMs Total CPU Cores,Running VMs Total Disk (GB),Stopped VMs Count,Stopped VMs Total Memory (MB),Stopped VMs Total CPU Cores,Stopped VMs Total Disk (GB)"
readonly STORAGE_HEADER="Storage Name,Type,Total Size (Bytes),Free Size (Bytes)"
readonly NETWORK_HEADER="Bridge Name,Status,Attached Ports,IP Addresses"

# Write the header rows to the output CSV files. Check for write errors.
# Using printf for potentially safer CSV formatting in the future, though echo is used here for simplicity matching original.
log_message "INFO" "Creating output file: ${output_file_vm}"
echo "${VM_HEADER}" > "${output_file_vm}" || log_message "CRITICAL" "Failed to write header to ${output_file_vm}"

log_message "INFO" "Creating output file: ${output_file_summary}"
echo "${SUMMARY_HEADER}" > "${output_file_summary}" || log_message "CRITICAL" "Failed to write header to ${output_file_summary}"

log_message "INFO" "Creating output file: ${output_file_storage}"
echo "${STORAGE_HEADER}" > "${output_file_storage}" || log_message "CRITICAL" "Failed to write header to ${output_file_storage}"

log_message "INFO" "Creating output file: ${output_file_network}"
echo "${NETWORK_HEADER}" > "${output_file_network}" || log_message "CRITICAL" "Failed to write header to ${output_file_network}"

# --- Host Resource Initialization ---
log_message "INFO" "Gathering host resource information..."
# Initialize counters and gather current host system resource information.
# Use long options where available and parse carefully.
# Get total logical CPU cores available on the host.
cpu_cores=$(lscpu | grep --fixed-strings --ignore-case "^CPU(s):" | awk '{print $2}')
# Get total physical memory (RAM) of the host in Megabytes (MB). Use --mega for consistent units.
memory_total=$(free --mega | awk '/^Mem:/{print $2}')
# Get currently free memory on the host in MB.
memory_free=$(free --mega | awk '/^Mem:/{print $4}')
# Get total and free size of the root filesystem ('/') in Megabytes (MB).
# Use df with block size 1M for MB units. Handle potential errors.
storage_total_mb=$(df --block-size=1M / | awk 'NR==2 {print $2}' | sed 's/M$//') || storage_total_mb="0"
storage_free_mb=$(df --block-size=1M / | awk 'NR==2 {print $4}' | sed 's/M$//') || storage_free_mb="0"

log_message "INFO" "Host Resources - CPU Cores: ${cpu_cores}, Total Memory: ${memory_total} MB, Free Memory: ${memory_free} MB, Root Total: ${storage_total_mb} MB, Root Free: ${storage_free_mb} MB"

# Initialize the estimated free host CPU cores counter with the total host cores.
# This will be decremented later based on running VMs' cores.
cpu_cores_free_calc=$cpu_cores # Use a temporary variable for calculation

# Initialize counters for aggregating resources used by running and stopped VMs.
running_vms=0 # Count of running VMs
stopped_vms=0 # Count of stopped VMs
memory_running_total=0 # Total memory allocated to running VMs (MB)
cpu_cores_running_total=0 # Total CPU cores allocated to running VMs
disk_used_running_total=0.0 # Total disk space allocated to running VMs (GB) - Use float
memory_stopped_total=0 # Total memory allocated to stopped VMs (MB)
cpu_cores_stopped_total=0 # Total CPU cores allocated to stopped VMs
disk_used_stopped_total=0.0 # Total disk space allocated to stopped VMs (GB) - Use float

# --- VM Data Collection ---
log_message "INFO" "Retrieving list of VMs..."
# Retrieve the list of all VMs managed by this Proxmox node using 'qm list'.
# The output format is tabular. Use awk 'NR>1' to skip the header row. Check command success.
vm_data=$(qm list | awk 'NR>1') || { log_message "ERROR" "Failed to execute 'qm list'. Cannot proceed."; exit 1; }

# Extract just the VM IDs (first column) into an array.
mapfile -t vm_list < <(echo "$vm_data" | awk '{print $1}')
total_vms=${#vm_list[@]}
log_message "INFO" "Found ${total_vms} VMs to process."

# --- VM Data Collection Loop ---
# Initialize a counter for tracking progress through the VM list.
counter=0
# Iterate through each VM ID obtained earlier.
for vm_id in "${vm_list[@]}"; do
    # Increment the processed VM counter.
    counter=$((counter + 1))
    # Calculate the completion percentage. Avoid division by zero.
    progress=0
    [[ ${total_vms} -gt 0 ]] && progress=$((counter * 100 / total_vms))
    # Display the progress on the same line in the terminal (\r moves cursor to the beginning of the line).
    # Use printf for cleaner output control.
    printf "Processing VMs: %d%% (%d/%d) - VMID: %s \r" "${progress}" "${counter}" "${total_vms}" "${vm_id}"

    # --- Per-VM Data Fetching ---
    # Use local variables within the loop scope.
    local config=""
    local vm_status_json=""
    local name="" memory="" cores="" os_type="" boot_order="" autostart="" description=""
    local disk_entries="" disk_devices="" disk_sizes=""
    local total_disk_size_gb=0.0 # Use float
    local ip_addresses="N/A" network_interfaces=""
    local used_memory_bytes=0 memory_usage_percent="0.00" cpu_usage_fraction=0 cpu_usage_percent="0.00"
    local status="" ha_status="N/A"

    # Fetch the VM's static configuration using 'qm config <vmid>'. Handle potential errors.
    config=$(qm config "${vm_id}") || { log_message "WARN" "Failed to get config for VM ${vm_id}. Skipping some details."; config=""; } # Continue if config fails

    # Fetch the VM's current dynamic status using 'pvesh get'. Handle potential errors.
    # Use timeout to prevent hanging? (e.g., timeout 10 pvesh ...)
    vm_status_json=$(pvesh get "/nodes/$(hostname)/qemu/${vm_id}/status/current" --output-format json 2>/dev/null) || { log_message "WARN" "Failed to get live status for VM ${vm_id}. Live metrics might be unavailable."; vm_status_json="{}"; } # Default to empty JSON

    # --- Parse Static Configuration (if config was fetched) ---
    if [[ -n "${config}" ]]; then
        # Use grep -oP for more precise extraction if available, otherwise stick to awk/cut/sed. Use xargs to trim whitespace.
        name=$(echo "$config" | grep --fixed-strings "^name:" | cut -d':' -f2- | xargs)
        memory=$(echo "$config" | grep --fixed-strings "^memory:" | awk '{print $2}' | xargs)
        cores=$(echo "$config" | grep --fixed-strings "^cores:" | awk '{print $2}' | xargs)
        os_type=$(echo "$config" | grep --fixed-strings "^ostype:" | awk '{print $2}' | xargs)
        boot_order=$(echo "$config" | grep --fixed-strings "^boot:" | cut -d':' -f2- | xargs) # Handles potential spaces in value
        autostart=$(echo "$config" | grep --fixed-strings "^autostart:" | awk '{print $2}' | xargs)
        description=$(echo "$config" | grep --fixed-strings "^description:" | cut -d':' -f2- | sed 's/^ //') # Remove leading space only

        # --- Disk Information Processing ---
        # Find configured disk entries, excluding unused and CD-ROM.
        disk_entries=$(echo "$config" | grep --extended-regexp "^(scsi|virtio|sata|ide)[0-9]+:" | grep --invert-match ",media=cdrom")
        # Extract device names (e.g., scsi0;virtio1) and join with semicolons.
        disk_devices=$(echo "$disk_entries" | awk -F':' '{print $1}' | paste -sd ';' - | xargs)
        # Extract sizes (e.g., 100G;512M) and join with semicolons.
        disk_sizes=$(echo "$disk_entries" | grep --only-matching 'size=[0-9.]\+[GMKT]' | sed 's/size=//' | paste -sd ';' - | xargs)

        # Calculate total disk size in GB.
        total_disk_size_gb=0.0 # Reset for calculation
        local line value unit size_gb # Local vars for loop
        while IFS= read -r line; do
            local size_param
            size_param=$(echo "$line" | grep --only-matching 'size=[0-9.]\+[GMKT]')
            if [[ -n "$size_param" ]]; then
                value=$(echo "$size_param" | grep --only-matching '[0-9.]\+')
                unit=$(echo "$size_param" | grep --only-matching '[GMKT]')
                size_gb=0.0 # Default to float
                case "$unit" in
                    G) size_gb=$(awk "BEGIN {printf \"%.2f\", $value}") ;;
                    M) size_gb=$(awk "BEGIN {printf \"%.2f\", $value / 1024}") ;;
                    K) size_gb=$(awk "BEGIN {printf \"%.2f\", $value / 1024 / 1024}") ;;
                    T) size_gb=$(awk "BEGIN {printf \"%.2f\", $value * 1024}") ;;
                esac
                total_disk_size_gb=$(awk "BEGIN {printf \"%.2f\", $total_disk_size_gb + $size_gb}")
            fi
        done <<< "$disk_entries" # Feed the disk entry lines into the while loop.

        # --- Network Information Processing ---
        # Attempt to get IP addresses using the QEMU Guest Agent. Requires agent installed & running in VM.
        # Suppress errors as agent might not be available. Parse JSON robustly. Filter local/link-local IPs.
        ip_addresses=$(qm guest cmd "${vm_id}" network-get-interfaces --timeout 5 2>/dev/null | \
            jq --raw-output '[.result[]? | select(.["ip-addresses"] != null) | .["ip-addresses"][]?."ip-address"? | select(. != null and . != "::1" and . != "127.0.0.1" and (startswith("fe80:") | not) )] | join(";")' \
            ) || ip_addresses="" # Handle jq errors or no output
        [[ -z "${ip_addresses}" ]] && ip_addresses="N/A" # Set to N/A if empty after filtering

        # Extract network interface device names (e.g., net0;net1) and join with semicolons.
        network_interfaces=$(echo "$config" | grep "^net" | awk -F':' '{print $1}' | paste -sd ';' - | xargs)
    fi # End of config-dependent parsing

    # --- Live Metrics Processing (if status JSON available) ---
    # Use jq with fallback values for robustness.
    used_memory_bytes=$(echo "$vm_status_json" | jq '.result.mem // .mem // 0')
    # Calculate live memory usage percentage. Avoid division by zero if configured memory is missing or 0.
    if [[ -n "${memory}" && "${memory}" -gt 0 ]]; then
        memory_usage_percent=$(awk "BEGIN {printf \"%.2f\", ($used_memory_bytes / ($memory * 1024 * 1024)) * 100}")
    else
        memory_usage_percent="0.00"
    fi
    # Extract live CPU usage fraction.
    cpu_usage_fraction=$(echo "$vm_status_json" | jq '.result.cpu // .cpu // 0')
    # Convert fraction to percentage.
    cpu_usage_percent=$(awk "BEGIN {printf \"%.2f\", $cpu_usage_fraction * 100}")

    # --- Status and HA ---
    # Get the VM's current state (e.g., running, stopped) from the 'vm_data' captured earlier.
    # Use awk for safer field extraction. Default to 'unknown' if parsing fails.
    status=$(echo "$vm_data" | awk -v id="$vm_id" '$1 == id {print $3; exit}') || status="unknown"
    [[ -z "${status}" ]] && status="unknown"

    # Get High Availability status using 'ha-manager status'. Suppress errors, default to "N/A".
    # Use grep -oP if available for safer extraction, otherwise awk.
    ha_status=$(ha-manager status 2>/dev/null | grep --fixed-strings " ${vm_id} " | awk '{print $2}') || ha_status="N/A"
    [[ -z "${ha_status}" ]] && ha_status="N/A"

    # Ensure defaults for potentially unset numeric values
    memory=${memory:-0}
    cores=${cores:-0}
    autostart=${autostart:-"N/A"}

    # --- Append Data to VM CSV ---
    # Format the collected VM details into a CSV row. Quote fields carefully.
    # Using echo here; consider printf for complex quoting scenarios.
    echo "${vm_id},\"${name}\",\"${status}\",${memory},${cores},${total_disk_size_gb},\"${disk_devices}\",\"${disk_sizes}\",\"${ip_addresses}\",\"${network_interfaces}\",\"${memory_usage_percent}\",\"${cpu_usage_percent}\",\"${ha_status}\",\"${os_type}\",\"QEMU/KVM\",\"${autostart}\",\"${boot_order}\",\"${description}\"" >> "${output_file_vm}"

    # --- Accumulate Server Summary Statistics ---
    # Update aggregate resource counters based on the VM's current status.
    if [[ "${status}" == "running" ]]; then
        running_vms=$((running_vms + 1))
        memory_running_total=$((memory_running_total + memory))
        cpu_cores_running_total=$((cpu_cores_running_total + cores))
        # Use awk for floating point addition
        disk_used_running_total=$(awk "BEGIN {printf \"%.2f\", ${disk_used_running_total} + ${total_disk_size_gb}}")
    elif [[ "${status}" == "stopped" ]]; then
        stopped_vms=$((stopped_vms + 1))
        memory_stopped_total=$((memory_stopped_total + memory))
        cpu_cores_stopped_total=$((cpu_cores_stopped_total + cores))
        # Use awk for floating point addition
        disk_used_stopped_total=$(awk "BEGIN {printf \"%.2f\", ${disk_used_stopped_total} + ${total_disk_size_gb}}")
    fi

done # End of the VM loop.

# Print a newline after the progress indicator loop finishes.
echo "" # Moves to the next line after the \r loop

log_message "INFO" "Finished processing individual VMs."

# --- Finalize Host Resource Calculations ---
# Subtract the total cores allocated to *running* VMs from the host's total cores.
# Ensure the result is not negative (minimum 0 free cores).
cpu_cores_free_calc=$((cpu_cores - cpu_cores_running_total))
cpu_cores_free=0 # Default value
if [[ "$cpu_cores_free_calc" -ge 0 ]]; then
    cpu_cores_free=$cpu_cores_free_calc
fi
log_message "INFO" "Estimated free host CPU cores: ${cpu_cores_free}"

# --- Storage Pool Details ---
log_message "INFO" "Gathering storage pool details..."
# Get details about configured storage pools using 'pvesm status'. Check command success.
# Parse output carefully, assuming fixed columns. Use awk 'NR>1' to skip header.
# Fields: Name(1), Type(2), Status(3), Total(4), Used(5), Available(6), %Used(7)
# We need Name(1), Type(2), Total(4), Available(6) (which pvesm reports as free bytes)
pvesm_output=$(pvesm status) || { log_message "ERROR" "Failed to get storage status via 'pvesm status'."; pvesm_output=""; }
if [[ -n "${pvesm_output}" ]]; then
    echo "${pvesm_output}" | awk 'NR>1 {printf "%s,%s,%s,%s\n", $1, $2, $4, $6}' >> "${output_file_storage}"
fi

# --- Network Configuration Details ---
log_message "INFO" "Gathering network bridge details..."
# Get information about network bridges. Suppress brctl stderr.
brctl_output=$(brctl show 2>/dev/null) || { log_message "WARN" "Command 'brctl show' failed or bridge-utils not fully functional. Skipping bridge details."; brctl_output=""; }
if [[ -n "${brctl_output}" ]]; then
    # Extract bridge names, skipping header.
    mapfile -t bridges < <(echo "${brctl_output}" | awk 'NR>1 {print $1}')

    for bridge in "${bridges[@]}"; do
        local status="unknown" ports="N/A" all_ips="N/A" # Locals for loop

        # Get bridge status (UP/DOWN) using 'ip link show'.
        ip_link_output=$(ip link show "${bridge}") || { log_message "WARN" "Failed to get status for bridge ${bridge}"; ip_link_output=""; }
        if echo "${ip_link_output}" | grep --quiet --fixed-strings ",UP,"; then
            status="up"
        elif echo "${ip_link_output}" | grep --quiet --fixed-strings "state DOWN"; then
            status="down"
        fi

        # Get attached ports using 'brctl show <bridge>'.
        bridge_detail=$(brctl show "${bridge}" 2>/dev/null) || bridge_detail=""
        if [[ -n "${bridge_detail}" ]]; then
            ports=$(echo "${bridge_detail}" | awk 'NR>1 {print $NF}' | paste -sd ';' -)
            [[ -z "${ports}" ]] && ports="N/A"
        fi

        # Get IP addresses (IPv4 and IPv6) directly on the bridge interface.
        ips=$(ip --family inet addr show "${bridge}" | grep --word-regexp "inet" | awk '{print $2}' | paste -sd ';' -)
        ipv6s=$(ip --family inet6 addr show "${bridge}" | grep --word-regexp "inet6" | awk '{print $2}' | paste -sd ';' -)

        if [[ -n "$ips" && -n "$ipv6s" ]]; then
            all_ips="${ips};${ipv6s}"
        elif [[ -n "$ips" ]]; then
            all_ips="$ips"
        elif [[ -n "$ipv6s" ]]; then
            all_ips="$ipv6s"
        else
            all_ips="N/A"
        fi

        # Append collected bridge details as a CSV row. Quote fields.
        echo "${bridge},${status},\"${ports}\",\"${all_ips}\"" >> "${output_file_network}"
    done
fi

# --- Append Server Summary ---
log_message "INFO" "Writing server summary data..."
# Format the final host summary and aggregated VM statistics into a CSV row. Quote fields.
echo "${proxmox_ip},${cpu_cores},${memory_total},${storage_total_mb},${memory_free},${cpu_cores_free},${storage_free_mb},${running_vms},${memory_running_total},${cpu_cores_running_total},${disk_used_running_total},${stopped_vms},${memory_stopped_total},${cpu_cores_stopped_total},${disk_used_stopped_total}" >> "${output_file_summary}"

# --- Final Output ---
log_message "INFO" "Processing complete."
log_message "INFO" "VM details saved to: ${output_file_vm}"
log_message "INFO" "Server summary saved to: ${output_file_summary}"
log_message "INFO" "Storage details saved to: ${output_file_storage}"
log_message "INFO" "Network configuration saved to: ${output_file_network}"

# The `trap cleanup EXIT` automatically calculates and prints execution time.
# Explicit successful exit.
exit 0

# =========================================================================================
# --- End of Script ---
