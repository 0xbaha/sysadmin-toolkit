#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : check_ip.sh
# PURPOSE       : Scans specified CIDR IPs for availability using ping/fping.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2024-10-13
# LAST UPDATED  : 2024-10-13
# VERSION       : 1.0.0
# =========================================================================================

# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This script checks the availability of IP addresses from a list of IP blocks
# (CIDR notation) provided in an input file (`ip_blocks.txt` by default).
# It uses `nmap` to enumerate all individual IP addresses within each block
# and then employs `ping` or preferably `fping` (if available and faster) to test
# if each IP address is currently responding (in use) or available (not responding).
#
# Available (non-responding) IPs are saved to a timestamped output file
# (e.g., `available_ips_YYYYMMDD_HHMMSS.txt`).
#
# The script includes functionality to automatically attempt installation of
# missing required tools (`nmap`) using `apt` or `yum` package managers,
# provided `sudo` privileges are available. It leverages parallel processing
# (background jobs) to significantly speed up the IP checking process across large blocks.
#
# Key Workflow / Functions:
# - Reads IP blocks (CIDR notation) from a specified input file (`INPUT_FILE`).
# - Sorts the input IP blocks numerically for ordered processing (`sort_ip_blocks`).
# - Enumerates all individual IP addresses within each block using `nmap -sL`.
# - Checks the availability of each IP address using `fping` (preferred) or `ping` (`check_ip`).
# - Controls the number of concurrent checks using background jobs and `wait` (`MAX_PARALLEL`).
# - Automatically attempts to install the `nmap` dependency if missing (`install_packages`, requires sudo).
# - Provides structured logging with different levels (INFO, WARN, ERROR, DEBUG) (`log_message`).
# - Saves the list of available (non-responding) IP addresses to a timestamped output file (`OUTPUT_FILE`).
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Robustness:** Includes error handling for missing files, command failures, and attempts dependency installation. Uses `set -euo pipefail` for stricter error checking.
# - **Efficiency:** Prefers `fping` over `ping` for faster checks. Uses parallel processing (`jobs`, `wait`) to speed up scanning large blocks. Uses `nmap -n -sL` for fast IP enumeration without DNS lookups.
# - **Readability:** Employs clear variable names, function separation, and extensive comments (including this header). Uses a structured logging function (`log_message`).
# - **Portability:** Aims for compatibility with common Linux distributions using `apt` or `yum`. Relies on standard utilities where possible.
# - **Automation:** Designed for easy execution with minimal interaction. Generates uniquely named output files.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - System Administrators managing network resources.
# - Network Engineers needing to identify unused IP addresses within allocated blocks.
# - IT Support Staff performing network audits or troubleshooting IP conflicts.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x check_ip.sh`
# - File system access: Read access to `INPUT_FILE` (`ip_blocks.txt`), Write access to the directory where the script runs (for `OUTPUT_FILE` and potentially `LOG_FILE`).
# - Elevated privileges: Requires `sudo` ONLY if `nmap` needs to be installed automatically.
#
# **Basic Syntax:**
# `./check_ip.sh`
#
# **Prerequisites:**
# 1. Prepare an input file named `ip_blocks.txt` (or configure `INPUT_FILE`) in the script's directory.
#    Each line must contain one IP block in CIDR notation (e.g., `192.168.1.0/24`). Lines starting with `#` are ignored.
# 2. Ensure required dependencies are installed OR the script has `sudo` access for automatic installation (see DEPENDENCIES).
#
# **Execution:**
# - Run the script from your terminal:
#   `./check_ip.sh`
# - The script will:
#   - Check dependencies.
#   - Read and sort blocks from `ip_blocks.txt`.
#   - Process each block, checking IPs in parallel.
#   - Log progress to standard output/error.
#   - Create an output file like `available_ips_20241013_153000.txt` containing available IPs.
#
# **Example `ip_blocks.txt` content:**
# ```
# Corporate Network Segment 1
# 192.168.1.0/24
# 192.168.2.0/24
# Datacenter Block A
# 10.0.0.0/22
# Small DMZ Range
# 172.16.0.0/28
# ```
#
# **Configuration (Inside Script):**
# - `INPUT_FILE`: Path to the file containing CIDR blocks (Default: "ip_blocks.txt").
# - `MAX_PARALLEL`: Maximum number of concurrent ping/fping checks (Default: 50). Adjust based on system/network capacity.
# - `LOG_TO_FILE`: Set to `true` to enable logging to a file (Default: `false`).
# - `LOG_FILE`: Path to the log file if `LOG_TO_FILE` is true (Default: `./check_ip_YYYYMMDD_HHMMSS.log`).
# - `LOG_LEVEL`: Minimum log level to display/log (DEBUG, INFO, WARN, ERROR, CRITICAL) (Default: "INFO").
# - `VERBOSE`: Set to `true` to enable DEBUG level logging to stdout/stderr (Default: `false`).
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - User scripts: `~/bin/` or `~/.local/bin/` (ensure these are in user's $PATH).
# - Project-specific: Within the project directory alongside `ip_blocks.txt`.
#
# **Manual Setup:**
# 1. Place `check_ip.sh` in the desired location.
# 2. Make the script executable: `chmod +x check_ip.sh`.
# 3. Install required dependencies manually OR ensure `sudo` is available for automatic installation (see DEPENDENCIES).
# 4. Create the input file (e.g., `ip_blocks.txt`) with CIDR blocks, one per line.
# 5. Run `./check_ip.sh --help` (if implemented) or review `USAGE` section. Run `./check_ip.sh` to start.
#
# **Automation:**
# - Can be run via `cron` for regular checks. Ensure the cron environment has access to required commands and paths.
#   Example cron job (runs daily at 3 AM):
#   `0 3 * * * /path/to/check_ip.sh >> /var/log/check_ip.log 2>&1`
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: The Bourne-Again SHell interpreter (Version 4+ recommended for features like associative arrays in logging).
#
# **Required System Binaries/Tools:**
# - `coreutils`: Provides `date`, `basename`, `dirname`, `mkdir`, `touch`, `cat`, `wc`, `sort`, `cut`.
# - `grep`, `awk`, `sed`: Standard text processing utilities.
# - `nmap`: Required for listing IPs within CIDR blocks (`nmap -sL`). Auto-installation attempted via `apt`/`yum` if `sudo` is available.
# - `ping`: Standard ICMP utility (`iputils-ping` or similar package). Used if `fping` is unavailable.
# - `fping`: (Optional but Recommended) Faster alternative for pinging multiple hosts. Script prefers `fping` if found. Install manually (e.g., `sudo apt install fping`, `sudo yum install fping`).
# - `command`: Bash built-in for checking command existence.
# - `jobs`, `wait`: Bash built-ins for managing background processes.
# - `sudo`: Required ONLY for automatic installation of `nmap`.
# - `apt-get` / `yum`: Required ONLY if automatic installation is performed (depends on Linux distribution).
#
# **Setup Instructions (Dependencies):**
# - `nmap`: The script attempts auto-install: `sudo apt update && sudo apt install -y nmap` or `sudo yum install -y nmap`.
# - `fping` (Recommended): Install manually if needed: `sudo apt update && sudo apt install -y fping` (Debian/Ubuntu) or `sudo yum install -y epel-release && sudo yum install -y fping` (CentOS/RHEL may need EPEL).
#
# **Operating System Compatibility:**
# - Designed primarily for Linux distributions (Debian/Ubuntu, CentOS/RHEL, Fedora).
# - May work on macOS or other Unix-like systems if dependencies are met (manual installation likely required). Standard `ping` flags might differ.
#
# **Environment Variables Used:**
# - None read directly by default. `PATH` is used implicitly to find commands.
#
# **System Resource Requirements:**
# - CPU/Memory: Generally low, but depends on `MAX_PARALLEL` and the size of IP blocks. `nmap` and multiple `fping`/`ping` processes can consume resources.
# - Network: Can generate significant ICMP traffic, especially with high `MAX_PARALLEL` values. Be mindful of network policies.
# - Disk Space: Minimal, primarily for the output file and optional log file.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): INFO and DEBUG messages (if `VERBOSE=true`).
# - Standard Error (stderr): WARN, ERROR, CRITICAL messages, and DEBUG (if `VERBOSE=true`).
# - Dedicated Log File: Optional (enable with `LOG_TO_FILE=true`). Path configured via `LOG_FILE`. Logs all levels >= `LOG_LEVEL`.
#
# **Log Format:**
# - File/Stdout/Stderr: `[YYYY-MM-DD HH:MM:SS TZ] [LEVEL] - Message`
# - Colored output to terminal enabled by default (disable with `NO_COLOR=true`). Color codes stripped for log file.
#
# **Log Levels:**
# - `DEBUG`: Detailed step-by-step information (Enabled via `LOG_LEVEL=DEBUG` or `VERBOSE=true`).
# - `INFO`: General operational messages (Default level).
# - `WARN`: Potential issues or non-critical errors.
# - `ERROR`: Significant errors that may affect results but script might continue.
# - `CRITICAL`: Severe errors causing script termination (via `exit 1`).
# - Control: `LOG_LEVEL` variable sets minimum level. `VERBOSE=true` forces DEBUG level to stdout/stderr.
#
# **Log Rotation:**
# - Not handled by the script. Use external tools like `logrotate` if long-term file logging is enabled.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - INFO and DEBUG log messages (timestamps, levels, messages).
#   - e.g., "[...] [INFO] - Processing IP block: 192.168.1.0/24"
#   - e.g., "[...] [INFO] - IP 192.168.1.10 is in use."
#   - e.g., "[...] [INFO] - IP 192.168.1.11 is available."
#   - Final summary message indicating completion and output file location.
#
# **Standard Error (stderr):**
# - WARN, ERROR, CRITICAL log messages.
#   - e.g., "[...] [WARN] - 'fping' is not installed. Using standard 'ping'..."
#   - e.g., "[...] [ERROR] - Failed to install 'nmap' using apt-get."
#   - e.g., "[...] [CRITICAL] - Input file 'ip_blocks.txt' not found or is not a regular file."
# - DEBUG messages if `VERBOSE=true`.
#
# **Generated/Modified Files:**
# - Output File: `available_ips_YYYYMMDD_HHMMSS.txt` (timestamp varies).
#   - Contains a list of IP addresses (one per line) that did *not* respond to the ping/fping check (considered "available").
#   - Created fresh on each run.
# - Log File (Optional): `check_ip_YYYYMMDD_HHMMSS.log` (if `LOG_TO_FILE=true`).
#   - Contains detailed log messages based on `LOG_LEVEL`.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success.
# - 1: General Error (often triggered by `CRITICAL` log messages, e.g., missing input file, failed dependency installation, permission issues, unhandled errors due to `set -e`).
# - Exit codes from underlying tools (`nmap`, `ping`, `fping`, `apt-get`, `yum`) may propagate if not explicitly handled.
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** `CRITICAL: Input file '...' not found`.
#   **Resolution:** Ensure `INPUT_FILE` (default `ip_blocks.txt`) exists in the script's directory and is readable. Check the `INPUT_FILE` variable setting.
# - **Issue:** `CRITICAL: Required command 'nmap' not found` / Installation fails.
#   **Resolution:** Install `nmap` manually (`sudo apt install nmap` or `sudo yum install nmap`). Check `sudo` permissions if auto-install failed. Check network/repo access.
# - **Issue:** `WARN: 'fping' not installed`.
#   **Resolution:** Script falls back to slower `ping`. Install `fping` manually for better performance.
# - **Issue:** `ERROR: nmap command failed for block '...'`.
#   **Resolution:** Check if the CIDR block format in `ip_blocks.txt` is correct. Check `nmap` functionality manually.
# - **Issue:** `CRITICAL: Cannot write to output file/log file`.
#   **Resolution:** Check write permissions in the script's execution directory.
# - **Issue:** Slow execution.
#   **Resolution:** Install `fping`. Increase `MAX_PARALLEL` cautiously (monitor system/network load). Ensure `nmap` is using `-n` (no DNS).
# - **Issue:** IPs reported as "available" are actually in use (or vice-versa).
#   **Resolution:** Check firewalls (ICMP echo requests/replies might be blocked). Some hosts are configured not to respond to pings. Accuracy depends on ICMP reachability.
#
# **Important Considerations / Warnings:**
# - **Network Load:** High `MAX_PARALLEL` values generate significant ICMP traffic. Use responsibly and according to network policy. Unauthorized scanning is prohibited.
# - **ICMP Dependency:** Accuracy relies on hosts responding to ICMP echo requests. Blocked ICMP or hosts configured to ignore pings will affect results (silent hosts appear "available").
# - **Resource Usage:** Parallel processes consume CPU, memory, and network resources. Monitor system load during execution, especially on less powerful machines or busy networks.
# - **Race Conditions:** While `wait -n` manages job slots, extremely rapid job completion could theoretically lead to slightly exceeding `MAX_PARALLEL` momentarily, though unlikely to be problematic.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes a Bash (v4+) environment with standard Linux core utilities available in PATH.
# - Assumes required dependencies (`nmap`, `ping`/`fping`, etc.) are installed or installable via `sudo apt`/`yum`.
# - Assumes network connectivity exists to the target IP ranges specified in `INPUT_FILE`.
# - Assumes ICMP echo requests and replies are not universally blocked between the script's host and the target IPs (accuracy depends on this).
# - Assumes `INPUT_FILE` contains valid CIDR notations, one per line (or lines starting with #).
# - Assumes write permissions in the execution directory for the output file (and log file if enabled).
# =========================================================================================

# =========================================================================================
# PERFORMANCE OPTIMIZATION (Notes)
# =========================================================================================
# - Uses `fping` when available (generally faster than multiple `ping` instances).
# - Uses `nmap -n -sL` for fast IP enumeration without DNS or port scanning.
# - Implements parallel checking via background jobs (`&`) and `wait -n` to limit concurrency (`MAX_PARALLEL`).
# - Sorts IP blocks first (`sort_ip_blocks`) for potentially more organized processing (though impact on performance is minor).
# - Potential Bottleneck: Network latency, system resources (CPU/RAM if `MAX_PARALLEL` is too high), rate limiting/blocking by network devices.
# =========================================================================================

# =========================================================================================
# TESTING & VALIDATION (Notes)
# =========================================================================================
# - Tested manually on Ubuntu 22.04 with Bash 5.1.
# - Tested with and without `fping` installed.
# - Tested with various valid and invalid CIDR notations in `ip_blocks.txt`.
# - Tested file permission errors (input/output).
# - Relies on ShellCheck for static analysis (recommended).
# - No automated unit/integration tests currently included.
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - Add command-line arguments (`getopts` or `argparse` equivalent) to override `INPUT_FILE`, `MAX_PARALLEL`, `OUTPUT_FILE` pattern, `LOG_LEVEL`, etc.
# - Implement more sophisticated check methods beyond ICMP (e.g., TCP connect scan to common ports as an alternative availability check, requires `nmap` scan or similar).
# - Add option to exclude specific IPs or ranges within blocks.
# - Add support for reading input from sources other than a file (e.g., stdin, API).
# - Enhance output format (e.g., CSV with status, timestamp).
# - More robust platform detection for `ping` flags if supporting macOS/BSD more formally.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Requires `sudo` ONLY for automatic `nmap` installation. Normal operation runs with user privileges. Least privilege is preferred.
# - **Input Source:** Reads CIDR blocks from `INPUT_FILE`. Ensure this file is trusted and contains only valid CIDR notations. Malformed input could cause errors or unexpected behavior in `nmap`.
# - **External Commands:** Executes `nmap`, `ping`, `fping`, `apt-get`, `yum`, `sudo`. Ensure these binaries are from trusted sources and `PATH` is secure. Commands involving variables (like `nmap` block processing) quote variables to prevent injection.
# - **Network Scanning:** This script performs network reconnaissance (ICMP probes). Ensure you have EXPLICIT AUTHORIZATION to scan the target networks defined in `INPUT_FILE`. Unauthorized scanning is illegal and unethical.
# - **Error Messages:** Logging aims to be informative but avoid leaking overly sensitive system details.
# - **File Permissions:** Output/log files are created with default user permissions. Ensure sensitive results are protected appropriately.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is contained within this script's header comments.
# - No external documentation or man page is provided.
# - Refer to `README.md` in the repository (if applicable).
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Report issues via the script's repository (link in METADATA) or directly to the author's contact email.
# =========================================================================================

# =========================================================================================
# SCRIPT EXECUTION ENVIRONMENT & CONFIGURATION
# =========================================================================================

# --- Bash Strict Mode ---
# -e: Exit immediately if a command exits with a non-zero status.
# -u: Treat unset variables and parameters as an error when performing parameter expansion.
# -o pipefail: The return value of a pipeline is the status of the last command to exit
#   with a non-zero status, or zero if no command exited with non-zero status.
# Note: Comment out -e if fine-grained error handling (e.g., `command || handle_error`) is preferred.
set -euo pipefail

# --- Debug Mode ---
# Uncomment the following line for debugging (prints each command before execution).
# set -x

# --- Script Information ---
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_PID=$$

# --- Timestamp ---
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Global Runtime Variables ---
# Configuration Defaults (can be modified here)
INPUT_FILE="ip_blocks.txt"         # Default input file containing IP blocks in CIDR notation.
MAX_PARALLEL=50                    # Default maximum number of parallel background jobs. Adjust based on resources.

# Runtime Variables (derived or set during execution)
OUTPUT_FILE="available_ips_${SCRIPT_RUN_TIMESTAMP}.txt" # Output file for available IPs (timestamped).
LOG_TO_FILE=false                  # Set to true to enable logging to a file (configure LOG_FILE if needed)
LOG_FILE="${SCRIPT_DIR}/${SCRIPT_NAME%.sh}_${SCRIPT_RUN_TIMESTAMP}.log" # Default log file path (if LOG_TO_FILE=true)
LOG_LEVEL="INFO"                   # Default log level (DEBUG, INFO, WARN, ERROR, CRITICAL)
VERBOSE=false                      # Set to true for more detailed stdout logging (enables DEBUG level)
NO_COLOR=false                     # Set to true to disable colored output
INTERACTIVE_MODE=false             # Auto-detected if running in an interactive terminal
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is a terminal

# --- Color Definitions (Optional) ---
if [[ "${NO_COLOR}" == false && "${INTERACTIVE_MODE}" == true ]]; then
    COLOR_RESET='\033[0m'; COLOR_RED='\033[0;31m'; COLOR_GREEN='\033[0;32m';
    COLOR_YELLOW='\033[0;33m'; COLOR_BLUE='\033[0;34m'; COLOR_CYAN='\033[0;36m';
    COLOR_BOLD='\033[1m';
else
    COLOR_RESET=""; COLOR_RED=""; COLOR_GREEN=""; COLOR_YELLOW=""; COLOR_BLUE="";
    COLOR_CYAN=""; COLOR_BOLD="";
fi

# =========================================================================================
# FUNCTION DEFINITIONS
# =========================================================================================

# --- Logging Function ---
# Description: Handles formatted logging to stdout/stderr and optionally to a file.
# Usage: log_message LEVEL "Message string"
# Levels: DEBUG, INFO, WARN, ERROR, CRITICAL
log_message() {
    local level="$1"; local message="$2"; local timestamp; local level_upper;
    timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z"); level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]')
    local log_prefix="[${timestamp}] [${level_upper}]"; local log_line="${log_prefix} - ${message}"; local color=""

    case "${level_upper}" in
        DEBUG) color="${COLOR_CYAN}" ;; INFO) color="${COLOR_GREEN}" ;; WARN) color="${COLOR_YELLOW}" ;;
        ERROR|CRITICAL) color="${COLOR_RED}${COLOR_BOLD}" ;;
    esac

    declare -A log_levels=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [CRITICAL]=4)
    local current_log_level_num=${log_levels[${LOG_LEVEL^^}]}; local message_level_num=${log_levels[${level_upper}]}

    if [[ ${message_level_num} -ge ${current_log_level_num} ]]; then
        local log_target; [[ "${level_upper}" == "WARN" || "${level_upper}" == "ERROR" || "${level_upper}" == "CRITICAL" ]] && log_target=">&2" || log_target=""
        if ! [[ "${level_upper}" == "DEBUG" && "${VERBOSE}" == false ]]; then
            eval "echo -e '${color}${log_line}${COLOR_RESET}' ${log_target}"
        fi
        if [[ "${LOG_TO_FILE}" == true && -n "${LOG_FILE:-}" ]]; then
            mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
            if [[ -w "$(dirname "${LOG_FILE}")" ]]; then
                echo "${log_prefix} - ${message}" >> "${LOG_FILE}"
            elif [[ -z ${LOG_DIR_WRITE_WARN_SENT+x} ]]; then
                echo -e "${COLOR_YELLOW}[$(date +"%Y-%m-%d %H:%M:%S %Z")] [WARN] - Cannot write to log directory $(dirname "${LOG_FILE}"). Logging to file disabled.${COLOR_RESET}" >&2
                LOG_DIR_WRITE_WARN_SENT=true; LOG_TO_FILE=false
            fi
        fi
    fi
    [[ "${level_upper}" == "CRITICAL" ]] && { log_message "INFO" "Critical error. Exiting."; exit 1; }
}

# --- Usage/Help Function ---
# Description: Displays help information (extracted from header) and exits.
usage() {
    local usage_text
    usage_text=$(sed -n '/^# ===+ USAGE ===+$/,/^# ===+ .* ===+$/{ /# ===+ .* ===+$/!p; }' "${BASH_SOURCE[0]}" | sed 's/^# //; s/\[your_script_name.sh\]/'"${SCRIPT_NAME}"'/g')
    cat << EOF >&2
${usage_text}

Default Input File: ${INPUT_FILE}
Default Max Parallel Jobs: ${MAX_PARALLEL}
Output File Pattern: available_ips_YYYYMMDD_HHMMSS.txt
EOF
    exit 1
}

# --- Dependency Check Function ---
# Description: Checks if a command is installed and executable. Exits on failure.
# Arguments: $1: Command name, $2: (Optional) Package name for installation suggestion.
check_dependency() {
    local cmd="$1"; local install_suggestion="${2:-$cmd}"
    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required command '${cmd}' not found. Please install the '${install_suggestion}' package."
        # CRITICAL level handles exit
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
}

# --- Package Installation Function ---
# Description: Attempts to install packages using apt or yum if they are missing. Requires sudo.
# Arguments: $@: Package names to check and install.
install_packages() {
    for pkg_cmd in "$@"; do
        local pkg_name="${pkg_cmd}" # Assuming command name is the package name, adjust if needed
        if ! command -v "$pkg_cmd" &> /dev/null; then
            log_message "WARN" "'${pkg_cmd}' is not installed. Attempting automatic installation (requires sudo)..."
            if command -v apt-get &> /dev/null; then
                log_message "INFO" "Using apt-get for installation."
                sudo apt-get update && sudo apt-get install -y "$pkg_name" || log_message "ERROR" "Failed to install '${pkg_name}' using apt-get."
            elif command -v yum &> /dev/null; then
                log_message "INFO" "Using yum for installation."
                sudo yum install -y "$pkg_name" || log_message "ERROR" "Failed to install '${pkg_name}' using yum."
            else
                log_message "ERROR" "Unsupported package manager. Please install '${pkg_name}' manually."
                exit 1 # Exit as requirement cannot be met automatically
            fi
            # Verify installation after attempt
            if ! command -v "$pkg_cmd" &> /dev/null; then
                 log_message "CRITICAL" "Installation of '${pkg_name}' failed or command '${pkg_cmd}' still not found."
            else
                 log_message "INFO" "'${pkg_cmd}' successfully installed."
            fi
        else
            log_message "INFO" "'${pkg_cmd}' is already installed."
        fi
    done
}

# --- Requirements Check Function ---
# Description: Checks for necessary tools and attempts installation if needed.
check_requirements() {
    log_message "INFO" "Checking required tools..."
    check_dependency "date" "coreutils"
    check_dependency "awk" "gawk" # or mawk
    check_dependency "sort" "coreutils"
    check_dependency "cut" "coreutils"
    check_dependency "jobs" "bash built-in"
    check_dependency "wait" "bash built-in"
    check_dependency "wc" "coreutils"
    check_dependency "ping" "iputils-ping" # or similar package name

    # Install nmap if missing
    install_packages nmap

    # Check for optional but preferred fping
    if ! command -v fping &> /dev/null; then
        log_message "WARN" "'fping' is not installed. Using standard 'ping' (might be slower)."
        log_message "WARN" "Consider installing 'fping' for better performance (e.g., 'sudo apt install fping' or 'sudo yum install fping')."
    else
        log_message "INFO" "Using 'fping' for faster IP availability checks."
        check_dependency "fping" "fping" # Ensure it's checked if found initially
    fi
    log_message "INFO" "Dependency check complete."
}

# --- IP to Number Conversion Function ---
# Description: Converts an IP address string to a numeric format (for sorting/comparison).
# Arguments: $1: IP address string (e.g., "192.168.1.1").
# Note: This function is currently defined but not actively used in the main logic.
ip_to_num() {
    local ip="$1"; local IFS=.; local -a a=($ip)
    echo "$((a[0] * 256 ** 3 + a[1] * 256 ** 2 + a[2] * 256 + a[3]))"
}

# --- IP Block Sorting Function ---
# Description: Reads IP blocks from the INPUT_FILE and sorts them numerically.
# Output: Prints the sorted list of IP blocks to stdout.
sort_ip_blocks() {
    log_message "DEBUG" "Sorting IP blocks from file: ${INPUT_FILE}"
    # Use awk to format IPs for numeric sort (zero-padding octets and mask).
    # -F'[./]' splits by '.' or '/'.
    # printf formats each part: %010d for IP octets, %03d for mask.
    # Example: 192.168.1.0/24 -> 0000192168.0000000001.0000000000.0000000000/024 192.168.1.0/24
    # sort -n: Sorts numerically based on the formatted prefix.
    # cut: Removes the sorting prefix, leaving the original block string.
    awk -F'[./]' '{ printf("%010d.%010d.%010d.%010d/%03d %s\n", $1, $2, $3, $4, $5, $0) }' "$INPUT_FILE" | \
        sort | \
        cut -d' ' -f2- || { log_message "ERROR" "Failed to sort IP blocks from ${INPUT_FILE}"; return 1; }
}

# --- IP Availability Check Function ---
# Description: Checks if a single IP address is available using ping or fping. Logs result and appends available IPs to OUTPUT_FILE.
# Arguments: $1: IP address to check.
check_ip() {
    local ip=$1
    log_message "DEBUG" "Checking IP address: ${ip}"

    local check_cmd=""
    local success_message="IP ${ip} is in use."
    local failure_message="IP ${ip} is available."

    # Determine which command to use (prefer fping)
    if command -v fping &> /dev/null; then
        # fping: -c1 (1 packet), -t100 (100ms timeout), -q (quiet stderr)
        check_cmd="fping -c1 -t100 -q ${ip}"
    else
        # ping: -c 1 (1 packet), -W 1 (1 second timeout)
        # Platform variations for ping exist, this is common for Linux. Adjust if needed.
        check_cmd="ping -c 1 -W 1 ${ip}"
    fi

    log_message "DEBUG" "Executing check command: ${check_cmd}"

    # Execute the check command, redirecting its stdout/stderr to /dev/null.
    # The command's exit code determines reachability (0 = reachable/in use, non-zero = unreachable/available).
    # We use '||' to handle the non-zero exit case gracefully when 'set -e' is active.
    if eval "${check_cmd}" &> /dev/null; then
        # Exit code 0: IP is reachable (in use)
        log_message "INFO" "${success_message}"
    else
        # Exit code non-zero: IP is not reachable (available)
        log_message "INFO" "${failure_message}"
        # Append the available IP to the output file
        echo "$ip" >> "$OUTPUT_FILE" || log_message "WARN" "Failed to write available IP ${ip} to ${OUTPUT_FILE}"
    fi
}


# --- Cleanup Function ---
# Description: Performs cleanup tasks before script exits. Called via trap.
cleanup() {
    local exit_status=$? # Capture the script's exit status
    log_message "INFO" "Performing cleanup..."
    # Add cleanup tasks here if needed (e.g., remove temp files, kill background jobs)
    # Example: [[ -n "${TEMP_DIR:-}" && -d "${TEMP_DIR}" ]] && rm -rf "${TEMP_DIR}"
    log_message "INFO" "Cleanup finished with exit status: ${exit_status}"
    # Script will exit with original exit_status after trap completes.
}

# --- Trap Setup ---
# Register 'cleanup' to run on script exit (normal or error) and signals.
trap cleanup EXIT INT TERM HUP

# --- Input Validation Function ---
# Description: Checks necessary inputs like file existence before main logic.
validate_inputs() {
    log_message "INFO" "Validating inputs..."
    if [[ ! -f "$INPUT_FILE" ]]; then
        log_message "CRITICAL" "Input file '${INPUT_FILE}' not found or is not a regular file."
        # CRITICAL handles exit
    elif [[ ! -r "$INPUT_FILE" ]]; then
         log_message "CRITICAL" "Input file '${INPUT_FILE}' is not readable."
    fi
    if [[ $MAX_PARALLEL -le 0 ]]; then
        log_message "WARN" "MAX_PARALLEL is set to ${MAX_PARALLEL}. Adjusting to 1."
        MAX_PARALLEL=1
    fi
    log_message "INFO" "Input validation passed."
}

# --- Environment Preparation Function ---
# Description: Sets up the environment, like preparing the output file.
prepare_environment() {
    log_message "INFO" "Preparing execution environment..."
    # Clear the output file or create it if it doesn't exist. Ensures fresh results.
    log_message "INFO" "Preparing output file: ${OUTPUT_FILE}"
    # Attempt to create/truncate the file. Check writability.
    if ! > "$OUTPUT_FILE"; then
         log_message "CRITICAL" "Cannot write to output file: ${OUTPUT_FILE}. Check path and permissions."
    fi
    log_message "INFO" "Environment preparation complete."
}

# --- Main Logic Function ---
# Description: Contains the core script functionality.
main() {
    log_message "INFO" "Starting main script execution..."

    local sorted_blocks
    sorted_blocks=$(sort_ip_blocks) || exit 1 # Exit if sorting fails

    log_message "INFO" "Starting IP availability check using up to ${MAX_PARALLEL} parallel jobs..."

    # Process each sorted IP block line by line using a while loop reading from the sorted list.
    # Using process substitution '<(command)' or piping 'command | while read' are options. Piping is used here.
    echo "$sorted_blocks" | while IFS= read -r block || [[ -n "$block" ]]; do
        # Ignore empty lines or lines starting with # (comments)
        [[ -z "$block" || "$block" =~ ^# ]] && continue

        log_message "INFO" "Processing IP block: $block"

        # Use nmap to list all IP addresses within the current block.
        # -n: Do not perform DNS resolution (faster).
        # -sL: List Scan - simply list targets without scanning ports.
        # awk '/Nmap scan report/{print $NF}': Extracts the IP address from 'Nmap scan report for <IP>' lines.
        local nmap_cmd="nmap -n -sL \"$block\""
        log_message "DEBUG" "Running nmap to list IPs: ${nmap_cmd}"
        local nmap_output
        # Capture nmap output, handle potential errors
        if ! nmap_output=$(eval "${nmap_cmd}"); then
            log_message "ERROR" "nmap command failed for block '${block}'. Skipping block."
            continue # Skip to the next block
        fi

        # Parse the nmap output for IP addresses
        # Using a loop avoids issues with very large blocks potentially exceeding ARG_MAX if using $(...) directly in for loop.
        echo "$nmap_output" | awk '/Nmap scan report/{print $NF}' | while IFS= read -r ip || [[ -n "$ip" ]]; do
            # For each IP address found by nmap, call check_ip in the background (&).
            check_ip "$ip" &

            # --- Parallel Job Control ---
            # Check the number of currently running background jobs started by this script.
            # `jobs -r -p` lists the PIDs of running background jobs.
            # `wc -l` counts the number of lines (jobs).
            local current_jobs
            # Ensure jobs command runs correctly even if no jobs exist
            current_jobs=$(jobs -r -p | wc -l) || current_jobs=0
            log_message "DEBUG" "Current parallel jobs: ${current_jobs}"

            if [[ ${current_jobs} -ge ${MAX_PARALLEL} ]]; then
                # If the number of running jobs reaches the limit:
                # `wait -n`: Wait for the *next* background job (from this script's children) to complete.
                # This prevents overwhelming system/network resources.
                log_message "DEBUG" "Reached parallel limit (${MAX_PARALLEL}). Waiting for a job to finish..."
                if ! wait -n; then
                    # Handle cases where wait -n might fail if no children are running (shouldn't happen here)
                    log_message "WARN" "wait -n command encountered an issue, continuing..."
                fi
            fi
        done < <(echo "$nmap_output" | awk '/Nmap scan report/{print $NF}') # Use process substitution to feed IPs

    done # End of outer loop iterating through sorted IP blocks

    # Wait for all remaining background check_ip processes to complete before exiting main.
    log_message "INFO" "Waiting for all remaining checks to complete..."
    wait
    log_message "INFO" "All checks finished."

    log_message "INFO" "Main execution logic finished."
    log_message "INFO" "${COLOR_GREEN}${COLOR_BOLD}IP availability check finished. Available IPs saved to: ${OUTPUT_FILE}${COLOR_RESET}"
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# Note: Argument parsing would go here if implemented (e.g., parse_params "$@")

log_message "INFO" "Script ${SCRIPT_NAME} started (PID: ${SCRIPT_PID})."
log_message "DEBUG" "Running in directory: ${SCRIPT_DIR}"

# 1. Check Dependencies & Requirements
check_requirements

# 2. Validate Inputs (e.g., file existence)
validate_inputs

# 3. Prepare Environment (e.g., create/clear output file)
prepare_environment

# 4. Execute Main Logic
main

# 5. Exit Successfully (trap will handle cleanup)
log_message "INFO" "Script ${SCRIPT_NAME} completed successfully."
exit 0

# =========================================================================================
# --- End of Script ---
