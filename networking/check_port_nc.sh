#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : check_port_nc.sh
# PURPOSE       : Checks server IPs for open ports using netcat; generates reports.
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
# This script checks a list of server IP addresses provided in an input file
# (default: 'list_server_ip.txt' in script dir) for the status (open or closed) of a specified
# set of common TCP ports (default: 22, 80, 443, 8080, 3306, 3389). It uses the 'netcat'
# (nc) utility for port scanning with a configurable timeout (default: 1s).
#
# If 'nc' is not found, the script attempts to install it using common Linux package
# managers (apt, yum, dnf, pacman, zypper), requiring sudo privileges.
#
# Key Workflow / Functions:
# - Parses command-line arguments for input file, output directory, ports, timeout, verbosity.
# - Sets Bash strict mode (`set -euo pipefail`) for robustness.
# - Implements detailed logging (DEBUG, INFO, WARN, ERROR, CRITICAL) to console and a timestamped log file.
# - Validates input file existence/readability and output directory writability.
# - Checks for dependencies (`nc`, `date`, `sort`, package managers if needed) and attempts auto-install for `nc`.
# - Reads IP addresses line-by-line from the input file.
# - Sorts and removes duplicate IP addresses from the input file *in place using a temporary file*.
# - Skips empty lines, comments, and basic invalid IPv4 formats in the input file.
# - Iterates through each valid IP and specified port.
# - Uses `nc -z -w<timeout>` to perform the connection check.
# - Records results (Timestamp, IP, Port, Status) to a detailed timestamped CSV file.
# - Records summary results (IP, Status - Active/Inactive) to a summary timestamped CSV file.
# - Includes trap mechanism for cleanup (e.g., removing temporary files).
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Robustness:** Uses strict mode (`set -euo pipefail`), performs dependency checks, handles errors via logging and exit codes, includes cleanup trap.
# - **Modularity:** Uses functions for distinct tasks (logging, dependency checks, argument parsing, validation, environment setup, port check, main logic).
# - **Configurability:** Allows overriding defaults (input file, output dir, ports, timeout) via command-line arguments.
# - **Readability:** Employs clear variable names, comments, consistent formatting, and descriptive log messages.
# - **Automation:** Reads input from file, attempts dependency installation, generates timestamped reports.
# - **Safety:** Uses `mktemp` for temporary file creation, avoids `eval` where possible, performs basic input validation.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - System Administrators
# - Network Engineers
# - DevOps Engineers
# - IT Support Staff
# - Security Analysts (for basic network reconnaissance)
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x check_port_nc.sh`
# - File system access: Read access to input IP file. Write access to output directory (for CSV/log files) and input IP file (for in-place sort).
# - Network access: Outbound TCP connections to target IPs/ports.
# - Elevated privileges: Requires `sudo` ONLY if `netcat (nc)` needs to be installed automatically. Port scanning itself usually does not require root.
#
# **Basic Syntax:**
#   ./check_port_nc.sh [options]
#
# **Options:**
#   -h, --help         Display this help message and exit.
#   -v, --verbose      Enable verbose output (DEBUG level logging).
#   --no-color       Disable colored output in the console.
#   -i, --input FILE   Specify the path to the input IP list file (Default: './list_server_ip.txt').
#   -o, --output-dir DIR Specify the directory for output CSV and log files (Default: script directory).
#   -p, --ports PORTS  Comma-separated list of ports to check (Default: "22,80,443,8080,3306,3389").
#   -t, --timeout SEC  Set connection timeout in seconds for 'nc' (Default: 1).
#
# **Arguments:**
#   None. All configuration is via options or defaults.
#
# **Common Examples:**
# 1. Run with default settings:
#    `./check_port_nc.sh`
#
# 2. Run with a specific IP list and check only ports 80 and 443:
#    `./check_port_nc.sh -i /path/to/my_ips.txt -p "80,443"`
#
# 3. Run with verbose output, 3-second timeout, and custom output directory:
#    `./check_port_nc.sh -v -t 3 -o /var/log/port_checks/`
#
# 4. Run and disable color output:
#    `./check_port_nc.sh --no-color`
#
# 5. Get help:
#    `./check_port_nc.sh --help`
#
# **Advanced Execution (Automation):**
# - Example cron job running daily at 3:00 AM, using specific options:
#   `0 3 * * * /path/to/check_port_nc.sh -i /etc/script_configs/list_server_ip.txt -o /var/log/port_status/ >> /var/log/port_status/cron.log 2>&1`
#   (Ensure `nc` is pre-installed or manage sudo password prompts if needed by cron).
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - User scripts: `~/bin/` or `~/.local/bin/` (ensure in user's $PATH)
# - System-wide scripts: `/usr/local/sbin/` or `/opt/scripts/`
#
# **Manual Setup:**
# 1. Place the script in the chosen location.
# 2. Set executable permissions: `chmod +x check_port_nc.sh`.
# 3. Ensure required dependencies are installed (see DEPENDENCIES section), especially `nc`.
# 4. Create the input IP list file (default: `list_server_ip.txt` in script dir) or specify path with `-i`.
# 5. Ensure the output directory exists and is writable, or specify path with `-o`.
# 6. Run initially with `--help` or `-v` to test.
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/usr/bin/env bash`: The Bourne-Again SHell interpreter. Assumes Bash v4+ for features like associative arrays (`declare -A` in logging).
#
# **Required System Binaries/Tools:**
# - `coreutils`: Provides `date`, `mkdir`, `chmod`, `cat`, `basename`, `dirname`, `mktemp`, `sort`, `tr`, `echo`, `sed`.
# - `grep`: For pattern searching (used implicitly by `check_dependency` via `command -v`).
# - `nc` (netcat): Core utility for port scanning. Script attempts auto-install.
# - `command`: Bash built-in for checking command existence.
# - `getopts`: Bash built-in for parsing command-line options.
# - `sudo`: Required *only* for automatic installation of `nc`.
# - Package Managers (one of): `apt-get`, `yum`, `dnf`, `pacman`, `zypper` - needed for `nc` auto-install.
#
# **Setup Instructions (if dependencies are not standard):**
# - `nc` is the primary external dependency.
# - To check if installed: `command -v nc`
# - To install manually (examples):
#   - Debian/Ubuntu: `sudo apt update && sudo apt install netcat-openbsd` or `netcat-traditional` or `netcat`
#   - RHEL/CentOS/Fedora: `sudo dnf install nc` or `sudo yum install nc`
#   - Arch: `sudo pacman -Syu openbsd-netcat`
#   - openSUSE: `sudo zypper install netcat-openbsd`
#
# **Operating System Compatibility:**
# - Designed primarily for Linux distributions with Bash v4+ and one of the supported package managers.
# - May function on macOS if `nc` and core utilities are present (Bash v3 might be default, install newer Bash). Package auto-installation will likely fail on macOS.
#
# **Environment Variables Used:**
# - None explicitly read by the script, but `PATH` is crucial for finding commands.
#
# **System Resource Requirements:**
# - CPU: Low.
# - Memory: Low (< 50MB typically).
# - Disk I/O: Minimal (reading input, writing small CSV/log files). Uses temp file for sorting.
# - Network: Generates one TCP connection attempt per target IP/port. Can be significant for large lists/many ports.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): INFO messages, final summary.
# - Standard Error (stderr): WARN, ERROR, CRITICAL messages, DEBUG messages (if `-v` enabled).
# - Dedicated Log File: Yes. Path: `{OUTPUT_DIR}/{SCRIPT_NAME_WITHOUT_EXT}_{TIMESTAMP}.log` (e.g., `./output/check_port_nc_20250420_103800.log`). Contains all messages >= LOG_LEVEL.
#
# **Log Format:**
# - `[YYYY-MM-DD HH:MM:SS ZONE] [LEVEL] [script:function:line] - Message` (e.g., `[2025-04-20 10:38:00 WIB] [INFO] [check_port_nc:main:250] - Starting main script execution...`)
#
# **Log Levels (Implemented):**
# - `DEBUG`: Detailed step-by-step info (enabled by `-v` or `--verbose`).
# - `INFO`: General operational messages (default level).
# - `WARN`: Potential issues, recoverable problems, skipped items.
# - `ERROR`: Significant errors, likely preventing completion of a specific task but script might continue.
# - `CRITICAL`: Severe errors causing immediate script termination (via `exit 1`).
# - Control: Default is INFO. Set to DEBUG with `-v`. Log file includes all messages >= INFO (or DEBUG if `-v` used).
#
# **Log Rotation:**
# - Not handled by the script itself. Each run creates a new timestamped log file.
# - Recommendation: Use external tools like `logrotate` or scheduled cleanup scripts (`find ... -mtime +X -delete`) to manage old log files in the output directory.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - INFO level log messages (unless `-v` is used, then DEBUG also goes to stderr).
# - Final summary message indicating completion and file paths.
#
# **Standard Error (stderr):**
# - WARN, ERROR, CRITICAL log messages.
# - DEBUG log messages if `-v` or `--verbose` is used.
#
# **Generated/Modified Files:**
# - Detailed Results CSV: `{OUTPUT_DIR}/server_check_results_{TIMESTAMP}.csv`
#   Format: `Timestamp,IP Address,Port,Status` (Status: OPEN or CLOSED)
# - Summary Results CSV: `{OUTPUT_DIR}/server_check_summary_{TIMESTAMP}.csv`
#   Format: `IP Address,Status` (Status: Active or Inactive)
# - Log File: `{OUTPUT_DIR}/{SCRIPT_NAME_WITHOUT_EXT}_{TIMESTAMP}.log`
#   Contains detailed log messages based on LOG_LEVEL.
# - Input IP List File (`list_server_ip.txt` or path from `-i`): **Modified in place** to sort IPs and remove duplicates using a temporary file.
# - Temporary File(s): Created via `mktemp` during sorting (e.g., `list_server_ip.txt.XXXXXX`). Automatically removed on script exit via `trap cleanup`.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success.
# - 1: General/Critical Error (Caught by `log_message CRITICAL` or `set -e`). Includes:
#   - Missing/unreadable input file.
#   - Unwritable/uncreatable output directory.
#   - Missing critical dependency (`date`, `sort`) after install attempt.
#   - Failed `nc` installation.
#   - Invalid port number format.
#   - Failed sorting of IP list file.
#   - Invalid command-line argument/option value.
# - Other non-zero codes may be emitted by underlying commands if `set -e` triggers exit before `log_message CRITICAL`.
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** CRITICAL "Input IP list file not found/readable".
#   **Resolution:** Ensure the file exists at the specified path (default: `./list_server_ip.txt` or from `-i`) and has read permissions for the script user.
# - **Issue:** CRITICAL "Output directory ... not writable/creatable".
#   **Resolution:** Ensure the specified output directory (default: script dir or from `-o`) exists and has write permissions, or that parent directories allow its creation.
# - **Issue:** WARN/ERROR/CRITICAL related to 'nc' not found or install failure.
#   **Resolution:** Manually install `netcat` (`nc`) using system package manager. Ensure `sudo` works if relying on auto-install. Check network connectivity if install downloads fail. Verify correct package name (`netcat`, `nc`, `netcat-openbsd`, etc.).
# - **Issue:** Ports consistently show "CLOSED".
#   **Resolution:** Check firewalls (local, network, cloud security groups). Verify `nc` works manually (`nc -z -w<timeout> <IP> <PORT>`). Increase timeout (`-t SEC`) if network is slow.
# - **Issue:** WARN "Skipping invalid IP address format".
#   **Resolution:** Check format in the input IP file (should be standard IPv4 dot-decimal).
# - **Issue:** ERROR "Failed to sort or write to temporary file".
#   **Resolution:** Check write permissions in the directory containing the IP list file (temp file created there). Check disk space.
#
# **Important Considerations / Warnings:**
# - **Data Modification:** The input IP list file is **modified in place** (sorted, deduplicated). Backup the original file if order/duplicates are important.
# - **Sudo Requirement:** Automatic installation of `nc` requires `sudo`. If `nc` is missing and run without sudo rights (or passwordless sudo), installation fails.
# - **Network Traffic:** Generates scan traffic. Use responsibly and ensure compliance with network policies.
# - **Firewalls:** Results ("CLOSED") can indicate a closed port OR a firewall block.
# - **Timeout (`-t`):** Default (1s) might be too short for slow networks. Adjust as needed.
# - **IPv4 Only:** The script currently only processes/validates IPv4 addresses.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Executed in a `bash` (v4+) environment.
# - Standard Linux core utilities (`date`, `sort`, `mktemp`, etc.) are available in `$PATH`.
# - If `nc` needs installation: system uses a supported package manager (`apt`, `yum`, `dnf`, `pacman`, `zypper`) and `sudo` is available/functional.
# - Input IP file exists and is readable/writable (for sort). Output directory is writable.
# - Input file contains valid IPv4 addresses, one per line (basic format check included).
# - Network connectivity exists from script host to target IPs.
# =========================================================================================

# =========================================================================================
# PERFORMANCE OPTIMIZATION (Optional)
# =========================================================================================
# - **Current State:** Checks IPs and ports sequentially. Performance depends on the number of IPs, number of ports, and network latency/timeout value.
# - **Potential Bottlenecks:** Network latency for `nc` checks is the primary factor. Large number of IPs/ports will increase total runtime linearly.
# - **Optimization Notes:** No parallel processing implemented. For significantly faster scanning of large lists, consider tools like `nmap` or rewriting parts using parallel execution techniques (e.g., `xargs -P`, `parallel`, or async mechanisms in higher-level languages).
# =========================================================================================

# =========================================================================================
# TESTING & VALIDATION (Optional)
# =========================================================================================
# - **Test Strategy:** Primarily manual testing with various inputs and network conditions. Static analysis recommended.
# - **Key Test Cases (Recommended):**
#   - Valid/invalid command-line arguments (`-h`, `-i`, `-o`, `-p`, `-t`, `-v`, bad values).
#   - Missing/unreadable input file. Unwritable output directory.
#   - `nc` present vs. missing (testing auto-install with/without sudo).
#   - Input file with valid IPs, invalid IPs, comments, empty lines, duplicates.
#   - Network conditions: ports open, ports closed, ports filtered (timeout). Slow network (test timeout value).
#   - Large input file (check resource usage, completion time).
# - **Validation Tools:**
#   - **ShellCheck:** Highly recommended for static analysis (`shellcheck check_port_nc.sh`).
#   - Manual execution with `-v` flag to observe DEBUG logs.
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - Add support for checking IPv6 addresses.
# - Add option for UDP port checking (`nc -uz`).
# - Implement more robust IP address validation (e.g., checking octet ranges).
# - Add option for parallel scanning (e.g., using background processes, `xargs -P`, or GNU `parallel`).
# - Allow reading IPs from standard input.
# - Add option to specify output file names directly (instead of just directory).
# - Add support for reading config from a file in addition to CLI args.
# - Enhance `install_package` to handle more edge cases or specific package names per distro.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Requires `sudo` *only* for `nc` auto-install. Port scanning runs as the invoking user. Avoid running the entire script as root unless necessary for install.
# - **Input Sanitization:** Reads IPs from file, basic regex validation performed. Port numbers validated. Paths from CLI args (`-i`, `-o`) are used directly; ensure user invoking script controls these paths or they are validated appropriately if environment is untrusted. Timeout value validated as positive integer. Temporary files handled securely via `mktemp`.
# - **Sensitive Data Handling:** Does not handle passwords or API keys.
# - **Dependencies:** Relies on standard utilities and potentially `sudo`/package managers. Keep system updated. Use of `nc` constitutes network scanning - use responsibly.
# - **File Permissions:** Output files (CSV, log) created with default user umask. Input IP file requires read/write permissions for sort-in-place. Ensure appropriate permissions on input/output paths.
# - **External Command Execution:** Uses `nc`, `sort`, `date`, package managers. `sudo` use is explicit for install. Variables passed to commands (IPs, ports, timeout) are generally quoted.
# - **Network Exposure:** Makes outbound TCP connections. Does not listen on ports.
# - **Code Integrity:** Verify script source if obtained externally (e.g., `sha256sum`).
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is within this script's header comments.
# - Use `./check_port_nc.sh --help` for command-line usage.
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Report via the script's repository (if applicable) or contact email.
# =========================================================================================

# =========================================================================================
# SCRIPT EXECUTION ENVIRONMENT & CONFIGURATION
# =========================================================================================

# --- Bash Strict Mode ---
# -e: Exit immediately if a command exits with a non-zero status.
# -u: Treat unset variables and parameters as an error when performing parameter expansion.
# -o pipefail: The return value of a pipeline is the status of the last command to exit with a non-zero status,
# or zero if no command exited with a non-zero status.
set -euo pipefail

# --- Script Information ---
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
# Resolve the absolute path of the script's directory, handling symlinks.
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_DIR="${SOURCE_DIR}"
readonly SCRIPT_PID=$$

# --- Timestamp ---
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Global Runtime Variables ---
# Configuration Defaults (can be overridden by future arguments/config file)
VERBOSE=false
NO_COLOR=false
INTERACTIVE_MODE=false
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is a terminal

# Default Paths and Settings
DEFAULT_IP_LIST_FILE="${SCRIPT_DIR}/list_server_ip.txt"
DEFAULT_OUTPUT_DIR="${SCRIPT_DIR}" # Output files in the same directory by default
DEFAULT_PORTS=(22 80 443 8080 3306 3389) # Default common ports
DEFAULT_NC_TIMEOUT=1 # Default netcat timeout in seconds

# Base names for output files
OUTPUT_FILE_BASE="server_check_results"
SUMMARY_FILE_BASE="server_check_summary"

# Runtime variables that will be populated later
IP_LIST_FILE="${DEFAULT_IP_LIST_FILE}"
OUTPUT_DIR="${DEFAULT_OUTPUT_DIR}"
PORTS_TO_CHECK=("${DEFAULT_PORTS[@]}") # Use array copy
NC_TIMEOUT=${DEFAULT_NC_TIMEOUT}
LOG_FILE="${OUTPUT_DIR}/${SCRIPT_NAME%.sh}_${SCRIPT_RUN_TIMESTAMP}.log" # Centralized log file
LOG_TO_FILE=true # Enable file logging by default
LOG_LEVEL="INFO" # Default log level (DEBUG, INFO, WARN, ERROR, CRITICAL)
TEMP_DIR="" # Will be set by mktemp if needed

# --- Color Definitions (Optional) ---
if [[ "${NO_COLOR}" == false && "${INTERACTIVE_MODE}" == true ]]; then
    COLOR_RESET='\033[0m'; COLOR_RED='\033[0;31m'; COLOR_GREEN='\033[0;32m';
    COLOR_YELLOW='\033[0;33m'; COLOR_BLUE='\033[0;34m'; COLOR_CYAN='\033[0;36m';
    COLOR_BOLD='\033[1m';
else
    COLOR_RESET=""; COLOR_RED=""; COLOR_GREEN=""; COLOR_YELLOW="";
    COLOR_BLUE=""; COLOR_CYAN=""; COLOR_BOLD="";
fi

# =========================================================================================
# FUNCTION DEFINITIONS
# =========================================================================================

# --- Logging Function ---
# Usage: log_message LEVEL "Message string"
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z")
    local level_upper
    level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]')
    local log_prefix="[${timestamp}] [${level_upper}] [${SCRIPT_NAME}:${FUNCNAME[1]:-<main>}:${BASH_LINENO[0]}]"
    local log_line="${log_prefix} - ${message}"
    local color=""

    case "${level_upper}" in
        DEBUG) color="${COLOR_CYAN}" ;; INFO) color="${COLOR_GREEN}" ;; WARN) color="${COLOR_YELLOW}" ;;
        ERROR) color="${COLOR_RED}" ;; CRITICAL) color="${COLOR_BOLD}${COLOR_RED}" ;;
    esac

    declare -A log_levels=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [CRITICAL]=4)
    local current_log_level_num=${log_levels[${LOG_LEVEL^^}]}
    local message_level_num=${log_levels[${level_upper}]}

    if [[ ${message_level_num} -ge ${current_log_level_num} ]]; then
        local output_stream=1 # Default stdout
        if [[ "${level_upper}" == "WARN" || "${level_upper}" == "ERROR" || "${level_upper}" == "CRITICAL" ]]; then
            output_stream=2 # stderr for errors/warnings
        fi

        # Print to console (stdout/stderr)
        if ! [[ "${level_upper}" == "DEBUG" && "${VERBOSE}" == false ]]; then
             echo -e "${color}${log_line}${COLOR_RESET}" >&${output_stream}
        fi

        # Append to log file if enabled
        if [[ "${LOG_TO_FILE}" == true ]]; then
            if [[ -z ${LOG_DIR_WRITE_WARN_SENT+x} ]]; then # Check if unset
                # Ensure log directory exists
                mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
                if ! [[ -w "$(dirname "${LOG_FILE}")" ]]; then
                     echo -e "${COLOR_YELLOW}[${timestamp}] [WARN] - Cannot write to log directory $(dirname "${LOG_FILE}"). Logging to file disabled.${COLOR_RESET}" >&2
                     LOG_DIR_WRITE_WARN_SENT=true # Prevent repeating warning
                     LOG_TO_FILE=false
                fi
            fi
             # Append if still enabled
            if [[ "${LOG_TO_FILE}" == true ]]; then
                 # Strip color codes for file logging
                 echo "${log_prefix} - ${message}" >> "${LOG_FILE}"
            fi
        fi
    fi

    # Exit immediately for CRITICAL errors after logging
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        log_message "INFO" "Critical error encountered. Forcing script termination."
        # Cleanup will be called by trap EXIT
        exit 1 # Use a specific exit code for critical errors
    fi
}


# --- Usage/Help Function ---
usage() {
    # Extract usage info from script header comments
    local usage_text
    usage_text=$(sed -n '/^# ===+ USAGE ===+$/,/^# ===+ .* ===+$/{ /# ===+ .* ===+$/!p; }' "${BASH_SOURCE[0]}" | sed 's/^# //; s/\[your_script_name.sh\]/'"${SCRIPT_NAME}"'/g')

    cat << EOF >&2
${usage_text}

Default Configuration:
  IP List File: ${DEFAULT_IP_LIST_FILE}
  Output Directory: ${DEFAULT_OUTPUT_DIR}
  Ports: ${DEFAULT_PORTS[*]}
  Netcat Timeout: ${DEFAULT_NC_TIMEOUT}s
  Log File: ${LOG_FILE} (Timestamped on execution)

Use -h or --help for full options.
EOF
    exit 1
}

# --- Dependency Check Function ---
check_dependency() {
    local cmd="$1"
    local install_suggestion="${2:-$cmd}"
    log_message "DEBUG" "Checking for command: ${cmd}"
    if ! command -v "$cmd" &> /dev/null; then
        # Log as ERROR, let the calling logic decide if it's CRITICAL
        log_message "ERROR" "Required command '${cmd}' not found."
        log_message "ERROR" "Please install the '${install_suggestion}' package or ensure it's in the PATH."
        return 1 # Indicate failure
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
    return 0 # Indicate success
}

# --- Cleanup Function ---
cleanup() {
    local exit_status=$?
    log_message "INFO" "Performing cleanup..."
    # Remove temporary directory if created
    if [[ -n "${TEMP_DIR:-}" && -d "${TEMP_DIR}" ]]; then
        log_message "DEBUG" "Removing temporary directory: ${TEMP_DIR}"
        rm -rf "${TEMP_DIR}" || log_message "WARN" "Failed to remove temporary directory: ${TEMP_DIR}"
    fi
    log_message "INFO" "Cleanup finished. Exiting with status: ${exit_status}"
    # Note: Script exits with the original $? after trap finishes
}

# --- Trap Setup ---
trap cleanup EXIT INT TERM HUP

# --- Argument Parsing Function ---
# Basic parsing for key parameters. Expand as needed.
parse_params() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) usage ;;
            -v|--verbose) VERBOSE=true; LOG_LEVEL="DEBUG"; shift ;;
            --no-color) NO_COLOR=true; shift ;;
            -i|--input) IP_LIST_FILE="$2"; shift 2 ;;
            -o|--output-dir) OUTPUT_DIR="$2"; shift 2 ;;
            -p|--ports)
                IFS=',' read -ra PORTS_TO_CHECK <<< "$2"
                log_message "DEBUG" "Custom ports provided: ${PORTS_TO_CHECK[*]}"
                shift 2 ;;
            -t|--timeout)
                if [[ "$2" =~ ^[0-9]+$ && "$2" -gt 0 ]]; then
                    NC_TIMEOUT="$2"
                else
                    log_message "ERROR" "Invalid timeout value: '$2'. Must be a positive integer."
                    usage
                fi
                shift 2 ;;
            *) # Handle non-option arguments or unknown options
               # If you expect positional arguments, handle them here.
               # Otherwise, treat as error.
                log_message "ERROR" "Unknown option or argument: $1"
                usage ;;
        esac
    done

    # Re-evaluate LOG_FILE path if OUTPUT_DIR changed
    LOG_FILE="${OUTPUT_DIR}/${SCRIPT_NAME%.sh}_${SCRIPT_RUN_TIMESTAMP}.log"

    log_message "DEBUG" "Arguments parsed. Input: ${IP_LIST_FILE}, Output Dir: ${OUTPUT_DIR}, Ports: ${PORTS_TO_CHECK[*]}, Timeout: ${NC_TIMEOUT}s, Verbose: ${VERBOSE}"
}


# --- Package Installation Function ---
# Attempts to install a package using detected package manager.
install_package() {
    local package=$1
    local cmd_to_check="${2:-$package}" # Command to verify after install (e.g., 'nc' for 'netcat' package)
    log_message "INFO" "Attempting to install package '${package}'..."

    local install_cmd=""
    if check_dependency "apt-get" "apt"; then
        install_cmd="sudo apt-get update && sudo apt-get install -y \"${package}\""
    elif check_dependency "yum" "yum"; then
        install_cmd="sudo yum install -y \"${package}\""
    elif check_dependency "dnf" "dnf"; then
        install_cmd="sudo dnf install -y \"${package}\""
    elif check_dependency "pacman" "pacman"; then
        # Arch requires explicit sync before install usually
        install_cmd="sudo pacman -Sy --noconfirm \"${package}\""
    elif check_dependency "zypper" "zypper"; then
        install_cmd="sudo zypper install -y \"${package}\""
    else
        log_message "ERROR" "Could not detect a supported package manager (apt, yum, dnf, pacman, zypper)."
        return 1
    fi

    log_message "DEBUG" "Executing installation command: ${install_cmd}"
    if eval "${install_cmd}"; then
        log_message "INFO" "Installation command for '${package}' executed successfully."
        # Verify the actual command is now available
        if check_dependency "${cmd_to_check}"; then
            log_message "INFO" "Command '${cmd_to_check}' is now available."
            return 0
        else
            log_message "ERROR" "Package '${package}' installed, but command '${cmd_to_check}' is still not found. Installation might have failed or provides a different command."
            return 1
        fi
    else
        log_message "ERROR" "Installation command failed for package '${package}'."
        return 1
    fi
}

# --- Input Validation Function ---
validate_inputs() {
    log_message "INFO" "Validating inputs and configuration..."

    if [[ ! -f "${IP_LIST_FILE}" ]]; then
        log_message "CRITICAL" "Input IP list file not found: ${IP_LIST_FILE}"
    elif [[ ! -r "${IP_LIST_FILE}" ]]; then
        log_message "CRITICAL" "Input IP list file is not readable: ${IP_LIST_FILE}"
    fi

    if ! mkdir -p "${OUTPUT_DIR}"; then
        log_message "CRITICAL" "Output directory '${OUTPUT_DIR}' could not be created."
    elif [[ ! -w "${OUTPUT_DIR}" ]]; then
        log_message "CRITICAL" "Output directory '${OUTPUT_DIR}' is not writable."
    fi

    # Validate ports array
    if [[ ${#PORTS_TO_CHECK[@]} -eq 0 ]]; then
        log_message "CRITICAL" "No ports specified for checking."
    fi
    for port in "${PORTS_TO_CHECK[@]}"; do
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then
            log_message "CRITICAL" "Invalid port number specified: '${port}'. Must be between 1 and 65535."
        fi
    done

    log_message "INFO" "Input validation passed."
}

# --- Environment Preparation Function ---
prepare_environment() {
    log_message "INFO" "Preparing execution environment..."

    # Check core dependencies
    if ! check_dependency "nc" "netcat"; then
        log_message "WARN" "'nc' command not found. Attempting automatic installation..."
        # Try common package names, checking for 'nc' command after each attempt
        if ! install_package "netcat" "nc" && ! install_package "netcat-openbsd" "nc" && ! install_package "nc" "nc" ; then
             log_message "CRITICAL" "Failed to install 'netcat' using common package names (netcat, netcat-openbsd, nc). Please install it manually."
        fi
    fi
    check_dependency "date" "coreutils" || exit 1 # Critical for timestamps
    check_dependency "sort" "coreutils" || exit 1 # Critical for IP list handling

    # Sort and deduplicate IP list file in place
    log_message "INFO" "Sorting and removing duplicates from IP list file: ${IP_LIST_FILE}"
    # Create temporary file for sorting result
    local temp_sorted_ips
    temp_sorted_ips=$(mktemp "${IP_LIST_FILE}.XXXXXX")
    log_message "DEBUG" "Using temporary file for sorting: ${temp_sorted_ips}"
    # Ensure temp file is removed on exit (redundant with trap, but good practice)
    TEMP_DIR=$(dirname "${temp_sorted_ips}") # Set TEMP_DIR for cleanup trap

    if sort -Vu "${IP_LIST_FILE}" > "${temp_sorted_ips}"; then
        # Check if sort command succeeded before moving
        mv "${temp_sorted_ips}" "${IP_LIST_FILE}"
        log_message "INFO" "IP list sorted and deduplicated successfully."
    else
        log_message "ERROR" "Failed to sort or write to temporary file '${temp_sorted_ips}'. Check permissions and disk space."
        # Optionally remove the temp file if it exists but is potentially empty/corrupt
        rm -f "${temp_sorted_ips}"
        exit 1 # Exit if sorting fails
    fi

    # Construct final output file paths
    OUTPUT_FILE="${OUTPUT_DIR}/${OUTPUT_FILE_BASE}_${SCRIPT_RUN_TIMESTAMP}.csv"
    SUMMARY_FILE="${OUTPUT_DIR}/${SUMMARY_FILE_BASE}_${SCRIPT_RUN_TIMESTAMP}.csv"

    # Initialize Output Files (create/overwrite with headers)
    log_message "INFO" "Initializing detailed results file: ${OUTPUT_FILE}"
    echo "Timestamp,IP Address,Port,Status" > "$OUTPUT_FILE"
    log_message "INFO" "Initializing summary results file: ${SUMMARY_FILE}"
    echo "IP Address,Status" > "$SUMMARY_FILE"

    log_message "INFO" "Environment preparation complete."
}

# --- Port Checking Function ---
# Checks if a specific TCP port is open on a given IP address using netcat.
check_port() {
    local ip=$1
    local port=$2
    local timeout=${NC_TIMEOUT} # Use global timeout setting

    log_message "DEBUG" "Checking port ${port} on IP ${ip} with timeout ${timeout}s"
    # -z: Zero-I/O mode (scan).
    # -w<timeout>: Set connection timeout.
    # Redirect stdout and stderr to /dev/null to suppress nc messages.
    if nc -z -w"${timeout}" "$ip" "$port" >/dev/null 2>&1; then
        log_message "DEBUG" "Port ${port} on ${ip} is OPEN"
        return 0 # Success (port open)
    else
        log_message "DEBUG" "Port ${port} on ${ip} is CLOSED or timed out"
        return 1 # Failure (port closed or timeout)
    fi
}

# --- Main Logic Function ---
main() {
    log_message "INFO" "Starting main script execution: Port Scan"
    log_message "INFO" "Reading IPs from: ${IP_LIST_FILE}"
    log_message "INFO" "Checking Ports: ${PORTS_TO_CHECK[*]}"
    log_message "INFO" "Output Dir: ${OUTPUT_DIR}"

    local ip_count=0
    local active_ip_count=0
    local inactive_ip_count=0

    # Read IP list file line by line using process substitution for safety
    while IFS= read -r ip || [[ -n "$ip" ]]; do
        # Trim whitespace
        ip=$(echo "$ip" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        # Skip empty lines and comments
        if [[ -z "$ip" || "$ip" =~ ^# ]]; then
            continue
        fi

        ((ip_count++))
        log_message "INFO" "Processing IP ${ip_count}: ${ip}"

        # Basic IPv4 format validation (improve regex if needed for stricter check)
        if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            log_message "WARN" "Skipping invalid IP address format in ${IP_LIST_FILE}: '${ip}'"
            continue
        fi

        local current_timestamp # Timestamp for detailed log entry
        current_timestamp=$(date +'%Y-%m-%d %H:%M:%S %Z') # Use consistent format
        local ip_active=false # Flag per IP

        # Loop through specified ports
        for port in "${PORTS_TO_CHECK[@]}"; do
            if check_port "$ip" "$port"; then
                # Port is OPEN
                echo "$current_timestamp,$ip,$port,OPEN" >> "$OUTPUT_FILE"
                ip_active=true # Mark IP as active
            else
                # Port is CLOSED
                echo "$current_timestamp,$ip,$port,CLOSED" >> "$OUTPUT_FILE"
            fi
        done # End port loop for this IP

        # Write summary status for this IP
        if [[ "$ip_active" == true ]]; then
            log_message "INFO" "IP ${ip} marked as Active (at least one port open)."
            echo "$ip,Active" >> "$SUMMARY_FILE"
            ((active_ip_count++))
        else
            log_message "INFO" "IP ${ip} marked as Inactive (no common ports open)."
            echo "$ip,Inactive" >> "$SUMMARY_FILE"
            ((inactive_ip_count++))
        fi

    done < "${IP_LIST_FILE}" # Feed file content to the while loop

    log_message "INFO" "Finished processing ${ip_count} IPs."
    log_message "INFO" "Summary: ${active_ip_count} Active IPs, ${inactive_ip_count} Inactive IPs."
    log_message "INFO" "Detailed results saved to: ${OUTPUT_FILE}"
    log_message "INFO" "IP activity summary saved to: ${SUMMARY_FILE}"

    log_message "INFO" "Main execution logic finished."
}


# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# 1. Parse Command Line Arguments
parse_params "$@"

# 2. Load Configuration File (Optional - implement load_config if needed)
# load_config

# 3. Validate Inputs and Configuration
validate_inputs

# 4. Check Dependencies and Prepare Environment
prepare_environment

# 5. Execute Main Logic
main

# 6. Exit Successfully (cleanup runs automatically via trap)
log_message "INFO" "Script completed successfully."
exit 0

# =========================================================================================
# --- End of Script ---
