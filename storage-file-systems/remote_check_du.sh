#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : remote_check_du.sh
# PURPOSE       : Collects top 'du' entries remotely via SSH; outputs CSV/logs.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2024-11-10
# LAST UPDATED  : 2024-11-10
# VERSION       : 1.0.0
# =========================================================================================

# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This script automates the process of checking disk usage on multiple remote servers.
# It reads server connection details (IP, port, username, password) from a specified
# credentials file. For each server, it attempts an SSH connection using 'sshpass'
# for non-interactive login. On successful connection, it executes the 'du' command
# to find the largest files/directories, sorts them, and retrieves the top N entries.
# The results (or connection errors) are appended to a timestamped CSV report file.
# Detailed connection errors or issues during remote command execution are logged
# to a separate timestamped log file. This version incorporates enhanced logging,
# error handling, and environment management based on best practices.
#
# Key Workflow / Functions:
# - Reads server list and credentials from a specified file (default: './credentials.txt').
# - Validates input parameters and configuration settings.
# - Checks for required dependencies (sshpass, ssh, coreutils).
# - Sets up a secure temporary directory for intermediate files.
# - Initializes timestamped output (CSV) and log files.
# - Iterates through each server in the credentials file.
# - Establishes an SSH connection using 'sshpass' and provided credentials with a timeout.
# - Executes 'du -ah / 2>/dev/null | sort -rh | head -n N' remotely.
# - Captures SSH connection status and remote command success/failure.
# - Logs detailed messages (DEBUG, INFO, WARN, ERROR, CRITICAL) to console and log file.
# - Formats successful disk usage results into a single CSV row per server.
# - Logs connection failures or empty results appropriately in CSV and log file.
# - Performs cleanup (removes temporary files) on exit using traps.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY (Optional but Recommended)
# =========================================================================================
# - Modularity: Uses functions for distinct tasks (logging, dependency check, SSH execution, validation, cleanup).
# - Robustness: Implements strict mode (set -euo pipefail), traps for cleanup, checks dependencies and file existence/permissions. Handles SSH errors gracefully without stopping the entire script.
# - Readability: Uses clear variable names, extensive comments, consistent formatting, and logging levels. Long options for 'set' commands are preferred (`errexit` vs `-e`).
# - Automation: Designed for unattended execution (e.g., via cron), using non-interactive SSH login.
# - Security Awareness: Includes explicit warnings about using `sshpass` and disabling host key checking. Recommends SSH keys and secure credential handling.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - System Administrators responsible for monitoring server disk usage.
# - DevOps Engineers managing infrastructure health and performing automated checks.
# - IT Support Teams needing quick reports on disk space consumption across multiple servers.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x remote_check_du.sh`
# - File system access: Read access to the credentials file (`credentials.txt` by default). Write access to the script's directory (or specified OUTPUT_DIR/LOG_DIR) for creating report and log files.
# - Network access: Outbound connections allowed to target servers on their specified SSH ports (default 22).
# - Elevated privileges: Not required for the script itself, but the user specified in `credentials.txt` needs appropriate permissions on the *remote* servers to run `du`, `sort`, `head` and read directories (potentially including `/`).
#
# **Basic Syntax:**
#   `bash remote_check_du.sh`
#   or if executable:
#   `./remote_check_du.sh`
#   (Note: This version does not accept command-line arguments yet; configuration is via variables within the script.)
#
# **Setup:**
# - Create a credentials file (default: `credentials.txt` in the script's directory).
# - Format: One server per line: `server_ip port username password` (space-separated).
#   Example: `192.168.1.100 22 admin P@sswOrd123`
#   - Blank lines and lines starting with `#` are ignored.
# - Update configuration variables inside the script (e.g., `CREDENTIALS_FILE`, `TOP_ENTRIES`, `SSH_TIMEOUT`) if defaults are not suitable.
#
# **Outputs:**
# - Report File: A CSV report file named `top_usage_report_YYYYMMDD_HHMMSS.csv` in the output directory (`.` by default).
# - Log File: A log file named `top_usage_log_YYYYMMDD_HHMMSS.log` in the log directory (`.` by default).
# - Standard Output (stdout): INFO and DEBUG level log messages (if LOG_LEVEL allows).
# - Standard Error (stderr): WARN, ERROR, and CRITICAL level log messages.
#
# **Automation Example (cron):**
# - Run daily at 3:00 AM, changing to the script's directory first:
#   `0 3 * * * cd /path/to/script/directory && ./remote_check_du.sh >> /var/log/remote_du_check.log 2>&1`
#   (Ensure the cron environment has necessary PATH or use full paths in the script/cron job).
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - User-specific: `~/bin/` or `~/.local/bin/` (ensure in user's $PATH)
# - System-wide: `/usr/local/sbin/` or `/usr/local/bin/`
#
# **Manual Setup:**
# 1. Place the script (`remote_check_du.sh`) in the chosen location.
# 2. Set executable permissions: `chmod +x /path/to/remote_check_du.sh`.
# 3. Ensure ownership is appropriate (e.g., `chown user:group /path/to/remote_check_du.sh`).
# 4. Install required dependencies (see DEPENDENCIES section).
# 5. Create the `credentials.txt` file (or configure `CREDENTIALS_FILE` variable) with server details and ensure it has secure permissions (`chmod 600 credentials.txt`).
# 6. Adjust configuration variables within the script if needed (e.g., `OUTPUT_DIR`, `LOG_DIR`).
# 7. Run the script manually once (`./remote_check_du.sh`) to test and ensure output/log directories are writable by the executing user.
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: Bourne-Again SHell (Version >= 4.x recommended for features like `declare -A`). Uses bashisms (`set -o pipefail`, `[[ ]]`, `local`, `readonly`, process substitution). [3, 6]
#
# **Required System Binaries/Tools:**
# - `coreutils`: Provides `date`, `mkdir`, `chmod`, `cat`, `wc`, `head`, `sort`, `paste`, `tr`, `basename`, `dirname`, `mktemp`, `rm`.
# - `grep`: For pattern searching.
# - `sed`: For stream editing (used in `usage` and config loading).
# - `sshpass`: For non-interactive SSH password authentication (Version >= 1.0.6 recommended). **Security Warning:** See SECURITY CONSIDERATIONS.
# - `ssh`: OpenSSH client (`openssh-client` package).
# - `command`: Bash built-in for checking command existence.
# - Remote Server Tools: `du`, `sort`, `head` (expected to be available in the remote user's PATH).
#
# **Setup Instructions (if dependencies are not standard):**
# - Example installation (Debian/Ubuntu):
#   `sudo apt update && sudo apt install -y sshpass openssh-client coreutils grep sed`
# - Example installation (RHEL/CentOS/Fedora):
#   `sudo dnf update && sudo dnf install -y sshpass openssh-clients coreutils grep sed` (sshpass might be in EPEL repository).
#
# **Operating System Compatibility:**
# - Designed primarily for: Linux distributions (tested on Ubuntu, CentOS).
# - May require adjustments for macOS (e.g., `date` flags, potentially `sed` syntax) or other Unix-like systems.
#
# **Environment Variables Used:**
# - None read directly by default for configuration.
# - `PATH`: Standard variable, must include paths to required binaries (`ssh`, `sshpass`, etc.).
# - `SSHPASS`: Can be used by `sshpass` utility if set, but the script provides the password via `-p` argument. (Security Warning).
#
# **System Resource Requirements:**
# - Script Host: Minimal CPU/Memory. Disk space needed for report/log files (size depends on number of servers and log verbosity).
# - Remote Servers: Running `du -ah /` can be CPU and I/O intensive, especially on large filesystems. Monitor resource usage on target servers during execution. Consider running during off-peak hours or targeting specific directories instead of `/`.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): INFO and DEBUG level messages.
# - Standard Error (stderr): WARN, ERROR, CRITICAL level messages.
# - Dedicated Log File: Yes. Path defined by `LOG_FILE` variable (default: `./top_usage_log_YYYYMMDD_HHMMSS.log`).
#
# **Log Format:**
# - `[YYYY-MM-DD HH:MM:SS TZ] [LEVEL] - Message` (e.g., `[2025-04-20 17:30:00 WIB] [INFO] - Processing server 192.168.1.100`)
# - SSH command stderr (connection errors, etc.) is appended directly to the log file.
#
# **Log Levels (Controlled by `LOG_LEVEL` variable):**
# - `DEBUG`: Detailed step-by-step information.
# - `INFO`: General operational messages (default).
# - `WARN`: Potential issues or non-critical errors encountered.
# - `ERROR`: Significant errors affecting a specific server/operation but not stopping the script.
# - `CRITICAL`: Severe errors causing script termination (e.g., missing dependencies, unwritable directories).
#
# **Log Rotation:**
# - Not handled by the script. Use external tools like `logrotate`.
# - Example `logrotate` config (`/etc/logrotate.d/remote_du_check`):
#   ```
#   /path/to/log/directory/*.log {
#       daily
#       rotate 7
#       compress
#       delaycompress
#       missingok
#       notifempty
#       create 0640 <user> <group> # Set appropriate user/group
#   }
#   ```
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Prints INFO/DEBUG log messages based on `LOG_LEVEL`. Includes progress like "Processing server X of Y...".
#
# **Standard Error (stderr):**
# - Prints WARN, ERROR, CRITICAL log messages.
#
# **Generated Files:**
# - Report File: Path defined by `OUTPUT_FILE` (default: `./top_usage_report_YYYYMMDD_HHMMSS.csv`).
#   - Format: CSV with columns: `Timestamp`, `Server IP`, `Top Usage Files`.
#   - Content: For successful checks, `Top Usage Files` contains a semicolon-separated list of `du` output lines, enclosed in double quotes. Errors are noted (e.g., `"ERROR: Connection failed (Exit Status: X)"`).
# - Log File: Path defined by `LOG_FILE` (default: `./top_usage_log_YYYYMMDD_HHMMSS.log`). Contains detailed timestamped execution logs, including connection attempts and errors.
# - Temporary Directory/Files: Created via `mktemp` (e.g., `./remote_check_du.sh.XXXXXX/`). Contains intermediate output (`output_<server>_<port>.txt`). Automatically cleaned up on script exit via `trap`.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success - Script completed execution flow. Note: Individual server checks might have failed (logged in report/log file).
# - 1: General/Critical Error - Critical dependency missing, critical directory unwritable, other fatal errors handled by `log_message CRITICAL`.
# - Non-zero: May also exit non-zero due to `set -e` if an unexpected command fails outside the specifically handled SSH error section.
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** "Connection failed" in report/log.
#   **Resolution:** Verify IP, port, username, password in `credentials.txt`. Check network connectivity/firewalls. Verify SSH service on target server. Increase `SSH_TIMEOUT` if network is slow. Check `LOG_FILE` for detailed SSH errors.
# - **Issue:** "No large files found or permission error" in report.
#   **Resolution:** The `du` command likely lacked permission to read directories on the remote server (errors redirected to `/dev/null` remotely). Verify remote user permissions. Or, the scanned path (`/`) might genuinely have no large accessible files/dirs for that user.
# - **Issue:** Script exits with "CRITICAL: Credentials file not found or not readable."
#   **Resolution:** Ensure `credentials.txt` (or the file specified by `CREDENTIALS_FILE`) exists in the expected location and the script user has read permissions.
# - **Issue:** Script exits with "CRITICAL: Output directory not writable."
#   **Resolution:** Check permissions on the directory specified by `OUTPUT_DIR`. Ensure the script user can write to it.
#
# **Important Considerations / Warnings:**
# - **[Security Warning: Sensitive Data Handling]**: Using `sshpass` with passwords supplied via `-p` argument exposes the password in the process list (`ps aux`). Reading passwords from `credentials.txt` (plain text) is insecure. **Strongly recommend using SSH key-based authentication instead.** If passwords must be used, ensure `credentials.txt` has strict permissions (`chmod 600 credentials.txt`) and understand the risks.
# - **[Security Warning: SSH Host Keys]**: Uses `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null` to bypass host key checking. This simplifies automation but makes connections vulnerable to Man-in-the-Middle (MITM) attacks. In production, manage known_hosts properly or accept keys manually/securely beforehand.
# - **[Resource Usage]**: `du -ah /` is resource-intensive on target servers (CPU, I/O). Run during off-peak hours or scope `du` to specific directories if possible (e.g., modify `remote_cmd` variable).
# - **[Idempotency]**: The script is generally idempotent for reporting. Running it multiple times will generate new reports/logs without altering system state (other than creating files).
# - **[Concurrency]**: Not designed for concurrent execution against the same output files. Does not implement locking. Running multiple instances simultaneously could lead to corrupted CSV/log files.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes a Bash (v4+) environment with required dependencies installed and in PATH.
# - Assumes network connectivity exists between the script host and target servers.
# - Assumes `credentials.txt` exists, is readable, and correctly formatted (IP Port User Pass).
# - Assumes target systems are reachable via SSH using password authentication with the provided credentials.
# - Assumes the `du`, `sort`, `head` commands exist and are executable by the remote user on target systems.
# - Assumes the script execution directory (or specified `OUTPUT_DIR`/`LOG_DIR`) is writable.
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - Add command-line argument parsing (`getopts`) for specifying credentials file, output/log dirs, timeout, top N, log level, etc.
# - Implement support for SSH key-based authentication (potentially checking for keys before falling back to password/sshpass).
# - Add option to specify target directories for `du` instead of always using `/`.
# - Implement parallel execution (e.g., using `xargs -P` or GNU `parallel`) for faster processing of many servers.
# - Add configuration file support (e.g., `.conf`) for settings instead of hardcoding defaults.
# - Enhance remote command error detection (e.g., check `du` exit code specifically if possible).
# - Improve macOS compatibility if needed.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS (Summary - See details in relevant sections above)
# =========================================================================================
# - **Privilege Level:** Script itself needs user-level privileges. Remote user privileges defined in `credentials.txt` determine remote access capabilities. Least privilege principle should apply to the remote user.
# - **Input Sanitization:** Limited input (reads from `credentials.txt`). No direct command construction from external input. File paths (`CREDENTIALS_FILE`, `OUTPUT_DIR`, etc.) should be validated.
# - **Sensitive Data Handling:** **HIGH RISK** due to plain text passwords in `credentials.txt` and use of `sshpass`. SSH keys are strongly recommended. Ensure `credentials.txt` has `chmod 600` permissions.
# - **SSH Security:** Host key checking is disabled (`StrictHostKeyChecking=no`), posing a MITM risk. Manage host keys securely in production environments.
# - **Dependencies:** Relies on standard OS tools and `sshpass`. Keep packages updated. `sshpass` itself is a security concern.
# - **File Permissions:** Ensure `credentials.txt` is `600`. Output/log files created with default umask permissions. Temporary directory created securely via `mktemp`.
# - **External Command Execution:** Executes `sshpass`, `ssh`, and remote commands (`du`, `sort`, `head`). Ensure remote user has only necessary permissions.
# - **Error Message Verbosity:** Logs may contain IP addresses and usernames. Avoid logging passwords.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is contained within this script's header comments.
# - See REPOSITORY link for potential external README or issue tracking.
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Report via the script's repository (see REPOSITORY link) or author's contact email.
# =========================================================================================

# =========================================================================================
# SCRIPT EXECUTION ENVIRONMENT & CONFIGURATION
# =========================================================================================

# --- Bash Strict Mode ---
# -e: Exit immediately if a command exits with a non-zero status.
# -u: Treat unset variables and parameters as an error during expansion.
# -o pipefail: The return value of a pipeline is the status of the last command
#              to exit with a non-zero status, or zero if none failed.
set -euo pipefail

# --- Debug Mode ---
# Uncomment the next line for verbose command execution tracing
# set -x

# --- Script Information ---
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_DIR="${SOURCE_DIR}"
readonly SCRIPT_PID=$$

# --- Timestamp ---
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Global Configuration Variables (Defaults) ---
# These can potentially be overridden by command-line arguments or a config file in future versions.
DEFAULT_CREDENTIALS_FILE="${SCRIPT_DIR}/credentials.txt"
DEFAULT_OUTPUT_DIR="${SCRIPT_DIR}"
DEFAULT_LOG_DIR="${SCRIPT_DIR}"
DEFAULT_TOP_ENTRIES=10
DEFAULT_SSH_TIMEOUT=10
DEFAULT_LOG_LEVEL="INFO" # Levels: DEBUG, INFO, WARN, ERROR, CRITICAL
DEFAULT_NO_COLOR=false
DEFAULT_LOG_TO_FILE=true

# --- Runtime Variables ---
# Initialize with defaults, may be changed later (e.g., by future argument parsing)
CREDENTIALS_FILE="${DEFAULT_CREDENTIALS_FILE}"
OUTPUT_DIR="${DEFAULT_OUTPUT_DIR}"
LOG_DIR="${DEFAULT_LOG_DIR}"
TOP_ENTRIES=${DEFAULT_TOP_ENTRIES}
SSH_TIMEOUT=${DEFAULT_SSH_TIMEOUT}
LOG_LEVEL="${DEFAULT_LOG_LEVEL}"
NO_COLOR=${DEFAULT_NO_COLOR}
LOG_TO_FILE=${DEFAULT_LOG_TO_FILE}
INTERACTIVE_MODE=false
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is a terminal

OUTPUT_FILE="${OUTPUT_DIR}/top_usage_report_${SCRIPT_RUN_TIMESTAMP}.csv"
LOG_FILE="${LOG_DIR}/top_usage_log_${SCRIPT_RUN_TIMESTAMP}.log"
TEMP_DIR="" # Will be set by prepare_environment using mktemp

# --- Color Definitions ---
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
log_message() {
    local level="$1"
    local message="$2"
    local timestamp; timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z")
    local level_upper; level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]')
    local log_prefix="[${timestamp}] [${level_upper}]"
    local log_line="${log_prefix} - ${message}"
    local color=""

    declare -A log_levels=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [CRITICAL]=4)
    local current_log_level_num=${log_levels[${LOG_LEVEL^^}]}
    local message_level_num=${log_levels[${level_upper}]}

    # Check severity against current log level
    if [[ ${message_level_num} -ge ${current_log_level_num} ]]; then
        # Determine color
        case "${level_upper}" in
            DEBUG) color="${COLOR_CYAN}" ;; INFO) color="${COLOR_GREEN}" ;;
            WARN) color="${COLOR_YELLOW}" ;; ERROR) color="${COLOR_RED}" ;;
            CRITICAL) color="${COLOR_BOLD}${COLOR_RED}" ;;
        esac

        # Output to stderr for WARN/ERROR/CRITICAL, stdout otherwise
        if [[ "${level_upper}" == "WARN" || "${level_upper}" == "ERROR" || "${level_upper}" == "CRITICAL" ]]; then
            echo -e "${color}${log_line}${COLOR_RESET}" >&2
        else
            # Only print DEBUG if explicitly enabled (could add a VERBOSE flag later)
            if [[ "${level_upper}" != "DEBUG" || "${LOG_LEVEL^^}" == "DEBUG" ]]; then
                 echo -e "${color}${log_line}${COLOR_RESET}"
            fi
        fi

        # Append to log file if enabled and possible
        if [[ "${LOG_TO_FILE}" == true ]]; then
             if [[ -w "$(dirname "${LOG_FILE}")" ]]; then
                 # Strip color codes for file logging
                 echo "${log_prefix} - ${message}" >> "${LOG_FILE}"
             elif [[ -z ${LOG_DIR_WRITE_WARN_SENT+x} ]]; then # Warn only once
                 echo -e "${COLOR_YELLOW}[${timestamp}] [WARN] - Cannot write to log directory $(dirname "${LOG_FILE}"). Logging to file disabled.${COLOR_RESET}" >&2
                 declare -g LOG_DIR_WRITE_WARN_SENT=true # Prevent repeating warning
                 LOG_TO_FILE=false # Disable further file logging attempts
             fi
        fi
    fi

    # Exit immediately for CRITICAL errors
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        log_message "ERROR" "Critical error encountered. Exiting script."
        # Cleanup is handled by trap
        exit 1 # Use a specific exit code? e.g., exit 1 for general critical
    fi
}

# --- Usage/Help Function ---
usage() {
    # Extract Usage section from header (Placeholder - refine extraction if needed)
    local usage_text
    usage_text=$(sed -n '/^# ===+ USAGE ===+$/,/^# ===+ .* ===+$/{ /# ===+ .* ===+$/!p; }' "${BASH_SOURCE[0]}" | sed 's/^# //; s/\[your_script_name.sh\]/'"${SCRIPT_NAME}"'/g')

    cat << EOF >&2
${usage_text}

Default Credentials File: ${DEFAULT_CREDENTIALS_FILE}
Default Output Directory: ${DEFAULT_OUTPUT_DIR}
Default Log File: ${LOG_FILE} (Timestamped on execution)
EOF
    exit 1
}

# --- Dependency Check Function ---
check_dependency() {
    local cmd="$1"
    local install_suggestion="${2:-$cmd}"
    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required command '${cmd}' not found."
        log_message "ERROR" "Please install the '${install_suggestion}' package (e.g., using 'apt', 'dnf', 'brew')."
        # CRITICAL log message handles exit
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
}

# --- Cleanup Function ---
cleanup() {
    local exit_status=$?
    log_message "DEBUG" "Performing cleanup..."
    # Remove temporary directory if it was created
    if [[ -n "${TEMP_DIR:-}" && -d "${TEMP_DIR}" ]]; then
        log_message "DEBUG" "Removing temporary directory: ${TEMP_DIR}"
        rm -rf "${TEMP_DIR}" || log_message "WARN" "Failed to remove temporary directory: ${TEMP_DIR}"
    fi
    # Close file descriptor 3 if still open (belt and suspenders)
    exec 3<&- &>/dev/null || true
    log_message "INFO" "Script finished with exit status: ${exit_status}"
    exit "${exit_status}" # Ensure script exits with the original status
}

# --- Trap Setup ---
# Register 'cleanup' to run on EXIT, INT, TERM, HUP signals.
trap cleanup EXIT INT TERM HUP

# --- Argument Parsing Function (Placeholder) ---
# Currently, this script doesn't take command-line arguments, but this provides structure.
parse_params() {
    log_message "DEBUG" "Parsing command line parameters (none currently implemented)."
    # Add getopts loop here if arguments are needed in the future
    # Example: while getopts ":hc:v" opt; do ... done
    # Ensure all arguments ($@) are handled or rejected if unexpected
    if [[ $# -gt 0 ]]; then
        log_message "WARN" "This script does not currently accept command-line arguments. Ignoring: $*"
        # Optionally call usage or exit if arguments are strictly forbidden
        # usage
    fi
}

# --- Input Validation Function ---
validate_inputs() {
    log_message "INFO" "Validating inputs and configuration..."

    # Check if credentials file exists and is readable
    if [[ ! -f "${CREDENTIALS_FILE}" || ! -r "${CREDENTIALS_FILE}" ]]; then
        log_message "CRITICAL" "Credentials file '${CREDENTIALS_FILE}' not found or not readable."
    fi
    if [[ ! -s "${CREDENTIALS_FILE}" ]]; then
         log_message "WARN" "Credentials file '${CREDENTIALS_FILE}' is empty."
         # Decide if this should be critical or just a warning
    fi


    # Validate numeric values
    if ! [[ "${TOP_ENTRIES}" =~ ^[0-9]+$ ]] || [[ ${TOP_ENTRIES} -le 0 ]]; then
        log_message "CRITICAL" "Invalid TOP_ENTRIES value: '${TOP_ENTRIES}'. Must be a positive integer."
    fi
    if ! [[ "${SSH_TIMEOUT}" =~ ^[0-9]+$ ]] || [[ ${SSH_TIMEOUT} -le 0 ]]; then
        log_message "CRITICAL" "Invalid SSH_TIMEOUT value: '${SSH_TIMEOUT}'. Must be a positive integer."
    fi

    # Validate log level
     if ! [[ "${LOG_LEVEL^^}" =~ ^(DEBUG|INFO|WARN|ERROR|CRITICAL)$ ]]; then
        log_message "WARN" "Invalid LOG_LEVEL '${LOG_LEVEL}'. Defaulting to INFO."
        LOG_LEVEL="INFO"
    fi


    # Check if output and log directories are writable
    if ! mkdir -p "${OUTPUT_DIR}"; then
        log_message "CRITICAL" "Output directory '${OUTPUT_DIR}' could not be created."
    elif [[ ! -w "${OUTPUT_DIR}" ]]; then
        log_message "CRITICAL" "Output directory '${OUTPUT_DIR}' is not writable."
    fi

    if [[ "${LOG_TO_FILE}" == true ]]; then
        if ! mkdir -p "$(dirname "${LOG_FILE}")"; then
            log_message "WARN" "Log directory '$(dirname "${LOG_FILE}")' could not be created. Disabling file logging."
            LOG_TO_FILE=false
        elif [[ ! -w "$(dirname "${LOG_FILE}")" ]]; then
            log_message "WARN" "Log directory '$(dirname "${LOG_FILE}")' is not writable. Disabling file logging."
            LOG_TO_FILE=false
        fi
    fi

    log_message "INFO" "Input validation passed."
}

# --- Environment Preparation Function ---
prepare_environment() {
    log_message "INFO" "Preparing execution environment..."

    # Create a secure temporary directory for the script's use
    TEMP_DIR=$(mktemp -d "${SCRIPT_DIR}/${SCRIPT_NAME}.XXXXXX")
    log_message "DEBUG" "Created temporary directory: ${TEMP_DIR}"
    # TEMP_DIR will be cleaned up by the 'trap cleanup'

    # Initialize Output CSV File with Header
    log_message "DEBUG" "Initializing output file: ${OUTPUT_FILE}"
    if ! echo "Timestamp,Server IP,Top Usage Files" > "$OUTPUT_FILE"; then
         log_message "CRITICAL" "Failed to write header to output file: ${OUTPUT_FILE}"
    fi


    # Initialize Log File with Header if logging to file
    if [[ "${LOG_TO_FILE}" == true ]]; then
        log_message "DEBUG" "Initializing log file: ${LOG_FILE}"
        if ! echo "Log for Top Disk Usage Script - $(date)" > "$LOG_FILE"; then
             log_message "WARN" "Failed to write header to log file: ${LOG_FILE}. File logging might fail."
             # Continue script execution, but file logging might be unreliable.
        fi
    fi

    log_message "INFO" "Environment preparation complete."
}


# --- Check Disk Usage Function ---
# Connects to a remote server, runs du, processes results.
# Arguments: $1: server_ip, $2: port, $3: username, $4: password
check_disk_usage() {
    local server_ip=$1
    local port=$2
    local username=$3
    local password=$4
    local timestamp; timestamp=$(date +"%Y-%m-%d %H:%M:%S") # Timestamp for this specific check
    local remote_cmd="du -ah / 2>/dev/null | sort -rh | head -n ${TOP_ENTRIES}"
    local temp_output_file; temp_output_file="${TEMP_DIR}/output_${server_ip}_${port}.txt" # Unique temp file per server call
    local ssh_exit_status

    log_message "INFO" "Checking disk usage on ${username}@${server_ip}:${port}"

    # Temporarily disable exit on error (-e) for the ssh command only
    set +e
    sshpass -p "$password" ssh \
        -p "$port" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout="${SSH_TIMEOUT}" \
        "${username}@${server_ip}" \
        "${remote_cmd}" > "${temp_output_file}" 2>> "${LOG_FILE}"
    ssh_exit_status=$?
    set -e # Re-enable exit on error

    if [[ ${ssh_exit_status} -ne 0 ]]; then
        log_message "ERROR" "SSH connection or command failed for ${server_ip} (Exit Status: ${ssh_exit_status}). Check log file."
        # Use printf for safer CSV formatting, especially with potential quotes in error message
        printf "%s,%s,\"ERROR: Connection failed (Exit Status: %s)\"\n" \
            "$timestamp" "$server_ip" "$ssh_exit_status" >> "$OUTPUT_FILE"
    else
        # Check if the temp file has content (size > 0)
        if [[ -s "${temp_output_file}" ]]; then
             log_message "DEBUG" "Successfully retrieved disk usage from ${server_ip}"
            # Process the output: join lines with '; '
            local top_files
            top_files=$(paste -sd "; " "${temp_output_file}" | tr -d '\n') # Ensure no trailing newline

            # Append to CSV, quoting the file list
            printf "%s,%s,\"%s\"\n" "$timestamp" "$server_ip" "$top_files" >> "$OUTPUT_FILE"
        else
            log_message "WARN" "SSH successful for ${server_ip}, but no disk usage output received (check permissions or command on remote host)."
            printf "%s,%s,\"No large files found or permission error\"\n" \
                "$timestamp" "$server_ip" >> "$OUTPUT_FILE"
        fi
    fi

    # Clean up the specific temporary file for this server connection
    rm -f "${temp_output_file}"
    log_message "DEBUG" "Finished processing ${server_ip}."
}


# --- Main Logic Function ---
main() {
    log_message "INFO" "Starting main script execution..."

    # Check if credentials file is empty after validation warnings
    if [[ ! -s "${CREDENTIALS_FILE}" ]]; then
         log_message "ERROR" "Credentials file '${CREDENTIALS_FILE}' is empty. No servers to process."
         exit 0 # Not a script error, but nothing to do.
    fi

    local total_servers
    total_servers=$(wc -l < "${CREDENTIALS_FILE}")
    local processed=0
    local server_ip port username password

    log_message "INFO" "Found ${total_servers} server(s) listed in ${CREDENTIALS_FILE}."

    # Open the credentials file using file descriptor 3 for safe reading
    exec 3< "$CREDENTIALS_FILE"

    # Read line by line
    while IFS=' ' read -r server_ip port username password <&3 || [[ -n "$server_ip" ]]; do # Handle last line without newline
        # Skip empty lines or lines starting with #
        if [[ -z "$server_ip" || "$server_ip" =~ ^# ]]; then
            log_message "DEBUG" "Skipping empty or commented line."
            continue
        fi

        ((processed++))
        log_message "INFO" "Processing server ${processed} of ${total_servers}: ${server_ip}"
        # Log credentials being used (Mask password in production!)
        log_message "DEBUG" "Credentials - IP: ${server_ip}, Port: ${port}, User: ${username}, Pass: ********"

        # Call the function for the current server
        check_disk_usage "$server_ip" "$port" "$username" "$password"

        # Reset variables for next iteration (paranoid check)
        server_ip="" port="" username="" password=""

    done

    # Close the file descriptor
    exec 3<&-

    log_message "INFO" "Finished processing all servers listed in ${CREDENTIALS_FILE}."
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# 1. Parse Command Line Arguments (Currently none)
parse_params "$@"

# 2. Validate Inputs and Configuration (Files, Paths, Variables)
validate_inputs

# 3. Check Dependencies (Required external commands)
log_message "INFO" "Checking required dependencies..."
check_dependency "sshpass" "sshpass - Non-interactive SSH password provider (SECURITY RISK)"
check_dependency "ssh" "openssh-client - SSH client"
check_dependency "wc" "coreutils - Word count utility"
check_dependency "date" "coreutils - Date/time utility"
check_dependency "paste" "coreutils - Merge lines utility"
check_dependency "tr" "coreutils - Translate characters utility"
check_dependency "mktemp" "coreutils - Create temporary files utility"
check_dependency "sort" "coreutils - Sort utility (remote dependency)"
check_dependency "head" "coreutils - Head utility (remote dependency)"
check_dependency "du" "coreutils - Disk usage utility (remote dependency)"

# 4. Prepare Environment (Create temp dirs, initialize files)
prepare_environment

# 5. Execute Main Logic
main

# 6. Exit Successfully (Cleanup is handled by trap)
# The 'trap cleanup EXIT' will run automatically here.
# log_message is called within cleanup to indicate completion.
# Exit code is handled by cleanup to preserve original status.

# =========================================================================================
# --- End of Script ---
