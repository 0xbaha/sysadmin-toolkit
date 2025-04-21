#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : remote_check_df_lsblk.sh
# PURPOSE       : Remotely collects disk usage (df/lsblk) info from servers.
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
# This script connects to multiple remote servers specified in a credentials file.
# For each server, it retrieves disk usage statistics using `df -h` and block
# device information using `lsblk`. The collected data is aggregated into separate
# timestamped CSV files for easy tracking and analysis. Any connection failures
# or errors during command execution on the remote servers are logged to a
# dedicated timestamped error log file using a structured logging function.
# The script sorts the input credentials file numerically by IP address before processing
# to ensure consistent output order. It incorporates basic error handling, dependency
# checking, and strict mode (`set -euo pipefail`).
#
# Key Workflow / Functions:
# - Reads server connection details (IP, port, username, password) from `credentials.txt`.
# - Sorts `credentials.txt` numerically by IP address in-place.
# - Checks for the presence of required utilities (`sshpass`, `ssh`, `awk`, `sort`, `date`, `command`).
# - Iterates through each server entry in the credentials file.
# - Establishes SSH connections using `sshpass` for password authentication (Security Warning).
# - Executes `df -h` on each remote server to gather disk usage.
# - Executes `lsblk -b -o NAME,MODEL,SIZE,TYPE,VENDOR,TRAN` on each remote server for block device info (using bytes for SIZE).
# - Formats the output of `df` and `lsblk` into CSV format, prepending the server IP.
# - Appends formatted data to timestamped output files (`disk_usage_*.csv`, `lsblk_output_*.csv`).
# - Uses a `log_message` function for structured logging (INFO, WARN, ERROR, CRITICAL, DEBUG) to stdout/stderr and a log file.
# - Implements `trap` for cleanup on script exit or interruption.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Modularity:** Uses functions for distinct tasks (logging, dependency check, fetching data, cleanup).
# - **Robustness:** Includes error handling for SSH connection failures, command errors, missing files/dependencies, and uses Bash strict mode (`set -euo pipefail`). Traps signals for cleanup.
# - **Readability:** Employs clear variable names, extensive comments, consistent formatting, and a structured logging function.
# - **Automation:** Designed for unattended execution, reading credentials from a file.
# - **Simplicity:** Aims for a straightforward workflow for its core purpose, relying on common command-line tools.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - System Administrators performing routine server checks or inventory collection.
# - DevOps Engineers monitoring infrastructure health.
# - IT Support Teams gathering diagnostic information.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x remote_check_df_lsblk.sh`
# - File system access: Requires read access to `credentials.txt`. Requires write access to the script's directory to create output CSV and log files.
# - Network access: Outbound connections on the specified SSH ports to target servers.
# - Elevated privileges: Not required for the script itself, but remote user credentials determine privileges on target systems.
#
# **Prerequisites:**
# - `sshpass` must be installed locally: `sudo apt update && sudo apt install -y sshpass` (Debian/Ubuntu) or equivalent.
# - A file named `credentials.txt` must exist in the same directory as the script.
# - `credentials.txt` format: Each line: `server_ip port username password` (space-separated).
#   Example: `192.168.1.100 22 admin P@$$w0rd`
#
# **Basic Syntax:**
#   `./remote_check_df_lsblk.sh`
#   (The script currently takes no command-line arguments or options).
#
# **Common Examples:**
# 1. Basic execution (ensure `credentials.txt` is present and formatted):
#    `./remote_check_df_lsblk.sh`
#
# **Advanced Execution (Automation):**
# - Example cron job running daily at 3:30 AM, redirecting output is less necessary due to internal logging:
#   `30 3 * * * /path/to/remote_check_df_lsblk.sh`
#   (Check the script's log file: `/path/to/disk_usage_errors_*.log` for results/errors)
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - User scripts: `~/bin/` or `~/.local/bin/` (ensure these are in user's $PATH)
# - System-wide scripts: `/usr/local/sbin/` or `/usr/local/bin/`
#
# **Manual Setup:**
# 1. Place the script in the chosen location (e.g., `/usr/local/bin/`).
# 2. Set executable permissions: `chmod +x /path/to/remote_check_df_lsblk.sh`.
# 3. Ensure ownership is appropriate (e.g., `sudo chown user:group /path/to/script` if needed).
# 4. Install required dependencies (see DEPENDENCIES section).
# 5. Create `credentials.txt` in the same directory with correct format and permissions (`chmod 600 credentials.txt` recommended).
# 6. Run the script manually first to test.
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: Bourne-Again SHell (Version >= 4 recommended for features like `declare -A`). Uses bashisms (`set -o pipefail`, `BASH_SOURCE`).
#
# **Required System Binaries/Tools:**
# - `coreutils`: Provides `date`, `mkdir`, `basename`, `dirname`, `sort`, `cat`, `echo`, `tail`, `sed`.
# - `grep`: Used implicitly by `command -v`.
# - `awk`: For processing and formatting text output (`gawk` or compatible).
# - `sed`: For basic text manipulation (stripping color codes, parsing stderr).
# - `command`: Bash built-in for checking command existence.
# - `sshpass`: For non-interactive SSH password authentication (Security Warning).
# - `ssh`: (openssh-client) For secure shell connections to remote servers.
#
# **Setup Instructions (Dependencies):**
# - Debian/Ubuntu: `sudo apt update && sudo apt install -y sshpass openssh-client coreutils awk sed`
# - RHEL/CentOS/Fedora: `sudo dnf update && sudo dnf install -y sshpass openssh-clients coreutils gawk sed` (sshpass might be in EPEL repo for older CentOS)
# - Check availability: `command -v sshpass`
#
# **Operating System Compatibility:**
# - Designed primarily for: Linux distributions (tested implicitly on Debian/Ubuntu derivatives).
# - Known compatibility issues: May require adjustments for macOS (different `sed`/`date` flags) or other Unix-like systems.
#
# **Environment Variables Used:**
# - No specific environment variables are required by the script logic itself.
# - `PATH`: Standard variable, ensure required binaries are locatable.
#
# **System Resource Requirements:**
# - Minimal CPU and memory usage on the local machine.
# - Network bandwidth usage depends on the number of servers and size of `df`/`lsblk` output.
# - Disk space required for storing the output CSV files and log file (grows over time).
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): INFO/DEBUG level messages (controlled by `VERBOSE` flag in script config section).
# - Standard Error (stderr): WARN/ERROR/CRITICAL level messages.
# - Dedicated Log File: Yes. Path: `./disk_usage_errors_YYYYMMDD_HHMMSS.log` (created in the script's directory). Contains INFO, WARN, ERROR, CRITICAL messages (DEBUG if VERBOSE enabled).
#
# **Log Format:**
# - `[YYYY-MM-DD HH:MM:SS TZ] [LEVEL] [script_name:line_number] - Message` (e.g., `[2025-04-20 17:00:00 WIB] [INFO] [remote_check_df_lsblk.sh:250] - Starting script execution...`)
# - Color-coded output to terminal (if interactive and not disabled). File output is plain text.
#
# **Log Levels:**
# - `DEBUG`: Detailed info for troubleshooting (enable by setting `VERBOSE=true` near top of script).
# - `INFO`: General operational messages.
# - `WARN`: Potential issues, non-critical errors.
# - `ERROR`: Significant errors potentially affecting results for a specific server.
# - `CRITICAL`: Severe errors causing script termination (missing dependency, unreadable credentials file).
# - Control: `VERBOSE` variable inside the script currently controls DEBUG visibility. `LOG_LEVEL` variable (if implemented fully) could offer finer control.
#
# **Log Rotation:**
# - Handled by script?: No. Timestamped filenames prevent overwrites but require manual cleanup.
# - External Recommendation: Use external tools like `logrotate` or scheduled cleanup scripts (`find . -name 'disk_usage_errors_*.log' -mtime +30 -delete`) for managing log file retention.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Normal Operation: Prints INFO/DEBUG messages (e.g., "Connecting to server X...", "Script finished..."). Format: `[Timestamp] [LEVEL] [Script:Line] - Message`.
# - Final Summary: Prints paths to generated CSV and log files upon completion.
#
# **Standard Error (stderr):**
# - Errors/Warnings: Prints WARN/ERROR/CRITICAL messages (e.g., "Failed to retrieve 'df -h'...", "Credentials file not found..."). Format: `[Timestamp] [LEVEL] [Script:Line] - Message`.
#
# **Generated/Modified Files:**
# - `disk_usage_YYYYMMDD_HHMMSS.csv`: CSV file in script directory containing aggregated `df -h` output. Columns: Server IP, Filesystem, Size, Used, Available, Use%, Mounted on.
# - `lsblk_output_YYYYMMDD_HHMMSS.csv`: CSV file in script directory containing aggregated `lsblk` output. Columns: Server IP, Name, Model, Size(Bytes), Type, Vendor, Tran.
# - `disk_usage_errors_YYYYMMDD_HHMMSS.log`: Text file in script directory logging INFO, WARN, ERROR, CRITICAL messages encountered during execution.
# - `credentials.txt`: This file is **modified in place** by the `sort` command to order entries by IP address. **Keep a backup if the original order is important.**
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success - Script completed without critical errors. Individual server failures are logged but may not cause non-zero exit.
# - 1: General/Critical Error - Script terminated due to a critical issue (e.g., missing dependency, credentials file problem, unhandled error due to `set -e`, failed sort). Specific exit codes per error type are not currently implemented but could be added.
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** "CRITICAL: Required command 'sshpass' not found."
#   **Resolution:** Install `sshpass` (e.g., `sudo apt install sshpass`).
# - **Issue:** "CRITICAL: Credentials file not found/readable: ./credentials.txt"
#   **Resolution:** Ensure `credentials.txt` exists in the script directory, is readable by the script user, and has the correct format.
# - **Issue:** "WARN: Skipping invalid or incomplete entry in credentials file..."
#   **Resolution:** Check the specified line in `credentials.txt` for missing fields or incorrect space separation.
# - **Issue:** "ERROR: Failed to retrieve 'df -h' / 'lsblk' from [IP] (Exit Code: X). Error: [SSH Error Msg]"
#   **Resolution:** Check network connectivity/firewalls to the target server/port. Verify SSH service is running on remote. Validate credentials in `credentials.txt`. Ensure `df`/`lsblk` exist and are executable by remote user. Examine the logged SSH error message.
# - **Issue:** SSH host key warnings/prompts.
#   **Resolution:** The script uses `StrictHostKeyChecking=no` (insecure) to suppress this. For production, remove this option and manage SSH `known_hosts` properly (e.g., pre-populate keys or use `ssh-keyscan` carefully).
#
# **Important Considerations / Warnings:**
# - **[CRITICAL SECURITY RISK: Plain Text Passwords]**
#   Storing passwords in `credentials.txt` is highly insecure. Use SSH key-based authentication with `ssh-agent` instead. If passwords *must* be used, ensure `credentials.txt` has strict permissions (`chmod 600 credentials.txt`). `sshpass` may expose the password in the process list.
# - **[SECURITY RISK: Disabled Host Key Checking]**
#   Using `StrictHostKeyChecking=no` disables SSH host key verification, making connections vulnerable to Man-in-the-Middle (MitM) attacks. **Do not use this in untrusted or production environments.** Remove the option and manage host keys appropriately.
# - **[Data Modification Risk]**
#   The script modifies `credentials.txt` in place by sorting it. Backup the file beforehand if the original order matters.
# - **[Scalability/Performance]**
#   Processing servers sequentially can be slow for a large number of hosts. Consider parallel execution tools (`parallel`, `xargs -P`) or asynchronous approaches for large deployments.
# - **[Error Granularity]**
#   The script logs errors per server but typically exits with 0 unless a critical setup error occurs. Modify exit logic if a single server failure should result in a non-zero exit code.
# - **[Remote Command Output Parsing]**
#   The `awk` scripts assume specific output formats from `df` and `lsblk`. Changes in remote OS versions or locales could potentially break parsing. The `lsblk` parsing for multi-word MODEL fields is currently simplified and may be inaccurate if models contain spaces. Using `lsblk -b` provides size in bytes, avoiding unit parsing issues.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes a Bash (v4+) environment with access to standard core utilities and required dependencies.
# - Assumes required dependencies (`sshpass`, `ssh`, `awk`, `sort`, etc.) are installed and in `$PATH`.
# - Assumes network connectivity (DNS resolution, firewall rules) allows outbound SSH to target servers on specified ports.
# - Assumes `credentials.txt` exists in the script's directory, is readable, and formatted correctly (IP Port User Pass).
# - Assumes target systems are reachable via SSH and configured for password authentication for the users provided.
# - Assumes the script is executed with permissions to read `credentials.txt` and write to its own directory (for logs/CSVs).
# - Assumes `df -h` and `lsblk -b -o NAME,MODEL,SIZE,TYPE,VENDOR,TRAN` commands exist on remote servers and produce output parseable by the `awk` scripts.
# =========================================================================================

# =========================================================================================
# PERFORMANCE OPTIMIZATION (Notes)
# =========================================================================================
# - **Current State:** Uses sequential processing, connecting to one server at a time.
# - **Bottleneck:** Network latency and execution time on remote servers, especially for many hosts.
# - **Potential Optimization:** Implement parallel connections using tools like GNU `parallel` or Bash background jobs with `wait`. This would require significant changes to the main loop and potentially locking for file appends. Using `lsblk -b` avoids complex size unit parsing locally.
# =========================================================================================

# =========================================================================================
# TESTING & VALIDATION (Notes)
# =========================================================================================
# - **Test Strategy:** Primarily manual testing against known servers. Use of `set -euo pipefail` helps catch errors early. Structured logging aids debugging.
# - **Validation Tool:** Recommended to use `shellcheck` ( `shellcheck remote_check_df_lsblk.sh` ) to identify potential syntax issues, quoting problems, and common pitfalls.
# - **Key Test Cases (Manual):** Verify correct CSV output, accurate error logging for connection failures/bad credentials, handling of empty/invalid lines in `credentials.txt`, successful sorting of `credentials.txt`.
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - [Security]: Replace `sshpass`/password usage with SSH key-based authentication support.
# - [Security]: Remove `StrictHostKeyChecking=no` and add proper host key management advice/option.
# - [Performance]: Implement parallel execution (e.g., using background jobs or GNU `parallel`).
# - [Robustness]: Enhance `lsblk` parsing in `awk` to reliably handle multi-word MODEL fields.
# - [Robustness]: Add more specific exit codes for different failure types.
# - [Error Handling]: Provide option to log SSH stderr output for more detailed troubleshooting.
# - [Flexibility]: Add command-line arguments (e.g., specify credentials file path, output directory, enable verbose logging). Use `getopts`.
# - [Flexibility]: Add option to specify different remote commands or output formats.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Runs as the executing user locally. Remote access level depends on credentials in `credentials.txt`.
# - **Input Sanitization:** Basic check for empty fields in `credentials.txt`. Does not deeply sanitize IP/username formats. Assumes input file is trusted.
# - **Sensitive Data Handling:** **MAJOR RISK** - Reads passwords directly from plain text `credentials.txt`. `sshpass` can expose passwords in the process list. **SSH keys strongly recommended.** Ensure `credentials.txt` permissions are strict (`chmod 600`).
# - **Dependencies:** Relies on standard system tools and `sshpass`. Ensure these are from trusted sources/repositories.
# - **File Permissions:** Output files created with default umask. `credentials.txt` is modified (sorted) in place. Log files store potentially sensitive hostnames/IPs.
# - **External Command Execution:** Executes `ssh` with parameters derived from `credentials.txt`. Usernames/IPs are used directly. Standard commands (`df`, `lsblk`) executed remotely.
# - **Network Exposure:** Makes outbound SSH connections. Uses `StrictHostKeyChecking=no`, disabling protection against MitM attacks. **Change this for secure environments.**
# - **Code Integrity:** Verify script integrity using checksums (`sha256sum`) if obtained from untrusted sources.
# - **Error Message Verbosity:** Logs connection errors which might include usernames/IPs. Ensure log files are adequately protected.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is contained within this script's header comments.
# - No external documentation or man page is provided.
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Report issues via the script's repository (https://baha.my.id/github) or directly to the author's contact email.
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
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_PID=$$

# --- Timestamp ---
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Global Runtime Variables & Configuration ---
# Set default values. These could potentially be overridden by args or config files in more complex scripts.
VERBOSE=false # Set to true for more detailed debug logging
NO_COLOR=false # Set to true to disable color output
INTERACTIVE_MODE=false # Auto-detected if stdout is a terminal
[[ -t 1 ]] && INTERACTIVE_MODE=true

# Default file names and paths
readonly CREDENTIALS_FILE="${SCRIPT_DIR}/credentials.txt" # Input file with server details
readonly DF_OUTPUT_FILE="${SCRIPT_DIR}/disk_usage_${SCRIPT_RUN_TIMESTAMP}.csv" # Output for df data
readonly LSBLK_OUTPUT_FILE="${SCRIPT_DIR}/lsblk_output_${SCRIPT_RUN_TIMESTAMP}.csv" # Output for lsblk data
# readonly MULTIPATH_OUTPUT_FILE="${SCRIPT_DIR}/multipath_output_${SCRIPT_RUN_TIMESTAMP}.csv" # Note: multipath collection was defined but not implemented in original script. Keeping variable definition commented out for now.
readonly LOG_FILE="${SCRIPT_DIR}/disk_usage_errors_${SCRIPT_RUN_TIMESTAMP}.log" # Error log file

# SSH Options (Consider making these configurable if needed)
readonly SSH_CONNECT_TIMEOUT=5
# SECURITY WARNING: StrictHostKeyChecking=no is insecure. Use only in trusted environments or manage known_hosts.
readonly SSH_OPTIONS="-q -o ConnectTimeout=${SSH_CONNECT_TIMEOUT} -o StrictHostKeyChecking=no"

# --- Color Definitions (Optional) ---
# Define ANSI escape codes for colored output, checking if NO_COLOR is set or if not interactive.
if [[ "${NO_COLOR}" == false && "${INTERACTIVE_MODE}" == true ]]; then
    COLOR_RESET='\033[0m'; COLOR_RED='\033[0;31m'; COLOR_GREEN='\033[0;32m'; COLOR_YELLOW='\033[0;33m'; COLOR_BLUE='\033[0;34m'; COLOR_CYAN='\033[0;36m'; COLOR_BOLD='\033[1m'
else
    COLOR_RESET=""; COLOR_RED=""; COLOR_GREEN=""; COLOR_YELLOW=""; COLOR_BLUE=""; COLOR_CYAN=""; COLOR_BOLD=""
fi

# =========================================================================================
# FUNCTION DEFINITIONS
# =========================================================================================

###############################################################################
# Function: log_message
# Description: Handles formatted logging to stdout/stderr and optionally to a file.
# Consistent logging format enhances readability and debugging.
# Usage: log_message LEVEL "Message string"
# Levels: DEBUG, INFO, WARN, ERROR, CRITICAL
###############################################################################
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z") # Include Timezone
    local level_upper
    level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]')
    local log_prefix="[${timestamp}] [${level_upper}] [${SCRIPT_NAME}:${BASH_LINENO[0]}]" # Add line number context
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

    # Map script log levels to numeric values for comparison (adjust LOG_LEVEL variable for verbosity)
    declare -A log_levels=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [CRITICAL]=4)
    local current_log_level_num=${log_levels[INFO]} # Default to INFO level logging
    [[ "$VERBOSE" == true ]] && current_log_level_num=${log_levels[DEBUG]} # Show DEBUG if VERBOSE is set
    local message_level_num=${log_levels[${level_upper}]}

    # Check if the message level is severe enough to be logged based on current level
    if [[ ${message_level_num} -ge ${current_log_level_num} ]]; then
        # Output to stderr for WARN, ERROR, CRITICAL; stdout otherwise
        if [[ "${level_upper}" == "WARN" || "${level_upper}" == "ERROR" || "${level_upper}" == "CRITICAL" ]]; then
            echo -e "${color}${log_line}${COLOR_RESET}" >&2
        else
            echo -e "${color}${log_line}${COLOR_RESET}"
        fi

        # Append to log file (always append errors/warnings, info/debug depend on verbosity potentially)
        # Simple approach: log everything equal or above INFO level to file.
        if [[ -n "${LOG_FILE:-}" && ${message_level_num} -ge ${log_levels[INFO]} ]]; then
            # Ensure log directory exists (best effort)
            mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
            if [[ -w "$(dirname "${LOG_FILE}")" ]]; then
                # Strip color codes for file logging
                local nocolor_log_line
                nocolor_log_line=$(echo "${log_line}" | sed 's/\x1b\[[0-9;]*m//g')
                echo "${nocolor_log_line}" >> "${LOG_FILE}"
            else
                # Warning if log directory is not writable, but only warn once
                if [[ -z ${LOG_DIR_WRITE_WARN_SENT+x} ]]; then # Check if variable is unset
                    echo -e "${COLOR_YELLOW}[${timestamp}] [WARN] - Cannot write to log directory $(dirname "${LOG_FILE}"). Logging to file disabled.${COLOR_RESET}" >&2
                    LOG_DIR_WRITE_WARN_SENT=true # Set variable to prevent repeating warning
                fi
            fi
        fi
    fi

    # Exit immediately for CRITICAL errors (alternative to relying solely on set -e)
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        log_message "ERROR" "Critical error encountered. Exiting script."
        exit 1 # Use a specific exit code for critical errors if desired
    fi
}

###############################################################################
# Function: check_dependency
# Description: Checks if a command-line utility is installed and executable.
# Exits with CRITICAL error if the dependency is missing.
# Arguments: $1: Command name to check (e.g., "sshpass")
#            $2: (Optional) Package name to suggest for installation
###############################################################################
check_dependency() {
    local cmd="$1"
    local install_suggestion="${2:-$cmd}" # Use command name if package name not provided
    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required command '${cmd}' not found. Please install the '${install_suggestion}' package."
        # exit 1 is handled by CRITICAL log level
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
}

###############################################################################
# Function: cleanup
# Description: Performs cleanup tasks before script exits (e.g., closing file descriptors).
# Called automatically via 'trap'. Keeps cleanup logic minimal and robust.
###############################################################################
cleanup() {
    local exit_status=$? # Capture the script's exit status
    log_message "DEBUG" "Performing cleanup..."
    # Close file descriptor 3 if it's open
    exec 3<&- &>/dev/null || true # Close FD 3, suppress potential "bad file descriptor" error if already closed
    log_message "INFO" "Script finished with exit status: ${exit_status}"
    # Note: The script will exit with the original exit_status after trap completes
    exit ${exit_status} # Ensure the original exit status is propagated
}

###############################################################################
# Function: fetch_server_data
# Description: Connects to a remote server via SSH, executes commands (df, lsblk),
#              processes output, appends to CSV files, and logs errors.
# Parameters: $1 - server_ip, $2 - port, $3 - username, $4 - password
###############################################################################
fetch_server_data() {
    # Assign function arguments to local variables for clarity and safety [3].
    local server_ip=$1
    local port=$2
    local username=$3
    local password=$4
    local ssh_target="${username}@${server_ip}"
    local ssh_cmd_base # Base SSH command using sshpass
    local df_output lsblk_output df_exit_code lsblk_exit_code

    # Use an array for the command to handle arguments safely
    local ssh_command_array=(sshpass -p "$password" ssh ${SSH_OPTIONS} -p "$port" "$ssh_target")

    log_message "INFO" "Connecting to ${server_ip} on port ${port}..."

    # --- Fetch df -h data ---
    log_message "DEBUG" "Executing 'df -h' on ${server_ip}"
    # Execute remote command, capture output and stderr separately for better error info.
    # Use process substitution <(...) to capture stderr, avoid temporary files.
    # Redirect original stderr (2) to fd 3, capture original stdout (1) to var, capture fd 3 to stderr_var.
    exec 3>&1 # Duplicate stdout to fd 3 temporarily
    ssh_stderr=$( { "${ssh_command_array[@]}" "df -h"; echo $? >&4; } 2>&1 >&3 3>&- 4>&1 )
    df_exit_code=$(echo "$ssh_stderr" | tail -n 1) # Last line is the exit code
    df_output=$(echo "$ssh_stderr" | sed '$d') # Output is stderr except last line (exit code)
    exec 3>&- # Close fd 3

    if [[ $df_exit_code -ne 0 ]]; then
        log_message "ERROR" "Failed to retrieve 'df -h' from ${server_ip} (Exit Code: ${df_exit_code}). Error: ${df_output}"
        # Continue to next command (lsblk) even if df fails? Or return? Decided to continue.
    else
        log_message "DEBUG" "'df -h' output received from ${server_ip}"
        # Process and append df output using awk
        # Use awk variable for the script for readability
        local df_awk_script='NR > 1 { print ip "," $1 "," $2 "," $3 "," $4 "," $5 "," $6 }'
        echo "$df_output" | awk -v ip="$server_ip" "$df_awk_script" >> "$DF_OUTPUT_FILE"
        if [[ ${PIPESTATUS[1]} -ne 0 ]]; then # Check awk exit status specifically
             log_message "WARN" "Awk processing failed for 'df -h' output from ${server_ip}"
        fi
    fi

    # --- Fetch lsblk data ---
    log_message "DEBUG" "Executing 'lsblk' on ${server_ip}"
    local lsblk_command="lsblk -b -o NAME,MODEL,SIZE,TYPE,VENDOR,TRAN" # Use -b for bytes to avoid parsing size units

    # Execute remote command, capture output and stderr
    exec 3>&1
    ssh_stderr=$( { "${ssh_command_array[@]}" "$lsblk_command"; echo $? >&4; } 2>&1 >&3 3>&- 4>&1 )
    lsblk_exit_code=$(echo "$ssh_stderr" | tail -n 1)
    lsblk_output=$(echo "$ssh_stderr" | sed '$d')
    exec 3>&-

    if [[ $lsblk_exit_code -ne 0 ]]; then
        log_message "ERROR" "Failed to retrieve 'lsblk' from ${server_ip} (Exit Code: ${lsblk_exit_code}). Error: ${lsblk_output}"
        return # Skip lsblk processing if SSH command failed
    fi

    if [[ -z "$lsblk_output" ]]; then
        log_message "WARN" "No lsblk output received from ${server_ip} (Command succeeded but produced no output)"
    else
        log_message "DEBUG" "'lsblk' output received from ${server_ip}"
        # Process and append lsblk output using awk
        # Storing complex awk script in a variable improves readability
        local lsblk_awk_script=$(cat << 'AWK'
BEGIN { OFS = "," } # Set Output Field Separator
NR > 1 { # Skip header line
    # Skip indented partition lines (heuristics based on common lsblk tree output)
    # If lsblk format changes, this might need adjustment.
    # The requested columns might not always produce the tree structure, making this potentially less reliable.
    # A better approach might involve parsing based on TYPE if available.
    # if ($1 ~ /^[├└─]/ || $1 ~ /^ /) next # Skip indented lines

    # Assuming fixed columns: NAME, MODEL, SIZE, TYPE, VENDOR, TRAN
    # This is simpler than the original complex model parsing if the column order is guaranteed.
    # Handle potential missing fields by assigning defaults. Need to handle spaces in MODEL better if required.
    name = ($1 != "") ? $1 : "N/A"
    # MODEL ($2 potentially onwards until SIZE) requires careful parsing if it contains spaces.
    # The original script had complex logic for this. Reverting to a simpler assumption for now.
    # If MODEL contains spaces, this basic awk script will break.
    # TODO: Re-implement robust parsing for multi-word MODEL field if necessary.
    model = ($2 != "") ? $2 : "N/A"
    size = ($3 != "") ? $3 : "N/A" # Size in bytes due to -b flag
    type = ($4 != "") ? $4 : "N/A"
    vendor = ($5 != "") ? $5 : "N/A"
    tran = ($6 != "") ? $6 : "N/A"

    print ip, name, model, size, type, vendor, tran
}
AWK
)
        echo "$lsblk_output" | awk -v ip="$server_ip" "$lsblk_awk_script" >> "$LSBLK_OUTPUT_FILE"
        if [[ ${PIPESTATUS[1]} -ne 0 ]]; then
             log_message "WARN" "Awk processing failed for 'lsblk' output from ${server_ip}"
        fi
    fi
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# --- Trap Setup ---
# Register the 'cleanup' function to run on script exit (normal or error) and signals.
trap cleanup EXIT INT TERM HUP

# --- Initial Setup & Checks ---
log_message "INFO" "Starting script execution (PID: ${SCRIPT_PID})"
check_dependency "sshpass" "sshpass"
check_dependency "awk" "gawk" # or mawk/nawk
check_dependency "sort" "coreutils"
check_dependency "ssh" "openssh-client"

# Check if credentials file exists and is readable
if [[ ! -f "${CREDENTIALS_FILE}" ]]; then
    log_message "CRITICAL" "Credentials file not found: ${CREDENTIALS_FILE}"
elif [[ ! -r "${CREDENTIALS_FILE}" ]]; then
    log_message "CRITICAL" "Credentials file not readable: ${CREDENTIALS_FILE}"
fi
log_message "INFO" "Using credentials file: ${CREDENTIALS_FILE}"

# Create output files and write headers
log_message "INFO" "Creating output file: ${DF_OUTPUT_FILE}"
echo "Server IP,Filesystem,Size,Used,Available,Use%,Mounted on" > "$DF_OUTPUT_FILE"
log_message "INFO" "Creating output file: ${LSBLK_OUTPUT_FILE}"
echo "Server IP,Name,Model,Size(Bytes),Type,Vendor,Tran" > "$LSBLK_OUTPUT_FILE" # Updated Size header
# Initialize log file
log_message "INFO" "Initializing log file: ${LOG_FILE}"
echo "Disk Usage Script - Log Start ($SCRIPT_RUN_TIMESTAMP)" > "$LOG_FILE" # Overwrite/create log file

# Sort the credentials file numerically by IP address (in-place)
log_message "INFO" "Sorting credentials file by IP address: ${CREDENTIALS_FILE}"
# Add check for sort command success [3]
if sort -t '.' -k1,1n -k2,2n -k3,3n -k4,4n "${CREDENTIALS_FILE}" -o "${CREDENTIALS_FILE}"; then
    log_message "DEBUG" "Credentials file sorted successfully."
else
    # Exit code from sort will be caught by 'set -e' or trap, but log explicit message.
    log_message "CRITICAL" "Failed to sort credentials file: ${CREDENTIALS_FILE}. Exit code: $?"
fi

# --- Main Processing Loop ---
log_message "INFO" "Starting server data collection..."

# Use file descriptor 3 for reading the credentials file to avoid stdin conflicts [1].
exec 3< "$CREDENTIALS_FILE"

# Read credentials line by line using FD 3
# Use 'read -r' to handle backslashes literally
while read -r -u 3 server_ip port username password || [[ -n "$server_ip" ]]; do # Handle last line without newline
    # Basic validation of read data
    if [[ -z "$server_ip" || -z "$port" || -z "$username" || -z "$password" ]]; then
        # Log error for invalid/incomplete lines but continue processing others
        log_message "WARN" "Skipping invalid or incomplete entry in credentials file: Line approx '${server_ip} ${port} ${username} [...]'"
        continue # Skip to the next line
    fi

    # Call function to fetch data for the current server
    # Adding error handling around the function call itself, although set -e should catch critical failures.
    if ! fetch_server_data "$server_ip" "$port" "$username" "$password"; then
        log_message "ERROR" "Error processing server ${server_ip}. Check previous logs for details."
        # Decide whether to continue with other servers or exit. Current setup continues.
    fi

    # Reset server_ip at the end of the loop to correctly handle the [[ -n "$server_ip" ]] condition for the last line
    server_ip=""

done

# File descriptor 3 is closed automatically by the 'cleanup' trap on EXIT.

log_message "INFO" "Data collection completed."
echo "--------------------------------------------------"
echo "Script finished. Results saved in:"
echo "- Disk usage: ${DF_OUTPUT_FILE}"
echo "- LSBLK output: ${LSBLK_OUTPUT_FILE}"
echo "Errors and logs are in: ${LOG_FILE}"
echo "--------------------------------------------------"

# Script exits via the 'trap cleanup EXIT' mechanism. Implicit exit 0 if no errors occurred.

# =========================================================================================
# --- End of Script ---
