#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : stress_test_local_resources.sh
# PURPOSE       : Applies configurable CPU/memory/disk stress load on Linux systems.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2024-11-02
# LAST UPDATED  : 2024-11-02
# VERSION       : 1.0.0
# =========================================================================================

# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This script is designed to stress test a Linux system's core resources:
# - CPU Load: Uses 'stress-ng' to target approximately 90% utilization across
#   all available CPU cores.
# - Memory Load: Uses 'stress-ng' to allocate and utilize approximately 90% of
#   the total available system memory.
# - Disk Usage: Continuously creates 1GB files (using /dev/urandom) in a specified
#   target directory until the disk usage reaches 90% capacity.
# - Monitoring: Periodically records CPU load, memory usage, and target disk usage
#   percentages to a statistics log file using standard Linux tools (top, free, df).
# - Control: Provides commands to start the test, gracefully stop all background
#   processes (CPU/memory stress, disk filling, monitoring), and calculate
#   average resource usage from the latest statistics log.
#
# Key Functions:
# - Checks for required sudo permissions.
# - Attempts automatic installation of the 'stress-ng' dependency if missing (using apt).
# - Validates and optionally sets permissions for the target disk fill directory.
# - Launches 'stress-ng' for CPU and memory load in the background.
# - Launches a disk filling process (`fill_disk`) in the background.
# - Launches a resource monitoring loop (`monitor_resources`) in the background.
# - Stores PIDs of background processes in a file (`resource_test_pids`) for reliable termination.
# - Provides 'stop' command to terminate all script-initiated background processes.
# - Provides 'count' command to parse the stats log and calculate average CPU, Memory,
#   and Disk usage over the test duration.
# - Creates timestamped log files for general info/errors (`resource_test_info_*`) and
#   resource statistics (`resource_test_stats_*`).
# - Includes basic error handling and structured logging.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Resource Intensity:** Intentionally designed to push CPU, memory, and disk
#   resources towards high utilization levels for effective stress testing.
# - **Robustness:** Includes checks for prerequisites (sudo, dependencies), basic
#   error handling (directory permissions, command failures), and reliable process
#   management via PID tracking for clean termination. Uses `set -euo pipefail` for stricter execution.
# - **Monitoring:** Provides continuous feedback on resource consumption through
#   periodic logging to a dedicated statistics file.
# - **Control:** Offers simple command-line arguments for starting, stopping, and
#   analyzing the test run.
# - **Readability:** Employs functions, comments, clear variable names, and structured logging.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - System Administrators
# - Performance Testers
# - DevOps Engineers
# - Infrastructure Engineers
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x stress_test_local_resources.sh`
# - Requires `sudo` privileges for:
#   - Initial check (`sudo -v`).
#   - Installing packages (`stress-ng` via `apt-get`).
#   - Killing processes reliably via `stop` command (`sudo kill`).
#   - Potentially creating/modifying the target directory (`TARGET_DIR_CONFIG`/`/data` via `sudo mkdir`/`sudo chmod`).
#
# **Basic Syntax:**
# `sudo ./stress_test_local_resources.sh [start|stop|count]`
#
# **Arguments:**
#   start    : (Optional) Explicitly starts the stress test. This is the default action
#              if no argument is provided.
#   stop     : Terminates all background processes associated with the stress test
#              (CPU/memory stress, disk fill, monitoring) using the stored PIDs.
#   count    : Parses the latest `resource_test_stats_*.log` file in the script's directory
#              and calculates the average CPU Load, Memory Usage, and Disk Usage percentages
#              recorded during the test run. Does not typically require `sudo`.
#
# **Common Examples:**
# 1. Start the stress test (requires sudo):
#    `sudo ./stress_test_local_resources.sh`
#    or
#    `sudo ./stress_test_local_resources.sh start`
#
# 2. Stop the running stress test:
#    `sudo ./stress_test_local_resources.sh stop`
#
# 3. Calculate average stats from the last run (does not require sudo):
#    `./stress_test_local_resources.sh count`
#
# **Advanced Execution (Automation):**
# - The script detaches background processes using `disown`. It can be started and will
#   continue running even if the initiating terminal is closed. Use the `stop` command
#   for termination.
# - For unattended runs (e.g., via cron), ensure the environment has `sudo` access (e.g., via `/etc/sudoers`)
#   and that paths are correctly specified. Redirect output appropriately.
#   Example cron entry (run daily at 2 AM, modify path as needed):
#   `0 2 * * * /path/to/stress_test_local_resources.sh start >> /var/log/stress_test_cron.log 2>&1`
#   (Note: Stopping requires separate manual or scheduled `sudo ... stop` command).
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - Place the script in a suitable location, e.g., `/usr/local/sbin/` or `/opt/scripts/`
#   or a user's home directory (`~/bin/`). Ensure the location is appropriate for `sudo` execution if needed.
#
# **Setup:**
# 1. Place the script in the chosen location.
# 2. Make the script executable: `chmod +x stress_test_local_resources.sh`.
# 3. **IMPORTANT:** Modify the `TARGET_DIR_CONFIG` variable within the script's
#    "Execution Environment & Configuration" section to point to the filesystem/directory
#    you wish to target for the disk fill operation.
# 4. If the specified directory doesn't exist or isn't writable by the executing user, the script
#    defaults to `/data`, attempts to create it (`sudo mkdir -p`), and set group write permissions
#    (`sudo chmod g+w`). Ensure this behavior is acceptable or modify `TARGET_DIR_CONFIG`.
# 5. Ensure all dependencies listed in the "DEPENDENCIES & ENVIRONMENT" section are met.
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: The Bourne-Again SHell interpreter (Version >= 4.x recommended due to features like associative arrays in logging).
#
# **Required System Binaries/Tools:**
# - `coreutils`: Provides `date`, `mkdir`, `chmod`, `cat`, `echo`, `basename`, `dirname`, `pwd`, `rm`, `ls`, `head`, `sleep`, `tr`, `tee`, `test`, `whoami`.
# - `grep`: For pattern searching (uses `-oP` for Perl Compatible Regex).
# - `awk`: For text processing.
# - `sed`: For stream editing.
# - `sudo`: For elevated privileges.
# - `bc`: For floating-point arithmetic.
# - `top`, `free`, `df`: For system resource monitoring.
# - `nproc`: For determining CPU core count.
# - `stress-ng`: Core stress testing tool (script attempts installation via `apt-get`).
# - `ps`: For checking process status (used in `stop_resource_test`).
# - `kill`: For sending signals to processes (used in `stop_resource_test`, `monitor_resources`).
# - `disown`: Bash built-in to detach background processes.
# - `command`: Bash built-in for checking command existence.
# - `mktemp` (Optional, used in template but not explicitly required by current script logic).
#
# **Setup Instructions (if dependencies are not standard):**
# - `stress-ng`: If not found, the script attempts: `sudo apt-get update && sudo apt-get install -y stress-ng`.
#   Manual installation needed on non-Debian/Ubuntu systems (e.g., `yum install stress-ng`, `dnf install stress-ng`). Check EPEL repository for RHEL/CentOS.
# - Other tools (`bc`, `nproc`, coreutils, etc.) are typically part of standard Linux distributions. Install if missing using the system's package manager.
#
# **Operating System Compatibility:**
# - Designed primarily for Debian-based Linux distributions (like Ubuntu) due to `apt-get` usage.
# - Should work on other Linux distributions with potential modification of the `stress-ng` installation command in `check_dependency` function. Core functionality relies on common Linux utilities.
# - Not tested on macOS or BSD variants (utilities like `top`, `df`, `sed` may have different flags/output).
#
# **Environment Variables Used:**
# - Standard variables like `PATH` are implicitly used to find commands.
# - No custom environment variables are required by default. `VERBOSE` flag can be set internally.
#
# **System Resource Requirements:**
# - CPU: High utilization expected (close to 90% target * number of cores).
# - Memory: High utilization expected (close to 90% target).
# - Disk Space: Requires significant free space in `TARGET_DIR` for disk fill (up to 90% usage). Space needed depends on filesystem size.
# - Disk I/O: High write I/O expected during the disk fill phase.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): General informational messages, start/stop confirmations, final status, output from `count`. Colorized if terminal supports it.
# - Standard Error (stderr): Warning, Error, and Critical messages. Colorized if terminal supports it.
# - Dedicated Log Files: Yes. Created in the script's execution directory (`${SCRIPT_DIR}`).
#   1. Info Log: `resource_test_info_YYYYMMDD_HHMMSS.log` - Contains combined stdout/stderr from the script's run (including `log_message` output) and raw output from `stress-ng`. Format: `[YYYY-MM-DD HH:MM:SS TZ] [LEVEL] - Message`.
#   2. Stats Log: `resource_test_stats_YYYYMMDD_HHMMSS.log` - Records periodic resource usage snapshots. Format: `YYYY-MM-DD HH:MM:SS: CPU Load - [CPU]%, Memory Usage - [MEM]%, Disk Usage - [DISK]%`.
#
# **Log Format:**
# - Defined within the `log_message` and `monitor_resources` functions. Includes timestamp, level, and message. Log files do not contain ANSI color codes.
#
# **Log Levels (controlled internally, potentially via future flags):**
# - `DEBUG`: Detailed info for troubleshooting (Output controllable via `VERBOSE` variable).
# - `INFO`: Standard operational messages.
# - `WARN`: Potential issues or non-critical errors.
# - `ERROR`: Significant errors that may impact functionality.
# - `CRITICAL`: Severe errors causing script termination (via `log_message`).
#
# **Log Rotation:**
# - Not automatically managed by the script. New timestamped log files are created on each `start` run.
# - Recommendation: Use external tools like `logrotate` for managing log file size and retention if needed. Manual cleanup of old `resource_test_*_*.log` files is required otherwise.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - INFO/DEBUG level messages from `log_message`.
# - Confirmation messages when processes start/stop.
# - Final status message showing running PIDs and log file names upon start.
# - Formatted average statistics when using the `count` command.
#
# **Standard Error (stderr):**
# - WARN/ERROR/CRITICAL level messages from `log_message`.
# - Error messages from failed commands if not redirected.
#
# **Generated/Modified Files:**
# - Info Log: `${SCRIPT_DIR}/resource_test_info_YYYYMMDD_HHMMSS.log`.
# - Stats Log: `${SCRIPT_DIR}/resource_test_stats_YYYYMMDD_HHMMSS.log`.
# - PID File: `${SCRIPT_DIR}/resource_test_pids` (Temporary file storing background PIDs, created on start, deleted by `stop`).
# - Large Data Files: `large_file_*.dat` created in `TARGET_DIR` by the `fill_disk` function. **THESE ARE NOT AUTOMATICALLY DELETED.** Manual cleanup is required after testing.
# - `/data` Directory: May be created by the script if `TARGET_DIR_CONFIG` is invalid and the fallback is used.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success (Script initiation successful, `stop` completed, `count` completed).
# - 1: General Error (e.g., Invalid argument, Critical log message triggered exit). Specific codes below are preferred.
# - 2: Dependency Error (e.g., `stress-ng` install failed, critical command missing).
# - 3: Configuration Error (e.g., Invalid `TARGET_DIR`, permission issues on directories).
# - 4: Argument Error (Handled by `usage` function, typically exits 1).
# - 5: Permission Denied (e.g., `sudo -v` failed, cannot `chmod`/`mkdir` target dir).
# - 6: File System Error (e.g., Cannot write to PID file, `dd` fails unexpectedly - caught within functions).
# (Note: `set -e` will cause exit on unhandled command failures with their specific non-zero code).
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** "stress-ng not found" / "Failed to install stress-ng".
#   **Resolution:** Ensure network connectivity, `apt-get` is working, or install `stress-ng` manually. Check permissions for `sudo apt-get`.
# - **Issue:** "Directory [TARGET_DIR] does not exist" / "No write permission".
#   **Resolution:** Verify `TARGET_DIR_CONFIG` variable. Create directory manually or ensure script has permissions to create `/data`. Check and fix permissions (`chmod`, `chown`).
# - **Issue:** System becomes unresponsive or unstable.
#   **Resolution:** Expected due to high load. Use `sudo ./stress_test_local_resources.sh stop` from another terminal. If system is locked, a hard reboot may be needed. **Use only on non-critical systems.**
# - **Issue:** "Error creating file ... Disk might be full" / `dd` errors.
#   **Resolution:** Disk fill stops near 90% or on errors. Check free space in `TARGET_DIR`. Manually clean up `large_file_*.dat` files. Check `INFO_LOG` for `dd` error messages.
# - **Issue:** `count` command reports "No valid data found" or "No statistics log file found".
#   **Resolution:** Ensure the stress test was started and ran long enough to generate stats. Check if `monitor_resources` process started (check PID in `INFO_LOG`). Verify `resource_test_stats_*.log` file exists in `${SCRIPT_DIR}` and contains valid lines.
# - **Issue:** `stop` command fails to terminate processes.
#   **Resolution:** Check `INFO_LOG` for errors. Verify PIDs in `resource_test_pids` file were correct. Processes might have already exited. Manual `sudo kill -9 <PID>` might be needed.
#
# **Important Considerations / Warnings:**
# - **CRITICAL WARNING: HIGH RESOURCE USAGE:** This script intentionally consumes high CPU, memory, and disk I/O, potentially making the system slow, unresponsive, or unstable.
# - **CRITICAL WARNING: DISK SPACE CONSUMPTION:** The disk fill function writes large files to `TARGET_DIR` until ~90% usage. **These files ARE NOT automatically deleted.** Manually clean up `large_file_*.dat` files after testing.
# - **CRITICAL WARNING: DO NOT RUN ON PRODUCTION / CRITICAL SYSTEMS.** Use only on dedicated test systems.
# - **Idempotency:** The script is NOT idempotent. Running `start` multiple times will launch additional sets of processes and create new log files. The `stop` command targets PIDs from the *last* start run via the PID file.
# - **Concurrency:** Running multiple instances of `start` concurrently is NOT recommended and will likely interfere with PID tracking and potentially disk filling. No locking mechanism is implemented.
# - **Resource Limits:** `stress-ng` attempts to use configured percentages, but actual usage depends on system behavior and other running processes. OOM killer might terminate processes if memory pressure is too high.
# - **Background Processes:** Processes are detached (`disown`). Use `stop` command for termination. Rebooting the system will also terminate them.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes a Linux-based operating system with Bash (v4+).
# - Assumes standard core utilities (`awk`, `sed`, `grep`, `top`, `free`, `df`, etc.) are available and behave as expected on Linux.
# - Assumes `apt-get` is the package manager for `stress-ng` installation attempt (modify `check_dependency` if needed).
# - Assumes the user running the script (or the user invoking `sudo`) has the necessary privileges.
# - Assumes `TARGET_DIR_CONFIG` is set correctly or the default `/data` is acceptable.
# - Assumes network connectivity if `stress-ng` installation is needed.
# =========================================================================================

# =========================================================================================
# TESTING & VALIDATION
# =========================================================================================
# **Test Strategy:** Manual testing.
# **Key Test Cases Covered (Informal):**
# - Script starts successfully, creates logs and PID file.
# - `stress-ng`, `fill_disk`, `monitor_resources` processes run in background.
# - Statistics are logged periodically to `stats` log.
# - Disk fill stops around 90% usage.
# - `stop` command terminates background processes and removes PID file.
# - `count` command correctly parses latest stats log and calculates averages.
# - Handles missing `stress-ng` by attempting installation.
# - Handles invalid `TARGET_DIR` by falling back to default.
# - Handles missing write permissions by attempting `chmod`.
# - Error messages are logged appropriately.
# **Validation Environment:**
# - Tested OS: Ubuntu 20.04 LTS, Ubuntu 22.04 LTS (example).
# - Tested Bash Version(s): 5.x.
# **Automation:**
# - Static analysis performed using ShellCheck.
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - Add command-line flags (e.g., `-d <dir>`, `-t <timeout>`, `-c <cpus>`, `-m <mem>%`, `-i <interval>`) to override configuration variables.
# - Implement more sophisticated memory stress options (e.g., different allocation patterns).
# - Add network stress component using `stress-ng` or other tools.
# - Add I/O stress specific options beyond just disk filling (`stress-ng --io`).
# - Implement parallel disk filling for faster saturation on multi-disk systems.
# - Add option to automatically clean up generated data files after `stop`.
# - Improve portability/compatibility testing (macOS, other Linux distros).
# - Add unit/integration tests (e.g., using BATS).
# - Option for JSON output from `count` command.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Requires `sudo` for installation, process killing, and potential directory management. Strives for least privilege otherwise (e.g., checking write permissions as current user).
# - **Input Sanitization:** Limited command-line arguments (`start|stop|count`). Internal variables (`TARGET_DIR_CONFIG`) should be set carefully by the user editing the script. Paths are used in commands like `df`, `mkdir`, `chmod`, `dd`; ensure `TARGET_DIR` does not contain malicious elements if modified. Variables are generally quoted (`"${VAR}"`) to prevent word splitting/globbing issues.
# - **Sensitive Data Handling:** Does not handle passwords or API keys.
# - **Dependencies:** Relies on standard system tools and `stress-ng`. `stress-ng` installation attempted via `apt-get`. Ensure tools are from trusted sources.
# - **File Permissions:** Log files and PID file created with default user permissions (via script execution) in `${SCRIPT_DIR}`. Large data files created in `TARGET_DIR`. `sudo chmod g+w` or `sudo mkdir` may be used on `TARGET_DIR` or `/data`. Ensure `${SCRIPT_DIR}` and `TARGET_DIR` permissions are appropriate.
# - **External Command Execution:** Executes `sudo apt-get`, `sudo kill`, `sudo mkdir`, `sudo chmod`, `stress-ng`, `dd`, `top`, `free`, `df`, etc. The arguments to these are mostly controlled by the script logic or system information (`nproc`, `free`), reducing direct injection risk from *external* input, but modification of the script itself could introduce risks.
# - **Network Exposure:** Only requires network access if `apt-get` is needed for `stress-ng`. Does not listen on ports or make other outbound connections.
# - **Code Integrity:** Recommend verifying script integrity via checksums if obtained from untrusted sources. `sha256sum stress_test_local_resources.sh`.
# - **Error Message Verbosity:** `log_message` function controls output. Sensitive data is not expected in standard operation, but full paths are logged.
# - **Resource Exhaustion (Denial of Service):** The script's primary purpose is resource exhaustion. Run only in controlled environments where this is the intended goal.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is contained within this script's header comments.
# - No external documentation (README, Wiki, man page) is currently provided.
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Report issues via the script's repository (if available) or directly to the author's contact email. Provide logs (`info` and `stats`) and steps to reproduce.
# =========================================================================================

# =========================================================================================
# Execution Environment & Configuration
# =========================================================================================

# --- Bash Strict Mode ---
# Exit immediately if a command exits with a non-zero status.
# Treat unset variables as an error during parameter expansion.
# Pipeline return status is the status of the last command to exit non-zero.
set -euo pipefail

# --- Debug Mode ---
# Uncomment the following line for debugging (prints commands before execution)
# set -x

# --- Script Information ---
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_PID=$$

# --- Timestamp ---
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Global Runtime Variables & Configuration Defaults ---
VERBOSE=false # Set to true for more detailed output (e.g., via a -v flag if added)
NO_COLOR=false # Set to true to disable colored output
INTERACTIVE_MODE=false # Detect if running in an interactive terminal
[[ -t 1 ]] && INTERACTIVE_MODE=true

# Configuration (Can be modified by user/config file if logic added)
TARGET_DIR_CONFIG="/path/to/directory" # << IMPORTANT: User should modify this path
LOG_INTERVAL=10 # Statistics logging frequency in seconds
DEFAULT_FALLBACK_DIR="/data" # Fallback directory if TARGET_DIR_CONFIG is invalid
DISK_TARGET_USAGE=90 # Target disk usage percentage for fill_disk function
CPU_LOAD_TARGET=90 # Target CPU load percentage for stress-ng
MEMORY_ALLOCATION_TARGET="90%" # Target memory allocation per worker for stress-ng
STRESS_TIMEOUT_SECONDS=$((365 * 24 * 60 * 60)) # Effectively infinite timeout for stress-ng

# Runtime Variables (Populated during execution)
INFO_LOG="${SCRIPT_DIR}/resource_test_info_${SCRIPT_RUN_TIMESTAMP}.log"
STATS_LOG="${SCRIPT_DIR}/resource_test_stats_${SCRIPT_RUN_TIMESTAMP}.log"
PID_FILE="${SCRIPT_DIR}/resource_test_pids"
TARGET_DIR="" # Will be validated and set during runtime
CPU_CORES=0
TOTAL_MEM_MB=0
STRESS_PID=0
DISK_FILL_PID=0
MONITOR_PID=0
EXIT_CODE=0 # Default exit code

# --- Color Definitions (Optional) ---
if [[ "${NO_COLOR}" == false && "${INTERACTIVE_MODE}" == true ]]; then
    COLOR_RESET='\033[0m'; COLOR_RED='\033[0;31m'; COLOR_GREEN='\033[0;32m'; COLOR_YELLOW='\033[0;33m'; COLOR_BLUE='\033[0;34m'; COLOR_BOLD='\033[1m';
else
    COLOR_RESET=""; COLOR_RED=""; COLOR_GREEN=""; COLOR_YELLOW=""; COLOR_BLUE=""; COLOR_BOLD="";
fi

################################################################################
# Function Definitions
################################################################################

# --- Logging Function ---
# Usage: log_message LEVEL "Message"
# Levels: DEBUG, INFO, WARN, ERROR, CRITICAL
log_message() {
    local level="$1"
    local message="$2"
    local timestamp; timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z")
    local level_upper; level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]')
    local log_prefix="[${timestamp}] [${level_upper}]"
    local log_line="${log_prefix} - ${message}"
    local color=""

    case "${level_upper}" in
        DEBUG) color="${COLOR_BLUE}" ;;
        INFO) color="${COLOR_GREEN}" ;;
        WARN) color="${COLOR_YELLOW}" ;;
        ERROR) color="${COLOR_RED}" ;;
        CRITICAL) color="${COLOR_BOLD}${COLOR_RED}" ;;
    esac

    # Map log levels for comparison (adjust LOG_LEVEL variable to control verbosity)
    declare -A log_levels=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [CRITICAL]=4)
    local current_log_level_num=${log_levels["INFO"]} # Default to INFO level logging
    [[ "$VERBOSE" == true ]] && current_log_level_num=${log_levels["DEBUG"]}
    local message_level_num=${log_levels[${level_upper}]}

    if [[ ${message_level_num} -ge ${current_log_level_num} ]]; then
        # Output to stderr for WARN/ERROR/CRITICAL, stdout otherwise
        if [[ "${level_upper}" =~ ^(WARN|ERROR|CRITICAL)$ ]]; then
            echo -e "${color}${log_line}${COLOR_RESET}" >&2
        else
            echo -e "${color}${log_line}${COLOR_RESET}"
        fi
        # Append raw message to the INFO log file
        echo "${log_prefix} - ${message}" >> "${INFO_LOG}"
    fi

    # Exit on CRITICAL errors
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        log_message "ERROR" "Critical error triggered script exit."
        exit 1 # Use a specific exit code if desired
    fi
}

# --- Statistics Logging Function ---
# Separate function for stats log to keep format distinct.
# Usage: log_stat "Message for stats log"
log_stat() {
    local message="$1"
    echo "${message}" >> "${STATS_LOG}"
}


# --- Usage/Help Function ---
usage() {
    # Extract usage info from header (or define manually)
    local usage_text
    usage_text=$(sed -n '/^# ===+ USAGE ===+$/,/^# ===+ .* ===+$/{ /# ===+ .* ===+$/!p; }' "${BASH_SOURCE[0]}" | sed 's/^# //; s/\[your_script_name.sh\]/'"${SCRIPT_NAME}"'/g')

    cat << EOF >&2
${usage_text}

Log Files:
  Info Log:   ${INFO_LOG} (Pattern: resource_test_info_YYYYMMDD_HHMMSS.log)
  Stats Log:  ${STATS_LOG} (Pattern: resource_test_stats_YYYYMMDD_HHMMSS.log)
PID File:   ${PID_FILE}

Configuration Defaults:
  Target Directory: ${TARGET_DIR_CONFIG} (Fallback: ${DEFAULT_FALLBACK_DIR})
  Log Interval: ${LOG_INTERVAL} seconds
EOF
    exit 1
}

# --- Dependency Check Function ---
# Usage: check_dependency "command" ["package-name"]
check_dependency() {
    local cmd="$1"
    local pkg="${2:-$cmd}"
    if ! command -v "$cmd" &> /dev/null; then
        log_message "ERROR" "Required command '${cmd}' not found."
        log_message "INFO" "Attempting to install '${pkg}' using apt..."
        if sudo apt-get update && sudo apt-get install -y "$pkg"; then
            log_message "INFO" "'${pkg}' installed successfully."
        else
            log_message "CRITICAL" "Failed to install '${pkg}'. Please install it manually."
            # CRITICAL log level handles exit
        fi
    else
         log_message "DEBUG" "Dependency check passed for command: ${cmd}"
    fi
}

# --- General Dependency Check Function ---
# Usage: check_command_exists "command" ["purpose"]
check_command_exists() {
    local cmd="$1"
    local purpose="${2:-}"
    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required command '${cmd}' not found. ${purpose} Please install it."
        # CRITICAL log level handles exit
    fi
     log_message "DEBUG" "Dependency check passed for command: ${cmd}"
}


# --- Cleanup Function ---
# Registered via trap to run on script exit/interrupt.
# Primarily ensures temporary files are handled if needed.
# Note: Does NOT stop running processes by default; use 'stop' command for that.
cleanup() {
    local exit_status=$?
    log_message "INFO" "Running cleanup function (exit status: ${exit_status})..."
    # Example: Remove PID file if it exists (stop command should ideally remove it cleanly)
    # if [[ -f "${PID_FILE}" ]]; then
    #     log_message "DEBUG" "Removing PID file: ${PID_FILE}"
    #     rm -f "${PID_FILE}" || log_message "WARN" "Could not remove PID file: ${PID_FILE}"
    # fi
    # Add removal of other temp files if created by the script here.
    log_message "INFO" "Cleanup finished."
    # Script exits with the original $exit_status after trap completes.
}

# --- Trap Setup ---
trap cleanup EXIT INT TERM HUP

# --- Function: Stop Resource Test ---
# Terminates background processes listed in the PID file.
stop_resource_test() {
    log_message "INFO" "Executing stop command..."
    check_command_exists "sudo" "Required to kill processes."
    check_command_exists "kill"
    check_command_exists "rm"

    if [ -f "$PID_FILE" ]; then
        log_message "INFO" "Stopping all resource test processes listed in ${PID_FILE}..."
        local pids_to_stop
        pids_to_stop=$(cat "${PID_FILE}") # Read all PIDs first

        for pid in $pids_to_stop; do
            if [[ -n "$pid" && "$pid" =~ ^[0-9]+$ ]]; then
                log_message "INFO" "Attempting to stop process with PID ${pid}..."
                # Check if process exists before trying to kill
                if ps -p "$pid" > /dev/null; then
                    if sudo kill "$pid"; then
                        log_message "INFO" "Successfully signaled process ${pid} to stop."
                        # Optional: Wait briefly and send SIGKILL if still alive
                        # sleep 2
                        # if ps -p "$pid" > /dev/null; then
                        #     log_message "WARN" "Process ${pid} did not terminate with SIGTERM, sending SIGKILL."
                        #     sudo kill -9 "$pid" || log_message "ERROR" "Failed to send SIGKILL to PID ${pid}."
                        # fi
                    else
                        log_message "WARN" "Failed to send SIGTERM to process ${pid}. It might require manual intervention or different permissions."
                    fi
                else
                    log_message "WARN" "Process with PID ${pid} does not exist or already stopped."
                fi
            else
                log_message "WARN" "Invalid PID found in ${PID_FILE}: '${pid}'. Skipping."
            fi
        done

        log_message "INFO" "Removing PID file: ${PID_FILE}"
        if rm -f "$PID_FILE"; then
             log_message "INFO" "PID file removed."
        else
             log_message "ERROR" "Failed to remove PID file: ${PID_FILE}"
        fi
        log_message "INFO" "Stop process completed. Check logs for details. Some processes might take time to exit."
    else
        log_message "WARN" "No resource test processes seem to be running (PID file '${PID_FILE}' not found)."
    fi
    exit 0
}


# --- Function: Calculate Averages ---
# Computes average resource usage from the latest statistics log.
calculate_averages() {
    log_message "INFO" "Executing count command..."
    check_command_exists "ls"
    check_command_exists "head"
    check_command_exists "grep"
    check_command_exists "bc"

    # Find the most recent stats log file in the script's directory
    local latest_stats_log
    latest_stats_log=$(ls -t "${SCRIPT_DIR}"/resource_test_stats_*.log 2>/dev/null | head -n 1)

    if [[ -z "$latest_stats_log" || ! -f "$latest_stats_log" ]]; then
        log_message "ERROR" "No statistics log file found (pattern: resource_test_stats_*.log in ${SCRIPT_DIR}). Run the stress test first."
        exit 1
    fi
    log_message "INFO" "Calculating averages from log file: ${latest_stats_log}"

    local total_cpu=0 total_memory=0 total_disk=0 count=0
    local line cpu memory disk

    # Process the statistics log file line by line
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Extract values robustly, default to 0 if pattern fails
        cpu=$(echo "$line" | grep -oP 'CPU Load - \K[0-9.]+' || echo "0")
        memory=$(echo "$line" | grep -oP 'Memory Usage - \K[0-9.]+' || echo "0")
        disk=$(echo "$line" | grep -oP 'Disk Usage - \K[0-9.]+' || echo "0") # Assumes disk usage is already %

        # Validate extracted numbers (basic check)
        if [[ "$cpu" =~ ^[0-9.]+$ && "$memory" =~ ^[0-9.]+$ && "$disk" =~ ^[0-9.]+$ ]]; then
            total_cpu=$(echo "$total_cpu + $cpu" | bc)
            total_memory=$(echo "$total_memory + $memory" | bc)
            total_disk=$(echo "$total_disk + $disk" | bc)
            ((count++))
        else
            log_message "WARN" "Skipping invalid line in stats log: ${line}"
        fi
    done < "$latest_stats_log"

    if [ "$count" -eq 0 ]; then
        log_message "ERROR" "No valid data points found in '${latest_stats_log}' to calculate averages."
        exit 1
    fi

    # Calculate averages using bc for floating-point math
    local avg_cpu avg_memory avg_disk
    avg_cpu=$(echo "scale=2; $total_cpu / $count" | bc)
    avg_memory=$(echo "scale=2; $total_memory / $count" | bc)
    avg_disk=$(echo "scale=2; $total_disk / $count" | bc)

    # Output results
    echo "-----------------------------------------------------"
    echo "Average Resource Usage from: ${latest_stats_log}"
    echo "Data points considered: ${count}"
    echo "-----------------------------------------------------"
    echo "Average CPU Load:     ${avg_cpu}%"
    echo "Average Memory Usage: ${avg_memory}%"
    echo "Average Disk Usage:   ${avg_disk}%"
    echo "-----------------------------------------------------"
    exit 0
}

# --- Function: Fill Disk ---
# Continuously creates 1GB files until disk usage threshold is met.
fill_disk() {
    log_message "INFO" "Starting disk fill process in '${TARGET_DIR}' (Target: ${DISK_TARGET_USAGE}%)..."
    check_command_exists "df"
    check_command_exists "awk"
    check_command_exists "date"
    check_command_exists "dd" "Core utility for creating large files."
    check_command_exists "tee" # Used indirectly via log_message

    local current_usage file_timestamp file_name dd_exit_status

    while true; do
        # Get current disk usage percentage robustly
        current_usage=$(df "${TARGET_DIR}" | awk 'NR==1{for(i=1;i<=NF;i++)if($i~/%/){p=i;break}} NR==2{sub(/%/,"",$p);print $p}')

        if [[ -z "$current_usage" || ! "$current_usage" =~ ^[0-9]+$ ]]; then
             log_message "ERROR" "Error retrieving disk usage for '${TARGET_DIR}'. Stopping disk fill."
             # Optionally try to clean up PID file entry here if possible, or rely on 'stop'
             return 1 # Indicate failure
        fi
        log_message "DEBUG" "Current disk usage in '${TARGET_DIR}': ${current_usage}%"

        if (( current_usage >= DISK_TARGET_USAGE )); then
            log_message "INFO" "Disk usage (${current_usage}%) reached or exceeded target (${DISK_TARGET_USAGE}%) in '${TARGET_DIR}'. Stopping disk fill."
            return 0 # Indicate success/completion
        fi

        # Generate unique filename and create 1GB file
        file_timestamp=$(date +%Y%m%d_%H%M%S_%N) # Nanoseconds for uniqueness
        file_name="large_file_${file_timestamp}.dat"
        local full_file_path="${TARGET_DIR}/${file_name}"

        log_message "DEBUG" "Creating 1GB file: ${full_file_path}"
        # Using /dev/urandom for less compressible data, suppress dd output
        if dd if=/dev/urandom of="${full_file_path}" bs=1M count=1024 status=none; then
            dd_exit_status=$?
            if [[ ${dd_exit_status} -ne 0 ]]; then
                 log_message "ERROR" "dd command failed with exit code ${dd_exit_status} while creating '${file_name}'. Disk might be full or other error occurred. Stopping disk fill."
                 # Optional: Attempt to remove partial file
                 rm -f "${full_file_path}" || log_message "WARN" "Failed to remove potentially partial file: ${full_file_path}"
                 return 1 # Indicate failure
            fi
            log_message "DEBUG" "Successfully created file: ${file_name}"
        else
             # Handle cases where dd itself fails to execute (permissions etc) though set -e should catch this
             log_message "ERROR" "Failed to execute dd command for file '${file_name}'. Stopping disk fill."
             return 1
        fi

        # Optional small sleep to avoid overly aggressive looping
        # sleep 0.1
    done
}


# --- Function: Monitor Resources ---
# Background loop to periodically log CPU, Memory, Disk usage.
monitor_resources() {
    log_message "INFO" "Starting resource monitoring loop (Interval: ${LOG_INTERVAL}s)..."
    check_command_exists "kill" "Used to check if main stress process is running."
    check_command_exists "date"
    check_command_exists "top" "Used for CPU load."
    check_command_exists "sed"
    check_command_exists "bc" "Used for CPU load calculation."
    check_command_exists "free" "Used for memory usage."
    check_command_exists "awk"
    check_command_exists "df" "Used for disk usage."
    check_command_exists "sleep"

    local cpu_idle cpu_load mem_usage disk_usage

    # Check if the main stress process PID is valid and running before starting loop
    if [[ -z "$STRESS_PID" || "$STRESS_PID" -eq 0 || ! kill -0 "$STRESS_PID" 2>/dev/null ]]; then
        log_message "ERROR" "Monitoring loop: Main stress process (PID ${STRESS_PID:-'not set'}) not found or not running. Exiting monitor."
        return 1
    fi

    log_stat "Monitoring started at $(date)" # Log start time to stats log

    # Loop as long as the main stress process is running
    while kill -0 "$STRESS_PID" 2>/dev/null; do
        # Get CPU Load % (100 - idle %)
        # Using -bn1 for non-interactive single snapshot. Parsing assumes standard Linux `top` format.
        cpu_idle=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.,]*\).*%* id.*/\1/" | sed 's/,/./')
        if [[ "$cpu_idle" =~ ^[0-9.]+$ ]]; then
            cpu_load=$(echo "scale=2; 100 - $cpu_idle" | bc)
        else
            log_message "WARN" "Could not parse CPU idle percentage from top output."
            cpu_load="N/A"
        fi

        # Get Memory Usage %
        mem_usage=$(free -m | awk '/Mem:/ {printf("%.2f"), $3/$2*100}')
        if ! [[ "$mem_usage" =~ ^[0-9.]+$ ]]; then
             log_message "WARN" "Could not parse Memory usage percentage from free output."
             mem_usage="N/A"
        fi

        # Get Disk Usage % for the target directory's filesystem
        disk_usage=$(df "$TARGET_DIR" | awk 'NR==1{for(i=1;i<=NF;i++)if($i~/%/){p=i;break}} NR==2{sub(/%/,"",$p);print $p}')
        if ! [[ "$disk_usage" =~ ^[0-9]+$ ]]; then # Allow integer only for disk %
            log_message "WARN" "Could not parse Disk usage percentage from df output for ${TARGET_DIR}."
            disk_usage="N/A"
        fi

        # Log the collected statistics to the stats log file
        log_stat "$(date '+%Y-%m-%d %H:%M:%S'): CPU Load - ${cpu_load}%, Memory Usage - ${mem_usage}%, Disk Usage - ${disk_usage}%"

        # Wait for the defined interval
        sleep "$LOG_INTERVAL"
    done

    log_message "INFO" "Monitoring loop: Main stress process (PID $STRESS_PID) appears to have stopped. Stopping monitor."
    log_stat "Monitoring stopped at $(date)" # Log end time to stats log
    return 0
}

# --- Argument Parsing Function ---
parse_params() {
    if [[ $# -eq 0 || "$1" == "start" ]]; then
        log_message "INFO" "Action: Start Stress Test"
        # Proceed with main execution flow
    elif [[ "$1" == "stop" ]]; then
        stop_resource_test # Function handles exit
    elif [[ "$1" == "count" ]]; then
        calculate_averages # Function handles exit
    else
        log_message "ERROR" "Invalid argument: '$1'"
        usage # Function handles exit
    fi
}

# --- Input Validation Function ---
validate_inputs() {
    log_message "INFO" "Validating inputs and environment..."

    # 1. Check sudo permissions early
    log_message "DEBUG" "Checking for sudo permissions..."
    if ! sudo -v; then
        log_message "CRITICAL" "This script requires sudo privileges for dependency installation and process management. Please run with sudo or a user with sudo access."
        # CRITICAL handles exit
    else
        log_message "INFO" "Sudo permissions verified."
    fi

    # 2. Validate Target Directory
    log_message "INFO" "Validating target directory for disk fill: '${TARGET_DIR_CONFIG}'"
    if [[ -d "${TARGET_DIR_CONFIG}" ]]; then
        log_message "INFO" "Target directory '${TARGET_DIR_CONFIG}' exists."
        TARGET_DIR="${TARGET_DIR_CONFIG}"
    else
        log_message "WARN" "Configured target directory '${TARGET_DIR_CONFIG}' does not exist. Falling back to default: '${DEFAULT_FALLBACK_DIR}'"
        TARGET_DIR="${DEFAULT_FALLBACK_DIR}"
        log_message "INFO" "Attempting to create fallback directory: ${TARGET_DIR}"
        if sudo mkdir -p "${TARGET_DIR}"; then
             log_message "INFO" "Successfully created fallback directory: ${TARGET_DIR}"
        else
             log_message "CRITICAL" "Failed to create fallback directory: ${TARGET_DIR}. Check permissions."
        fi
    fi

    # 3. Validate Write Permissions for Target Directory
    log_message "INFO" "Checking write permissions for: ${TARGET_DIR}"
    # Use `sudo -u "$(whoami)"` to test as the *current* user, even if script ran with sudo initially.
    # This assumes the stress test (dd command) runs as the user who invoked the script.
    # If `dd` needs to run as root, test with `sudo test -w` instead. Let's assume current user.
    if sudo -u "$(whoami)" test -w "${TARGET_DIR}"; then
        log_message "INFO" "Write permission confirmed for current user in '${TARGET_DIR}'."
    else
        log_message "WARN" "No write permission for current user in '${TARGET_DIR}'. Attempting to set permissions..."
        # Grant write permissions to the user's primary group. Adjust if needed (e.g., 775, or specific user/group).
        if sudo chmod g+w "${TARGET_DIR}"; then
            log_message "INFO" "Set group write permission on '${TARGET_DIR}'."
            # Re-verify
            if ! sudo -u "$(whoami)" test -w "${TARGET_DIR}"; then
                 log_message "CRITICAL" "Failed to obtain write permission for '${TARGET_DIR}' even after chmod. Check ownership and permissions."
            fi
        else
             log_message "CRITICAL" "Failed to set write permissions on '${TARGET_DIR}' using sudo chmod g+w."
        fi
    fi

    # 4. Validate Log Directory Writability (only needed if logging to file)
    # Initial check during logging is sufficient, but could add explicit check here if preferred.
    # log_message "DEBUG" "Checking log directory writability: $(dirname ${INFO_LOG})"
    # if ! mkdir -p "$(dirname ${INFO_LOG})" || ! [[ -w "$(dirname ${INFO_LOG})" ]]; then
    #      log_message "CRITICAL" "Cannot write to log directory: $(dirname ${INFO_LOG})"
    # fi

    log_message "INFO" "Input validation complete."
}


# --- Check Dependencies Function ---
check_dependencies() {
    log_message "INFO" "Checking required dependencies..."
    # Core Utils (assumed present usually, but good practice)
    check_command_exists "basename"
    check_command_exists "dirname"
    check_command_exists "cd"
    check_command_exists "pwd"
    check_command_exists "date"
    check_command_exists "echo"
    check_command_exists "cat"
    check_command_exists "tr"
    check_command_exists "ps"
    check_command_exists "grep"
    check_command_exists "sed"
    check_command_exists "awk"
    check_command_exists "test"
    check_command_exists "whoami"
    check_command_exists "chmod"
    check_command_exists "mkdir"
    check_command_exists "rm"
    check_command_exists "ls"
    check_command_exists "head"
    check_command_exists "sleep"

    # Specific Tools
    check_command_exists "sudo" "Required for elevated privileges."
    check_command_exists "bc" "Required for calculations."
    check_command_exists "top" "Required for CPU monitoring."
    check_command_exists "free" "Required for memory monitoring."
    check_command_exists "df" "Required for disk monitoring/filling."
    check_command_exists "nproc" "Required to determine CPU cores."
    check_command_exists "kill" "Required for stopping processes."
    check_command_exists "disown" "Bash built-in, used to detach background processes."
    check_command_exists "tee" "Used for logging to console and file simultaneously."
    check_command_exists "dd" "Required for disk filling."

    # Main stress tool - attempt installation if missing
    check_dependency "stress-ng" "stress-ng" # Uses specific installer logic

    log_message "INFO" "All required dependencies verified."
}


# --- Prepare Environment Function ---
prepare_environment() {
    log_message "INFO" "Preparing execution environment..."

    # Touch log files to create them early (optional)
    touch "${INFO_LOG}" || log_message "WARN" "Could not touch info log file: ${INFO_LOG}"
    touch "${STATS_LOG}" || log_message "WARN" "Could not touch stats log file: ${STATS_LOG}"

    # Ensure PID file is clean before starting
    log_message "INFO" "Clearing previous PID file if it exists: ${PID_FILE}"
    rm -f "${PID_FILE}" || log_message "WARN" "Could not remove existing PID file: ${PID_FILE}"
    touch "${PID_FILE}" || log_message "CRITICAL" "Could not create PID file: ${PID_FILE}"
    chmod 644 "${PID_FILE}" || log_message "WARN" "Could not set permissions on PID file: ${PID_FILE}" # Ensure readable

    # Get System Info needed for configuration
    log_message "INFO" "Gathering system information..."
    if CPU_CORES=$(nproc); then
        log_message "INFO" "Detected ${CPU_CORES} logical CPU cores."
    else
        log_message "WARN" "Could not determine CPU cores using nproc. Defaulting to 1."
        CPU_CORES=1
    fi

    if TOTAL_MEM_MB=$(free -m | awk '/Mem:/ {print $2}'); then
         log_message "INFO" "Detected ${TOTAL_MEM_MB} MB total physical memory."
    else
         log_message "WARN" "Could not determine total memory using free. Memory stress config might be inaccurate."
         TOTAL_MEM_MB=1024 # Default to 1GB for calculation safety
    fi

    log_message "INFO" "Environment preparation complete."
}


# --- Main Logic Function ---
main() {
    log_message "INFO" "Starting main script execution: Stress Test"

    # --- Configure Stress Parameters ---
    local cpu_workers=${CPU_CORES}
    # Simple heuristic for memory workers (1 per 2GB, min 1)
    local memory_workers=$(( TOTAL_MEM_MB / 2048 ))
    [[ "$memory_workers" -lt 1 ]] && memory_workers=1

    log_message "INFO" "Stress Test Configuration:"
    log_message "INFO" "  CPU Workers: ${cpu_workers} (Target Load: ${CPU_LOAD_TARGET}%)"
    log_message "INFO" "  Memory Workers: ${memory_workers} (Target Allocation: ${MEMORY_ALLOCATION_TARGET} each)"
    log_message "INFO" "  Disk Fill Target: ${DISK_TARGET_USAGE}% in '${TARGET_DIR}'"
    log_message "INFO" "  Monitoring Interval: ${LOG_INTERVAL}s"
    log_message "INFO" "  Stress-NG Timeout: ${STRESS_TIMEOUT_SECONDS}s (approx. 1 year)"

    # --- Start CPU/Memory Stress ---
    log_message "INFO" "Starting stress-ng for CPU and Memory load..."
    stress-ng --cpu "$cpu_workers" --cpu-load "$CPU_LOAD_TARGET" \
              --vm "$memory_workers" --vm-bytes "$MEMORY_ALLOCATION_TARGET" \
              --timeout "$STRESS_TIMEOUT_SECONDS" \
              &>> "${INFO_LOG}" & # Append both stdout/stderr to info log
    STRESS_PID=$!

    if [[ -n "$STRESS_PID" && "$STRESS_PID" -gt 0 && kill -0 "$STRESS_PID" 2>/dev/null ]]; then
        echo "$STRESS_PID" >> "$PID_FILE"
        disown "$STRESS_PID" # Detach from shell
        log_message "INFO" "CPU and Memory stress test started with PID ${STRESS_PID}."
    else
        log_message "ERROR" "Failed to start stress-ng or capture its PID. Check ${INFO_LOG} for details."
        # Consider exiting if stress-ng is critical
        # exit 1
        STRESS_PID=0 # Ensure PID is invalid
    fi

    # --- Start Disk Fill ---
    log_message "INFO" "Starting disk fill process in the background..."
    fill_disk & # Run the function in the background
    DISK_FILL_PID=$!

    if [[ -n "$DISK_FILL_PID" && "$DISK_FILL_PID" -gt 0 && kill -0 "$DISK_FILL_PID" 2>/dev/null ]]; then
        echo "$DISK_FILL_PID" >> "$PID_FILE"
        disown "$DISK_FILL_PID" # Detach from shell
        log_message "INFO" "Disk fill process started with PID ${DISK_FILL_PID}."
    else
        log_message "ERROR" "Failed to start disk fill process or capture its PID."
        DISK_FILL_PID=0 # Ensure PID is invalid
    fi

    # --- Start Monitoring ---
    if [[ "$STRESS_PID" -ne 0 ]]; then # Only start monitor if stress-ng started
        log_message "INFO" "Starting resource monitoring process in the background..."
        monitor_resources & # Run the function in the background
        MONITOR_PID=$!

        if [[ -n "$MONITOR_PID" && "$MONITOR_PID" -gt 0 && kill -0 "$MONITOR_PID" 2>/dev/null ]]; then
            echo "$MONITOR_PID" >> "$PID_FILE"
            disown "$MONITOR_PID" # Detach from shell
            log_message "INFO" "Monitoring process started with PID ${MONITOR_PID}."
        else
            log_message "ERROR" "Failed to start monitoring process or capture its PID."
            MONITOR_PID=0 # Ensure PID is invalid
        fi
    else
         log_message "WARN" "Skipping resource monitoring because stress-ng process failed to start."
         MONITOR_PID=0
    fi

    # --- Final Status Output ---
    log_message "INFO" "Background processes launched. Script execution technically complete."
    echo "-----------------------------------------------------" | tee -a "${INFO_LOG}"
    echo " Resource Stress Test Initiated" | tee -a "${INFO_LOG}"
    echo "-----------------------------------------------------" | tee -a "${INFO_LOG}"
    [[ "$STRESS_PID" -ne 0 ]] && echo "  - CPU/Memory Stress PID: ${STRESS_PID}" | tee -a "${INFO_LOG}"
    [[ "$DISK_FILL_PID" -ne 0 ]] && echo "  - Disk Fill PID: ${DISK_FILL_PID}" | tee -a "${INFO_LOG}"
    [[ "$MONITOR_PID" -ne 0 ]] && echo "  - Monitoring PID: ${MONITOR_PID}" | tee -a "${INFO_LOG}"
    echo "  - General Info Log: ${INFO_LOG}" | tee -a "${INFO_LOG}"
    echo "  - Statistics Log: ${STATS_LOG} (updates every ${LOG_INTERVAL}s)" | tee -a "${INFO_LOG}"
    echo "-----------------------------------------------------" | tee -a "${INFO_LOG}"
    echo " Use command:" | tee -a "${INFO_LOG}"
    echo "   sudo ${SCRIPT_DIR}/${SCRIPT_NAME} stop" | tee -a "${INFO_LOG}"
    echo " to terminate all test processes." | tee -a "${INFO_LOG}"
    echo " Use command:" | tee -a "${INFO_LOG}"
    echo "   ${SCRIPT_DIR}/${SCRIPT_NAME} count" | tee -a "${INFO_LOG}"
    echo " to calculate average statistics from the latest run." | tee -a "${INFO_LOG}"
    echo "-----------------------------------------------------" | tee -a "${INFO_LOG}"

    log_message "INFO" "Script main logic finished. Background processes continue."
}

################################################################################
# Script Execution Flow
################################################################################

# 1. Parse Command Line Arguments
#    (Handles 'stop' and 'count' which exit directly)
parse_params "$@"

# 2. Validate Inputs (Sudo Check, Target Dir)
validate_inputs

# 3. Check Dependencies (Installs stress-ng if needed)
check_dependencies

# 4. Prepare Environment (Clean PID file, Get System Info)
prepare_environment

# 5. Execute Main Logic (Start stress, disk fill, monitoring)
main

# 6. Exit Successfully (Main script process exits, background jobs continue)
#    Trap ensures cleanup runs.
log_message "INFO" "Script completed initiation successfully. Background tasks running."
exit ${EXIT_CODE} # Exit with 0 if no errors occurred

# =========================================================================================
# --- End of Script ---
