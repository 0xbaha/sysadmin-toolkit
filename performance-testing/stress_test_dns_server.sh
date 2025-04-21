#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : stress_test_dns_server.sh
# PURPOSE       : Automates continuous background DNS stress testing with logging.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2024-11-07
# LAST UPDATED  : 2024-11-07
# VERSION       : 1.0.0
# =========================================================================================

# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This script automates DNS stress testing by performing randomized,
# high-volume DNS queries on a specified DNS server. The script runs
# in the background, periodically sending DNS queries using `dnsperf`
# at random intervals and for random durations. Each test's detailed results
# and a summary report are saved in timestamped files for review and analysis.
#
# The script is designed to run continuously and persistently in the
# background using `nohup`, ignoring terminal interruptions, until explicitly stopped.
# It includes dependency checking (and installation attempt via `apt` for Debian/Ubuntu),
# robust logging with different levels, and process management via a PID file.
#
# Key Functions:
# - Sets strict Bash mode (`set -euo pipefail`).
# - Checks for and optionally installs required dependencies (`dnsperf`, `bc`) using `apt`.
# - Restarts itself in the background using `nohup` for persistent operation.
# - Manages its background process using a PID file (`dns_stress_test.pid`).
# - Creates a sample query file (`dns_queries.txt`) if one doesn't exist.
# - Runs `dnsperf` against a specified DNS server (`DNS_SERVER`) using queries from `QUERY_FILE`.
# - Executes tests for randomized durations selected from `DURATION_OPTIONS`.
# - Waits for randomized intervals between tests, selected from `INTERVAL_OPTIONS`.
# - Provides structured logging (`log_message` function) with levels (DEBUG, INFO, WARN, ERROR, CRITICAL).
# - Logs general script activity (start, stop, waits, test completion) to `LOG_FILE` or stdout/stderr.
# - Saves raw `dnsperf` output for each test run to `./results/dns_stress_test_output_TIMESTAMP.txt`.
# - Parses raw output and saves key metrics (QPS, latency, success/loss rates) to `./results/dns_test_summary_TIMESTAMP.txt`.
# - Provides mechanisms to stop (`stop` command) and get help (`help` command).
# - Implements `trap` for cleanup on exit/interrupt.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Automation:** Designed for unattended, continuous background execution.
# - **Robustness:** Includes strict mode, dependency checks, `nohup`, PID file management, and signal trapping for cleanup.
# - **Randomization:** Uses randomized durations and intervals to simulate variable load patterns.
# - **Simplicity:** Focuses on orchestrating `dnsperf` with clear, sequential logic within the main loop.
# - **Logging:** Provides structured, multi-level logging for monitoring and diagnostics.
# - **Modularity:** Uses functions for distinct tasks (logging, dependency checks, test execution, cleanup, etc.).
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - System Administrators
# - Network Engineers
# - DevOps Engineers
# - IT Support Teams performing DNS server load testing or validation.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x stress_test_dns_server.sh`
# - File system access: Requires write permissions in the script's directory (or configured log/output directories) to create log, PID, query (if missing), and result files.
# - Network access: Requires outbound network connectivity to the target `DNS_SERVER` on port 53 (UDP/TCP).
# - Elevated privileges: Requires `sudo` privileges *only* if dependencies (`dnsperf`, `bc`) need to be installed via `apt` on Debian/Ubuntu systems.
#
# **Basic Syntax:**
#   `./stress_test_dns_server.sh [COMMAND]`
#
# **Commands:**
#   (no command)   : Starts the script in the background using `nohup`. Logs to configured `LOG_FILE`
#                    (default: `./dns_stress_test.log`). Creates configured `PID_FILE` (default: `./dns_stress_test.pid`).
#   `stop`           : Stops the running background instance identified by the `PID_FILE`.
#   `help`, `--help` : Displays this usage information and exits.
#
# **Internal Options (Not for direct user invocation):**
#   `--no-restart` : Internal flag used when the script restarts itself with `nohup` to prevent looping restarts.
#
# **Configuration:**
# - Primary configuration is done by editing variables within the script's
#   "Global Runtime Variables" section (e.g., `DNS_SERVER`, `QUERY_FILE`, `LOG_FILE`, `PID_FILE`,
#   `DURATION_OPTIONS`, `INTERVAL_OPTIONS`).
#
# **Common Examples:**
# 1. Start the stress test in the background with default settings:
#    `./stress_test_dns_server.sh`
#    (Monitor progress via `tail -f dns_stress_test.log` and check the `./results/` directory)
#
# 2. Stop the running stress test:
#    `./stress_test_dns_server.sh stop`
#
# 3. Get help:
#    `./stress_test_dns_server.sh help`
#
# **Advanced Execution (Automation):**
# - The script is designed for background execution via its internal `nohup` mechanism.
# - Can be managed by process supervisors (like systemd or supervisorctl) if needed, but ensure the `stop` command or manual `kill` using the PID file is used for graceful termination.
# - Example cron job (ensure environment variables like PATH are correctly set):
#   `@reboot /path/to/stress_test_dns_server.sh`
#   (Note: built-in `nohup` provides persistence; cron might be redundant unless specific scheduling is needed)
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - User scripts: `~/bin/` or `~/.local/bin/` (ensure these are in user's $PATH)
# - System-wide scripts: `/usr/local/sbin/` or `/opt/scripts/`
#
# **Manual Setup:**
# 1. Place the script (`stress_test_dns_server.sh`) in the desired location.
# 2. Ensure it has execute permissions: `chmod +x stress_test_dns_server.sh`.
# 3. **Crucially, edit the script** to set the correct `DNS_SERVER` IP address in the configuration section.
# 4. Optionally, customize other configuration variables (`QUERY_FILE`, `LOG_FILE`, `PID_FILE`, `DURATION_OPTIONS`, `INTERVAL_OPTIONS`).
# 5. Optionally, create a custom query file at the location specified by `QUERY_FILE`. If not present, a default one (`./dns_queries.txt`) will be created relative to the script's directory.
# 6. Install dependencies manually if not using Debian/Ubuntu or if automatic installation fails (see DEPENDENCIES section).
# 7. Run the script (`./stress_test_dns_server.sh`) to start it in the background.
#
# **Integration:**
# - Can be started manually or via system startup mechanisms (`@reboot` cron, systemd). Ensure the working directory context is appropriate if run via automation, especially for relative paths like the default `QUERY_FILE`, `LOG_FILE`, `PID_FILE`, and `./results/` directory. Running from the script's own directory is recommended.
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: Version >= 4.0 recommended (uses `declare -A`, `pipefail`).
#
# **Required System Binaries/Tools:**
# - `coreutils`: Provides `date`, `mkdir`, `chmod`, `cat`, `basename`, `dirname`, `sleep`, `echo`, `ps`, `kill`, `rm`, `tr`.
# - `dnsperf`: Core tool for performing DNS load testing. (Script attempts `apt install dnsperf` if missing on Debian/Ubuntu).
# - `bc`: Basic calculator utility for floating-point arithmetic (parsing results). (Script attempts `apt install bc` if missing).
# - `grep`: For parsing text output from `dnsperf`.
# - `awk`: For extracting specific fields from text output.
# - `command`: Bash built-in for checking command existence.
# - `nohup`: For running the script persistently in the background.
# - `sudo`: Required *only* for automatic installation attempt of `dnsperf` and `bc` via `apt`.
#
# **Setup Instructions (Dependencies):**
# - The script attempts auto-install using `apt` on Debian/Ubuntu if `dnsperf` or `bc` are missing.
# - Manual installation on Debian/Ubuntu:
#   `sudo apt update && sudo apt install -y dnsperf bc`
# - Manual installation on RHEL/CentOS/Fedora (package names may vary slightly):
#   `sudo dnf update && sudo dnf install -y bind-utils bc` (or `yum install bind-utils bc`)
# - Manual installation on macOS (using Homebrew):
#   `brew install bind bc` (`dnsperf` is part of `bind`)
#
# **Operating System Compatibility:**
# - Designed primarily for Debian-based Linux distributions (e.g., Ubuntu) due to `apt` usage.
# - Should work on other Linux distributions and potentially macOS if dependencies are manually installed and core utilities are present.
#
# **Environment Variables Used:**
# - None directly used for configuration (script uses internal variables).
# - `PATH`: Standard variable; ensure all required binaries are locatable.
#
# **System Resource Requirements:**
# - CPU/Memory: Depends heavily on `dnsperf` intensity (duration, query rate, concurrency - not explicitly controlled here). Can range from low to high. Monitor usage.
# - Disk I/O: Moderate for writing log, raw output, and summary files to the script's directory or configured paths.
# - Network: Can generate significant DNS query traffic towards the target `DNS_SERVER`. Ensure this is acceptable and monitored.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - **General Log File:** Configured via `LOG_FILE` variable (default: `./dns_stress_test.log`). Captures script start/stop, dependency checks, test cycle start/wait messages, warnings, and errors. Stdout/stderr of the background process are redirected here via `nohup`.
# - **Raw Output Files:** `./results/dns_stress_test_output_YYYYMMDD_HHMMSS.txt`. Contains the full, unmodified standard output from each `dnsperf` run. Created in a `results` subdirectory relative to the script.
# - **Summary Report Files:** `./results/dns_test_summary_YYYYMMDD_HHMMSS.txt`. Contains key metrics parsed from the raw output for each test run. Created in the `results` subdirectory.
# - **PID File:** Configured via `PID_FILE` variable (default: `./dns_stress_test.pid`). Stores the process ID of the background script instance.
# - **Standard Output/Error (Terminal):** Initial start messages when launching in background, and status messages from the `stop` or `help` commands are printed to the console. Errors during initial launch might also appear.
#
# **Log Format (General Log File / Stdout/Stderr):**
# - `[YYYY-MM-DD HH:MM:SS TZ] [LEVEL] - Message` (e.g., `[2025-04-20 17:00:00 WIB] [INFO] - Starting main execution loop...`)
# - Colors are used for levels in interactive terminals, stripped for file logging.
#
# **Log Levels:**
# - `DEBUG`: Detailed step-by-step information (e.g., selected duration, command execution details). Enabled via `VERBOSE=true` config.
# - `INFO`: General operational messages (script start/stop, test cycle start/end, waits). Default level.
# - `WARN`: Potential issues or non-critical errors (e.g., stale PID file found, cannot write to log dir, parsing issues).
# - `ERROR`: Significant errors that likely impact functionality (e.g., `dnsperf` command failed, failed to stop process).
# - `CRITICAL`: Severe errors causing immediate script termination (e.g., missing critical dependency after install attempt, unwritable config/output dirs).
#
# **Log Rotation:**
# - Not handled internally. Log files (`LOG_FILE`, `results/*.txt`) will grow over time.
# - Recommend using external tools like `logrotate` for the main `LOG_FILE` if long-term execution is planned.
# - Output/summary files in `./results/` are timestamped; manage manually or via separate cleanup scripts based on age/size/count.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Normal Operation (Background): Primarily directed to `LOG_FILE`. May show initial startup messages if run interactively before daemonizing. Shows INFO/DEBUG messages if `LOG_TO_FILE=false`.
# - `stop` Command: Status messages regarding stopping the process.
# - `help` Command: Usage information.
#
# **Standard Error (stderr):**
# - Normal Operation (Background): Primarily directed to `LOG_FILE`. May show initial startup errors. Shows WARN/ERROR/CRITICAL messages.
# - `stop` Command: Error messages if stopping fails.
# - `help` Command: Usage information (conventionally sent to stderr).
#
# **Generated/Modified Files:**
# - Log File: Path specified by `LOG_FILE` (default: `./dns_stress_test.log`). Appended with operational logs.
# - PID File: Path specified by `PID_FILE` (default: `./dns_stress_test.pid`). Created on start, removed on clean stop/cleanup. Contains PID of the background process.
# - Query File: Path specified by `QUERY_FILE` (default: `./dns_queries.txt`). Created with sample content if it doesn't exist.
# - Raw Output Files: `./results/dns_stress_test_output_YYYYMMDD_HHMMSS.txt`. One created per test run. Contains raw `dnsperf` output.
# - Summary Report Files: `./results/dns_test_summary_YYYYMMDD_HHMMSS.txt`. One created per test run. Contains parsed key metrics.
# - Directories: `./results/` subdirectory is created if it doesn't exist. Log/PID/Query file directories are also created if possible.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success (Script started in background successfully, `stop` command completed successfully, `help` displayed).
# - 1: Critical Error (Dependency missing after install attempt, unwritable directories, `kill` failed, invalid arguments via `usage`). Background process might exit with 1 on CRITICAL log events.
# - Non-zero (Implicit): `dnsperf` might exit non-zero (logged as ERROR), `sudo apt` might fail (logged as CRITICAL). Failures due to `set -e`.
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** `dnsperf` or `bc` command not found.
#   **Resolution:** Ensure `sudo apt install dnsperf bc` (or equivalent for your OS) was successful. Check `LOG_FILE` for installation errors. Verify `PATH`.
# - **Issue:** Script doesn't start in background / `nohup` fails / exits immediately.
#   **Resolution:** Check permissions in the script's directory. Check system resources. Check `LOG_FILE` for early CRITICAL errors (e.g., unwritable PID directory).
# - **Issue:** Script stops unexpectedly.
#   **Resolution:** Check `LOG_FILE` for ERROR or CRITICAL messages. Check system logs (`/var/log/syslog`, `journalctl`) for external signals or resource issues (OOM killer).
# - **Issue:** `stop` command fails ("PID file not found", "Process with PID not found", "Failed to send kill signal").
#   **Resolution:** Check if `PID_FILE` exists and path is correct. Verify the PID inside exists (`ps aux | grep PID`). The process might have died, the file might be stale (script attempts cleanup), or permissions prevent signaling.
# - **Issue:** High resource usage (CPU, Network).
#   **Resolution:** `dnsperf` is the likely cause. Adjust `DURATION_OPTIONS` / `INTERVAL_OPTIONS` in the script config. Monitor the target `DNS_SERVER`.
# - **Issue:** Permission denied creating files/directories.
#   **Resolution:** Ensure the user running the script has write permissions in the script's directory (for default paths) or the configured `LOG_FILE`, `PID_FILE`, `QUERY_FILE` directories and `./results/`.
#
# **Important Considerations / Warnings:**
# - **Network Load:** This script WILL generate significant DNS query traffic. Use responsibly. Ensure target `DNS_SERVER` can handle the load and that testing is permitted. Monitor network impact.
# - **Resource Usage:** Monitor CPU/memory on the machine running the script.
# - **Continuous Operation:** Runs indefinitely until stopped (`stop` command, `kill`, or system shutdown).
# - **Output Files:** Timestamped files in `./results/` accumulate. Implement a cleanup strategy (manual or automated) if needed.
# - **Idempotency:** Not strictly idempotent. Running `start` when already running (with a valid PID file) will fail. Each test run creates unique output files.
# - **Concurrency:** Designed to run as a single instance, managed by the PID file. No internal locking for multiple concurrent runs.
# - **Rate Limiting:** No rate limiting applied to `dnsperf` by default. High QPS can occur.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes a Bash (v4+) environment with access to standard core utilities.
# - Assumes required dependencies (`dnsperf`, `bc`, etc.) are installed or can be installed via `apt` (on Debian/Ubuntu).
# - Assumes `sudo` is available and configured (potentially passwordless) if dependency installation is needed.
# - Assumes network connectivity to the target `DNS_SERVER`.
# - Assumes write permissions in the script's directory for default file/directory creation.
# - Assumes the script is executed with appropriate user privileges for its actions (file writing, process signaling).
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Requires `sudo` *only* for optional dependency installation via `apt`. Normal operation runs as the executing user. Avoid running the main test loop as root.
# - **Input Sanitization:** Configuration variables (`DNS_SERVER`, file paths) are used directly. Ensure paths are controlled. No direct execution of user-supplied commands. The `stop`/`help` arguments are simple string comparisons.
# - **Sensitive Data Handling:** No passwords or API keys handled. Target DNS server IP is stored in the script configuration.
# - **Dependencies:** Relies on standard system utilities and `dnsperf`/`bc`. Ensure these are from trusted sources/repositories.
# - **File Permissions:** Files/directories (logs, PID, results) are created with default user permissions (`umask`). The PID file might be world-readable. Consider setting a stricter `umask` before running if needed.
# - **External Command Execution:** Executes `dnsperf`, `ps`, `kill`, `apt`. Variables used in commands (like `${DNS_SERVER}`, `${QUERY_FILE}`) should be properly quoted (as implemented) to prevent unexpected word splitting or globbing issues, though the risk is low with typical IP/path values.
# - **Network Exposure:** Makes outbound connections to the target `DNS_SERVER` on port 53. Does not listen on any ports.
# - **Denial of Service Risk:** High potential to overload the target `DNS_SERVER` or intermediate network infrastructure. **Use with extreme caution and only on servers you own or have explicit permission to test.**
# - **Error Message Verbosity:** Error messages logged might contain file paths or PIDs, generally acceptable for this type of tool but avoid leaking sensitive info if modifying.
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
# - Bug Reports/Issues: Report issues via the script's repository (if available) or directly to the author's contact email.
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

# --- Debug Mode ---
# Uncomment the following line for debugging purposes:
# Prints each command and its arguments to stderr before it is executed.
# set -x

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
# Configuration variables - modify these to suit your environment.

# DNS_SERVER: IP address of the DNS server to be tested.
# Replace "10.202.0.180" with the actual IP address of the target DNS server.
DNS_SERVER="10.202.0.180"

# QUERY_FILE: Path to the file containing DNS queries to be used in the test.
# Each line should be a query (e.g., "example.com A").
# If the file doesn't exist, the script will create a sample one.
QUERY_FILE="${SCRIPT_DIR}/dns_queries.txt" # Default path relative to script location

# LOG_FILE: Path to the file where general script logs will be stored.
LOG_FILE="${SCRIPT_DIR}/dns_stress_test.log" # Default path relative to script location

# PID_FILE: Path to the file storing the Process ID (PID) of the running script instance.
# Used by the 'stop' command.
PID_FILE="${SCRIPT_DIR}/dns_stress_test.pid" # Default path relative to script location

# DURATION_OPTIONS: Array defining possible test durations in seconds.
# The script randomly selects one duration for each test run.
# Example: 120s (2 min), 600s (10 min), 1800s (30 min), 3600s (60 min).
DURATION_OPTIONS=(120 600 1800 3600)

# INTERVAL_OPTIONS: Array defining possible wait intervals in seconds between tests.
# The script randomly selects one interval after completing a test run.
# Example: 1 sec, 2 sec, 3 sec.
INTERVAL_OPTIONS=(1 2 3)

# Runtime state variables (usually not modified directly)
VERBOSE=false # Controls debug logging level
LOG_TO_FILE=true # Controls logging to LOG_FILE (will be disabled if directory not writable)
INTERACTIVE_MODE=false # Automatically determined if running in a TTY
[[ -t 1 ]] && INTERACTIVE_MODE=true

# --- Color Definitions (Optional) ---
# Define ANSI escape codes for colored output, checking if NO_COLOR is set or if not interactive.
# NO_COLOR is not implemented here, but the structure allows it.
if [[ "${INTERACTIVE_MODE}" == true ]]; then
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
# Description: Handles formatted logging to stdout/stderr and optionally to a file.
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

    # Determine color based on level for terminal output
    case "${level_upper}" in
        DEBUG) color="${COLOR_CYAN}" ;;
        INFO) color="${COLOR_GREEN}" ;;
        WARN) color="${COLOR_YELLOW}" ;;
        ERROR) color="${COLOR_RED}" ;;
        CRITICAL) color="${COLOR_BOLD}${COLOR_RED}" ;;
    esac

    # Map script log levels to numeric values for comparison (Simple hierarchy)
    declare -A log_levels=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [CRITICAL]=4)
    local current_log_level_num=1 # Default to INFO level
    # Adjust current_log_level_num based on VERBOSE flag or future LOG_LEVEL variable
     [[ "${VERBOSE}" == true ]] && current_log_level_num=0 # Show DEBUG if verbose

    local message_level_num=${log_levels[${level_upper}]}

    # Check if the message level is severe enough to be logged
    if [[ ${message_level_num} -ge ${current_log_level_num} ]]; then
        # Output to stderr for WARN, ERROR, CRITICAL; stdout otherwise
        if [[ "${level_upper}" == "WARN" || "${level_upper}" == "ERROR" || "${level_upper}" == "CRITICAL" ]]; then
            echo -e "${color}${log_line}${COLOR_RESET}" >&2
        else
            echo -e "${color}${log_line}${COLOR_RESET}"
        fi

        # Append to log file if enabled
        if [[ "${LOG_TO_FILE}" == true ]]; then
            # Ensure log directory exists (attempt to create if missing)
             if ! mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null; then
                # Check if already warned to avoid spamming
                if [[ -z ${LOG_DIR_CREATE_WARN_SENT+x} ]]; then
                    echo -e "${COLOR_YELLOW}[$(date +"%Y-%m-%d %H:%M:%S %Z")] [WARN] - Cannot create log directory $(dirname "${LOG_FILE}"). Logging to file disabled.${COLOR_RESET}" >&2
                    LOG_DIR_CREATE_WARN_SENT=true
                    LOG_TO_FILE=false # Disable further file logging attempts
                fi
            elif [[ ! -w "$(dirname "${LOG_FILE}")" ]]; then
                 # Check if already warned
                 if [[ -z ${LOG_DIR_WRITE_WARN_SENT+x} ]]; then
                     echo -e "${COLOR_YELLOW}[$(date +"%Y-%m-%d %H:%M:%S %Z")] [WARN] - Cannot write to log directory $(dirname "${LOG_FILE}"). Logging to file disabled.${COLOR_RESET}" >&2
                     LOG_DIR_WRITE_WARN_SENT=true
                     LOG_TO_FILE=false # Disable further file logging attempts
                 fi
            else
                # Strip color codes for file logging
                echo "${log_prefix} - ${message}" >> "${LOG_FILE}"
            fi
        fi
    fi

    # Exit immediately for CRITICAL errors
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        log_message "ERROR" "Critical error encountered. Exiting script." # Log before exit
        exit 1 # Use a specific exit code for critical errors if desired
    fi
}

# --- Dependency Check Function ---
# Description: Checks if a given command-line utility is available in the system's PATH.
# Arguments: $1 - The name of the command to check (e.g., "dnsperf").
# Returns: 0 (success) if the command exists, 1 (failure) otherwise.
check_command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# --- Dependency Installation Function ---
# Description: Checks for required dependencies and attempts to install them using apt.
# Requires sudo privileges if installation is needed.
check_and_install_dependencies() {
    local dependencies_missing=false
    local pkgs_to_install=()

    log_message "INFO" "Checking for required dependencies: dnsperf, bc..."

    if ! check_command_exists dnsperf; then
        log_message "WARN" "Command 'dnsperf' not found."
        dependencies_missing=true
        pkgs_to_install+=("dnsperf") # Use dnsperf package name (common)
    else
        log_message "DEBUG" "Dependency check passed for command: dnsperf"
    fi

    if ! check_command_exists bc; then
        log_message "WARN" "Command 'bc' not found."
        dependencies_missing=true
        pkgs_to_install+=("bc")
    else
        log_message "DEBUG" "Dependency check passed for command: bc"
    fi

    if [[ "${dependencies_missing}" == true ]]; then
        log_message "INFO" "Attempting to install missing dependencies (${pkgs_to_install[*]}). This may require sudo privileges."
        # Check if apt exists before trying to use it
        if check_command_exists apt; then
            # Attempt update and install
            if sudo apt update -y && sudo apt install -y "${pkgs_to_install[@]}"; then
                 log_message "INFO" "Successfully installed missing dependencies."
                 # Re-verify after install attempt
                 for pkg in "${pkgs_to_install[@]}"; do
                     if ! check_command_exists "$pkg"; then
                          log_message "CRITICAL" "Failed to install or find command '${pkg}' even after installation attempt. Please install manually."
                     fi
                 done
            else
                 log_message "CRITICAL" "Failed to install dependencies using 'apt'. Please install manually: sudo apt install ${pkgs_to_install[*]}"
            fi
        else
            log_message "CRITICAL" "'apt' command not found. Cannot automatically install dependencies. Please install manually: ${pkgs_to_install[*]}"
        fi
    else
        log_message "INFO" "All required dependencies are present."
    fi
}


# --- Cleanup Function ---
# Description: Performs cleanup tasks before script exits (e.g., removing PID file).
# Designed to be called via 'trap'.
cleanup() {
    local exit_status=$? # Capture the script's exit status
    log_message "INFO" "Performing cleanup..."

    # Remove PID file only if it exists and contains the current script's PID
    if [[ -f "${PID_FILE}" ]]; then
        local stored_pid
        stored_pid=$(cat "${PID_FILE}")
        if [[ "${stored_pid}" -eq "${SCRIPT_PID}" ]]; then
             log_message "DEBUG" "Removing PID file: ${PID_FILE}"
             rm -f "${PID_FILE}" || log_message "WARN" "Failed to remove PID file: ${PID_FILE}"
        else
             log_message "DEBUG" "PID file ${PID_FILE} does not belong to this process (${SCRIPT_PID} vs ${stored_pid}). Not removing."
        fi
    fi

    # Add other cleanup tasks here if needed (e.g., temp files)

    log_message "INFO" "Cleanup finished. Exiting with status: ${exit_status}"
    # Note: The script will exit with the original exit_status after trap completes
}

# --- Trap Setup ---
# Register the 'cleanup' function to run on script exit or specific signals.
trap cleanup EXIT INT TERM HUP


# --- Usage/Help Function ---
# Description: Displays basic usage information and exits.
usage() {
    cat << EOF >&2
Usage: ${SCRIPT_NAME} [COMMAND]

Automates DNS stress testing against a specified server.

Commands:
  (no command)   Starts the stress test script in the background using nohup.
                 Logs to ${LOG_FILE}. Creates ${PID_FILE}.
  stop           Stops the running background instance identified by ${PID_FILE}.
  help           Displays this help message and exits.

Configuration (modify variables within the script):
  DNS_SERVER       : Target DNS server IP (${DNS_SERVER})
  QUERY_FILE       : Path to query file (${QUERY_FILE})
  LOG_FILE         : Path to main log file (${LOG_FILE})
  PID_FILE         : Path to PID file (${PID_FILE})
  DURATION_OPTIONS : Test durations in seconds (${DURATION_OPTIONS[*]})
  INTERVAL_OPTIONS : Wait intervals in seconds (${INTERVAL_OPTIONS[*]})
EOF
    exit 1 # Exit with a non-zero status after showing help
}


# --- Environment Preparation Function ---
# Description: Sets up the environment before the main logic runs.
# (e.g., creates sample query file, ensures log directory exists)
prepare_environment() {
    log_message "INFO" "Preparing execution environment..."

    # Ensure log directory exists and is writable (already checked partially in log_message)
    if [[ "${LOG_TO_FILE}" == true ]]; then
        if ! mkdir -p "$(dirname "${LOG_FILE}")" || [[ ! -w "$(dirname "${LOG_FILE}")" ]]; then
            log_message "WARN" "Log directory '$(dirname "${LOG_FILE}")' is not writable or could not be created. Disabling file logging."
            LOG_TO_FILE=false
        else
             # Touch the log file to ensure it exists (optional)
             touch "${LOG_FILE}" || log_message "WARN" "Could not touch log file: ${LOG_FILE}"
        fi
    fi

    # Check if the specified query file exists. Create a sample if not.
    if [[ ! -f "${QUERY_FILE}" ]]; then
        log_message "INFO" "Query file '${QUERY_FILE}' not found. Creating a sample file..."
        # Use 'cat << EOL' (here document) for multi-line input redirection.
        # Ensure the directory exists first
        if mkdir -p "$(dirname "${QUERY_FILE}")" && [[ -w "$(dirname "${QUERY_FILE}")" ]]; then
            cat << EOL > "${QUERY_FILE}"
example.com A
google.com A
openai.com A
facebook.com AAAA
yahoo.com MX
amazon.com A
microsoft.com A
apple.com A
cloudflare.com A
example.org NS
example.net TXT
reddit.com A
# Add more diverse queries or high-traffic domains as needed
EOL
            log_message "INFO" "Sample query file created at '${QUERY_FILE}'."
        else
             log_message "CRITICAL" "Could not create sample query file at '${QUERY_FILE}'. Directory not writable or cannot be created."
        fi
    else
        log_message "INFO" "Using existing query file: ${QUERY_FILE}"
    fi

    log_message "INFO" "Environment preparation complete."
}


# --- DNS Test Execution Function ---
# Description: Executes a single DNS stress test using dnsperf, parses results,
#              and writes a summary report to a timestamped file.
# Arguments: None. Uses global variables for configuration.
# Outputs: Creates raw output and summary report files per run. Logs status.
run_dns_test() {
    # Randomly select test duration and calculate end time
    local duration=${DURATION_OPTIONS[RANDOM % ${#DURATION_OPTIONS[@]}]}
    log_message "DEBUG" "Selected duration: ${duration} seconds."

    # Get current timestamp for unique filenames
    local timestamp
    timestamp=$(date +'%Y%m%d_%H%M%S') # Consistent timestamp format

    # Define output filenames within the script's directory or a dedicated output subdir
    local output_basedir="${SCRIPT_DIR}/results" # Store results in a subdir
    mkdir -p "${output_basedir}" || log_message "WARN" "Could not create results directory: ${output_basedir}" # Try to create dir

    local output_file="${output_basedir}/dns_stress_test_output_${timestamp}.txt"
    local result_file="${output_basedir}/dns_test_summary_${timestamp}.txt"

    log_message "INFO" "Starting DNS stress test run (Timestamp: ${timestamp}). Duration: ${duration}s, Server: ${DNS_SERVER}"
    log_message "INFO" "Raw output will be saved to: ${output_file}"
    log_message "INFO" "Summary report will be saved to: ${result_file}"

    # --- Execute dnsperf ---
    # Options:
    # -s: Target DNS server IP.
    # -d: Input data file containing queries.
    # -l: Duration limit for the test in seconds.
    # -q: Query rate limit (optional, consider adding as a variable if needed)
    # -c: Concurrency level (optional, consider adding as a variable if needed)
    log_message "DEBUG" "Executing: dnsperf -s ${DNS_SERVER} -d \"${QUERY_FILE}\" -l ${duration}"
    if ! dnsperf -s "${DNS_SERVER}" -d "${QUERY_FILE}" -l "${duration}" > "${output_file}"; then
        # Log error but try to continue parsing if output file was created partially
        log_message "ERROR" "dnsperf command failed with exit status $?. Check ${output_file} for details."
        # Depending on desired robustness, might exit here or attempt parsing anyway
    fi
    log_message "DEBUG" "dnsperf execution finished."


    # --- Parse Results ---
    log_message "DEBUG" "Parsing results from ${output_file}..."
    local total_queries="N/A"
    local completed_queries="N/A"
    local lost_queries="N/A"
    local qps="N/A"
    local avg_latency="N/A"
    local min_latency="N/A"
    local max_latency="N/A"
    local loss_rate="N/A"
    local success_rate="N/A"

    # Use grep/awk/tr carefully, check if file exists and is readable first
    if [[ -f "${output_file}" && -r "${output_file}" ]]; then
        # Extract metrics using grep and awk. Add default value if grep fails.
        total_queries=$(grep "Queries sent" "${output_file}" | awk '{print $3}' || echo "N/A")
        completed_queries=$(grep "Queries completed" "${output_file}" | awk '{print $3}' || echo "N/A")
        lost_queries=$(grep "Queries lost" "${output_file}" | awk '{print $3}' || echo "N/A")
        qps=$(grep "Queries per second" "${output_file}" | awk '{print $4}' || echo "N/A")

        # Latency parsing requires more steps
        local latency_line
        latency_line=$(grep "Average Latency" "${output_file}" || echo "")
        if [[ -n "${latency_line}" ]]; then
            avg_latency=$(echo "$latency_line" | awk '{print $4}' || echo "N/A")
            # Remove trailing comma from min latency
            min_latency=$(echo "$latency_line" | awk '{print $6}' | tr -d ',' || echo "N/A")
            # Remove closing parenthesis from max latency
            max_latency=$(echo "$latency_line" | awk '{print $8}' | tr -d ')' || echo "N/A")
        fi

        # Calculate success/loss rates using 'bc' if values are numeric
        if [[ "$total_queries" =~ ^[0-9]+$ && "$lost_queries" =~ ^[0-9]+$ && "$completed_queries" =~ ^[0-9]+$ && "$total_queries" -gt 0 ]]; then
            loss_rate=$(echo "scale=2; (${lost_queries} / ${total_queries}) * 100" | bc)
            success_rate=$(echo "scale=2; (${completed_queries} / ${total_queries}) * 100" | bc)
        elif [[ "$total_queries" == "0" ]]; then
             loss_rate="0.00"
             success_rate="0.00" # Or N/A if 0 queries sent means no success
        else
            log_message "WARN" "Could not calculate rates due to non-numeric or zero total queries."
            loss_rate="N/A"
            success_rate="N/A"
        fi
    else
        log_message "ERROR" "Cannot read dnsperf output file: ${output_file}"
    fi

    log_message "DEBUG" "Parsing complete. QPS: ${qps}, Avg Latency: ${avg_latency}s"

    # --- Write Summary Report ---
    log_message "DEBUG" "Writing summary report to ${result_file}..."
    # Use a heredoc for cleaner multi-line echo
    cat << EOL > "${result_file}"
==============================
 DNS Stress Test Summary
==============================
Timestamp          : ${timestamp}
Target DNS Server  : ${DNS_SERVER}
Duration of Test   : ${duration} seconds
Query File Used    : ${QUERY_FILE}
------------------------------
Queries Sent       : ${total_queries}
Queries Completed  : ${completed_queries}
Queries Lost       : ${lost_queries}
------------------------------
Success Rate       : ${success_rate}%
Loss Rate          : ${loss_rate}%
Queries per Second : ${qps} QPS
------------------------------
Average Latency    : ${avg_latency} s
Minimum Latency    : ${min_latency} s
Maximum Latency    : ${max_latency} s
------------------------------
Raw Output File    : ${output_file}
==============================
EOL

    if [[ $? -ne 0 ]]; then
        log_message "ERROR" "Failed to write summary report to ${result_file}."
    else
        log_message "INFO" "DNS Stress Test Run (Timestamp: ${timestamp}) Completed. Summary: ${result_file}"
    fi
}


# --- Main Logic Function ---
# Description: Contains the core execution loop of the script.
# Continuously runs DNS tests at random intervals.
main() {
    log_message "INFO" "Starting main execution loop (PID: ${SCRIPT_PID})."
    log_message "INFO" "DNS Server: ${DNS_SERVER}, Query File: ${QUERY_FILE}"
    log_message "INFO" "Durations: ${DURATION_OPTIONS[*]}s, Intervals: ${INTERVAL_OPTIONS[*]}s"
    log_message "INFO" "Press Ctrl+C or use '${SCRIPT_NAME} stop' to terminate."

    # Main execution loop: continuously run tests at random intervals.
    # This loop runs indefinitely until the script is stopped or interrupted.
    while true; do
        # Run the DNS test function. Consider running in background (&)
        # if you want intervals to start immediately, but this can lead
        # to overlapping tests if durations are long and intervals short.
        # Current implementation runs tests sequentially.
        run_dns_test

        # Randomly select a wait interval
        local interval=${INTERVAL_OPTIONS[RANDOM % ${#INTERVAL_OPTIONS[@]}]}
        log_message "INFO" "Waiting ${interval} seconds until the next test cycle..."

        # Pause execution for the selected interval
        sleep "${interval}"
    done

    # This part is generally unreachable due to the infinite loop,
    # but good practice to have a final log message if the loop could exit.
    # log_message "INFO" "Main execution loop finished."
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# --- Argument Handling ---
# Simple argument handling for 'stop', 'help', and '--no-restart' (internal).
# Does not use getopts for simplicity based on original script needs.
if [[ "${1:-}" == "stop" ]]; then
    log_message "INFO" "Stop command received."
    if [[ -f "$PID_FILE" ]]; then
        PID=$(cat "$PID_FILE")
        log_message "INFO" "Attempting to stop DNS stress test script with PID ${PID}..."
        # Check if the process exists before trying to kill
        if ps -p "${PID}" > /dev/null; then
             # Attempt to kill the process and remove the PID file upon success
             if kill "${PID}"; then
                 sleep 1 # Give process time to terminate before removing PID file
                 rm -f "$PID_FILE"
                 log_message "INFO" "DNS stress test script (PID ${PID}) stopped successfully."
             else
                 log_message "ERROR" "Failed to send kill signal to PID ${PID}. It might require manual intervention or permissions."
                 # Consider trying 'kill -9' here cautiously or advising manual kill
                 exit 1
             fi
        else
             log_message "WARN" "Process with PID ${PID} not found. Removing stale PID file ${PID_FILE}."
             rm -f "$PID_FILE"
        fi
    else
        log_message "WARN" "PID file ${PID_FILE} not found. Script might not be running or PID file was manually removed."
    fi
    exit 0 # Exit successfully after handling 'stop' command.
elif [[ "${1:-}" == "help" || "${1:-}" == "--help" ]]; then
    usage
fi

# --- Background Execution / Daemonization ---
# Check if already running in background (via --no-restart flag)
# If not, restart the script in the background using nohup.
if [[ "${1:-}" != "--no-restart" ]]; then
    # Check if already running by checking PID file
    if [[ -f "${PID_FILE}" ]]; then
         existing_pid=$(cat "${PID_FILE}")
         if ps -p "${existing_pid}" > /dev/null; then
              log_message "ERROR" "Script appears to be already running with PID ${existing_pid} (PID file: ${PID_FILE}). Use '${SCRIPT_NAME} stop' first."
              exit 1
         else
              log_message "WARN" "Found stale PID file (${PID_FILE}) for PID ${existing_pid}. Removing it."
              rm -f "${PID_FILE}"
         fi
    fi

    log_message "INFO" "Starting DNS stress test script in background..."
    log_message "INFO" "Output and errors will be logged to: ${LOG_FILE}"
    # Execute the script itself with '--no-restart' in the background using nohup.
    # Redirect stdout and stderr to the LOG_FILE.
    nohup "${BASH_SOURCE[0]}" --no-restart >> "${LOG_FILE}" 2>&1 &
    # Save the PID of the background process to the PID_FILE.
    local bg_pid=$!
    echo "${bg_pid}" > "${PID_FILE}"
    log_message "INFO" "Script started in background with PID ${bg_pid}. PID saved to ${PID_FILE}."
    log_message "INFO" "Monitor log file: tail -f ${LOG_FILE}"
    log_message "INFO" "To stop: ./${SCRIPT_NAME} stop"
    exit 0 # Exit the current foreground script instance.
fi

# --- Script continues here only if invoked with --no-restart (i.e., running in background) ---
log_message "INFO" "Script running in background mode (PID: ${SCRIPT_PID})."

# 1. Check Dependencies
check_and_install_dependencies

# 2. Prepare Environment (create sample query file if needed)
prepare_environment

# 3. Execute Main Logic (infinite loop)
main

# --- End of Background Execution Logic ---
# This point is typically not reached due to the infinite loop in main()
# and the EXIT trap handling cleanup.
exit 0

# =========================================================================================
# --- End of Script ---
