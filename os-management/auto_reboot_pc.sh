#!/bin/bash
# SPDX-FileCopyrightText: © 2025 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : auto_reboot_pc.sh
# PURPOSE       : Monitors user logins; reboots system if idle for defined period.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2025-04-09
# LAST UPDATED  : 2025-04-09
# VERSION       : 1.0.0
# =========================================================================================

# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This script periodically checks for active user login sessions using the 'who' command.
# It performs this check at regular intervals (`INTERVAL`) for a total monitoring duration
# (`TOTAL_DURATION`). If, at any point during this monitoring window, the script finds
# zero active sessions, it logs the event, flags the system for a reboot via `systemctl reboot`,
# and stops monitoring immediately. If sessions are consistently detected throughout the entire
# window, no reboot is initiated.
#
# The primary goal is to ensure unattended machines (like kiosks or lab PCs) are rebooted
# if left logged out for a specified duration, potentially for maintenance or to reset the state.
# The script includes basic argument parsing, logging (to stdout/stderr, syslog, and optionally file),
# dependency checks, and error handling.
#
# Key Workflow / Functions:
# - Parses command-line arguments for configuration overrides (duration, interval, logging).
# - Validates input parameters.
# - Checks for the presence of required system commands.
# - Enters a monitoring loop:
#   - Checks active user sessions using the `who | wc -l` command combination.
#   - If zero sessions are detected, sets a `REBOOT_NEEDED` flag and breaks the loop.
#   - If sessions are detected, sleeps for `INTERVAL` seconds before the next check.
# - After the loop (either completed or broken early), checks the `REBOOT_NEEDED` flag.
# - If the flag is true, executes `systemctl reboot` (unless `--dry-run` is active).
# - If the flag is false, logs that no reboot is needed.
# - Uses a structured logging function (`log_message`) for different severity levels.
# - Uses `trap` for basic cleanup on exit/interrupt.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Simplicity**: Focuses solely on the core task of checking user sessions and triggering a reboot, while adding robustness via standard template features (logging, args, checks).
# - **Reliability**: Aims to accurately detect the absence of interactive user sessions using standard tools. Includes dependency checks and basic error handling.
# - **Automation**: Designed for unattended execution (e.g., via cron), requiring minimal user interaction post-setup.
# - **Flexibility**: Uses command-line arguments to override default timings and logging behavior.
# - **Readability**: Employs clear variable names, comments, functions, and consistent formatting based on the template.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - System Administrators managing public computer labs, kiosks, or shared workstations.
# - IT Support Teams responsible for automated system maintenance and uptime.
# - DevOps Engineers looking for simple automation scripts for system state management.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x auto_reboot_pc.sh`
# - System privileges: Requires root/sudo privileges to execute `/usr/bin/systemctl reboot`.
# - File system access: Write access to log directory/file if `--log-file` is used.
#
# **Basic Syntax:**
#   ./auto_reboot_pc.sh [options]
#
# **Options:**
#   -h, --help           Display the help message and exit.
#   -v, --verbose        Enable verbose output (sets log level to DEBUG).
#   -d, --debug          Enable Bash debug mode (`set -x`). Prints every command.
#       --dry-run        Simulate execution; show intended actions (like reboot) without performing them.
#   -T, --duration SECS  Set total monitoring duration in seconds (Default: 600).
#   -i, --interval SECS  Set check interval in seconds (Default: 5).
#   -t, --tag TAG        Set the syslog tag (Default: shift_reboot).
#       --no-color       Disable colored output.
#       --log-file PATH  Enable logging to the specified file path instead of only syslog/stderr.
#       --log-level LEVEL Set log level (DEBUG, INFO, WARN, ERROR, CRITICAL; Default: INFO).
#       --no-syslog      Disable logging to syslog via 'logger'.
#
# **Common Examples:**
# 1. Run with default settings (10-minute duration, 5-second interval, log to syslog):
#    `sudo ./auto_reboot_pc.sh`
#
# 2. Run with a 5-minute duration and 15-second interval, verbose output:
#    `sudo ./auto_reboot_pc.sh -v --duration 300 --interval 15`
#
# 3. Perform a dry run to see what would happen, logging to a file:
#    `sudo ./auto_reboot_pc.sh --dry-run --log-file /var/log/auto_reboot_test.log`
#
# 4. Run with default timings but disable syslog logging (only uses stderr/stdout/file):
#    `sudo ./auto_reboot_pc.sh --no-syslog`
#
# 5. Get help:
#    `./auto_reboot_pc.sh --help`
#
# **Advanced Execution (Automation via cron):**
# - Edit the root crontab (recommended due to reboot privilege requirement): `sudo crontab -e`
# - Add a line to run the script periodically. Example: Run every 15 minutes, logging script execution errors to a separate file.
#   `*/15 * * * * /usr/local/sbin/auto_reboot_pc.sh >> /var/log/auto_reboot_pc_cron.log 2>&1`
#
#   Cron Job Line Explanation:
#   `*/15 * * * *`: Defines the schedule (every 15 minutes).
#   `/usr/local/sbin/auto_reboot_pc.sh`: Absolute path to this script. **Using full paths in cron is crucial.**
#   `>> /var/log/auto_reboot_pc_cron.log`: Appends script's standard output (minimal) to a log file.
#   `2>&1`: Redirects standard error to the same log file, capturing potential execution errors (e.g., script not found, permission issues at launch, getopt not found).
#   Note: Internal operational logs (INFO, WARN, etc.) are handled by the script's logging settings (syslog by default, or --log-file).
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - Place the script in a standard administrative directory, such as:
#   - `/usr/local/sbin/` (Common for locally installed admin scripts requiring root)
#   Ensure the chosen location is included in the `PATH` for root or specify the full path when executing/scheduling.
#
# **Manual Setup:**
# 1. Place the script in the chosen location (e.g., `/usr/local/sbin/auto_reboot_pc.sh`).
# 2. Set appropriate ownership: `sudo chown root:root /usr/local/sbin/auto_reboot_pc.sh`
# 3. Set executable permissions: `sudo chmod 700 /usr/local/sbin/auto_reboot_pc.sh` (Restrictive permissions recommended)
# 4. Install required dependencies if missing (see DEPENDENCIES section, though most are standard).
# 5. Set up scheduling (e.g., cron job) as described in the USAGE section.
# 6. Run the script initially with `--dry-run` and `-v` to test configuration and behavior. `sudo /usr/local/sbin/auto_reboot_pc.sh --dry-run -v`
#
# **Integration:**
# - **Cron Job:** Primary intended method. Ensure the cron job runs as a user with reboot privileges (typically root). Use absolute paths.
# - **Systemd Timer (Alternative):** Create `.service` and `.timer` files in `/etc/systemd/system/` for more advanced scheduling and dependency management compared to cron.
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: The Bourne-Again SHell interpreter. Relies on Bash features (e.g., `[[ ]]`, `declare -A`, `set -euo pipefail`). Version 4+ recommended.
#
# **Required System Binaries/Tools:**
# - `coreutils`: Provides `who`, `wc`, `sleep`, `date`, `id`, `basename`, `dirname`, `mkdir`, `touch`, `echo`, `tr`.
# - `systemd`: Provides `systemctl` (for rebooting).
# - `util-linux`: Provides `logger` (for syslog) and `getopt` (for argument parsing). Package name for logger might vary (e.g., bsdutils on Debian/Ubuntu).
# - `grep`, `sed`: Used internally by some functions (e.g., `usage`, `load_config` if implemented).
#
# **Setup Instructions (if dependencies are not standard):**
# - These tools are standard components of most modern Linux distributions using systemd.
# - Verify presence if needed: `command -v bash who wc sleep logger systemctl date id basename dirname getopt`
# - Example installation (Debian/Ubuntu): `sudo apt update && sudo apt install -y coreutils systemd util-linux` (Most are usually pre-installed)
# - Example installation (RHEL/CentOS/Fedora): `sudo dnf update && sudo dnf install -y coreutils systemd util-linux`
#
# **Operating System Compatibility:**
# - Designed primarily for Linux distributions using the **systemd** init system (e.g., RHEL/CentOS 7+, Fedora, Ubuntu 16.04+, Debian 8+, Arch Linux, etc.).
# - **Incompatible** with non-systemd systems (e.g., older Linux with SysVinit, macOS, BSD variants) without modifying the reboot command (`systemctl reboot`).
#
# **Environment Variables Used:**
# - This script does not rely on specific environment variables for its core operation, but standard ones like `PATH` are implicitly used to find commands.
#
# **System Resource Requirements:**
# - Minimal. Consumes very little CPU (mostly idle during `sleep`) and negligible memory/disk I/O during monitoring. The `systemctl reboot` command itself has standard resource implications.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Error (stderr): Used for WARN, ERROR, CRITICAL messages by default. Also used for DEBUG messages if `--verbose` is set.
# - Standard Output (stdout): Used for INFO messages by default (unless suppressed by redirection).
# - System Log (syslog/journald): Enabled by default via the `logger` command. Can be disabled with `--no-syslog`.
# - Dedicated Log File: Optional, enabled via `--log-file PATH`. Appends logs to the specified file.
#
# **Log Location (Primary - Syslog):**
# - Check standard system log files like `/var/log/syslog`, `/var/log/messages`, or use `journalctl`.
# - **Syslog Tag:** Controlled by `--tag TAG` (Default: `shift_reboot`).
#   - Example Filter Command: `journalctl -t shift_reboot -f`
#   - Example Filter Command (older systems): `grep 'shift_reboot' /var/log/syslog`
#
# **Log Format:**
# - Stdout/Stderr/File: `[YYYY-MM-DD HH:MM:SS ZONE] [LEVEL] - Message` (Colorized if interactive and not disabled)
# - Syslog: Uses standard syslog format determined by the system's logging daemon, message content is `Message`. Priority/facility set based on level (e.g., `user.info`, `user.warning`).
#
# **Log Levels:**
# - `DEBUG`: Detailed step-by-step info (Enabled via `--verbose` or `--log-level DEBUG`).
# - `INFO`: General operational messages (Default level).
# - `WARN`: Potential issues or non-critical errors.
# - `ERROR`: Significant errors, potentially preventing task completion.
# - `CRITICAL`: Severe errors causing script termination.
# - Control: `--log-level LEVEL` argument. Default is `INFO`. `--verbose` sets level to `DEBUG`.
#
# **Log Rotation:**
# - Syslog: Managed by the system's `syslogd`/`journald` configuration (e.g., `logrotate`, journald size limits). No script action needed.
# - File Log (`--log-file`): **Not handled by the script.** Requires external setup using tools like `logrotate` if rotation is needed for the specified file.
# - Cron Log (from `>>` redirection): Requires external setup using `logrotate`.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Prints INFO and DEBUG level messages (DEBUG only if verbose). Designed to be minimal for INFO. Cron jobs often redirect this.
#
# **Standard Error (stderr):**
# - Prints WARN, ERROR, and CRITICAL level messages. Also used for `set -x` output if `--debug` is enabled. Captures initialization errors (e.g., command not found before logging starts).
#
# **Generated/Modified Files:**
# - **System Logs:** Actively writes messages via `logger` if syslog is enabled.
# - **Optional Log File:** If `--log-file PATH` is used, this file is created/appended to.
# - **Optional Cron Log:** If cron output is redirected (`>> file 2>&1`), that file captures stdout/stderr *from the cron execution context*.
# - The script **does not** create or modify any other configuration or data files. It does not use temporary files.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - **0:** Success (Monitoring completed, no reboot condition met, or --dry-run successful).
# - **1:** General Error (e.g., `set -e` triggered, argument parsing internal error, `CRITICAL` log message triggered). Also used if `systemctl reboot` command fails after being called.
# - **Non-zero (from dependencies):** If required commands (`getopt`, `who`, etc.) fail and `set -e` is active, their exit code might be returned. `check_dependency` function explicitly triggers exit code 1 via CRITICAL log.
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** Script doesn't run/fails silently in cron.
#   **Resolution:** Check cron daemon logs. Verify absolute script path in crontab. Check cron output log file (e.g., `/var/log/auto_reboot_pc_cron.log`) for early errors (path, permissions, `getopt not found`). Ensure `chmod +x`. Ensure cron user is root. Check `$PATH` in cron environment if dependencies fail.
# - **Issue:** Permission Denied on `systemctl reboot`.
#   **Resolution:** Script MUST run as root or via `sudo`. Ensure cron job runs as root.
# - **Issue:** `command not found: getopt` (or others like `who`, `logger`, `systemctl`).
#   **Resolution:** Install missing package (see DEPENDENCIES). Verify command exists in `/usr/bin` or `/bin`. Ensure `$PATH` is correct in execution environment (especially cron).
# - **Issue:** System reboots even when users *seem* active (e.g., GUI session).
#   **Resolution:** `who` tracks interactive terminal logins (TTYs, SSH). It likely **will not** detect GUI sessions without terminals, background tasks, etc. Confirm if this detection method is sufficient. Consider alternatives if needed (e.g., query desktop environment idle status, check specific processes).
# - **Issue:** Script fails on non-systemd OS.
#   **Resolution:** Replace `/usr/bin/systemctl reboot` with the appropriate command (e.g., `shutdown -r now`).
#
# **Important Considerations / Warnings:**
# - **CRITICAL: Automatic Reboot Risk:** This script forcefully reboots the system without user confirmation if conditions are met. **THIS CAN CAUSE DATA LOSS OR SERVICE INTERRUPTION.** Understand the implications. Test extensively using `--dry-run` and appropriate timings in a safe environment before deploying.
# - **`who` Command Limitations:** Only detects sessions reported by `who`. May not reflect all forms of user "activity". Define "inactive" carefully for your use case.
# - **Systemd Dependency:** Hard requirement for reboot functionality.
# - **Privilege Requirement:** Needs root to reboot. Secure the script file itself (permissions 700, owned by root).
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes the system uses `systemd` as its init system.
# - Assumes the `who` command accurately reflects the desired state of "no active interactive user sessions" for triggering a reboot.
# - Assumes the script is executed with root privileges.
# - Assumes standard utilities (`bash`, `who`, `wc`, `sleep`, `logger`, `systemctl`, `getopt`, `date`, `id`, `basename`, `dirname`) are installed and in the system `PATH`.
# - Assumes the system's logging service (syslog/journald) is operational if syslog logging is enabled.
# =========================================================================================

# =========================================================================================
# PERFORMANCE OPTIMIZATION
# =========================================================================================
# - Resource consumption is minimal. The script spends most of its time in `sleep`.
# - No specific performance optimizations are implemented or generally needed due to the low-intensity nature of the checks.
# =========================================================================================

# =========================================================================================
# TESTING & VALIDATION
# =========================================================================================
# - **Test Strategy:** Manual testing recommended. Use `--dry-run` extensively.
# - **Key Test Cases:**
#   - Run with no users logged in (expect reboot or dry-run message).
#   - Run with users logged in (expect "no reboot needed" message).
#   - Test various `--duration` and `--interval` values.
#   - Test `--log-file` option.
#   - Test `--no-syslog` option.
#   - Test argument validation (e.g., non-numeric duration).
#   - Test help message (`--help`).
#   - Run as non-root (expect failure on reboot attempt).
# - **Automation:** Static analysis using `shellcheck` is recommended.
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - Add support for a configuration file (e.g., `/etc/auto_reboot.conf`) to manage settings instead of only arguments.
# - Implement more sophisticated session detection methods (e.g., checking specific processes, querying D-Bus for desktop idle times).
# - Add locking mechanism (e.g., `flock`) to prevent multiple instances from running simultaneously if scheduled frequently.
# - Provide options for different reboot actions (e.g., shutdown, custom command).
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Requires **root** privileges for `systemctl reboot`. This is the highest privilege. Justification: Required to perform system reboot. Ensure script file permissions are strict (e.g., `chmod 700`, `chown root:root`) to prevent tampering. Only deploy on systems where unattended reboots are explicitly desired and safe.
# - **Input Sanitization:** Command-line arguments are parsed by `getopt`. Numerical arguments (`--duration`, `--interval`) are validated to be positive integers. String arguments (`--tag`, `--log-file`, `--log-level`) are used directly but validated where appropriate (log level) or used in contexts where injection risk is low (syslog tag, file path creation). No user input is used to construct executable commands directly.
# - **Sensitive Data Handling:** No passwords, API keys, or other sensitive data are handled.
# - **Dependencies:** Relies on standard system binaries (`coreutils`, `systemd`, `util-linux`). Keep the underlying OS and packages updated to mitigate vulnerabilities in these tools.
# - **File Permissions:** If `--log-file` is used, the script attempts `mkdir -p` and writes to the file. Ensure the target directory/file has appropriate permissions, or run as root (which is needed anyway for reboot). Logs could potentially contain system state information if DEBUG is enabled; secure log files appropriately.
# - **External Command Execution:** Executes `who`, `wc`, `sleep`, `logger`, `systemctl`, `date`, `id`, `basename`, `dirname`, `mkdir`, `touch`, `getopt`, `echo`, `tr`. These are standard system commands. `systemctl reboot` is the most critical.
# - **Code Integrity:** Verify script integrity using checksums if obtained from untrusted sources.
# - **Denial of Service:** Misconfiguration (e.g., very short duration/interval combined with frequent cron execution) could lead to unintended reboot loops. Configure scheduling and script timings carefully.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is within this script's header comments.
# - Use `./auto_reboot_pc.sh --help` for command-line usage summary.
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Report issues via the repository link (if provided in METADATA) or direct contact.
# =========================================================================================

# =========================================================================================
# SCRIPT EXECUTION ENVIRONMENT & CONFIGURATION
# =========================================================================================

# --- Bash Strict Mode ---
# -e: Exit immediately if a command exits with a non-zero status.
# -u: Treat unset variables and parameters (other than $@ or $*) as an error.
# -o pipefail: The return value of a pipeline is the status of the last command
#              to exit with a non-zero status, or zero if no command exited
#              with a non-zero status.
set -euo pipefail

# --- Debug Mode ---
# Uncomment the following line for debugging purposes (prints each command before execution).
# set -x

# --- Script Information ---
# Using BASH_SOURCE[0] is generally more robust than $0, especially with symlinks.
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
# Resolve the absolute path of the script's directory.
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_DIR="${SOURCE_DIR}"
readonly SCRIPT_PID=$$

# --- Timestamp ---
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Global Runtime Variables ---
# Configuration Defaults (can be overridden by arguments)
VERBOSE=false               # Controls detailed output to stdout/stderr.
DEBUG_MODE=false            # Enables 'set -x'.
DRY_RUN=false               # Simulate actions without performing the reboot.
NO_COLOR=false              # Disable colored output.
INTERACTIVE_MODE=false      # Detect if running in an interactive terminal.
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is connected to a terminal.

# Script-specific Defaults (Original hardcoded values)
# Define the total time (in seconds) the script will monitor for active user sessions.
DEFAULT_TOTAL_DURATION=600
# Set the time interval (in seconds) between consecutive checks for active sessions.
DEFAULT_INTERVAL=5
# Syslog tag used by logger
DEFAULT_SYSLOG_TAG="shift_reboot"

# Runtime variables that will be populated/used later
TOTAL_DURATION=${DEFAULT_TOTAL_DURATION}
INTERVAL=${DEFAULT_INTERVAL}
SYSLOG_TAG="${DEFAULT_SYSLOG_TAG}"
LOG_LEVEL="INFO" # Default log level (DEBUG, INFO, WARN, ERROR, CRITICAL)
# The original script used `logger`, so we enable syslog logging by default.
LOG_TO_SYSLOG=true
# File logging is disabled by default unless explicitly configured/enabled.
LOG_TO_FILE=false
LOG_FILE="" # Path to log file, if enabled.
# Initialize the core flag within the script's scope (will be set in main).
REBOOT_NEEDED=false

# --- Color Definitions (Optional) ---
# Define ANSI escape codes for colored output, checking if disabled or not interactive.
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
# Description: Handles formatted logging to stdout/stderr, optionally to syslog,
#              and optionally to a file. Based on specified log level.
# Usage: log_message LEVEL "Message string"
# Levels: DEBUG, INFO, WARN, ERROR, CRITICAL
log_message() {
    local level="$1"; local message="$2"
    local timestamp; timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z")
    local level_upper; level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]')
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

    # Map script log levels to numeric values for comparison
    declare -A log_levels=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [CRITICAL]=4)
    local current_log_level_num=${log_levels[${LOG_LEVEL^^}]}
    local message_level_num=${log_levels[${level_upper}]}

    # Check if the message level is severe enough to be logged based on LOG_LEVEL
    if [[ ${message_level_num} -ge ${current_log_level_num} ]]; then
        # Output to stderr for WARN, ERROR, CRITICAL; stdout otherwise
        if [[ "${level_upper}" == "WARN" || "${level_upper}" == "ERROR" || "${level_upper}" == "CRITICAL" ]]; then
            echo -e "${color}${log_line}${COLOR_RESET}" >&2
        else
            # Only print DEBUG if VERBOSE is true
            if [[ "${level_upper}" == "DEBUG" && "${VERBOSE}" == false ]]; then
                : # Do nothing for DEBUG messages if not verbose
            else
                echo -e "${color}${log_line}${COLOR_RESET}"
            fi
        fi

        # Send to syslog if enabled
        if [[ "${LOG_TO_SYSLOG}" == true ]]; then
             # Use logger command with the specified tag. Map levels roughly.
             local logger_priority="user.info" # Default
             case "${level_upper}" in
                DEBUG) logger_priority="user.debug" ;;
                INFO) logger_priority="user.info" ;;
                WARN) logger_priority="user.warning" ;;
                ERROR) logger_priority="user.err" ;;
                CRITICAL) logger_priority="user.crit" ;;
             esac
             # Check if logger command exists before using it
             if command -v logger &> /dev/null; then
                logger -t "${SYSLOG_TAG}" -p "${logger_priority}" -- "${message}"
             elif [[ -z ${LOGGER_MISSING_WARN_SENT+x} ]]; then
                echo -e "${COLOR_YELLOW}[${timestamp}] [WARN] - 'logger' command not found. Cannot log to syslog.${COLOR_RESET}" >&2
                LOGGER_MISSING_WARN_SENT=true # Prevent repeating warning
             fi
        fi

        # Append to log file if enabled and path is set
        if [[ "${LOG_TO_FILE}" == true && -n "${LOG_FILE}" ]]; then
            # Ensure log directory exists
            local log_dir; log_dir="$(dirname "${LOG_FILE}")"
            if ! mkdir -p "${log_dir}" 2>/dev/null && [[ ! -d "${log_dir}" ]]; then
                 if [[ -z ${LOG_DIR_CREATE_WARN_SENT+x} ]]; then
                    echo -e "${COLOR_YELLOW}[${timestamp}] [WARN] - Could not create log directory ${log_dir}. File logging disabled.${COLOR_RESET}" >&2
                    LOG_DIR_CREATE_WARN_SENT=true
                    LOG_TO_FILE=false
                 fi
            elif [[ ! -w "${log_dir}" ]]; then
                if [[ -z ${LOG_DIR_WRITE_WARN_SENT+x} ]]; then
                    echo -e "${COLOR_YELLOW}[${timestamp}] [WARN] - Cannot write to log directory ${log_dir}. File logging disabled.${COLOR_RESET}" >&2
                    LOG_DIR_WRITE_WARN_SENT=true
                    LOG_TO_FILE=false
                fi
            else
                 # Strip color codes for file logging
                 echo "${log_prefix} - ${message}" >> "${LOG_FILE}"
            fi
        fi
    fi

    # Exit immediately for CRITICAL errors after attempting to log
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        echo -e "${COLOR_BOLD}${COLOR_RED}Critical error encountered. Exiting script.${COLOR_RESET}" >&2
        # Cleanup will be handled by trap
        exit 1 # Use a specific exit code for critical errors
    fi
}


# --- Usage/Help Function ---
# Description: Displays help information derived from the script's header and exits.
usage() {
    local usage_text
    # Extract the Usage section from this script's header comments.
    usage_text=$(sed -n '/^# ===+ USAGE ===+$/,/^# ===+ .* ===+$/{ /# ===+ .* ===+$/!p; }' "${BASH_SOURCE[0]}" | sed 's/^# //; s/\[your_script_name.sh\]/'"${SCRIPT_NAME}"'/g')

    cat << EOF >&2
${usage_text}

Options:
  -h, --help           Display this help message and exit.
  -v, --verbose        Enable verbose output (shows DEBUG messages).
  -d, --debug          Enable Bash debug mode (set -x). Prints every command.
      --dry-run        Simulate execution; show intended actions (like reboot) without performing them.
  -T, --duration SECS  Set total monitoring duration in seconds (Default: ${DEFAULT_TOTAL_DURATION}).
  -i, --interval SECS  Set check interval in seconds (Default: ${DEFAULT_INTERVAL}).
  -t, --tag TAG        Set the syslog tag (Default: ${DEFAULT_SYSLOG_TAG}).
      --no-color       Disable colored output.
      --log-file PATH  Enable logging to the specified file path.
      --log-level LEVEL Set log level (DEBUG, INFO, WARN, ERROR, CRITICAL; Default: ${LOG_LEVEL}).
      --no-syslog      Disable logging to syslog via 'logger'.

EOF
    exit 1 # Exit with a non-zero status after showing help
}


# --- Dependency Check Function ---
# Description: Checks if required command-line utilities are installed and executable.
# Arguments: $1: Command name (e.g., "who")
#            $2: (Optional) Package name suggestion
check_dependency() {
    local cmd="$1"; local install_suggestion="${2:-$cmd}"
    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required command '${cmd}' not found."
        log_message "ERROR" "Please install the package providing '${cmd}' (e.g., '${install_suggestion}') using your system's package manager."
        # exit handled by CRITICAL log level
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
}


# --- Cleanup Function ---
# Description: Performs cleanup tasks before script exits (currently none needed).
# Called via 'trap'. Keep simple; avoid commands that might fail easily.
cleanup() {
    local exit_status=$? # Capture the script's exit status
    log_message "DEBUG" "Performing cleanup..."
    # No temporary files or background processes to clean up in this script.
    # Add cleanup tasks here if future versions need them (e.g., remove temp files, lock files).
    log_message "INFO" "Script exiting with status: ${exit_status}"
    # Script will exit with the original exit_status after trap completes.
}


# --- Trap Setup ---
# Register the 'cleanup' function to run on specific signals and script exit.
# EXIT: Normal script termination or exit due to 'set -e'.
# INT: Interrupt signal (Ctrl+C).
# TERM: Termination signal (`kill` command).
# HUP: Hangup signal.
trap cleanup EXIT INT TERM HUP


# --- Argument Parsing Function ---
# Description: Parses command-line options using getopt (for long options).
parse_params() {
    # Define short options
    local short_opts="hvdt:T:i:t:"
    # Define long options
    local long_opts="help,verbose,debug,dry-run,duration:,interval:,tag:,no-color,log-file:,log-level:,no-syslog"

    # Use getopt to parse options. Note: requires 'util-linux' package.
    # Check if getopt is available
    if ! command -v getopt &> /dev/null; then
        log_message "CRITICAL" "'getopt' command not found. It is required for parsing command-line options. Please install 'util-linux'."
    fi

    # -o: short options, -l: long options, --name: program name for errors
    # "$@": pass all script arguments
    # Temporarily disable exit on error (-e) for getopt parsing
    set +e
    local parsed_options
    parsed_options=$(getopt -o "${short_opts}" --long "${long_opts}" -n "$SCRIPT_NAME" -- "$@")
    local parse_status=$?
    set -e # Re-enable exit on error

    if [[ ${parse_status} -ne 0 ]]; then
        # getopt reports errors to stderr, so just show usage
        usage
    fi

    # Use 'eval set --' to handle quoted arguments correctly
    eval set -- "$parsed_options"

    # Process parsed options
    while true; do
        case "$1" in
            -h|--help) usage ;;
            -v|--verbose) VERBOSE=true; LOG_LEVEL="DEBUG"; shift ;; # Verbose implies DEBUG level
            -d|--debug) DEBUG_MODE=true; set -x; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            -T|--duration) TOTAL_DURATION="$2"; shift 2 ;;
            -i|--interval) INTERVAL="$2"; shift 2 ;;
            -t|--tag) SYSLOG_TAG="$2"; shift 2 ;;
            --no-color) NO_COLOR=true; shift ;;
            --log-file) LOG_TO_FILE=true; LOG_FILE="$2"; shift 2 ;;
            --log-level) LOG_LEVEL=$(echo "$2" | tr '[:lower:]' '[:upper:]'); shift 2 ;;
            --no-syslog) LOG_TO_SYSLOG=false; shift ;;
            --) shift; break ;; # End of options
            *) log_message "CRITICAL" "Internal error in argument parsing."; break ;; # Should not happen
        esac
    done

    # Handle remaining arguments if any (this script doesn't expect positional args)
    if [[ $# -gt 0 ]]; then
        log_message "ERROR" "Unexpected positional argument(s): $*"
        usage
    fi

    log_message "DEBUG" "Arguments parsed. Verbose: ${VERBOSE}, Debug: ${DEBUG_MODE}, DryRun: ${DRY_RUN}, Duration: ${TOTAL_DURATION}, Interval: ${INTERVAL}, SyslogTag: ${SYSLOG_TAG}, LogFile: ${LOG_FILE:-None}, LogLevel: ${LOG_LEVEL}, Syslog: ${LOG_TO_SYSLOG}"
}


# --- Configuration Loading Function ---
# Description: This script does not use a separate configuration file by default.
# This function is a placeholder. Could be implemented later if needed.
load_config() {
    log_message "DEBUG" "Configuration file loading skipped (not implemented in this script)."
    # If implemented:
    # - Check if a config file path was provided or use a default.
    # - Read file line by line (avoid 'source' for security).
    # - Update variables *only* if they weren't set by command-line arguments.
}


# --- Input Validation Function ---
# Description: Performs checks on finalized configuration values before execution.
validate_inputs() {
    log_message "INFO" "Validating inputs and configuration..."

    # Validate numerical values
    if ! [[ "${TOTAL_DURATION}" =~ ^[0-9]+$ ]] || [[ ${TOTAL_DURATION} -le 0 ]]; then
        log_message "CRITICAL" "Invalid total duration: '${TOTAL_DURATION}'. Must be a positive integer."
    fi
    if ! [[ "${INTERVAL}" =~ ^[0-9]+$ ]] || [[ ${INTERVAL} -le 0 ]]; then
        log_message "CRITICAL" "Invalid interval: '${INTERVAL}'. Must be a positive integer."
    fi
    if [[ ${INTERVAL} -gt ${TOTAL_DURATION} ]]; then
        log_message "WARN" "Check interval (${INTERVAL}s) is greater than total duration (${TOTAL_DURATION}s). Script will only check once."
    fi

    # Validate log level
    if ! [[ "${LOG_LEVEL}" =~ ^(DEBUG|INFO|WARN|ERROR|CRITICAL)$ ]]; then
         log_message "WARN" "Invalid log level specified: '${LOG_LEVEL}'. Using default 'INFO'."
         LOG_LEVEL="INFO"
    fi

    # Validate log file path if provided
    if [[ "${LOG_TO_FILE}" == true ]]; then
        if [[ -z "${LOG_FILE}" ]]; then
             log_message "WARN" "File logging enabled (--log-file) but no path provided. Disabling file logging."
             LOG_TO_FILE=false
        else
             local log_dir; log_dir="$(dirname "${LOG_FILE}")"
             if ! mkdir -p "${log_dir}" 2>/dev/null && [[ ! -d "${log_dir}" ]]; then
                log_message "WARN" "Cannot create or access log directory: ${log_dir}. Disabling file logging."
                LOG_TO_FILE=false
             elif [[ ! -w "${log_dir}" ]]; then
                log_message "WARN" "Log directory is not writable: ${log_dir}. Disabling file logging."
                LOG_TO_FILE=false
             fi
        fi
    fi

    log_message "INFO" "Input validation passed."
}


# --- Preparation Function ---
# Description: Sets up the environment (currently minimal).
prepare_environment() {
    log_message "INFO" "Preparing execution environment..."
    # No specific preparation needed for this script's logic.
    # Could check root privileges here if needed early.
    log_message "INFO" "Environment preparation complete."
}


# --- Main Logic Function ---
# Description: Contains the core functionality derived from the original script.
main() {
    log_message "INFO" "Starting main script execution..."
    log_message "INFO" "Monitoring for user sessions. Duration: ${TOTAL_DURATION}s, Interval: ${INTERVAL}s."
    if [[ "${DRY_RUN}" == true ]]; then
        log_message "WARN" "Dry Run mode enabled. Reboot will be simulated but not executed."
    fi

    # --- Configuration Variables for Main Logic ---
    # Initialize the flag here, within the main logic scope.
    REBOOT_NEEDED=false
    # Calculate the total number of checks needed based on final duration/interval.
    local loops=$(( TOTAL_DURATION / INTERVAL ))
    # Handle case where interval might not divide duration evenly, ensure at least one loop if duration > 0
    if [[ $(( TOTAL_DURATION % INTERVAL )) -ne 0 && ${TOTAL_DURATION} -gt 0 ]]; then
        loops=$(( loops + 1 ))
    elif [[ ${loops} -eq 0 && ${TOTAL_DURATION} -gt 0 ]]; then
         loops=1 # Ensure at least one check if duration is positive but <= interval
    fi
    log_message "DEBUG" "Calculated number of checks: ${loops}"

    # --- Monitoring Loop ---
    log_message "INFO" "Starting monitoring loop..."
    for (( i=1; i<=loops; i++ )); do
        log_message "DEBUG" "Check #${i}..."
        local session_count
        # Use command substitution robustly
        session_count=$(who | wc -l) || {
            log_message "ERROR" "Failed to execute 'who | wc -l'. Cannot determine session count. Aborting check loop.";
            # Decide if this is critical enough to exit or just warn and continue?
            # Let's exit as the core logic is broken.
            exit 1;
        }
        log_message "DEBUG" "Active session count: ${session_count}"

        # Evaluate if the number of active sessions is exactly zero.
        if [[ "${session_count}" -eq 0 ]]; then
            local elapsed_seconds=$(( i * INTERVAL ))
            # If interval > duration, elapsed might exceed total duration, cap it.
            [[ ${elapsed_seconds} -gt ${TOTAL_DURATION} ]] && elapsed_seconds=${TOTAL_DURATION}

            log_message "WARN" "No active session detected at second ${elapsed_seconds} (Check ${i}/${loops}). Condition met."
            REBOOT_NEEDED=true
            log_message "INFO" "Exiting monitoring loop early."
            break # Exit the loop immediately.
        fi

        # If active sessions were found, pause before the next check, unless it's the last iteration.
        if [[ ${i} -lt ${loops} ]]; then
            log_message "DEBUG" "Session(s) detected. Sleeping for ${INTERVAL} seconds..."
            sleep "${INTERVAL}"
        fi
    done # End of the 'for' loop.

    log_message "INFO" "Monitoring loop finished."

    # --- Final Action ---
    log_message "INFO" "Evaluating final action..."
    if [[ "${REBOOT_NEEDED}" == true ]]; then
        log_message "WARN" "Reboot condition was met during monitoring."
        if [[ "${DRY_RUN}" == true ]]; then
            log_message "WARN" "[DRY RUN] Would execute reboot command now: /usr/bin/systemctl reboot"
        else
            log_message "CRITICAL" "Executing system reboot command: /usr/bin/systemctl reboot"
            # Ensure systemctl exists before calling
            if ! command -v /usr/bin/systemctl &> /dev/null; then
                 log_message "CRITICAL" "/usr/bin/systemctl command not found. Cannot reboot."
                 # Exit handled by CRITICAL log level
            fi
            # Check for root privileges before attempting reboot
            if [[ "$(id -u)" -ne 0 ]]; then
                 log_message "CRITICAL" "Script needs root privileges to execute 'systemctl reboot'. Reboot aborted."
                 # Exit handled by CRITICAL log level
            fi
            # Execute the reboot command
            /usr/bin/systemctl reboot || {
                # This part might not execute if reboot is immediate, but good practice.
                log_message "ERROR" "'systemctl reboot' command failed to execute.";
                exit 1;
            }
            # If the script somehow continues after sending reboot, log it.
            log_message "INFO" "Reboot command issued. System should be shutting down."
            # Add a small sleep to allow reboot process to potentially terminate the script cleanly.
            sleep 5
        fi
    else
        log_message "INFO" "User session(s) were detected consistently during the ${TOTAL_DURATION}-second monitoring window."
        log_message "INFO" "No reboot required based on current policy."
    fi

    log_message "INFO" "Main execution logic finished."
}


# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# 1. Parse Command Line Arguments
parse_params "$@" # Pass all arguments received by the script

# 2. Load Configuration File (Placeholder)
load_config # Uses CONFIG_FILE variable set by defaults or parse_params

# 3. Validate Inputs and Configuration
validate_inputs

# 4. Check Dependencies
log_message "INFO" "Checking required dependencies..."
check_dependency "who"       "coreutils"
check_dependency "wc"        "coreutils"
check_dependency "logger"    "bsdutils or util-linux" # Package name varies
check_dependency "sleep"     "coreutils"
check_dependency "systemctl" "systemd"
check_dependency "date"      "coreutils"
check_dependency "id"        "coreutils"
check_dependency "basename"  "coreutils"
check_dependency "dirname"   "coreutils"
check_dependency "getopt"    "util-linux" # Required for argument parsing
log_message "INFO" "Dependency checks passed."

# 5. Prepare Environment
prepare_environment

# 6. Execute Main Logic
main

# 7. Exit Successfully (if not rebooted)
# The 'trap cleanup EXIT' will run automatically.
# Note: log_message "INFO" "Script completed successfully." is now in cleanup()
exit 0 # Explicitly exit with success code

# =========================================================================================
# --- End of Script ---
