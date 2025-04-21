#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : rsync_mirror.sh
# PURPOSE       : Automated rsync mirrors source to remote with robust features.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2024-11-11
# LAST UPDATED  : 2024-11-11
# VERSION       : 1.0.0
# =========================================================================================

# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This script automates the process of mirroring a local directory to a remote server
# using rsync over SSH. It follows best practices for Bash scripting, including strict mode,
# extensive logging, modular functions, command-line argument parsing, and cleanup handling.
# If the configuration file ('rsync_mirror.conf') is not found in the script's directory,
# it interactively prompts the user to generate it.
#
# Key Functions & Features:
# - Interactive Configuration: Guides the user to create 'rsync_mirror.conf' if missing,
#   storing source/destination paths, credentials (SSH key preferred), logging directory,
#   retry counts, email settings, and other operational parameters. Allows regeneration
#   via the `--regenerate-config` command-line argument. Uses atomic write via temp file.
# - Robust Argument Parsing: Supports standard options like `-h` (help), `-v` (verbose),
#   and long options like `--regenerate-config`, `--dry-run`, `--no-color`, `--debug`.
# - rsync Execution: Performs the directory synchronization using rsync with standard
#   archive mode (`-a`) and delete functionality (`--delete`). Shows progress (`--info=progress2`).
# - Authentication: Supports both SSH key (recommended for security and automation) and
#   password-based authentication (requires 'sshpass' utility and stores password in the
#   config file - use with extreme caution due to security risks).
# - Enhanced Logging: Implements a structured `log_message` function with configurable
#   log levels (DEBUG, INFO, WARN, ERROR, CRITICAL). Supports optional colored output
#   to console (disabled via `--no-color` or if not interactive). Logs to both console
#   (stdout/stderr based on level) and timestamped summary/progress log files. Includes
#   timezone in timestamps.
# - Retry Logic: Automatically retries the rsync operation a configurable number of times
#   (`MAX_RETRIES`) upon failure, with a short delay between attempts.
# - Email Notifications: Optionally sends email alerts on final success or failure after
#   all retries, using the system's 'mail' or 'mailx' utility.
# - Dry-Run Mode: Supports simulation via `--dry-run` command-line flag (overrides config)
#   or the `DRY_RUN` setting in the configuration file.
# - Backup Deletes: Optionally backs up files on the destination that are about to be
#   deleted or overwritten by rsync, adding a configurable suffix (`BACKUP_SUFFIX`).
# - Dependency Checking: Verifies the presence of required command-line tools (`rsync`,
#   `ssh`, coreutils, etc.) and conditional tools (`sshpass`, `mail`/`mailx`, `numfmt`)
#   before execution, providing user-friendly error messages and suggested package names.
# - Background Execution: Initiates the main `run_rsync` function (which includes retries)
#   in a background subshell and detaches it using `disown`, allowing the main script
#   to exit quickly while the sync process continues independently.
# - Strict Mode & Error Handling: Uses `set -euo pipefail` for robust error handling.
#   Implements `trap` for cleanup actions (e.g., removing temp files) on script exit or interruption.
# - Modularity: Code is organized into functions for clarity and maintainability
#   (e.g., logging, argument parsing, config handling, dependency checks, rsync execution, cleanup).
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Robustness:** Employs strict mode (`set -euo pipefail`), explicit dependency checks,
#   trapped cleanup, retry logic for the core task, atomic file writes for config generation,
#   and detailed, leveled logging to ensure reliable operation and aid troubleshooting.
# - **Automation:** Designed for unattended execution, utilizing background processing (`&` and `disown`)
#   and optional email notifications. Minimal interaction required after initial setup.
# - **User-Friendliness:** Provides interactive configuration generation, clear console output
#   (with optional colors), informative log files, and standard command-line options (`-h`, `-v`).
# - **Security:** Prioritizes secure practices: Strongly recommends SSH keys over passwords, warns
#   explicitly about password storage risks, sets restrictive permissions (600) on the config file,
#   uses proper variable quoting, and avoids unnecessary elevated privileges.
# - **Modularity & Readability:** Organizes code into well-defined functions with comments,
#   following a standard Bash template structure for improved maintainability.
# - **Portability:** Aims for compatibility with common Linux distributions, using standard utilities
#   where possible, but relies on Bash features (bashisms). Notes potential macOS differences.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - System Administrators needing automated file mirroring or backups between servers.
# - DevOps Engineers incorporating synchronization tasks into deployment or maintenance workflows.
# - Developers or Power Users requiring a reliable, configurable method to keep directories in sync.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x rsync_mirror.sh` required.
# - File system access: Read on `SRC_DIR`; Write in script's directory (for `rsync_mirror.conf`);
#   Write in `LOG_DIR`.
# - Network access: Outbound SSH to `DEST_HOST` on `SSH_PORT`.
# - Remote permissions: `DEST_USER` needs SSH login and write permissions in `DEST_DIR`.
# - Elevated privileges: Generally not needed unless `LOG_DIR` requires it or for dependency installs.
#
# **Basic Syntax:**
#   `./rsync_mirror.sh [OPTIONS]`
#
# **Options (Command-Line Arguments):**
#   `-h`, `--help`         : Display this help message and exit.
#   `-v`, `--verbose`      : Enable verbose output (DEBUG level logging).
#   `-d`, `--debug`        : Enable Bash debug mode (`set -x`). Implies `-v`.
#   `--regenerate-config`  : Force interactive regeneration of the configuration file.
#   `--dry-run`            : Simulate rsync actions without making changes. Overrides
#                              the `DRY_RUN` setting in the config file for this run.
#   `--no-color`           : Disable colored output in the console.
#
# **Configuration (via `rsync_mirror.conf`):**
# - The script primarily relies on `rsync_mirror.conf` (located in the script's directory)
#   for operational parameters (paths, credentials, behavior).
# - Generated interactively if missing or via `--regenerate-config`.
# - See the generated file or `generate_config` function for details on all keys.
#
# **Common Examples:**
# 1. First run (will prompt for config):
#    `./rsync_mirror.sh`
# 2. Standard run (uses existing config):
#    `./rsync_mirror.sh`
# 3. Test changes with verbose output and dry run simulation:
#    `./rsync_mirror.sh -v --dry-run`
# 4. Force reconfiguration:
#    `./rsync_mirror.sh --regenerate-config`
#
# **Cron Usage:**
#   `0 3 * * * /path/to/rsync_mirror.sh --no-color > /dev/null 2>&1`
#   (Use `--no-color`. Redirect cron output as script logs to files. Ensure `PATH` is set
#    or use full paths to dependencies if needed in the cron environment.)
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Location:** Place `rsync_mirror.sh` in a suitable directory (e.g., `~/bin/`, `/usr/local/sbin/`).
# **Permissions:** `chmod +x /path/to/rsync_mirror.sh`. Adjust ownership if needed.
# **Dependencies:** Install required tools (see DEPENDENCIES).
# **Configuration:** Run interactively once (`./rsync_mirror.sh`) to generate `rsync_mirror.conf`.
# **Review:** Carefully review `rsync_mirror.conf`. Set `DRY_RUN=false` only when ready.
# **Authentication:** Set up SSH keys (recommended) if `USE_SSH_KEY=true`.
# **Log Directory:** Ensure `LOG_DIR` (default `/var/log/rsync_mirror`) exists and is writable
#   by the script user (may require `sudo mkdir /var/log/rsync_mirror && sudo chown user:group ...`).
# **Integration:** Add to cron (`crontab -e`) or systemd timer for automation.
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:** `/bin/bash`
# **Required Core Tools:** `basename`, `dirname`, `date`, `mkdir`, `chmod`, `cat`, `tr`, `echo`,
#   `sleep`, `wc`, `du`, `awk`, `find`, `sed`, `tail`, `mktemp` (most provided by `coreutils`,
#   `gawk`, `findutils`, `sed`). `command` (Bash built-in).
# **Required Sync Tools:** `rsync`, `ssh` (OpenSSH client).
# **Conditionally Required:**
#   - `sshpass`: Only if `USE_SSH_KEY=false` (Password auth).
#   - `mail` / `mailx`: Only if `ENABLE_EMAIL=true` (Email notifications).
#   - `numfmt` (`coreutils`): Optional, for human-readable sizes in pre-sync analysis.
# **Setup:** Script checks dependencies and suggests package names (e.g., `rsync`, `openssh-client`,
#   `coreutils`, `gawk`, `findutils`, `sed`, `mailutils`/`mailx`, `sshpass`).
# **OS Compatibility:** Primarily Linux. macOS may need adjustments (`date`, `sed`, tool paths).
# **Environment Variables:** Uses `PATH` to find commands. Does not rely on other specific env vars.
#   Configuration is file-based (`rsync_mirror.conf`). `SSH_AUTH_SOCK` may be used by `ssh`.
# **Resources:** Script: Low. `rsync`: Variable, depends on data size/count, network, I/O.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination:** Configurable via `LOG_DIR` (default `/var/log/rsync_mirror`).
# **Log Files:** Timestamped files per run:
#   - Summary: `${LOG_DIR}/rsync_summary_YYYYMMDD_HHMMSS.log` (Overall status, errors, warnings, analysis)
#   - Progress: `${LOG_DIR}/rsync_progress_YYYYMMDD_HHMMSS.log` (Raw `rsync` stdout)
# **Console Output:** Logs to `stdout` (INFO, DEBUG) and `stderr` (WARN, ERROR, CRITICAL).
#   Optional ANSI colors (disable via `--no-color` or if not interactive).
# **Log Format:** `[YYYY-MM-DD HH:MM:SS ZZZ] [LEVEL] - Message` (ZZZ is timezone). File logs have colors stripped.
# **Log Levels:** `DEBUG` (shown if `-v`), `INFO`, `WARN`, `ERROR`, `CRITICAL` (exits script). Default level `INFO`.
# **Rotation:** Not handled internally. Use external `logrotate`.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):** Initial status messages, INFO/DEBUG level log messages, final background initiation confirmation.
# **Standard Error (stderr):** Help message (`-h`), argument errors, dependency errors, config generation errors, WARN/ERROR/CRITICAL level log messages.
# **Generated/Modified Files:**
#   - `rsync_mirror.conf`: Created/overwritten atomically (via temp file) in script's dir. Perms set to 600.
#   - Log Files: `rsync_summary_*.log`, `rsync_progress_*.log` in `LOG_DIR`.
#   - Destination (`DEST_DIR`): Modified by `rsync` to mirror `SRC_DIR`.
#   - Backups (Optional): Files renamed in `DEST_DIR` if `BACKUP_DELETES=true`.
#   - Temp Files: Temporary file used during config generation (cleaned up via `trap`).
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes (Main Script):**
#   - 0: Script successfully initiated the background sync process and exited. **Does NOT reflect sync success.**
#   - 1: General error during setup (dependency missing, config invalid, permissions, argument error, critical log message).
# **Background Process Status:** Success/failure of the actual `rsync` operation (including retries) is determined asynchronously by the background process. Check logs or email notifications for the final outcome. Rsync's own exit codes are logged.
# **Troubleshooting:** Refer to log files (`SUMMARY_LOG` first). Check permissions (`SRC_DIR`, `LOG_DIR`, `DEST_DIR`, SSH keys), network connectivity, firewall rules, SSH configuration (`sshd` status, `authorized_keys`), config file correctness (`rsync_mirror.conf`), disk space, and dependency installation. Test SSH manually (`ssh -p <port> <user>@<host>`).
# **Warnings:**
#   - **DATA DELETION:** `--delete` is active. Files missing in source WILL BE DELETED from destination. Use `--dry-run` extensively for testing. `BACKUP_DELETES=true` helps but is not a full backup. **Maintain separate backups.**
#   - **PASSWORD SECURITY:** Storing passwords (`USE_SSH_KEY=false`) is **HIGHLY INSECURE**. Use SSH keys. Ensure config file has 600 permissions.
#   - **Resource Usage:** Monitor network/disk/CPU during large syncs.
#   - **Background Reliability:** `disown` helps, but for critical tasks, consider `systemd` or `tmux`/`screen`.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Running in `/bin/bash`.
# - Required dependencies are installed and in `PATH`.
# - Network connectivity exists to `DEST_HOST`.
# - User has necessary local read/write permissions and remote SSH/write permissions.
# - `rsync_mirror.conf` resides in the same directory as the script.
# - SSH server on `DEST_HOST` is running and configured correctly for the chosen auth method.
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - Add `-c`/`--config` option to specify config file location.
# - Implement locking (`flock`) to prevent concurrent runs.
# - Add options for rsync features (compression `-z`, bandwidth limit, excludes).
# - Enhance logging (syslog/journald, levels via args).
# - More robust background management (optional `nohup`, systemd integration examples).
# - Add pre/post-sync hook script execution points.
# - More sophisticated input validation (e.g., email format check).
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege:** Runs as user; avoid root unless necessary for `LOG_DIR` or installs. `DEST_USER` needs only necessary remote perms.
# - **Input:** Config values used in commands. Uses quoting. Validate paths. Trust config source.
# - **Sensitive Data:** **Password in config (`USE_SSH_KEY=false`) is major risk.** Use SSH keys. Config perms set to 600. `sshpass` exposes password in process list.
# - **Dependencies:** Keep system/tools updated (`rsync`, `ssh`, `sshpass`).
# - **Permissions:** Config `600`. Logs default umask. Rsync `-a` preserves source perms.
# - **External Commands:** Executes `rsync`, `ssh`, etc. Quoting used. Verify config values.
# - **Network:** Outbound SSH. Encrypted connection. Ensure firewall rules are appropriate.
# - **Code Integrity:** Verify script source if downloaded.
# - **Temp Files:** Uses `mktemp` for secure temporary file creation during config generation; cleaned up via `trap`.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is within this header. Config options documented in generated file.
# - No separate README/man page.
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Via repository or author's contact.
# - Feature Requests: Via repository or author's contact.
# =========================================================================================

# =========================================================================================
# SCRIPT EXECUTION ENVIRONMENT & CONFIGURATION
# =========================================================================================

# --- Bash Strict Mode ---
# -e: Exit immediately if a command exits with a non-zero status.
# -u: Treat unset variables and parameters as an error when performing parameter expansion.
# -o pipefail: The return value of a pipeline is the status of the last command to exit
#              with a non-zero status, or zero if no command exited with a non-zero status.
set -euo pipefail

# --- Debug Mode ---
# Uncomment the following line for debugging purposes (prints each command before execution):
# set -x

# --- Script Information ---
# Use BASH_SOURCE[0] for better portability and handling symlinks.
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
# Resolve the absolute path of the script's directory, handling symlinks.
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_DIR="${SOURCE_DIR}"
readonly SCRIPT_PID=$$

# --- Timestamp ---
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Global Runtime Variables & Defaults ---
# These store the script's configuration and state. Defaults may be overridden.

# Configuration Defaults
VERBOSE=false # Flag for verbose output (more detailed logging)
DEBUG_MODE=false # Flag for debug mode (set -x) - Handled via parse_params
DRY_RUN_CMD=false # Flag to simulate actions (synonym for --dry-run argument, influences config generation default)
REGENERATE_CONFIG=false # Flag to force config regeneration
NO_COLOR=false # Flag to disable colored output
INTERACTIVE_MODE=false # Flag indicating if running in an interactive terminal
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is a terminal

# Default Paths & Files
DEFAULT_CONFIG_FILE="${SCRIPT_DIR}/rsync_mirror.conf" # Default config file path (in script's dir)
DEFAULT_LOG_DIR="/var/log/rsync_mirror" # Default directory for log files
DEFAULT_BACKUP_SUFFIX="_backup_${SCRIPT_RUN_TIMESTAMP}" # Default suffix for backups if enabled

# Runtime variables that will be populated later
CONFIG_FILE="${DEFAULT_CONFIG_FILE}"
LOG_DIR="${DEFAULT_LOG_DIR}" # Populated by load_config
LOG_FILE="" # Set in prepare_environment
SUMMARY_LOG="" # Set in prepare_environment
PROGRESS_LOG="" # Set in prepare_environment
LOG_TO_FILE=true # Control whether logging to file is enabled (Can be changed based on directory writability)
LOG_LEVEL="INFO" # Default log level (DEBUG, INFO, WARN, ERROR, CRITICAL)
TEMP_DIR="" # Set by mktemp if needed for future features

# Script-specific runtime variables (populated by load_config)
SRC_DIR=""
DEST_USER=""
DEST_HOST=""
DEST_DIR=""
SSH_PORT=""
MAX_RETRIES=""
DRY_RUN_CONFIG="" # Value from config file ('true'/'false')
BACKUP_DELETES=""
BACKUP_SUFFIX=""
USE_SSH_KEY=""
SSH_PASSWORD=""
ENABLE_EMAIL=""
EMAIL=""

# --- Color Definitions (Optional) ---
# Define ANSI escape codes for colored output, checking if NO_COLOR is set or if not interactive.
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

    # Define numeric log levels for comparison
    declare -A log_levels_map=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [CRITICAL]=4)
    local current_log_level_num=${log_levels_map[${LOG_LEVEL^^}]:-1} # Default to INFO if invalid
    local message_level_num=${log_levels_map[${level_upper}]:-1} # Default to INFO if invalid

    # Only process messages at or above the current LOG_LEVEL
    if [[ ${message_level_num} -ge ${current_log_level_num} ]]; then
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
            # Only print DEBUG messages if VERBOSE=true
            if [[ "${level_upper}" == "DEBUG" && "${VERBOSE}" == false ]]; then
                 : # Do nothing
            else
                echo -e "${color}${log_line}${COLOR_RESET}"
            fi
        fi

        # Append to summary log file if enabled and file path is set
        if [[ "${LOG_TO_FILE}" == true && -n "${SUMMARY_LOG}" ]]; then
            # Strip color codes for file logging
            local file_log_line
            # Basic color removal for this script's simple colors
            file_log_line=$(echo "${log_line}" | sed 's/\x1b\[[0-9;]*m//g')
            # Ensure log directory exists (best effort, main check in prepare_environment)
            mkdir -p "$(dirname "${SUMMARY_LOG}")" 2>/dev/null || true
            if [[ -w "$(dirname "${SUMMARY_LOG}")" ]]; then
                 echo "${file_log_line}" >> "${SUMMARY_LOG}"
            else
                # Warning if log directory is not writable, but only warn once
                if [[ -z ${LOG_DIR_WRITE_WARN_SENT+x} ]]; then # Check if variable is unset
                    echo -e "${COLOR_YELLOW}[${timestamp}] [WARN] - Cannot write to log directory $(dirname "${SUMMARY_LOG}"). Logging to file disabled.${COLOR_RESET}" >&2
                    LOG_DIR_WRITE_WARN_SENT=true # Set variable to prevent repeating warning
                    LOG_TO_FILE=false # Disable further file logging attempts
                fi
            fi
        # If logging to file isn't setup yet, print important messages to console anyway
        elif [[ "${level_upper}" == "ERROR" || "${level_upper}" == "CRITICAL" ]]; then
             echo -e "${color}${log_line}${COLOR_RESET}" >&2
        fi
    fi

    # Exit immediately for CRITICAL errors
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        log_message "INFO" "Critical error encountered. Exiting script."
        # Cleanup function is called via trap
        exit 1 # Use a specific exit code for critical errors if desired
    fi
}


# --- Usage/Help Function ---
# Description: Displays help information based on header comments and exits.
usage() {
    # Extracts the USAGE section from the script's header.
    local usage_text
    usage_text=$(sed -n '/^# ===+ USAGE ===+$/,/^# ===+ .* ===+$/{ /# ===+ .* ===+$/!p; }' "${BASH_SOURCE[0]}" | sed 's/^# //; s/\[your_script_name.sh\]/'"${SCRIPT_NAME}"'/g')

    cat << EOF >&2
${usage_text}

Default Configuration File: ${DEFAULT_CONFIG_FILE}
Default Log Directory: ${DEFAULT_LOG_DIR}
EOF
    exit 1 # Exit with error status after showing help
}

# --- Dependency Check Function ---
# Description: Checks if a command-line utility is installed and executable.
# Calls log_message with CRITICAL level (which exits) if the dependency is missing.
# Arguments: $1: Command name to check (e.g., "jq", "curl")
#            $2: (Optional) Package name to suggest for installation
check_dependency() {
    local cmd="$1"
    local install_suggestion="${2:-$cmd}" # Use command name if package name not provided

    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required command '${cmd}' not found. Please install the '${install_suggestion}' package."
        # exit is handled by CRITICAL log level
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
}

# --- Cleanup Function ---
# Description: Performs cleanup tasks before script exits (e.g., removing temp files).
# Called via 'trap'. Avoid complex logic here.
cleanup() {
    local exit_status=$? # Capture the script's exit status
    log_message "DEBUG" "Performing cleanup..."

    # Remove temporary directory if it was created
    if [[ -n "${TEMP_DIR:-}" && -d "${TEMP_DIR}" ]]; then
        log_message "DEBUG" "Removing temporary directory: ${TEMP_DIR}"
        rm -rf "${TEMP_DIR}" || log_message "WARN" "Failed to remove temporary directory: ${TEMP_DIR}"
    fi

    # Add other cleanup tasks if needed (e.g., removing lock files)

    log_message "DEBUG" "Cleanup finished. Script exiting with status: ${exit_status}"
    # Script exits with the original exit_status after trap completes
}

# --- Trap Setup ---
# Register the 'cleanup' function to run on specific signals and on script exit.
trap cleanup EXIT INT TERM HUP


# --- Argument Parsing Function ---
# Description: Parses command-line options. Uses standard getopts for short options.
parse_params() {
    while getopts ":hvd-:" opt; do
        # Handle long options manually using OPTARG and OPTIND
        # See: https://stackoverflow.com/a/28466267/995118
        # And: https://stackoverflow.com/a/7069755/995118
        if [[ "$opt" == "-" ]]; then # Long option found
            opt="${OPTARG%%=*}" # Extract long option name
            OPTARG="${OPTARG#*=}" # Extract argument (if any) value
            OPTIND=$((OPTIND - 1)) # Adjust OPTIND to potentially re-process argument value
            # Fall-through to case statement
        fi

        case $opt in
            h) usage ;; # Show help and exit
            v) VERBOSE=true ;; # Enable verbose mode (more logging)
            d) # Handle --debug as a long option synonym for set -x
               if [[ "$OPTARG" == "debug" ]]; then
                   DEBUG_MODE=true; set -x; log_message "DEBUG" "Bash debug mode (set -x) enabled."
               else
                  # If -d is used without --debug, treat it as invalid
                  log_message "ERROR" "Invalid option: -d (Did you mean --debug?)" >&2
                  usage
               fi
               ;;
            regenerate-config) REGENERATE_CONFIG=true ;;
            dry-run) DRY_RUN_CMD=true ;; # Command line dry run flag
            no-color) NO_COLOR=true ;; # Disable colors (re-evaluate colors now)
            # Re-evaluate color definitions if NO_COLOR was set
             help) usage ;; # Handle --help
             # Add other long options here
            \?) # Invalid short option
                log_message "ERROR" "Invalid option: -${OPTARG}" >&2
                usage ;;
            :) # Short option requires an argument, but none provided
                log_message "ERROR" "Option -${OPTARG} requires an argument." >&2
                usage ;;
            *) # Unknown long option
                if [[ "$opt" != "$OPTARG" ]]; then # Check if it was a long option
                   log_message "ERROR" "Invalid option: --${opt}" >&2
                   usage
                fi
                ;;
        esac
    done

    # Shift processed options away, leaving positional arguments in $@
    shift $((OPTIND-1))

    # This script doesn't expect positional arguments currently
    if [[ $# -gt 0 ]]; then
        log_message "ERROR" "Unexpected argument(s): $*"
        usage
    fi

    # Re-evaluate colors if NO_COLOR was set via argument
    if [[ "${NO_COLOR}" == true ]]; then
        COLOR_RESET=""; COLOR_RED=""; COLOR_GREEN=""; COLOR_YELLOW=""; COLOR_BLUE=""; COLOR_CYAN=""; COLOR_BOLD=""
    fi

    # Set LOG_LEVEL based on VERBOSE flag after parsing
    if [[ "$VERBOSE" == true ]]; then
        LOG_LEVEL="DEBUG"
    fi

    log_message "DEBUG" "Arguments parsed. Verbose: ${VERBOSE}, Regenerate Config: ${REGENERATE_CONFIG}, Dry Run Cmd: ${DRY_RUN_CMD}"
}


# --- Configuration Generation Function ---
# Description: Interactively prompts the user for settings and creates the config file.
#              Called if config is missing or regeneration is forced.
generate_config() {
    log_message "INFO" "Starting interactive configuration generation..."
    echo # Add a newline for better formatting
    echo "Configuration file '${CONFIG_FILE}' not found or regeneration requested."
    echo "Generating a new configuration file..."
    echo "Please provide the following details (leave blank for defaults where applicable):"

    # Use local variables within the function
    local src_dir dest_user dest_host dest_dir log_dir_local ssh_port_local max_retries_local email_local dry_run_local backup_deletes_local enable_email_local use_ssh_key_local ssh_password_local backup_suffix_local

    # --- Get User Input with Validation ---
    read -p "Enter the absolute path to the local Source Directory: " src_dir
    while [[ -z "$src_dir" || ! -d "$src_dir" ]]; do
        log_message "ERROR" "Source directory cannot be empty and must exist." >&2
        read -p "Enter the absolute path to the local Source Directory: " src_dir
    done

    read -p "Enter the Username for the remote destination server: " dest_user
    while [[ -z "$dest_user" ]]; do log_message "ERROR" "Destination username cannot be empty." >&2; read -p "Enter the Username: " dest_user; done

    read -p "Enter the Hostname or IP of the remote destination server: " dest_host
    while [[ -z "$dest_host" ]]; do log_message "ERROR" "Destination host cannot be empty." >&2; read -p "Enter the Hostname or IP: " dest_host; done

    read -p "Enter the absolute path to the remote Destination Directory: " dest_dir
    while [[ -z "$dest_dir" ]]; do log_message "ERROR" "Destination directory cannot be empty." >&2; read -p "Enter the Destination Directory: " dest_dir; done

    read -p "Enter the local directory to store logs [${DEFAULT_LOG_DIR}]: " log_dir_local
    log_dir_local=${log_dir_local:-${DEFAULT_LOG_DIR}}

    read -p "Enter the SSH port on the remote server [22]: " ssh_port_local
    ssh_port_local=${ssh_port_local:-22}
    while ! [[ "$ssh_port_local" =~ ^[0-9]+$ ]] || [ "$ssh_port_local" -lt 1 ] || [ "$ssh_port_local" -gt 65535 ]; do
        log_message "ERROR" "Invalid port number. Must be between 1 and 65535." >&2
        read -p "Enter the SSH port [22]: " ssh_port_local
        ssh_port_local=${ssh_port_local:-22}
    done

    read -p "Enter the maximum number of retry attempts on failure [3]: " max_retries_local
    max_retries_local=${max_retries_local:-3}
    while ! [[ "$max_retries_local" =~ ^[0-9]+$ ]]; do
        log_message "ERROR" "Invalid number of retries. Must be a non-negative integer." >&2
        read -p "Enter max retries [3]: " max_retries_local
        max_retries_local=${max_retries_local:-3}
    done

    read -p "Enable email notifications? (true/false) [false]: " enable_email_local
    enable_email_local=$(echo "${enable_email_local:-false}" | tr '[:upper:]' '[:lower:]')
    if [[ "$enable_email_local" == "true" ]]; then
        read -p "Enter the Email address to receive notifications: " email_local
        while [[ -z "$email_local" ]]; do log_message "ERROR" "Email address cannot be empty if notifications are enabled." >&2; read -p "Enter Email address: " email_local; done
    else
        email_local=""
    fi

    # Default dry run based on command line flag if provided, otherwise default true
    local dry_run_default="true"
    [[ "${DRY_RUN_CMD}" == true ]] && dry_run_default="true"
    read -p "Enable dry-run mode (no changes made)? (true/false) [${dry_run_default}]: " dry_run_local
    dry_run_local=$(echo "${dry_run_local:-${dry_run_default}}" | tr '[:upper:]' '[:lower:]')

    read -p "Enable backup of deleted files on destination? (true/false) [false]: " backup_deletes_local
    backup_deletes_local=$(echo "${backup_deletes_local:-false}" | tr '[:upper:]' '[:lower:]')

    if [[ "$backup_deletes_local" == "true" ]]; then
        read -p "Enter backup suffix [${DEFAULT_BACKUP_SUFFIX}]: " backup_suffix_local
        backup_suffix_local=${backup_suffix_local:-${DEFAULT_BACKUP_SUFFIX}}
    else
         backup_suffix_local="" # Ensure empty if backups are off
    fi


    # --- Authentication Method Selection ---
    read -p "Use SSH key authentication (recommended)? (true/false) [true]: " use_ssh_key_local
    use_ssh_key_local=$(echo "${use_ssh_key_local:-true}" | tr '[:upper:]' '[:lower:]')

    if [[ "$use_ssh_key_local" == "false" ]]; then
        log_message "WARN" "Using password authentication requires 'sshpass' and stores the password in the config file." >&2
        log_message "WARN" "This is insecure. SSH key authentication is strongly recommended." >&2
        read -s -p "Enter the SSH password for '${dest_user}@${dest_host}': " ssh_password_local
        echo # Print a newline after silent input.
        while [[ -z "$ssh_password_local" ]]; do
             log_message "ERROR" "Password cannot be empty for password authentication." >&2;
             read -s -p "Enter Password: " ssh_password_local; echo;
        done
    else
        ssh_password_local="" # Ensure password variable is empty if using SSH keys.
    fi

    # --- Write Configuration File ---
    log_message "INFO" "Writing configuration to '${CONFIG_FILE}'..."
    # Use a temporary file and rename for atomicity
    local temp_conf_file
    temp_conf_file=$(mktemp "${CONFIG_FILE}.XXXXXX")

    # Use 'cat << EOF' with appropriate quoting
    # Note: Using single quotes around $ssh_password_local in the EOF prevents shell expansion issues
    # if the password contains shell metacharacters, but stores the literal password.
    cat > "$temp_conf_file" << EOF
# rsync Mirror Configuration File
# Generated by ${SCRIPT_NAME} on $(date)

# --- Directories ---
# Absolute path to the local source directory to mirror. Must exist.
SRC_DIR="${src_dir}"

# Username for SSH connection to the destination server.
DEST_USER="${dest_user}"

# Hostname or IP address of the destination server.
DEST_HOST="${dest_host}"

# Absolute path to the destination directory on the remote server.
# Needs to be writable by DEST_USER.
DEST_DIR="${dest_dir}"

# Local directory where log files will be stored. Must be writable.
LOG_DIR="${log_dir_local}"

# --- Connection ---
# SSH port number on the remote server.
SSH_PORT="${ssh_port_local}"

# --- Behavior ---
# Maximum number of times to retry rsync upon transient failure (e.g., network error).
MAX_RETRIES="${max_retries_local}"

# If true, run rsync with --dry-run (simulate changes, no actual data transfer/deletion).
# Highly recommended for testing configuration changes.
DRY_RUN="${dry_run_local}"

# If true, files deleted on the destination because they no longer exist in the source
# will be backed up before deletion by adding the BACKUP_SUFFIX.
BACKUP_DELETES="${backup_deletes_local}"

# Suffix added to backed-up files if BACKUP_DELETES=true.
# If empty and backups enabled, a timestamped default will be used.
BACKUP_SUFFIX="${backup_suffix_local}"

# --- Authentication ---
# Use SSH key (true) or password (false)? SSH keys are strongly recommended for security.
# Set up passwordless SSH key login between source and destination for this user.
USE_SSH_KEY="${use_ssh_key_local}"

# SSH Password (only used if USE_SSH_KEY=false).
# WARNING: Storing passwords in plain text is insecure. Use SSH keys whenever possible.
# Requires 'sshpass' utility to be installed.
SSH_PASSWORD='${ssh_password_local}'

# --- Notifications ---
# Enable email notifications for final success or failure (true/false).
# Requires 'mail' or 'mailx' utility on the system running the script.
ENABLE_EMAIL="${enable_email_local}"

# Email address to send notifications to (only used if ENABLE_EMAIL=true).
EMAIL="${email_local}"

EOF

    # Set restrictive permissions BEFORE renaming
    chmod 600 "$temp_conf_file" || { log_message "ERROR" "Failed to set permissions on temp config file."; rm -f "$temp_conf_file"; exit 1; }

    # Atomically replace the config file
    mv "$temp_conf_file" "$CONFIG_FILE" || { log_message "ERROR" "Failed to move temp config file to ${CONFIG_FILE}."; rm -f "$temp_conf_file"; exit 1; }

    log_message "INFO" "Configuration file '${CONFIG_FILE}' created successfully with permissions 600."
    echo # Add newline for spacing
}

# --- Configuration Loading Function ---
# Description: Loads configuration variables from the CONFIG_FILE.
#              Exits if the config file is required but missing/unreadable.
load_config() {
    if [[ -f "${CONFIG_FILE}" && -r "${CONFIG_FILE}" ]]; then
        log_message "INFO" "Loading configuration from: ${CONFIG_FILE}"
        # Source the configuration file safely by reading line by line
        while IFS='=' read -r key value || [[ -n "$key" ]]; do
            # Trim leading/trailing whitespace
            key=$(echo "$key" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            value=$(echo "$value" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

            # Ignore empty lines and comments
            [[ -z "$key" || "$key" =~ ^# ]] && continue

            # Remove potential quotes around value (optional, adjust as needed)
            # Be careful with passwords containing quotes if removing them here
            value="${value#\"}"; value="${value%\"}"
            value="${value#\'}"; value="${value%\'}"

            # Assign to global variables (Use uppercase variable names from config)
            case "$key" in
                SRC_DIR) SRC_DIR="$value" ;;
                DEST_USER) DEST_USER="$value" ;;
                DEST_HOST) DEST_HOST="$value" ;;
                DEST_DIR) DEST_DIR="$value" ;;
                LOG_DIR) LOG_DIR="$value" ;;
                SSH_PORT) SSH_PORT="$value" ;;
                MAX_RETRIES) MAX_RETRIES="$value" ;;
                DRY_RUN) DRY_RUN_CONFIG="$value" ;; # Store config value separately
                BACKUP_DELETES) BACKUP_DELETES="$value" ;;
                BACKUP_SUFFIX) BACKUP_SUFFIX="$value" ;;
                USE_SSH_KEY) USE_SSH_KEY="$value" ;;
                SSH_PASSWORD) SSH_PASSWORD="$value" ;;
                ENABLE_EMAIL) ENABLE_EMAIL="$value" ;;
                EMAIL) EMAIL="$value" ;;
                *) log_message "WARN" "Ignoring unknown configuration key in ${CONFIG_FILE}: '${key}'" ;;
            esac
        done < "${CONFIG_FILE}"
        log_message "DEBUG" "Configuration loaded."
    else
        # Only critical if config wasn't just generated or regeneration wasn't requested
        if [[ "${REGENERATE_CONFIG}" == false ]]; then
             log_message "CRITICAL" "Configuration file '${CONFIG_FILE}' not found or not readable."
        else
            # This case should ideally not be reached if generate_config succeeded
             log_message "ERROR" "Configuration file '${CONFIG_FILE}' still not found after generation attempt."
             exit 1
        fi
    fi
}

# --- Input Validation Function ---
# Description: Validates loaded configuration values and script inputs. Exits on critical errors.
validate_inputs() {
    log_message "INFO" "Validating configuration and inputs..."
    local validation_failed=false

    # Array of essential variables expected to be non-empty
    local required_vars=("SRC_DIR" "DEST_USER" "DEST_HOST" "DEST_DIR" "LOG_DIR" "SSH_PORT" "MAX_RETRIES" "DRY_RUN_CONFIG" "BACKUP_DELETES" "USE_SSH_KEY" "ENABLE_EMAIL")

    for var in "${required_vars[@]}"; do
        if [[ -z "${!var-}" ]]; then # Check if variable is unset or empty
            log_message "ERROR" "Configuration variable '${var}' is missing or empty in '${CONFIG_FILE}'."
            validation_failed=true
        fi
    done

    # Validate specific values
    if [[ ! -d "$SRC_DIR" ]]; then
        log_message "ERROR" "Source directory '${SRC_DIR}' defined in config does not exist or is not a directory."
        validation_failed=true
    fi

    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [[ "$SSH_PORT" -lt 1 || "$SSH_PORT" -gt 65535 ]]; then
        log_message "ERROR" "Invalid SSH_PORT '${SSH_PORT}'. Must be between 1 and 65535."
        validation_failed=true
    fi

    if ! [[ "$MAX_RETRIES" =~ ^[0-9]+$ ]]; then
        log_message "ERROR" "Invalid MAX_RETRIES '${MAX_RETRIES}'. Must be a non-negative integer."
        validation_failed=true
    fi

    # Normalize boolean values from config (convert to lowercase true/false)
    DRY_RUN_CONFIG=$(echo "$DRY_RUN_CONFIG" | tr '[:upper:]' '[:lower:]')
    BACKUP_DELETES=$(echo "$BACKUP_DELETES" | tr '[:upper:]' '[:lower:]')
    USE_SSH_KEY=$(echo "$USE_SSH_KEY" | tr '[:upper:]' '[:lower:]')
    ENABLE_EMAIL=$(echo "$ENABLE_EMAIL" | tr '[:upper:]' '[:lower:]')

    if [[ "$DRY_RUN_CONFIG" != "true" && "$DRY_RUN_CONFIG" != "false" ]]; then
         log_message "ERROR" "Invalid DRY_RUN value '${DRY_RUN_CONFIG}'. Must be 'true' or 'false'."
         validation_failed=true
    fi
     if [[ "$BACKUP_DELETES" != "true" && "$BACKUP_DELETES" != "false" ]]; then
         log_message "ERROR" "Invalid BACKUP_DELETES value '${BACKUP_DELETES}'. Must be 'true' or 'false'."
         validation_failed=true
    fi
     if [[ "$USE_SSH_KEY" != "true" && "$USE_SSH_KEY" != "false" ]]; then
         log_message "ERROR" "Invalid USE_SSH_KEY value '${USE_SSH_KEY}'. Must be 'true' or 'false'."
         validation_failed=true
    fi
     if [[ "$ENABLE_EMAIL" != "true" && "$ENABLE_EMAIL" != "false" ]]; then
         log_message "ERROR" "Invalid ENABLE_EMAIL value '${ENABLE_EMAIL}'. Must be 'true' or 'false'."
         validation_failed=true
    fi


    # Conditional validation
    if [[ "$ENABLE_EMAIL" == "true" && -z "$EMAIL" ]]; then
        log_message "ERROR" "'EMAIL' address cannot be empty when 'ENABLE_EMAIL' is true."
        validation_failed=true
    fi
    if [[ "$USE_SSH_KEY" == "false" && -z "$SSH_PASSWORD" ]]; then
        log_message "ERROR" "'SSH_PASSWORD' cannot be empty when 'USE_SSH_KEY' is false."
        log_message "WARN" "Consider regenerating the config or switching to SSH keys for security."
        validation_failed=true
    fi

    if [[ "$validation_failed" == true ]]; then
        log_message "CRITICAL" "Input validation failed. Please correct the configuration file: ${CONFIG_FILE}"
    else
        log_message "INFO" "Input validation passed."
    fi
}

# --- Environment Preparation Function ---
# Description: Sets up the environment before the main logic runs.
#              (e.g., creates directories, initializes log files).
prepare_environment() {
    log_message "INFO" "Preparing execution environment..."

    # Ensure Log Directory exists and is writable
    if ! mkdir -p "${LOG_DIR}"; then
        log_message "CRITICAL" "Log directory '${LOG_DIR}' could not be created. Check permissions."
    elif [[ ! -w "${LOG_DIR}" ]]; then
        # Try to make it writable? Or just fail? For now, fail.
        log_message "CRITICAL" "Log directory '${LOG_DIR}' exists but is not writable by user $(whoami)."
    fi

    # Define unique log file paths now that LOG_DIR is validated
    SUMMARY_LOG="${LOG_DIR}/rsync_summary_${SCRIPT_RUN_TIMESTAMP}.log"
    PROGRESS_LOG="${LOG_DIR}/rsync_progress_${SCRIPT_RUN_TIMESTAMP}.log"
    LOG_FILE="${SUMMARY_LOG}" # Set the main log file for the log_message function

    # Initialize summary log file (check writability implicitly via touch)
    if ! touch "${SUMMARY_LOG}"; then
        log_message "CRITICAL" "Cannot write to summary log file: ${SUMMARY_LOG}"
    fi

    echo "==================================================" > "$SUMMARY_LOG" # Overwrite/Create
    echo "${SCRIPT_NAME} - Log Initialized: ${SCRIPT_RUN_TIMESTAMP}" >> "$SUMMARY_LOG"
    echo "==================================================" >> "$SUMMARY_LOG"
    log_message "INFO" "Logging initialized. Summary: ${SUMMARY_LOG}, Progress: ${PROGRESS_LOG}"

    # Create Output directory if needed (future use?)

    log_message "INFO" "Environment preparation complete."
}


# --- Email Sending Function ---
# Description: Sends an email notification if enabled in the configuration.
# Arguments: $1: Subject Line
#            $2: Message Body
send_email() {
    local subject="$1"
    local message="$2"

    if [[ "$ENABLE_EMAIL" != "true" ]]; then
        log_message "DEBUG" "Email notifications are disabled. Skipping email for: $subject"
        return
    fi

    # Check for mail command existence just before sending
    local mail_cmd=""
    if command -v mailx &> /dev/null; then
        mail_cmd="mailx"
    elif command -v mail &> /dev/null; then
        mail_cmd="mail"
    else
         log_message "WARN" "Neither 'mail' nor 'mailx' command found. Cannot send email notification."
         return # Cannot send email
    fi

    log_message "INFO" "Attempting to send email notification to ${EMAIL} using '${mail_cmd}'..."
    # Pipe the message body to the mail command. Capture status.
    if echo "$message" | "$mail_cmd" -s "$subject" "$EMAIL"; then
        log_message "INFO" "Email notification successfully sent to ${EMAIL}."
    else
        # Log an error if the mail command failed (returned non-zero exit status).
        log_message "ERROR" "Failed sending email notification to ${EMAIL} using '${mail_cmd}'. Check mail system logs."
    fi
}


# --- Pre-Sync Analysis Function ---
# Description: Performs a quick analysis of the source directory.
pre_sync_analysis() {
    log_message "INFO" "Starting pre-sync analysis for source: ${SRC_DIR}"

    # Re-validate SRC_DIR just in case something changed (though validate_inputs already checked)
    if [[ ! -d "$SRC_DIR" ]]; then
         log_message "ERROR" "Source directory '${SRC_DIR}' is invalid or became inaccessible during pre-sync analysis."
         return 1 # Return error code
    fi

    local total_files total_size_bytes estimated_speed estimated_time_sec
    local total_size_human

    # Use find -type f and wc -l for file count
    total_files=$(find "$SRC_DIR" -type f | wc -l)
    # Use du -sb for total size in bytes
    total_size_bytes=$(du -sb "$SRC_DIR" | awk '{print $1}')

    # Convert size to human-readable using numfmt
    if command -v numfmt &> /dev/null; then
       total_size_human=$(numfmt --to=iec-i --suffix=B "$total_size_bytes")
    else
       total_size_human="${total_size_bytes} Bytes (numfmt not found)"
    fi

    # Rough time estimate (example: 10 MiB/s) - Highly inaccurate but gives scale
    estimated_speed=$((10 * 1024 * 1024)) # Bytes per second
    if [[ $estimated_speed -gt 0 && $total_size_bytes -gt 0 ]]; then
        estimated_time_sec=$((total_size_bytes / estimated_speed))
        local minutes=$((estimated_time_sec / 60))
        local seconds=$((estimated_time_sec % 60))
        log_message "INFO" "Pre-Sync Analysis:"
        log_message "INFO" "  Total Files: ${total_files}"
        log_message "INFO" "  Total Size: ${total_size_human}"
        log_message "INFO" "  Estimated Transfer Time (at 10 MiB/s): ~${minutes}m ${seconds}s"
    else
        log_message "INFO" "Pre-Sync Analysis:"
        log_message "INFO" "  Total Files: ${total_files}"
        log_message "INFO" "  Total Size: ${total_size_human}"
        log_message "INFO" "  Estimated Transfer Time: N/A (zero size or speed)"
    fi
    log_message "INFO" "----------------------------------"
    return 0 # Success
}


# --- Rsync Execution Function ---
# Description: Executes the main rsync command with configured options, retry logic, and logging.
run_rsync() {
    local retries=0
    local rsync_exit_status=1 # Default to failure

    # Perform pre-sync analysis, exit function if it fails
    if ! pre_sync_analysis; then
         log_message "ERROR" "Pre-sync analysis failed. Aborting rsync."
         # Send failure email? Or let caller handle it? Let caller handle based on return code.
         return 1 # Indicate failure
    fi

    # Determine actual dry-run status (command line overrides config)
    local effective_dry_run="${DRY_RUN_CONFIG}" # Start with config value
    [[ "${DRY_RUN_CMD}" == true ]] && effective_dry_run="true" # Override if command line flag is set

    while [[ "$retries" -lt "$MAX_RETRIES" ]]; do
        log_message "INFO" "========== rsync Attempt $((retries + 1)) / ${MAX_RETRIES} =========="

        # --- Assemble rsync Command Options ---
        local rsync_opts=("-a" "--delete")

        # Use detailed progress info
        rsync_opts+=("--info=progress2")

        # Handle Backup option
        if [[ "$BACKUP_DELETES" == "true" ]]; then
            local current_backup_suffix="${BACKUP_SUFFIX:-$DEFAULT_BACKUP_SUFFIX}" # Use default if config is empty
            rsync_opts+=("--backup" "--suffix=${current_backup_suffix}")
            log_message "INFO" "Backup enabled: Deleted/changed files backed up with suffix '${current_backup_suffix}'."
        fi

        # Handle Dry Run option (based on effective value)
        if [[ "$effective_dry_run" == "true" ]]; then
            rsync_opts+=("--dry-run")
            log_message "WARN" "Dry run mode is ACTIVE. No actual changes will be made on the destination."
        fi

        # --- SSH Connection Setup ---
        local ssh_cmd="ssh -p ${SSH_PORT}" # Basic command
        local rsync_ssh_opt="-e ${ssh_cmd}" # Rsync option (needs careful quoting if passed as single string)
        local remote_dest="${DEST_USER}@${DEST_HOST}:${DEST_DIR}"

        # --- Execute rsync Command ---
        local log_cmd_display # Command string for logging (mask password)
        local actual_cmd_array=() # Array to hold the actual command and args safely

        # Build the command array and display string
        if [[ "$USE_SSH_KEY" == "false" ]]; then
            # --- Password Authentication ---
            check_dependency "sshpass" # Check dependency only when needed
            log_cmd_display="sshpass -p '********' rsync ${rsync_opts[*]} -e \"${ssh_cmd}\" \"${SRC_DIR}/\" \"${remote_dest}\"" # Mask password
            actual_cmd_array=(sshpass -p "$SSH_PASSWORD" rsync "${rsync_opts[@]}" -e "$ssh_cmd" "${SRC_DIR}/" "$remote_dest") # Trailing slash on SRC_DIR is important!
            log_message "INFO" "Executing rsync via password (masked): ${log_cmd_display}"
        else
            # --- SSH Key Authentication ---
            log_cmd_display="rsync ${rsync_opts[*]} -e \"${ssh_cmd}\" \"${SRC_DIR}/\" \"${remote_dest}\""
            actual_cmd_array=(rsync "${rsync_opts[@]}" -e "$ssh_cmd" "${SRC_DIR}/" "$remote_dest") # Trailing slash on SRC_DIR!
            log_message "INFO" "Executing rsync via SSH key: ${log_cmd_display}"
        fi

        # --- Execute and Capture Output/Status ---
        # Redirect stdout to progress log, stderr to summary log (append)
        # Run in foreground within this function, backgrounding is handled in main()
        if "${actual_cmd_array[@]}" > "$PROGRESS_LOG" 2>> "$SUMMARY_LOG"; then
            rsync_exit_status=$? # Should be 0 if command succeeds
            log_message "INFO" "rsync completed successfully on attempt $((retries + 1)). Exit status: ${rsync_exit_status}."
            # Send success email
            send_email "[SUCCESS] rsync: ${SRC_DIR} -> ${DEST_HOST}" \
                       "rsync mirror from '${SRC_DIR}' to '${remote_dest}' completed successfully.\n\nSummary log: ${SUMMARY_LOG}\nProgress log: ${PROGRESS_LOG}"
            return 0 # Success
        else
            rsync_exit_status=$? # Capture non-zero exit status
            log_message "ERROR" "rsync failed on attempt $((retries + 1)) with exit status ${rsync_exit_status}. Check logs."
            log_message "ERROR" "Progress Log excerpt (last 10 lines):"
            # Append last few lines of progress log to summary log for context
            tail -n 10 "$PROGRESS_LOG" >> "$SUMMARY_LOG" 2>&1 || log_message "WARN" "Could not read progress log for excerpt."
            log_message "ERROR" "See full details in Progress Log: ${PROGRESS_LOG}"
            log_message "ERROR" "See full errors in Summary Log: ${SUMMARY_LOG}"

            retries=$((retries + 1))
            if [[ "$retries" -lt "$MAX_RETRIES" ]]; then
                log_message "WARN" "Retrying in 10 seconds..."
                sleep 10
            fi
        fi
    done # End retry loop

    # If loop finishes, all retries failed
    log_message "CRITICAL" "rsync failed after ${MAX_RETRIES} attempts. Final exit status: ${rsync_exit_status}."
    # Send failure email
    send_email "[FAILURE] rsync: ${SRC_DIR} -> ${DEST_HOST}" \
               "rsync mirror from '${SRC_DIR}' to '${remote_dest}' FAILED after ${MAX_RETRIES} attempts. Final exit status: ${rsync_exit_status}.\n\nCheck logs.\nSummary: ${SUMMARY_LOG}\nProgress: ${PROGRESS_LOG}"

    return 1 # Failure
}


# --- Main Logic Function ---
# Description: Contains the core workflow orchestration after setup.
main() {
    log_message "INFO" "Starting main script execution logic..."

    # --- Configuration Check/Generation ---
    if [[ ! -f "$CONFIG_FILE" || "$REGENERATE_CONFIG" == true ]]; then
        if [[ "$REGENERATE_CONFIG" == true ]]; then
            # Ask for confirmation before overwriting
            read -p "Are you sure you want to overwrite '$CONFIG_FILE'? (y/N): " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                generate_config
            else
                log_message "INFO" "Configuration regeneration cancelled by user."
                # Decide whether to proceed with existing config or exit
                if [[ ! -f "$CONFIG_FILE" ]]; then
                   log_message "CRITICAL" "Configuration file '$CONFIG_FILE' does not exist and regeneration was cancelled."
                fi
                REGENERATE_CONFIG=false # Reset flag if cancelled
            fi
        else
            generate_config # Generate if missing
        fi
        # Reload config after potential generation/regeneration
        load_config
        validate_inputs # Re-validate after loading potentially new config
        # Re-prepare environment in case LOG_DIR changed? Or assume it's fixed after first prepare?
        # For simplicity, assume prepare_environment only needs to run once.
    else
        log_message "INFO" "Using existing configuration file: '${CONFIG_FILE}'"
        echo "To regenerate the configuration, run: ${SCRIPT_NAME} --regenerate-config"
    fi


    # --- Start Synchronization ---
    log_message "INFO" "Initiating rsync process in the background..."
    echo # Add newline for console output separation
    echo "${SCRIPT_NAME}: rsync process initiated. Check logs for progress and status:"
    echo "  Summary Log: ${SUMMARY_LOG}"
    echo "  Progress Log: ${PROGRESS_LOG}"
    echo # Add newline

    # Execute the run_rsync function in the background
    # The run_rsync function handles internal retries and final success/failure logging/email
    ( run_rsync ) &

    # Capture the PID of the backgrounded subshell running run_rsync
    local background_pid=$!
    log_message "INFO" "rsync process detached with PID ${background_pid}. It will continue running in the background."

    # Use disown to detach the background job from the current shell's job control.
    # This ensures the background process continues even if the parent shell exits (e.g., in cron).
    disown $background_pid || log_message "WARN" "Failed to disown background process PID ${background_pid}. It might terminate if the parent shell exits."


    log_message "INFO" "Main execution logic finished initiating background sync."
    # Note: Script exits here with 0, success/failure of sync is asynchronous.
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# 1. Parse Command Line Arguments
parse_params "$@"

# 2. Load Configuration File (Initial Load - might be reloaded in main if generated)
#    We load early to potentially get LOG_DIR if user specified non-default config via arg,
#    though this script currently doesn't support -c argument.
if [[ -f "$CONFIG_FILE" ]]; then
    load_config
else
    log_message "INFO" "Default configuration file '${CONFIG_FILE}' not found. Will attempt generation."
    # Set LOG_DIR to default temporarily for early logging if needed.
    LOG_DIR="${DEFAULT_LOG_DIR}"
fi

# 3. Check Core Dependencies (essential for basic operation and config loading/validation)
log_message "INFO" "Checking core dependencies..."
check_dependency "basename" "coreutils"
check_dependency "dirname" "coreutils"
check_dependency "date" "coreutils"
check_dependency "mkdir" "coreutils"
check_dependency "chmod" "coreutils"
check_dependency "cat" "coreutils"
check_dependency "tr" "coreutils"
check_dependency "sed" "sed"
check_dependency "awk" "gawk" # Or appropriate awk package
check_dependency "find" "findutils"
check_dependency "wc" "coreutils"
check_dependency "du" "coreutils"
check_dependency "sleep" "coreutils"
check_dependency "tail" "coreutils"
# Rsync and SSH are checked later, after config load determines if sshpass/mail are needed.

# 4. Validate Inputs (Initial validation based on potentially existing config)
#    Full validation happens again in main() if config is generated/regenerated.
if [[ -f "$CONFIG_FILE" && "$REGENERATE_CONFIG" == false ]]; then
   validate_inputs
fi

# 5. Prepare Environment (Setup logging based on loaded or default LOG_DIR)
prepare_environment

# 6. Check Sync-Specific Dependencies (Now that config is loaded and LOG_DIR exists)
log_message "INFO" "Checking synchronization-specific dependencies..."
check_dependency "rsync" "rsync"
check_dependency "ssh" "openssh-client"
if [[ "$USE_SSH_KEY" == "false" ]]; then
    # Only check sshpass if password authentication is explicitly configured
    check_dependency "sshpass" "sshpass"
fi
if [[ "$ENABLE_EMAIL" == "true" ]]; then
    # Check for mail/mailx only if email is enabled, but don't fail critically if missing
    if ! command -v mailx &> /dev/null && ! command -v mail &> /dev/null; then
        log_message "WARN" "'mail' or 'mailx' command not found, but email notifications are enabled. Emails will likely fail."
        log_message "WARN" "Please install 'mailutils' (Debian/Ubuntu) or 'mailx' (RHEL/CentOS/Fedora)."
    else
        log_message "DEBUG" "'mail' or 'mailx' found for email notifications."
    fi
fi
# Check numfmt if available, used in pre-sync analysis but not critical
if ! command -v numfmt &> /dev/null; then
     log_message "WARN" "'numfmt' command not found. File sizes in pre-sync analysis will be in bytes only."
fi


# 7. Execute Main Logic (Handles config generation/validation again, then starts sync)
main

# 8. Exit Successfully (Main script exits, background sync continues)
# Cleanup runs via trap EXIT
log_message "INFO" "Script initialization complete. Background sync process is running (PID: ${background_pid:-N/A})."
exit 0

# =========================================================================================
# --- End of Script ---
