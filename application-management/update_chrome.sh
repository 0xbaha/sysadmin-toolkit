#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : update_chrome.sh
# PURPOSE       : Checks/installs updates for a specific APT package if available.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2024-11-04
# LAST UPDATED  : 2024-11-04
# VERSION       : 1.0.0
# =========================================================================================

# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This script automates the process of checking for and installing updates for a specific
# package (defaulting to 'google-chrome-stable') using the APT package manager on
# Debian-based Linux systems (like Ubuntu).
#
# Key Workflow / Functions:
# - Parses command-line options for package name, verbosity, and help.
# - Uses functions for logging, dependency checking, argument parsing, validation, and cleanup.
# - Implements Bash strict mode (`set -euo pipefail`) for robustness.
# - Refreshes the local package repository index (`sudo apt update`).
# - Checks if an upgrade is available for the specified package (`apt list --upgradable`).
# - If an update exists, installs it non-interactively (`sudo apt install --only-upgrade -y`).
# - Provides structured, colored log messages to stdout/stderr based on severity and verbosity.
# - Performs cleanup on exit using a trap.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Targeted Update**: Focuses on updating only the specified package, minimizing system impact.
# - **Robustness**: Uses Bash strict mode (`set -euo pipefail`), function-based structure, basic error handling, and dependency checks.
# - **Automation**: Designed for non-interactive execution (e.g., via cron) using `-y` for apt install and clear logging.
# - **Readability**: Employs clear variable names, functional decomposition, and detailed comments.
# - **Simplicity**: Maintains a straightforward check-then-update logic, suitable for its specific purpose.
# - **Efficiency**: Uses quiet flags for apt commands (`-qq`) where appropriate to reduce noise during updates. Redirects `apt list` stderr.
# - **Safety**: Uses `--only-upgrade` to prevent accidental installation if the package isn't already present.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - System Administrators managing desktops/servers needing specific package updates (like Chrome).
# - IT Support Teams automating software maintenance tasks.
# - DevOps Engineers incorporating package updates into automation scripts.
# - Users preferring an automated, targeted way to keep specific software (like Chrome) updated.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x update_chrome.sh`
# - Requires `sudo` privileges to run `apt update` and `apt install`. The user running
#   the script must have appropriate sudo rights configured (e.g., belong to the 'sudo' group
#   or have specific NOPASSWD entry for commands used if full automation is needed).
#
# **Basic Syntax:**
#   ./update_chrome.sh [options]
#
# **Options:**
#   -h           Display this help message and exit.
#   -v           Enable verbose output (sets log level to DEBUG, prints more detail).
#   -p <package> Specify the package name to check/update (Default: "google-chrome-stable").
#
# **Common Examples:**
# 1. Check and update Google Chrome (default):
#    `./update_chrome.sh`
#    (May require running with `sudo ./update_chrome.sh` depending on sudo setup)
#
# 2. Check and update Firefox with verbose output:
#    `./update_chrome.sh -v -p firefox`
#
# 3. Get help:
#    `./update_chrome.sh -h`
#
# **Advanced Execution (Automation):**
# - Example Cron job running daily at 4 AM to update Chrome, logging to a dedicated file:
#   `0 4 * * * /path/to/update_chrome.sh -p google-chrome-stable > /var/log/update_chrome.log 2>&1`
#   (Ensure the path is correct, user running cron has sudo rights, and consider log rotation via `logrotate`)
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - System-wide scripts (requiring root/sudo): `/usr/local/sbin/` or `/opt/scripts/`.
# - User scripts: `~/bin/` or `~/.local/bin/` (ensure these are in user's $PATH).
#
# **Manual Setup:**
# 1. Place the script in the chosen location (e.g., `/usr/local/sbin/`).
# 2. Set appropriate ownership if system-wide: `sudo chown root:root /usr/local/sbin/update_chrome.sh`
# 3. Set executable permissions: `sudo chmod 750 /usr/local/sbin/update_chrome.sh` (or `chmod +x` for user scripts).
# 4. Ensure all dependencies are installed (see DEPENDENCIES section).
# 5. Run initially with `-h` or manually to test.
#
# **Integration:**
# - **Cron Job:** Add entry to crontab (`sudo crontab -e` or user crontab). Use full paths. Ensure cron environment has necessary context or source profile.
# - **Systemd Timer:** Create `.service` and `.timer` unit files for more flexible scheduling and management.
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: The Bourne-Again SHell interpreter. Uses Bash features (e.g., `set -o pipefail`, `[[ ]]`, `declare -A`).
#
# **Required System Binaries/Tools:**
# - `coreutils`: Provides `basename`, `dirname`, `date`, `echo`, `tr`. Assumed present on all Linux systems.
# - `apt`: The package manager for Debian-based systems (part of `apt` package).
# - `sudo`: Utility to execute commands with superuser privileges (part of `sudo` package).
# - `grep`: Tool for pattern searching (`grep -q`) (part of `grep` package).
# - `command`: Bash built-in for checking command existence.
# - `getopts`: Bash built-in for parsing short command-line options.
#
# **Setup Instructions (Dependencies are usually standard):**
# - Debian/Ubuntu: `sudo apt update && sudo apt install -y apt sudo grep coreutils bash` (These are typically pre-installed).
#
# **Operating System Compatibility:**
# - Designed primarily for Debian-based Linux distributions (e.g., Ubuntu, Debian, Linux Mint) using APT.
#
# **System State:**
# - An active internet connection to reach the configured APT repositories.
# - `sudo` must be installed and configured for the user running the script (passwordless sudo needed for full non-interactive cron execution).
# - The APT repository containing the target package (e.g., Google Chrome's official repo) must be correctly configured in `/etc/apt/sources.list` or `/etc/apt/sources.list.d/`.
#
# **Environment Variables Used:**
# - None directly consumed by the script logic itself.
# - Underlying tools like `apt` might respect proxy settings (e.g., `http_proxy`, `https_proxy`).
# - `PATH`: Standard variable, ensure `apt`, `sudo`, `grep` are locatable.
#
# **System Resource Requirements:**
# - Minimal: Low CPU and Memory usage. Disk space needed by `apt` for package list updates and downloads. Network bandwidth required for `apt update` and package downloads.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): INFO and DEBUG (if -v enabled) messages.
# - Standard Error (stderr): WARN, ERROR, CRITICAL messages. Also used for `usage()` output.
# - Dedicated Log File: No dedicated file logging implemented by default. Relies on redirection (e.g., in cron `> /path/to/log 2>&1`).
#
# **Log Format:**
# - Console Output: `[YYYY-MM-DD HH:MM:SS ZZZ] [LEVEL] - Message` (Colored if terminal supports it).
# - File Output (via redirection): Same format but without ANSI color codes.
#
# **Log Levels (Controlled by script logic and -v flag):**
# - `DEBUG`: Detailed step tracing (Enabled by `-v` flag, corresponds to `VERBOSE=true`).
# - `INFO`: General operational messages (start, stop, main actions).
# - `WARN`: Potential issues or non-fatal errors (not used currently but function supports it).
# - `ERROR`: Significant errors likely preventing task completion (e.g., `apt update` fails).
# - `CRITICAL`: Severe errors causing script termination (e.g., missing dependency, invalid arguments).
#
# **Log Rotation:**
# - Not handled by the script. If redirecting output to a file, use external tools like `logrotate` for managing log file size and retention.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Normal Operation: Prints INFO/DEBUG messages:
#   - Example: `[2025-04-20 18:00:00 WIB] [INFO] - Starting main script execution for package: google-chrome-stable`
#   - Example: `[2025-04-20 18:00:05 WIB] [INFO] - Update available for google-chrome-stable. Attempting upgrade...`
#   - Example: `[2025-04-20 18:00:15 WIB] [INFO] - google-chrome-stable has been updated successfully.`
#   - Example: `[2025-04-20 18:00:05 WIB] [INFO] - google-chrome-stable is already up to date or not installed.`
#   - Example: `[2025-04-20 18:00:15 WIB] [INFO] - Script completed successfully.`
#
# **Standard Error (stderr):**
# - Errors/Warnings: Prints ERROR/CRITICAL/WARN messages:
#   - Example: `[2025-04-20 18:00:05 WIB] [ERROR] - Failed to update package list ('sudo apt update -qq'). Check permissions or network.`
#   - Example: `[2025-04-20 18:00:15 WIB] [ERROR] - Failed to upgrade google-chrome-stable. Check apt output for details.`
#   - Example: `[2025-04-20 18:00:00 WIB] [CRITICAL] - Required command 'apt' not found.`
#   - Example: `[2025-04-20 18:00:00 WIB] [ERROR] - Invalid option: -x`
# - Help Output: The `usage()` function prints help text to stderr.
# - Note: Errors from `apt list --upgradable` are intentionally suppressed (`2>/dev/null`).
#
# **Generated/Modified Files:**
# - None directly created by this script (log files are via redirection).
# - Modifies the installed package specified by `PACKAGE_NAME` if an update is performed by `apt install`.
# - `apt` commands create/modify system files (e.g., in `/var/lib/apt/lists/`, `/var/cache/apt/`).
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success - Script completed its check/update process without script-level failure.
# - 1: General Error - Standard exit code for errors caught by `set -e`, critical log messages, argument parsing failures (`usage`), or explicit `exit 1` after failed apt commands.
# - (Potentially others from `apt` if not caught by `set -e` or `if ! cmd; then ... exit 1; fi` pattern)
#
# **Error Handling Mechanisms:**
# - `set -euo pipefail`: Exits on command failures, unset variables, or pipeline errors.
# - `log_message CRITICAL ...`: Logs a fatal error and exits with status 1.
# - `if ! command; then log_message ERROR ...; exit 1; fi`: Explicit checks for critical command failures (`apt update`, `apt install`).
# - `getopts`: Handles invalid options/missing arguments gracefully via `usage()` function (exits 1).
# - `trap cleanup EXIT INT TERM HUP`: Ensures cleanup runs regardless of exit reason.
#
# **Potential Failure Points & Troubleshooting:**
# - **Issue:** `apt update` or `apt install` fails.
#   **Resolution:** Check network connectivity. Verify repository configuration (e.g., `/etc/apt/sources.list.d/google-chrome.list`) and GPG keys (`sudo apt-key list`). Check sudo permissions. Look for detailed errors from `apt` in stderr. Run `sudo apt --fix-broken install` if suggested.
# - **Issue:** "Permission Denied" or sudo password prompt.
#   **Resolution:** Run script with `sudo`. Ensure user has necessary sudo rights. Configure passwordless sudo for `apt` commands if running unattended (e.g., via cron).
# - **Issue:** "Command not found: apt/sudo/grep".
#   **Resolution:** Install the missing package (`sudo apt install apt sudo grep`). Check `$PATH`.
# - **Issue:** Script reports "up to date" but update exists.
#   **Resolution:** Ensure `sudo apt update -qq` ran successfully first (check logs/stderr). Verify the package name (`-p` option) is correct. Check repository configuration.
# - **Issue:** Invalid option/argument errors.
#   **Resolution:** Check the `usage()` help text (`./update_chrome.sh -h`) for correct syntax.
#
# **Important Considerations:**
# - Implicit trust in the configured APT repositories (e.g., Google's). Ensure repos are legitimate.
# - The `-y` flag for `apt install` bypasses confirmation. Understand what `--only-upgrade` does.
# - Running with `sudo` grants significant privileges. Ensure script integrity and restrict execution permissions.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes running on a Debian-based Linux system using the `apt` package manager.
# - Assumes `bash` (v4+ recommended for `declare -A`) is available at `/bin/bash`.
# - Assumes standard utilities (`coreutils`, `grep`, `apt`, `sudo`) are installed and in `$PATH`.
# - Assumes the user running the script has sufficient `sudo` privileges for `apt update` and `apt install`.
# - Assumes the target package name provided (or defaulted) is correct for the `apt` system.
# - Assumes the necessary APT repositories are configured and reachable via the network.
# - Assumes an active internet connection is available.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Requires `sudo` privileges for core functionality (`apt update`, `apt install`). This grants root-equivalent access during those operations. Least privilege cannot be easily applied here due to the nature of package management. **Restrict script execution permissions (`chmod 700` or `750`) and ownership (`chown root:root` if system-wide).**
# - **Input Sanitization:** Basic validation is done for the `-p` option (non-empty check). The package name is passed directly to `apt`. While `apt` itself handles package names robustly, avoid constructing commands with unsanitized input if extending the script. Options `-h`, `-v` are flags.
# - **Sensitive Data Handling:** No passwords or API keys are handled by this script. `sudo` configuration handles authentication.
# - **Dependencies:** Relies on standard system tools (`bash`, `apt`, `sudo`, `grep`, `coreutils`). Keep the system and these tools updated via regular patching.
# - **Repository Trust:** The biggest security factor is the trust in the configured APT repositories. Ensure only legitimate and secure repositories (HTTPS, GPG signed) are configured, especially the one providing the target package (e.g., Google's official repo).
# - **File Permissions:** Does not create files directly (relies on redirection). `apt` manages permissions of its own files.
# - **External Command Execution:** Executes `apt`, `sudo`, `grep`, `date`, `echo`, `tr`, `basename`, `dirname`, `command`. These are well-defined commands. The package name is passed as data to `apt`.
# - **Network Exposure:** Makes outbound connections via `apt` to repository servers. Ensure firewalls permit this traffic (HTTP/HTTPS).
# - **Code Integrity:** Verify the script source if obtained externally. Use checksums if provided. `set -euo pipefail` helps prevent unexpected execution flow after errors.
# - **Error Message Verbosity:** Error messages aim to be informative but avoid leaking sensitive system details beyond what `apt` might output. CRITICAL errors about missing dependencies are explicit.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is within this script's header comments.
# - Use `./update_chrome.sh -h` for command-line usage help.
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baharuddin Aziz
# - Contact: contact [at] baha.my.id
# - Website: https://baha.my.id
# - Bug Reports/Issues: Report via Repository link if available (https://baha.my.id/github) or Contact email.
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - Implement robust logging to a dedicated file (`/var/log/` or configurable) with rotation options.
# - Add more explicit exit codes for different failure scenarios (e.g., apt update fail vs apt install fail).
# - Add prerequisite checks (e.g., verify network connectivity before running `apt`).
# - Add optional `--dry-run` flag to simulate without installing.
# - Add support for checking/updating multiple packages specified via arguments or config file.
# - Extend compatibility or provide separate scripts for other package managers (e.g., `dnf`, `yum`, `pacman`).
# - Consider using `getopt` (external command) for long option support (e.g., `--package`, `--verbose`).
# =========================================================================================

# =========================================================================================
# SCRIPT EXECUTION ENVIRONMENT & CONFIGURATION
# =========================================================================================

# --- Bash Strict Mode ---
# -e: Exit immediately if a command exits with a non-zero status.
# -u: Treat unset variables and parameters as an error during expansion.
# -o pipefail: The pipeline's return status is the status of the last command to exit non-zero.
set -euo pipefail

# --- Debug Mode ---
# Uncomment the following line for debugging (prints each command before execution).
# set -x

# --- Script Information ---
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_DIR="${SOURCE_DIR}"
readonly SCRIPT_PID=$$

# --- Timestamp ---
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Global Runtime Variables ---
# Configuration Defaults (Can be overridden by arguments)
VERBOSE=false        # Flag for verbose output
NO_COLOR=false       # Flag to disable colored output
PACKAGE_NAME="google-chrome-stable" # Default package to check/update
LOG_LEVEL="INFO"     # Default log level (DEBUG, INFO, WARN, ERROR, CRITICAL)

# Determine if running in an interactive terminal for color support
INTERACTIVE_MODE=false
[[ -t 1 ]] && INTERACTIVE_MODE=true

# --- Color Definitions (Optional) ---
if [[ "${NO_COLOR}" == false && "${INTERACTIVE_MODE}" == true ]]; then
    COLOR_RESET='\033[0m'; COLOR_RED='\033[0;31m'; COLOR_GREEN='\033[0;32m'
    COLOR_YELLOW='\033[0;33m'; COLOR_BLUE='\033[0;34m'; COLOR_CYAN='\033[0;36m'; COLOR_BOLD='\033[1m'
else
    COLOR_RESET=""; COLOR_RED=""; COLOR_GREEN=""; COLOR_YELLOW=""
    COLOR_BLUE=""; COLOR_CYAN=""; COLOR_BOLD=""
fi

# =========================================================================================
# FUNCTION DEFINITIONS
# =========================================================================================

# --- Logging Function ---
# Usage: log_message LEVEL "Message string"
log_message() {
    local level="$1"; local message="$2"; local timestamp; local level_upper; local log_prefix; local log_line; local color=""
    timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z")
    level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]')
    log_prefix="[${timestamp}] [${level_upper}]"
    log_line="${log_prefix} - ${message}"

    case "${level_upper}" in
        DEBUG) color="${COLOR_CYAN}" ;; INFO) color="${COLOR_GREEN}" ;; WARN) color="${COLOR_YELLOW}" ;;
        ERROR) color="${COLOR_RED}" ;; CRITICAL) color="${COLOR_BOLD}${COLOR_RED}" ;;
    esac

    declare -A log_levels=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [CRITICAL]=4)
    local current_log_level_num=${log_levels[${LOG_LEVEL^^}]}
    local message_level_num=${log_levels[${level_upper}]}

    if [[ ${message_level_num} -ge ${current_log_level_num} ]]; then
        if [[ "${level_upper}" == "WARN" || "${level_upper}" == "ERROR" || "${level_upper}" == "CRITICAL" ]]; then
            echo -e "${color}${log_line}${COLOR_RESET}" >&2
        else
            if [[ "${level_upper}" != "DEBUG" || "${VERBOSE}" == true ]]; then
                 echo -e "${color}${log_line}${COLOR_RESET}"
            fi
        fi
    fi

    if [[ "${level_upper}" == "CRITICAL" ]]; then
        log_message "ERROR" "Critical error encountered. Exiting script."
        # Cleanup will be handled by trap
        exit 1 # Exit immediately on critical errors
    fi
}

# --- Usage/Help Function ---
usage() {
    # Extract Usage section from header comments
    local usage_text
    usage_text=$(sed -n '/^# ===+ USAGE ===+$/,/^# ===+ .* ===+$/{ /# ===+ .* ===+$/!p; }' "${BASH_SOURCE[0]}" | sed 's/^# //; s/\[your_script_name.sh\]/'"${SCRIPT_NAME}"'/g')

    cat << EOF >&2
${usage_text}

Options:
  -h           Display this help message and exit.
  -v           Enable verbose output (sets log level to DEBUG).
  -p <package> Specify the package name to check/update (Default: "${PACKAGE_NAME}").

This script requires 'sudo' privileges for APT commands.
EOF
    exit 1
}

# --- Dependency Check Function ---
check_dependency() {
    local cmd="$1"
    local install_suggestion="${2:-$cmd}"
    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required command '${cmd}' not found. Please install '${install_suggestion}'."
        # Exit handled by CRITICAL log level
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
}

# --- Cleanup Function ---
# Called automatically on exit, interrupt, term, hangup signals via trap.
cleanup() {
    local exit_status=$? # Capture the script's exit status
    log_message "DEBUG" "Performing cleanup..."
    # No temporary files or specific resources to clean in this simple script.
    log_message "INFO" "Script finished with exit status: ${exit_status}"
    # Script will exit with the original exit_status after trap completes.
}

# --- Trap Setup ---
# Register the 'cleanup' function to run on script exit or specific signals.
trap cleanup EXIT INT TERM HUP

# --- Argument Parsing Function ---
parse_params() {
    while getopts ":hvp:" opt; do
        case $opt in
            h) usage ;;
            v) VERBOSE=true; LOG_LEVEL="DEBUG" ;;
            p) PACKAGE_NAME="$OPTARG" ;;
            \?) log_message "ERROR" "Invalid option: -${OPTARG}"; usage ;;
            :) log_message "ERROR" "Option -${OPTARG} requires an argument."; usage ;;
        esac
    done
    shift $((OPTIND-1)) # Shift processed options away

    # Check for unexpected positional arguments
    if [[ $# -gt 0 ]]; then
        log_message "ERROR" "Unexpected argument(s): $*"
        usage
    fi
    log_message "DEBUG" "Arguments parsed. Verbose: ${VERBOSE}, Package: ${PACKAGE_NAME}, LogLevel: ${LOG_LEVEL}"
}

# --- Input Validation Function ---
validate_inputs() {
    log_message "INFO" "Validating inputs and configuration..."
    if [[ -z "${PACKAGE_NAME}" ]]; then
        log_message "CRITICAL" "Package name cannot be empty. Use -p option or check default."
    fi
    # Basic check if sudo is available - doesn't guarantee permissions
    if ! command -v sudo &> /dev/null; then
        log_message "CRITICAL" "'sudo' command not found. This script requires sudo privileges."
    fi
    log_message "INFO" "Input validation passed (Package: '${PACKAGE_NAME}'). Requires sudo access for apt commands."
}

# --- Preparation Function ---
prepare_environment() {
    log_message "INFO" "Preparing execution environment..."
    # No specific preparation needed for this script (e.g., temp dirs)
    log_message "INFO" "Environment preparation complete."
}

# --- Main Logic Function ---
main() {
    log_message "INFO" "Starting main script execution for package: ${PACKAGE_NAME}"

    # Step 1: Update package repository information.
    log_message "INFO" "Updating package list using 'sudo apt update'. Sudo prompt may appear."
    if ! sudo apt update -qq; then
        log_message "ERROR" "Failed to update package list ('sudo apt update -qq'). Check permissions or network."
        exit 1 # Exit on failure
    fi
    log_message "INFO" "Package list updated successfully."

    # Step 2: Check if an update is available for the specified package.
    log_message "INFO" "Checking for available upgrades for '${PACKAGE_NAME}'..."
    # Use 'apt list --upgradable' and grep. Redirect stderr of 'apt list' to avoid clutter.
    # The exit status of 'grep -q' determines if the package is upgradable.
    if apt list --upgradable 2>/dev/null | grep -q "^${PACKAGE_NAME}/"; then
        log_message "INFO" "Update available for ${PACKAGE_NAME}. Attempting upgrade..."

        # Step 3: Install the update for the package.
        # Use --only-upgrade to prevent installing if not present. Use -y for non-interactive.
        log_message "INFO" "Running 'sudo apt install --only-upgrade ${PACKAGE_NAME} -y'. Sudo prompt may appear."
        if ! sudo apt install --only-upgrade "${PACKAGE_NAME}" -y; then
             log_message "ERROR" "Failed to upgrade ${PACKAGE_NAME}. Check apt output for details."
             exit 1 # Exit on failure
        fi
        log_message "INFO" "${PACKAGE_NAME} has been updated successfully."
    else
        # If 'grep -q' returns non-zero (false), no update matching the package name was found.
        log_message "INFO" "${PACKAGE_NAME} is already up to date or not installed."
    fi

    log_message "INFO" "Main execution logic finished."
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# 1. Parse Command Line Arguments
parse_params "$@"

# 2. Validate Inputs (Package name, basic sudo check)
validate_inputs

# 3. Check Dependencies (apt, sudo, grep)
log_message "INFO" "Checking required dependencies..."
check_dependency "apt" "apt package manager (typically apt)"
check_dependency "sudo" "sudo"
check_dependency "grep" "grep"

# 4. Prepare Environment (Minimal prep needed here)
prepare_environment

# 5. Execute Main Logic
main

# 6. Exit Successfully (Cleanup runs via trap)
log_message "INFO" "Script completed successfully."
exit 0 # Explicitly exit with success code

# =========================================================================================
# --- End of Script ---
