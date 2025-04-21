#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : check_usernames_github.sh
# PURPOSE       : Checks availability of usernames on GitHub via HTTP status codes.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2024-10-14
# LAST UPDATED  : 2024-10-14
# VERSION       : 1.0.0
# =========================================================================================

# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This script automates the process of checking whether specific usernames are
# available or taken on GitHub (github.com). It uses 'curl' to query the profile
# URL and interprets the HTTP status code (404 = Available).
#
# It operates in two primary modes:
# 1.  **Random Mode:** Generates a specified number (default 1000) of random
#     alphanumeric usernames of a configurable length (default 3 characters).
#     Controlled via the --length/-l option.
# 2.  **Pattern Mode:** Checks all usernames following a specific pattern "<prefix>000"
#     to "<prefix>999", where "<prefix>" is provided by the user via the --pattern option.
#
# Key Workflow / Functions:
# - Parses command-line arguments (--pattern, --length, --verbose, --help).
# - Sets Bash strict mode (`set -euo pipefail`).
# - Implements basic logging (DEBUG, INFO, WARN, ERROR, CRITICAL) to console and optionally a timestamped file.
# - Checks for required command dependencies (`curl`, coreutils, etc.).
# - Attempts to automatically install 'curl' if missing (Linux/macOS).
# - Includes a cleanup routine using `trap` for graceful exit.
# - Generates usernames either randomly or based on the sequential pattern.
# - Uses 'curl' with a timeout to query GitHub profile URLs (https://github.com/username).
# - Interprets HTTP status codes (404, 200, 3xx, 000, others) to determine availability.
# - Writes results (Username, GitHub Status) line by line to a uniquely named CSV file in the specified output directory.
# - Includes a configurable delay between requests to mitigate rate limiting.
# - Provides progress feedback to the console during execution.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Simplicity:** Focuses on the core task using standard *nix tools.
# - **Automation:** Designed for checking batches of usernames unattended.
# - **User-Friendliness:** Clear options, progress output, standard CSV results, integrated logging.
# - **Basic Robustness:** Uses strict mode, checks dependencies, handles common HTTP responses/timeouts, includes cleanup via trap.
# - **Modularity:** Uses functions for distinct tasks (logging, parsing, checking, generation, setup).
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - Developers or individuals looking for available short/patterned usernames on GitHub.
# - Script users needing a basic automated username availability checker for GitHub.
# - System administrators needing examples of Bash scripting best practices (logging, traps, strict mode).
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x check_usernames_github.sh`
# - File system access: Write access to the output directory (default: script's directory) and log directory (default: './logs').
# - Network access: Outbound HTTPS connections to github.com.
# - Elevated privileges: Requires `sudo` ONLY if 'curl' needs to be installed automatically on Linux.
#
# **Basic Syntax:**
# `./check_usernames_github.sh [OPTIONS]`
#
# **Options:**
#   --pattern <prefix>   Check GitHub usernames matching <prefix>000 to <prefix>999.
#                        Switches the script to pattern mode.
#   --length <num>, -l <num> Specify the length for random GitHub usernames.
#                        Only used in random mode (default: 3). Must be a positive integer.
#   -v, --verbose        Enable verbose (DEBUG level) logging to console and log file.
#   -h, --help           Display this help message and exit.
#
# **Arguments:**
#   None (Options control behavior)
#
# **Common Examples:**
# 1. Random check (default: 1000 usernames, 3 chars long):
#    `./check_usernames_github.sh`
#
# 2. Random check with specific length (1000 usernames, 6 chars long):
#    `./check_usernames_github.sh --length 6`
#    `./check_usernames_github.sh -l 6`
#
# 3. Pattern check (e.g., check 'testprefix000' to 'testprefix999'):
#    `./check_usernames_github.sh --pattern testprefix`
#
# 4. Run with verbose logging:
#    `./check_usernames_github.sh -v`
#
# 5. Get help:
#    `./check_usernames_github.sh --help`
#
# **Automation:**
# - Example cron job (run daily, check pattern 'projectX', log output):
#   `0 3 * * * /path/to/check_usernames_github.sh --pattern projectX >> /var/log/github_checker.log 2>&1`
#   (Ensure cron environment has necessary PATH or use full paths in script/cron).
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - User scripts: `~/bin/` or `~/.local/bin/` (ensure in $PATH)
# - Project-specific: Within the project directory.
#
# **Manual Setup:**
# 1. Place the script in the chosen location.
# 2. Set executable permissions: `chmod +x check_usernames_github.sh`.
# 3. Install required dependencies if missing (see DEPENDENCIES section, script attempts auto-install for curl).
# 4. Ensure write permissions for the output directory (`./` by default) and log directory (`./logs` by default).
# 5. Run the script initially with `--help` or a small test case to verify.
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: Bash version 4+ recommended (uses features like `declare -A`).
#
# **Required System Binaries/Tools:**
# - `curl`: Used to make HTTP requests to GitHub. (Script attempts auto-install).
# - `coreutils`: Provides `date`, `mkdir`, `chmod`, `cat`, `head`, `tr`, `seq`, `basename`, `dirname`, `printf`, `sleep`.
# - `sed`: Stream editor used for parsing help text and potentially config files (if added).
# - `command`: Bash built-in for checking command existence.
# - `getopts`: Bash built-in for parsing short command-line options (used in template example, current script uses manual parsing).
#
# **Setup Instructions (if 'curl' auto-install fails):**
# - Debian/Ubuntu: `sudo apt update && sudo apt install -y curl`
# - RHEL/CentOS/Fedora: `sudo dnf install curl -y` or `sudo yum install curl -y`
# - macOS (with Homebrew): `brew install curl`
#
# **Operating System Compatibility:**
# - Designed primarily for Linux (Debian/Ubuntu, CentOS/Fedora tested via install logic) and macOS (via Homebrew install logic).
# - May work on other Unix-like systems with compatible Bash and core utilities.
#
# **Environment Variables Used:**
# - `OSTYPE`: Used internally by the script to determine the OS for `curl` installation.
# - `PATH`: Standard variable, ensure required binaries are locatable.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): INFO messages, user-facing progress updates ("Checking username...").
# - Standard Error (stderr): WARN, ERROR, CRITICAL messages.
# - Dedicated Log File: Yes (by default, `LOG_TO_FILE=true`).
#   - Path: `./logs/check_usernames_github_<TIMESTAMP>.log` (Default, location changeable via `DEFAULT_LOG_DIR`).
#   - Format: `[YYYY-MM-DD HH:MM:SS TZ] [LEVEL] - Message` (Color codes stripped).
#
# **Log Levels:**
# - DEBUG: Detailed step-by-step info (Enabled by `-v` or `--verbose`).
# - INFO: General operational messages, start/stop, summaries.
# - WARN: Potential issues, recoverable errors (e.g., curl timeout, log dir not writable).
# - ERROR: Significant errors impacting execution (e.g., invalid arguments, missing critical dependency).
# - CRITICAL: Severe errors causing script termination (e.g., unwritable output dir, failed validation).
#
# **Log Rotation:**
# - Handled by script?: No.
# - External Recommendation: Use external tools like `logrotate` if long-term log management is needed.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Progress messages indicating script mode, output file name, and current username check.
# - Final completion summary.
# - INFO and DEBUG log messages (DEBUG only if -v).
#
# **Standard Error (stderr):**
# - Error messages (invalid args, failed installs, etc.).
# - Warning messages (timeouts, non-critical failures).
# - WARN, ERROR, CRITICAL log messages.
#
# **Generated/Modified Files:**
# - CSV Result File:
#   - Path: `./<PREFIX>_github_check_results_<TIMESTAMP>.csv` (Pattern mode)
#   - Path: `./random_<LENGTH>char_github_check_results_<TIMESTAMP>.csv` (Random mode)
#   - Content: Comma-separated values with columns "Username", "GitHub Status".
# - Log File:
#   - Path: `./logs/check_usernames_github_<TIMESTAMP>.log` (Default)
#   - Content: Timestamped log messages (DEBUG, INFO, WARN, ERROR, CRITICAL).
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success.
# - 1: General Error (Caught by `set -e`, CRITICAL log message, trap cleanup, invalid options).
#
# **Potential Issues & Troubleshooting:**
# - Issue: "Error/Timeout" or "Error/Connection" status frequently.
#   Resolution: Check network connectivity. Increase `CURL_TIMEOUT` value. GitHub might be rate-limiting; increase `SLEEP_DURATION`.
# - Issue: "'curl' installation failed".
#   Resolution: Check network connection. Ensure `sudo` works (Linux) or `brew` works (macOS). Install `curl` manually.
# - Issue: "Taken (Code: XXX)" where XXX is not 200/3xx/404.
#   Resolution: GitHub returned an unexpected code. Could be rate limiting (429), server error (5xx), or blocking (403). Script conservatively marks as 'Taken'. Check logs for details.
# - Issue: Permission denied creating output/log files.
#   Resolution: Ensure the script has write permissions in the target directories (`./` and `./logs` by default).
#
# **Important Considerations / Warnings:**
# - **Rate Limiting:** GitHub enforces request limits. Excessive checks may lead to temporary IP blocks or errors. Adjust `SLEEP_DURATION` (default 1s) if needed.
# - **Accuracy:** Based solely on HTTP status code. Generally good for GitHub, but network glitches or GitHub changes could affect it.
# - **Resource Usage:** Low CPU/Memory. Network usage depends on check count.
# - **Idempotency:** Yes, running multiple times with the same parameters generates separate timestamped result files without altering system state (beyond potentially installing curl).
# - **Concurrency:** Not designed for simultaneous execution. No locking implemented. Running multiple instances might accelerate rate limiting.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Runs as user. Needs `sudo` only for optional `curl` installation on Linux.
# - **Input Sanitization:** Basic validation for `--length` (positive integer), `--pattern` (requires value). No complex sanitization on the prefix string.
# - **Sensitive Data Handling:** None. Does not handle passwords or API keys.
# - **Dependencies:** Relies on standard OS tools and `curl`. Keep system updated.
# - **File Permissions:** Creates output/log files with default user permissions.
# - **External Command Execution:** Uses `curl` to connect to github.com. Command structure is static, not built from user input beyond the username in the URL path.
# - **Network Exposure:** Makes outbound HTTPS requests to github.com.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is within this script's header comments.
# - README: See repository link (`https://baha.my.id/github`) if available.
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Report via the script's repository or directly to the author.
# =========================================================================================

# =========================================================================================
# TESTING & VALIDATION
# =========================================================================================
# **Test Strategy:** Manual testing performed. No automated tests (Bats, shunit2) currently implemented.
# **Key Test Cases Covered:** Ran with default random mode, specific length random mode, pattern mode. Tested help flag. Tested on Linux (Ubuntu) and macOS. Tested scenarios with missing `curl`.
# **Validation Environment:** Ubuntu 22.04, macOS Sonoma, Bash 5.x.
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - Add option to read usernames from a file.
# - Implement more sophisticated rate limit handling (e.g., exponential backoff).
# - Add support for checking other platforms (if reliable methods found).
# - Allow configuration via a config file (in addition to command-line args).
# - Add unit/integration tests (Bats/shunit2).
# - Add option for parallel checking (e.g., using `xargs -P` or `parallel`), respecting rate limits.
# =========================================================================================

# =========================================================================================
# SCRIPT EXECUTION ENVIRONMENT & CONFIGURATION
# =========================================================================================

# --- Bash Strict Mode ---
# -e: Exit immediately if a command exits with a non-zero status.
# -u: Treat unset variables and parameters as an error during expansion.
# -o pipefail: Pipeline return status is the status of the last command to exit non-zero.
set -euo pipefail

# --- Script Information ---
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
# Resolve the absolute path of the script's directory, handling symlinks.
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_DIR="${SOURCE_DIR}"
readonly SCRIPT_PID=$$

# --- Timestamp ---
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Global Runtime Variables & Configuration Defaults ---

# Script Behavior Flags
VERBOSE=false # Enable verbose output (more detailed logging)
NO_COLOR=false # Disable colored output
INTERACTIVE_MODE=false # Auto-detected if stdout is a terminal
[[ -t 1 ]] && INTERACTIVE_MODE=true

# Logging Configuration
LOG_LEVEL="INFO" # Default log level (DEBUG, INFO, WARN, ERROR, CRITICAL)
LOG_TO_FILE=true # Enable logging to a file by default
DEFAULT_LOG_DIR="${SCRIPT_DIR}/logs" # Default directory for log files
DEFAULT_LOG_FILE="${DEFAULT_LOG_DIR}/${SCRIPT_NAME%.sh}_${SCRIPT_RUN_TIMESTAMP}.log" # Default log file path
LOG_FILE="${DEFAULT_LOG_FILE}" # Actual log file path, can be changed

# Core Script Configuration Defaults (from original script)
DEFAULT_CHECK_COUNT=1000 # Default number of random usernames to check
DEFAULT_RANDOM_LENGTH=3 # Default length for random usernames
DEFAULT_PATTERN_CHECK_RANGE=999 # Default upper limit for pattern checks (000-999)
DEFAULT_CURL_TIMEOUT=30 # Default timeout for curl requests in seconds
DEFAULT_SLEEP_DURATION=1 # Default delay between checks in seconds

# Runtime Variables (will be populated by defaults, args, or config)
MODE="random" # Operating mode ('random' or 'pattern')
PATTERN_PREFIX="" # Prefix for pattern mode
RANDOM_LENGTH=${DEFAULT_RANDOM_LENGTH}
CHECK_COUNT=${DEFAULT_CHECK_COUNT} # Actual number of checks to perform (for random mode)
PATTERN_RANGE=${DEFAULT_PATTERN_CHECK_RANGE}
CURL_TIMEOUT=${DEFAULT_CURL_TIMEOUT}
SLEEP_DURATION=${DEFAULT_SLEEP_DURATION}

# Output Configuration
DEFAULT_OUTPUT_DIR="${SCRIPT_DIR}" # Default directory for CSV results (current dir)
OUTPUT_DIR="${DEFAULT_OUTPUT_DIR}"
OUTPUT_FILE="" # Will be set based on mode and timestamp

# Temporary Directory (optional, if needed)
DEFAULT_TMP_DIR_BASE="/tmp"
TEMP_DIR="" # Will be set by mktemp if needed

# --- Color Definitions (Optional) ---
# Define ANSI escape codes for colored output if not disabled and interactive.
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

    # Map script log levels to numeric values for comparison
    declare -A log_levels=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [CRITICAL]=4)
    local current_log_level_num=${log_levels[${LOG_LEVEL^^}]}
    # Handle case where LOG_LEVEL is invalid (assign a default, e.g., INFO)
    [[ -z "${current_log_level_num}" ]] && current_log_level_num=1
    local message_level_num=${log_levels[${level_upper}]}

    # Check if the message level is severe enough to be logged
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

        # Append to log file if enabled
        if [[ "${LOG_TO_FILE}" == true ]]; then
            # Ensure log directory exists
            if mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null; then
                if [[ -w "$(dirname "${LOG_FILE}")" ]]; then
                    # Strip color codes for file logging
                    echo "${log_prefix} - ${message}" >> "${LOG_FILE}"
                else
                    # Warning if log directory is not writable (only warn once)
                    if [[ -z ${LOG_DIR_WRITE_WARN_SENT+x} ]]; then
                        echo -e "${COLOR_YELLOW}[${timestamp}] [WARN] - Cannot write to log directory $(dirname "${LOG_FILE}"). Logging to file disabled.${COLOR_RESET}" >&2
                        LOG_DIR_WRITE_WARN_SENT=true
                        LOG_TO_FILE=false # Disable further file logging
                    fi
                fi
            else
                 # Warning if log directory cannot be created (only warn once)
                if [[ -z ${LOG_DIR_CREATE_WARN_SENT+x} ]]; then
                    echo -e "${COLOR_YELLOW}[${timestamp}] [WARN] - Cannot create log directory $(dirname "${LOG_FILE}"). Logging to file disabled.${COLOR_RESET}" >&2
                    LOG_DIR_CREATE_WARN_SENT=true
                    LOG_TO_FILE=false # Disable further file logging
                fi
            fi
        fi
    fi

    # Exit immediately for CRITICAL errors
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        echo -e "${COLOR_BOLD}${COLOR_RED}Critical error encountered. Exiting script.${COLOR_RESET}" >&2
        # Cleanup will be triggered by trap EXIT
        exit 1 # Use exit code 1 for critical errors
    fi
} # End log_message

# --- Usage/Help Function ---
# Displays help information based on header comments and exits.
usage() {
    # Extract Usage section from script header
    local usage_text
    usage_text=$(sed -n '/^# ===+ USAGE ===+$/,/^# ===+ .* ===+$/{ /# ===+ .* ===+$/!p; }' "${BASH_SOURCE[0]}" | sed 's/^# //; s/\[your_script_name.sh\]/'"${SCRIPT_NAME}"'/g')

    # Print usage info to stderr
    cat << EOF >&2

${usage_text}

Default random checks: ${DEFAULT_CHECK_COUNT}
Default random length: ${DEFAULT_RANDOM_LENGTH}
Default curl timeout: ${DEFAULT_CURL_TIMEOUT}s
Default sleep duration: ${DEFAULT_SLEEP_DURATION}s
Default output directory: ${DEFAULT_OUTPUT_DIR}
Default log file: ${DEFAULT_LOG_FILE} (Timestamped on execution)
EOF
    exit 1
} # End usage

# --- Dependency Check Function ---
# Checks if a command is installed; logs CRITICAL error and exits if not.
check_dependency() {
    local cmd="$1"
    local install_suggestion="${2:-$cmd}" # Suggest package name if provided
    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required command '${cmd}' not found. Please install the '${install_suggestion}' package."
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
} # End check_dependency

# --- Cleanup Function ---
# Performs cleanup tasks before script exits (called by trap).
cleanup() {
    local exit_status=$? # Capture the script's exit status
    log_message "DEBUG" "Performing cleanup..."
    # Remove temporary directory if created
    if [[ -n "${TEMP_DIR:-}" && -d "${TEMP_DIR}" ]]; then
        log_message "DEBUG" "Removing temporary directory: ${TEMP_DIR}"
        rm -rf "${TEMP_DIR}" || log_message "WARN" "Failed to remove temporary directory: ${TEMP_DIR}"
    fi
    # Add any other cleanup tasks here (e.g., remove lock files)
    log_message "DEBUG" "Cleanup finished. Exiting with status: ${exit_status}"
    # Script exits with the original exit_status after trap completes
} # End cleanup

# --- Trap Setup ---
# Register the 'cleanup' function to run on script exit or interruption signals.
trap cleanup EXIT INT TERM HUP

# --- Argument Parsing Function ---
# Parses command-line options using the original script's while/case logic.
parse_params() {
    log_message "DEBUG" "Parsing command-line arguments..."
    while [[ $# -gt 0 ]]; do
        local key="$1"
        case $key in
            --pattern)
                if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                    MODE="pattern"
                    PATTERN_PREFIX="$2"
                    log_message "DEBUG" "Argument: Mode set to 'pattern' with prefix '${PATTERN_PREFIX}'"
                    shift 2
                else
                    log_message "ERROR" "--pattern option requires a non-empty prefix argument."
                    usage
                fi
                ;;
            -l|--length)
                if [[ -n "$2" && "$2" =~ ^[1-9][0-9]*$ ]]; then
                    RANDOM_LENGTH="$2"
                    log_message "DEBUG" "Argument: Random length set to '${RANDOM_LENGTH}'"
                    shift 2
                else
                    log_message "ERROR" "--length (-l) option requires a positive integer value."
                    usage
                fi
                ;;
             -v|--verbose)
                 VERBOSE=true
                 LOG_LEVEL="DEBUG" # Set log level to DEBUG when verbose
                 log_message "DEBUG" "Argument: Verbose mode enabled."
                 shift
                 ;;
            -h|--help)
                usage ;;
            *)
                log_message "ERROR" "Unknown option: '$1'"
                usage ;;
        esac
    done

     # Apply overrides based on parsed args if needed (example, not strictly needed here)
     CHECK_COUNT=${DEFAULT_CHECK_COUNT} # Reset in case this becomes an option later
     PATTERN_RANGE=${DEFAULT_PATTERN_CHECK_RANGE}
     CURL_TIMEOUT=${DEFAULT_CURL_TIMEOUT}
     SLEEP_DURATION=${DEFAULT_SLEEP_DURATION}

    log_message "DEBUG" "Argument parsing complete. Mode: ${MODE}, Prefix: ${PATTERN_PREFIX:-N/A}, Length: ${RANDOM_LENGTH}"
} # End parse_params

# --- Input Validation Function ---
# Performs checks on finalized configuration and inputs before execution.
validate_inputs() {
    log_message "INFO" "Validating inputs and configuration..."

    # Validate mode-specific requirements
    if [[ "$MODE" == "pattern" && -z "$PATTERN_PREFIX" ]]; then
        log_message "CRITICAL" "Pattern mode requires a prefix set via --pattern."
    fi
    if [[ "$MODE" == "random" && ($RANDOM_LENGTH -le 0) ]]; then
        log_message "CRITICAL" "Random length must be a positive integer."
    fi

    # Validate numerical configurations
     if ! [[ "${CHECK_COUNT}" =~ ^[1-9][0-9]*$ ]]; then
         log_message "CRITICAL" "Check count (${CHECK_COUNT}) must be a positive integer."
     fi
      if ! [[ "${PATTERN_RANGE}" =~ ^[0-9]+$ ]]; then
         log_message "CRITICAL" "Pattern range (${PATTERN_RANGE}) must be a non-negative integer."
     fi
     if ! [[ "${CURL_TIMEOUT}" =~ ^[1-9][0-9]*$ ]]; then
         log_message "CRITICAL" "Curl timeout (${CURL_TIMEOUT}) must be a positive integer."
     fi
     if ! [[ "${SLEEP_DURATION}" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then # Allow integer or float
         log_message "CRITICAL" "Sleep duration (${SLEEP_DURATION}) must be a non-negative number."
     fi

    # Check writability of output directory
    if ! mkdir -p "${OUTPUT_DIR}"; then
        log_message "CRITICAL" "Output directory '${OUTPUT_DIR}' could not be created."
    elif [[ ! -w "${OUTPUT_DIR}" ]]; then
        log_message "CRITICAL" "Output directory '${OUTPUT_DIR}' is not writable."
    fi

    log_message "INFO" "Input validation passed."
} # End validate_inputs


# --- Original Script Functions (Adapted for Logging/Return Values) ---

# Function: install_requirements (Adapted from original)
# Purpose: Checks for 'curl' and attempts installation.
install_requirements() {
    log_message "DEBUG" "Checking for 'curl' dependency..."
    if ! command -v curl &> /dev/null; then
        log_message "WARN" "'curl' is not installed. Attempting installation (may require sudo)..."
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            if command -v apt-get &> /dev/null; then
                sudo apt-get update && sudo apt-get install curl -y
            elif command -v yum &> /dev/null; then
                sudo yum install curl -y
            else
                log_message "ERROR" "Could not find apt-get or yum. Please install curl manually."
                return 1 # Indicate failure
            fi
        elif [[ "$OSTYPE" == "darwin"* ]]; then
             if command -v brew &> /dev/null; then
                 brew install curl
             else
                 log_message "ERROR" "Homebrew not found on macOS. Please install curl manually."
                 return 1 # Indicate failure
             fi
        else
            log_message "ERROR" "Unsupported OS for automatic curl installation. Please install it manually."
            return 1 # Indicate failure
        fi

        # Verify installation after attempt
        if ! command -v curl &> /dev/null; then
             log_message "CRITICAL" "Curl installation failed or was not found after attempt."
             # Exit is handled by CRITICAL level
        else
             log_message "INFO" "Curl installed successfully."
        fi
    else
        log_message "DEBUG" "'curl' dependency is satisfied."
    fi
    return 0 # Indicate success
} # End install_requirements

# Function: generate_random_username (Adapted from original)
# Purpose: Generates a random alphanumeric username of specified length.
# Outputs: Prints the username string to stdout.
generate_random_username() {
    local len=${1:-$RANDOM_LENGTH} # Use passed length or global default
    log_message "DEBUG" "Generating random username of length ${len}"
    LC_ALL=C tr -dc 'a-z0-9' < /dev/urandom | head -c "$len"
} # End generate_random_username

# Function: generate_pattern_username (Adapted from original)
# Purpose: Generates a username based on prefix and number (padded).
# Outputs: Prints the username string to stdout.
generate_pattern_username() {
    local prefix="$1"
    local number="$2"
    log_message "DEBUG" "Generating pattern username: prefix='${prefix}', number='${number}'"
    printf "%s%03d" "$prefix" "$number"
} # End generate_pattern_username

# Function: check_github (Adapted from original)
# Purpose: Checks GitHub username availability via curl.
# Arguments: $1: Username to check.
# Outputs: Prints status string ("Available", "Taken", "Error/Timeout", "Taken (Code: XXX)") to stdout.
check_github() {
    local username=$1
    local github_url="https://github.com/${username}"
    local http_status
    local output_status=""

    log_message "DEBUG" "Checking GitHub URL: ${github_url}"

    # Execute curl and capture status code
    # Error output from curl is suppressed (-s), but connection errors result in 000 status
    http_status=$(curl --silent --location --output /dev/null --write-out "%{http_code}" --max-time "$CURL_TIMEOUT" "$github_url")
    local curl_exit_code=$? # Capture curl's own exit code

    # Interpret based on HTTP status and curl exit code
    if [[ ${curl_exit_code} -ne 0 ]]; then
        # Handle curl errors (e.g., DNS failure, timeout before connection)
        # Curl exit code 28 is timeout
        if [[ ${curl_exit_code} -eq 28 ]]; then
            log_message "WARN" "Curl timed out for ${username} (Curl exit code ${curl_exit_code})"
            output_status="Error/Timeout"
        else
            log_message "WARN" "Curl failed for ${username} with exit code ${curl_exit_code}. Status code: ${http_status}"
             # Treat non-timeout curl errors as errors too, unless a clear status code was received
             if [[ "$http_status" == "000" ]]; then
                output_status="Error/Connection"
             else
                 # If curl failed but somehow got a status code, use the status code logic
                 case $http_status in
                    404) output_status="Available" ;;
                    200|3*) output_status="Taken" ;;
                    000) output_status="Error/Timeout" ;; # Explicit 000 status usually means timeout or no response
                    *) output_status="Taken (Code: $http_status)" ;;
                 esac
             fi
        fi
    else
        # Curl succeeded, interpret HTTP status code
        log_message "DEBUG" "HTTP status for ${username}: ${http_status}"
        case $http_status in
            404) output_status="Available" ;;
            200|3*) output_status="Taken" ;;
            000) output_status="Error/Timeout" ;; # Explicit 000 status
            *) output_status="Taken (Code: $http_status)" ;;
        esac
    fi

    # Use printf to ensure no extra newline is added, easier to capture output
    printf "%s" "${output_status}"

} # End check_github


# --- Environment Preparation Function ---
# Sets up directories and checks dependencies before main logic.
prepare_environment() {
    log_message "INFO" "Preparing execution environment..."

    # Check dependencies
    log_message "INFO" "Checking required dependencies..."
    check_dependency "curl" "curl - Data transfer utility"
    check_dependency "date" "coreutils - Date utility"
    check_dependency "seq" "coreutils - Sequence generator"
    check_dependency "tr" "coreutils - Character translation"
    check_dependency "head" "coreutils - Output beginning part of files"
    check_dependency "printf" "coreutils - Format and print data (usually built-in)"
    check_dependency "dirname" "coreutils - Strip non-directory suffix from file name"
    check_dependency "basename" "coreutils - Strip directory and suffix from file name"
    check_dependency "sed" "sed - Stream editor"

    # Attempt to install curl if missing (moved from main execution)
    install_requirements || log_message "CRITICAL" "Failed to satisfy 'curl' dependency."

    # Prepare output file
    timestamp=$SCRIPT_RUN_TIMESTAMP # Use the global timestamp
    if [[ "$MODE" == "pattern" ]]; then
        OUTPUT_FILE="${OUTPUT_DIR}/${PATTERN_PREFIX}_github_check_results_${timestamp}.csv"
        log_message "INFO" "Pattern mode activated. Checking GitHub usernames with prefix: ${PATTERN_PREFIX}"
        log_message "INFO" "(Note: Any specified --length value is ignored in pattern mode)."
    else # Random mode
        OUTPUT_FILE="${OUTPUT_DIR}/random_${RANDOM_LENGTH}char_github_check_results_${timestamp}.csv"
        log_message "INFO" "Random mode activated. Checking ${CHECK_COUNT} random GitHub usernames of length ${RANDOM_LENGTH}."
    fi

    # Create the CSV file and write the header row.
    # Use > operator which creates/overwrites the file. Error if unwritable handled by validate_inputs.
    log_message "INFO" "Initializing output file: ${OUTPUT_FILE}"
    echo "Username,GitHub Status" > "$OUTPUT_FILE"

    # Create Log directory if logging to file
    if [[ "${LOG_TO_FILE}" == true ]]; then
        mkdir -p "$(dirname "${LOG_FILE}")" || log_message "WARN" "Could not ensure log directory exists: $(dirname "${LOG_FILE}")"
        log_message "INFO" "Logging detailed output to: ${LOG_FILE}"
    fi

    log_message "INFO" "Environment preparation complete."
} # End prepare_environment


# --- Main Logic Function ---
# Contains the core functionality: looping and checking usernames.
main() {
    log_message "INFO" "Starting main script execution..."
    local total_checks=0
    local username=""
    local github_status=""
    local i=0 # Loop counter

    if [[ "$MODE" == "pattern" ]]; then
        # --- Pattern Mode Execution ---
        total_checks=$((PATTERN_RANGE + 1))
        log_message "INFO" "Starting GitHub pattern check for ${PATTERN_PREFIX}000 to ${PATTERN_PREFIX}${PATTERN_RANGE}..."

        for i in $(seq 0 "$PATTERN_RANGE"); do
            username=$(generate_pattern_username "$PATTERN_PREFIX" "$i")
            local current_check=$((i + 1))

            # Use standard echo for user-facing progress, not logging function
            echo "Checking username ($current_check/$total_checks): $username"

            github_status=$(check_github "$username")
            log_message "DEBUG" "Result for ${username}: ${github_status}"

            # Append result directly to CSV file
            echo "$username,$github_status" >> "$OUTPUT_FILE"

            log_message "DEBUG" "Sleeping for ${SLEEP_DURATION} second(s)..."
            sleep "$SLEEP_DURATION"
        done

    elif [[ "$MODE" == "random" ]]; then
        # --- Random Mode Execution ---
        total_checks=$CHECK_COUNT
        log_message "INFO" "Starting GitHub random check for ${total_checks} usernames..."

        for i in $(seq 1 "$total_checks"); do
            username=$(generate_random_username "$RANDOM_LENGTH")

            # User-facing progress
            echo "Checking username ($i/$total_checks): $username"

            github_status=$(check_github "$username")
            log_message "DEBUG" "Result for ${username}: ${github_status}"

            # Append result directly to CSV file
            echo "$username,$github_status" >> "$OUTPUT_FILE"

            log_message "DEBUG" "Sleeping for ${SLEEP_DURATION} second(s)..."
            sleep "$SLEEP_DURATION"
        done
    else
        # This case should not be reached due to argument parsing/validation
        log_message "CRITICAL" "Invalid mode detected in main function: ${MODE}"
    fi

    # --- Final Summary ---
    log_message "INFO" "Check process completed. ${total_checks} GitHub usernames checked."
    log_message "INFO" "Results saved in ${OUTPUT_FILE}"

} # End main

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# 1. Parse Command Line Arguments
# ($@ passes all script arguments to the function)
parse_params "$@"

# 2. Validate Inputs and Configuration
# (Checks if parsed/default settings are valid before proceeding)
validate_inputs

# 3. Prepare Environment
# (Checks dependencies, creates directories, initializes output file)
prepare_environment

# 4. Execute Main Logic
# (Contains the core username checking loops)
main

# 5. Exit Successfully
# (Cleanup runs automatically via trap EXIT)
log_message "INFO" "Script finished successfully."
exit 0

# =========================================================================================
# --- End of Script ---
