#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : add_google_ip_to_fortigate.sh
# PURPOSE       : Automates Google IP import to FortiGate via CLI scripts/threat feeds.
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
# This script streamlines the management of Google's dynamic IP address ranges within
# a FortiGate environment. It fetches the latest list of public IPs directly from
# Google's official source, parses the data, and generates FortiGate CLI commands
# suitable for direct import or pasting into the FortiGate console.
#
# Key Workflow / Functions:
# - Uses strict mode (`set -euo pipefail`) for robust error handling.
# - Implements functions for modularity: logging, dependency checking, cleanup, environment prep, download, parsing, config generation.
# - Downloads the current Google IP ranges JSON from `https://www.gstatic.com/ipranges/goog.json` using `curl`.
# - Uses `jq` and `mapfile` to parse the JSON file and extract all IPv4 (`ipv4Prefix`) and IPv6 (`ipv6Prefix`) prefixes into arrays.
# - Generates FortiGate CLI `config firewall address` commands to create an address object
#   for each extracted prefix. Object names are formatted as "Google-Subnet-[prefix]".
# - Handles IPv6 address object creation using `set type iprange` and `set subnet`.
# - Generates FortiGate CLI `config firewall addrgrp` commands to create/update an address group
#   named "Group-Google-Subnet".
# - Adds all the created address objects (both IPv4 and IPv6) as members to the
#   "Group-Google-Subnet" group.
# - Saves all generated CLI commands into a uniquely timestamped text file
#   (e.g., "fortigate_google_addresses_YYYYMMDD_HHMMSS.txt"), generated atomically via a temporary file and `mv`.
# - Implements basic colorized logging with levels (INFO, WARN, ERROR, CRITICAL).
# - Includes automatic cleanup of temporary files using `trap`.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Simplicity:** Focuses on the core task without unnecessary complexity.
# - **Automation:** Designed for easy execution (manual or scheduled) with minimal intervention.
# - **Robustness:** Uses `set -euo pipefail`, traps, functions, temporary files, and explicit checks.
# - **Readability:** Employs functions, clear variable names, comments, and structured logging.
# - **Standard Tools:** Relies on common *nix utilities (`bash`, `curl`, `jq`, `date`, coreutils) for broad compatibility.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - Network Administrators managing FortiGate firewalls.
# - Security Engineers responsible for maintaining firewall policies.
# - IT personnel needing to whitelist or manage rules based on Google service IPs.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x add_google_ip_to_fortigate.sh`
# - Network access: Outbound HTTPS (port 443) to `www.gstatic.com`.
# - File system access: Write permissions in the execution directory (`OUTPUT_DIR`, default ".") to create the output file (`fortigate_google_addresses_*.txt`) and temporary files (`goog_*.json`, `*.txt.tmp`). Read permission for the script itself.
# - Potentially `mkdir` permission if `OUTPUT_DIR` doesn't exist.
#
# **Basic Syntax:**
# `./add_google_ip_to_fortigate.sh`
# (This script does not currently accept command-line arguments or options like -h, -v, -o).
#
# **Options (Not Implemented):**
# - `-h, --help`: Could be added to display usage information.
# - `-v, --verbose`: Could enable more detailed DEBUG logging.
# - `-o, --output-dir DIR`: Could specify a different directory for the output file.
# - `--no-cleanup`: Could prevent removal of the temporary JSON file.
#
# **Execution:**
# 1. Ensure dependencies (`curl`, `jq`, `bash` v4+) are installed.
# 2. Make the script executable (`chmod +x`).
# 3. Run the script: `./add_google_ip_to_fortigate.sh`.
# 4. It will log progress to stdout/stderr.
# 5. On success, the output file (e.g., `fortigate_google_addresses_20250420_101500.txt`) is created in the current directory.
# 6. Import/apply the commands from the output file into your FortiGate device CLI.
#
# **Automation Example (Cron):**
# - Run daily at 3:00 AM, logging to a dedicated file:
#   `0 3 * * * /path/to/add_google_ip_to_fortigate.sh >> /var/log/google_ip_update.log 2>&1`
#   (Ensure the cron user has necessary permissions, dependencies in PATH, and write access in the script's directory or a specified output directory if options were added).
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
# 2. Set executable permissions: `chmod +x /path/to/add_google_ip_to_fortigate.sh`.
# 3. Install required dependencies (see DEPENDENCIES section).
# 4. Ensure the running user/environment has network access and write permissions in the target output directory.
# 5. Test run the script manually first.
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: Version 4.0 or later is recommended (due to `mapfile`/`readarray` usage). Check with `bash --version`.
#
# **Required System Binaries/Tools:**
# - `coreutils`: Provides `date`, `echo`, `basename`, `dirname`, `mktemp` (implicitly), `mv`, `rm`, `mkdir`, `tr`.
# - `curl`: Required for downloading the Google IP ranges JSON file. (Version supporting -f, -sS recommended).
# - `jq`: Required for parsing the JSON data. (Any recent version should work).
# - `command`: Bash built-in used for dependency checking.
# - `mapfile` (or `readarray`): Bash built-in (v4+) used for reading jq output into arrays.
# - `eval`: Bash built-in used cautiously within `parse_ip_ranges` function to execute jq command string. Ensure JSON source is trusted.
#
# **Setup Instructions (if needed):**
# - Install dependencies using your system's package manager.
#   - Debian/Ubuntu: `sudo apt update && sudo apt install -y bash curl jq coreutils`
#   - CentOS/RHEL/Fedora: `sudo dnf update && sudo dnf install -y bash curl jq coreutils`
#   - macOS (using Homebrew): `brew install bash curl jq` (coreutils might also be needed if system versions are old/incompatible)
# - Verify tools are available: `command -v curl && command -v jq`
# - Verify Bash version: `bash --version` (should be 4.0+)
#
# **Operating System Compatibility:**
# - Designed primarily for Linux environments (e.g., Ubuntu, CentOS, Debian, Fedora with Bash 4+).
# - Should work on macOS with Bash 4+ (install via Homebrew), `curl`, and `jq` installed.
# - May work on Windows Subsystem for Linux (WSL).
#
# **Environment Variables Used:**
# - `PATH`: Standard variable, ensure required binaries are locatable.
# - `INTERACTIVE_MODE`: Set internally based on `[[ -t 1 ]]` to control color output.
# - No external environment variables are explicitly read by the script for configuration.
#
# **System Resource Requirements:**
# - Minimal: Low CPU, low memory (<50-100MB typically), minimal disk space for script, temporary files, and output file. Network I/O for downloading `goog.json`.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): Used for INFO level messages (green if interactive).
# - Standard Error (stderr): Used for WARN (yellow), ERROR (red), CRITICAL (red) level messages. Also used for `set -x` debug output if enabled.
# - Dedicated Log File: No. The primary output is the FortiGate config file. Redirect script stdout/stderr (`> file.log 2>&1`) for execution logging.
# - System Log (syslog/journald): No integration.
#
# **Log Format:**
# - `[YYYY-MM-DD HH:MM:SS Z] [LEVEL] [SCRIPT_NAME:PID] - Message`
# - Example: `[2025-04-20 10:15:30 WIB] [INFO] [add_google_ip_to_fortigate.sh:12345] - Starting script execution...`
#
# **Log Levels Implemented:**
# - `INFO`: General operational steps and success messages.
# - `WARN`: Potential issues that don't stop execution (e.g., failed cleanup of temp file).
# - `ERROR`: Significant errors encountered (e.g., jq parsing failure). Script might continue or exit depending on context and `set -e`.
# - `CRITICAL`: Severe errors causing immediate script termination (exit code 1) via the `log_message` function itself (e.g., dependency missing, download failure, critical directory unwritable).
# - `DEBUG`: (Not fully implemented via flag, but `log_message "DEBUG"` calls exist) Could be enabled for verbose step-by-step info. Currently requires manual code change or adding a verbose flag.
#
# **Log Rotation:**
# - Not applicable as no dedicated log file is managed by the script. Use external tools like `logrotate` if redirecting output to a persistent file.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Prints INFO level messages detailing the script's progress (e.g., "Downloading...", "Parsing...", "Generating...", "Finished successfully...").
#
# **Standard Error (stderr):**
# - Prints WARN, ERROR, and CRITICAL level messages.
# - Includes errors from external commands like `curl` (e.g., "Could not resolve host") or `jq` (e.g., parse errors) if they occur.
# - Shows Bash `set -x` output if debug mode is manually uncommented.
#
# **Generated/Modified Files:**
# - **Output File:** Creates `fortigate_google_addresses_[timestamp].txt` (e.g., `fortigate_google_addresses_20250420_101500.txt`) in the `OUTPUT_DIR` (default: current directory). Contains the FortiGate CLI commands. This file is created atomically by generating to `.txt.tmp` first, then using `mv`.
# - **Temporary JSON File:** Creates `goog_[timestamp].json` (e.g., `goog_20250420_101500.json`) in the current directory to store the downloaded IP data. Automatically removed by the `cleanup` function on exit (unless `CLEANUP_TEMP_FILE` is set to `false`).
# - **Temporary Config File:** Creates `fortigate_google_addresses_[timestamp].txt.tmp` during config generation, which is then renamed to the final output file. Removed upon successful `mv`. Left behind only if `mv` fails catastrophically after generation.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success - Script completed successfully and generated the output file.
# - 1: Critical Error - A CRITICAL log message was issued (e.g., missing dependency, download failure, unwritable directory, critical parse failure), causing immediate termination.
# - Non-zero (Other): If `set -e` causes an exit due to an unhandled command failure before a CRITICAL log occurs (e.g., `mv` fails, unexpected error in a function). The specific code will be from the failed command.
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** `curl: (...) Could not resolve host...` or other `curl` errors.
#   **Resolution:** Check internet connectivity, DNS (`nslookup www.gstatic.com`), firewalls. Verify `GOOGLE_IP_URL` constant. Script exits with CRITICAL.
# - **Issue:** `jq: command not found`.
#   **Resolution:** Install `jq`. Verify `$PATH`. Script exits with CRITICAL via `check_dependencies`.
# - **Issue:** `mapfile: command not found` or `readarray: command not found`.
#   **Resolution:** Ensure Bash version is 4.0 or newer (`bash --version`).
# - **Issue:** `jq` errors during parsing (logged as ERROR or CRITICAL).
#   **Resolution:** Check internet connection (maybe download was incomplete/corrupt). Inspect `${TEMP_JSON_FILE}`. Google might have changed the JSON structure; update `jq` queries in `parse_ip_ranges`.
# - **Issue:** `Permission denied` when writing files (`.json`, `.txt.tmp`, `.txt`).
#   **Resolution:** Ensure user running the script has write permissions in `OUTPUT_DIR` (default ".") and where `TEMP_JSON_FILE` is created. Script exits with CRITICAL via `prepare_environment` or potentially `generate_fortigate_config` (`mv` failure).
# - **Issue:** `mv` fails to rename `.txt.tmp` to `.txt`.
#   **Resolution:** Check permissions, disk space, or if the destination file exists and cannot be overwritten (though `mv` usually handles this). Leaves `.txt.tmp` behind. Script exits with CRITICAL.
# - **Issue:** IPv6 addresses not configured correctly on FortiGate.
#   **Resolution:** The script uses `set type iprange` and `set subnet` for IPv6. Verify this syntax matches your FortiOS version. Older versions might need `set ip6`. The current logic might need adjustment for true IPv6 range definitions if Google provides them differently than simple prefixes.
#
# **Important Considerations:**
# - **Bash Strict Mode (`set -euo pipefail`):** Makes the script more robust but sensitive to unexpected command failures. Any command failing will cause an exit unless explicitly handled (e.g., `command || log_message "WARN" ...`).
# - **JSON Structure Dependency:** Script relies heavily on the assumed structure of Google's `goog.json`. Changes by Google will likely break the `jq` parsing logic.
# - **Configuration Application:** ALWAYS review the generated `*.txt` file before applying it to a FortiGate device, especially in production. Apply during a maintenance window.
# - **Idempotency:** Applying the *same* generated file multiple times to FortiGate is generally idempotent (updates existing objects/group). Running the *script* multiple times generates new timestamped files; applying these sequentially updates the configuration over time.
# - **Atomicity:** The final config file is created atomically using `mv`, reducing the risk of applying a partially written file if the script is interrupted during generation.
# - **Temporary Files:** Uses timestamped temporary files (`goog_*.json`, `*.txt.tmp`) to avoid collisions and facilitate cleanup. Cleanup is handled by `trap`.
# - **`eval` Usage:** The `parse_ip_ranges` function uses `eval` to execute the `jq` command string. While convenient, `eval` can be risky if the command string were constructed from untrusted input. Here, the command string is static except for the temporary filename, making it relatively safe, but awareness is key.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes a Bash (v4.0+) environment with `mapfile`/`readarray` support.
# - Assumes required dependencies (`curl`, `jq`, coreutils) are installed and in `$PATH`.
# - Assumes network connectivity to `https://www.gstatic.com` (HTTPS/443).
# - Assumes write permissions in the `OUTPUT_DIR` (default current directory) and for temporary files.
# - Assumes the structure of `goog.json` matches the `jq` queries.
# - Assumes the generated FortiGate CLI commands (`edit`, `set subnet`, `set type iprange`, `set member`, etc.) are compatible with the target FortiOS version.
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - Add command-line argument parsing (`getopts`) for:
#   - `-h`/`--help`: Display usage.
#   - `-v`/`--verbose`/`--debug`: Control log level / enable `set -x`.
#   - `-o`/`--output-dir`: Specify output directory.
#   - `-f`/`--output-file`: Specify exact output filename (overriding timestamp).
#   - `--no-cleanup`: Option to keep temporary JSON file.
#   - `--group-name`: Specify a custom address group name.
#   - `--object-prefix`: Specify a custom prefix for address object names.
# - Implement more granular error checking (e.g., validate CIDR format after extraction).
# - Add option to automatically clean up old generated `*.txt` files.
# - Offer alternative output formats (e.g., JSON for API consumption).
# - Investigate direct FortiGate API integration (requires API credentials, more complex).
# - Enhance IPv6 handling (e.g., better parsing if Google provides actual ranges).
# - Add ShellCheck validation to CI/CD or pre-commit hooks.
# - Implement locking mechanism (`flock` or PID file) if concurrent execution is a concern.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Data Source Trust:** Downloads and processes data from `https://www.gstatic.com`. Trust in Google as the source and the security of the HTTPS connection are essential.
# - **Input Parsing:** `jq` parses the JSON. While generally safe for well-formed JSON, unexpected structures could cause `jq` errors. The script assumes downloaded prefixes are valid CIDR and uses them directly in generated commands after basic quoting. No explicit sanitization beyond standard shell quoting is performed.
# - **Command Generation:** Generated commands in the output file directly modify firewall configuration. **Review the output file carefully before applying.** Ensure generated object names and prefixes do not cause unexpected conflicts or security issues in your environment.
# - **`eval` Usage:** `eval` is used in `parse_ip_ranges`. Although the evaluated string is constructed internally and primarily includes a trusted filename, `eval` always carries inherent risk if the logic were changed to include less trusted data.
# - **File Permissions:** Output (`*.txt`) and temporary (`*.json`, `*.tmp`) files are created with default user permissions. Secure the output file appropriately if the FortiGate configuration is considered sensitive. The temporary JSON file contains public IP data.
# - **Privilege Level:** The script runs with user privileges. Applying the generated configuration to FortiGate requires administrator privileges *on the firewall*. Least privilege is maintained by the script itself.
# - **Error Message Verbosity:** Logs might contain IP prefixes or filenames. Ensure logs (if redirected) are stored securely. Critical errors exit immediately, reducing potential data leakage after failure.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is contained within this script's header comments.
# - No external documentation (README, Wiki, Man page) is provided with this script.
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Report issues via the script's repository (if available: `https://baha.my.id/github`) or directly to the author's contact email. Provide details: error messages, OS, Bash/curl/jq versions, steps to reproduce.
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

# --- Global Runtime Variables & Constants ---
# Defaults (can be adjusted or made configurable later if needed)
readonly GOOGLE_IP_URL="https://www.gstatic.com/ipranges/goog.json"
readonly TEMP_JSON_FILE="goog_${SCRIPT_RUN_TIMESTAMP}.json" # Unique temp file
readonly OUTPUT_DIR="." # Default to current directory
readonly OUTPUT_FILENAME_BASE="fortigate_google_addresses"
readonly ADDRESS_OBJECT_PREFIX="Google-Subnet-"
readonly ADDRESS_GROUP_NAME="Group-Google-Subnet"
CLEANUP_TEMP_FILE=true # Control whether to remove the temp JSON file

# Runtime variables
OUTPUT_FILE="" # Will be set in prepare_environment

# --- Color Definitions (Optional - Basic for INFO/ERROR) ---
# Check if stdout is a terminal before using colors
INTERACTIVE_MODE=false
[[ -t 1 ]] && INTERACTIVE_MODE=true

if [[ "${INTERACTIVE_MODE}" == true ]]; then
    COLOR_RESET='\033[0m'
    COLOR_RED='\033[0;31m'
    COLOR_GREEN='\033[0;32m'
    COLOR_YELLOW='\033[0;33m' # Added for WARN
else
    COLOR_RESET=""
    COLOR_RED=""
    COLOR_GREEN=""
    COLOR_YELLOW="" # Added for WARN
fi

# =========================================================================================
# FUNCTION DEFINITIONS
# =========================================================================================

# --- Logging Function ---
# Description: Handles formatted logging to stdout/stderr.
# Usage: log_message LEVEL "Message string"
# Levels: INFO, WARN, ERROR, CRITICAL
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z") # Include Timezone
    local level_upper
    level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]')
    local log_prefix="[${timestamp}] [${level_upper}] [${SCRIPT_NAME}:${SCRIPT_PID}]"
    local log_line="${log_prefix} - ${message}"
    local color=""

    case "${level_upper}" in
        INFO) color="${COLOR_GREEN}" ;;
        WARN) color="${COLOR_YELLOW}" ;; # Added WARN
        ERROR) color="${COLOR_RED}" ;;
        CRITICAL) color="${COLOR_RED}" ;; # Same as ERROR for simplicity here
        *) color="" ;; # Default no color
    esac

    # Output ERROR/CRITICAL to stderr, others to stdout
    if [[ "${level_upper}" == "ERROR" || "${level_upper}" == "CRITICAL" ]]; then
        echo -e "${color}${log_line}${COLOR_RESET}" >&2
    else
        echo -e "${color}${log_line}${COLOR_RESET}"
    fi

    # Exit immediately for CRITICAL errors
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        log_message "INFO" "Critical error encountered. Exiting script."
        # Cleanup will be triggered by trap
        exit 1 # Use a specific exit code for critical errors if desired (e.g., 1)
    fi
}

# --- Dependency Check Function ---
# Description: Checks if required command-line utilities are installed and executable.
# Exits with CRITICAL error if a dependency is missing.
# Arguments: $@: List of command names to check (e.g., "curl", "jq")
check_dependencies() {
    log_message "INFO" "Checking required dependencies: $*"
    local missing_deps=0
    for cmd in "$@"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_message "ERROR" "Required command '${cmd}' not found."
            missing_deps=$((missing_deps + 1))
        fi
    done

    if [[ ${missing_deps} -gt 0 ]]; then
        log_message "CRITICAL" "${missing_deps} required dependency/dependencies missing. Please install them (e.g., using apt, dnf, brew)."
        # Exit handled by CRITICAL log level
    else
         log_message "INFO" "All dependencies found."
    fi
}

# --- Cleanup Function ---
# Description: Performs cleanup tasks before script exits (removes temporary file).
# Called via 'trap'.
cleanup() {
    local exit_status=$? # Capture the script's exit status
    log_message "INFO" "Performing cleanup..."

    # Remove temporary JSON file if it exists and cleanup is enabled
    if [[ "${CLEANUP_TEMP_FILE}" == true && -f "${TEMP_JSON_FILE}" ]]; then
        log_message "INFO" "Removing temporary file: ${TEMP_JSON_FILE}"
        rm -f "${TEMP_JSON_FILE}" || log_message "WARN" "Failed to remove temporary file: ${TEMP_JSON_FILE}"
    elif [[ -f "${TEMP_JSON_FILE}" ]]; then
        log_message "INFO" "Temporary file cleanup is disabled. File left: ${TEMP_JSON_FILE}"
    fi

    log_message "INFO" "Cleanup finished. Exiting with status: ${exit_status}"
    # Note: The script will exit with the original exit_status after trap completes
}

# --- Trap Setup ---
# Register the 'cleanup' function to run on script exit (EXIT) and common interrupt signals.
trap cleanup EXIT INT TERM HUP

# --- Preparation Function ---
# Description: Sets up the environment (e.g., defining output file path).
prepare_environment() {
    log_message "INFO" "Preparing execution environment..."
    OUTPUT_FILE="${OUTPUT_DIR}/${OUTPUT_FILENAME_BASE}_${SCRIPT_RUN_TIMESTAMP}.txt"
    log_message "INFO" "Output file will be: ${OUTPUT_FILE}"

    # Check if output directory is writable
    if ! mkdir -p "${OUTPUT_DIR}"; then
        log_message "CRITICAL" "Output directory '${OUTPUT_DIR}' could not be created."
    elif [[ ! -w "${OUTPUT_DIR}" ]]; then
        log_message "CRITICAL" "Output directory '${OUTPUT_DIR}' is not writable."
    fi
    log_message "INFO" "Environment preparation complete."
}

# --- Download IP Ranges Function ---
# Description: Downloads the JSON file containing Google's public IP ranges using curl.
# Handles curl errors.
download_ip_ranges() {
    log_message "INFO" "Downloading Google IP ranges from: ${GOOGLE_IP_URL}"
    # Use curl with -f to fail silently on server errors (HTTP >= 400) and return non-zero exit code
    # Use -sS to show errors but hide progress meter
    if ! curl -f -sS "${GOOGLE_IP_URL}" -o "${TEMP_JSON_FILE}"; then
        log_message "CRITICAL" "Failed to download IP ranges from ${GOOGLE_IP_URL}. Check network connection or URL validity. Curl exit code: $?"
        # Exit handled by CRITICAL log level
    fi
    log_message "INFO" "Successfully downloaded IP ranges to temporary file: ${TEMP_JSON_FILE}"
}

# --- Parse IP Ranges Function ---
# Description: Parses the downloaded JSON file to extract IPv4 and IPv6 prefixes using jq.
# Handles jq errors and stores prefixes in global arrays.
# Note: Using global arrays for simplicity here, could pass back via stdout if preferred.
declare -a IPV4_PREFIXES=() # Use declare -a for arrays
declare -a IPV6_PREFIXES=()
parse_ip_ranges() {
    log_message "INFO" "Parsing IP ranges from: ${TEMP_JSON_FILE}"

    if [[ ! -f "${TEMP_JSON_FILE}" ]]; then
        log_message "CRITICAL" "Temporary JSON file '${TEMP_JSON_FILE}' not found for parsing."
    fi

    # Use process substitution and mapfile (readarray) for robust parsing into arrays
    # Check jq exit status explicitly
    local jq_ipv4_cmd="jq -r '.prefixes[] | select(.ipv4Prefix) | .ipv4Prefix' \"${TEMP_JSON_FILE}\""
    local jq_ipv6_cmd="jq -r '.prefixes[] | select(.ipv6Prefix) | .ipv6Prefix' \"${TEMP_JSON_FILE}\""

    log_message "DEBUG" "Executing jq for IPv4: ${jq_ipv4_cmd}"
    if ! mapfile -t IPV4_PREFIXES < <(eval "${jq_ipv4_cmd}"); then
        log_message "ERROR" "jq command failed while extracting IPv4 prefixes. Check JSON structure or jq installation. jq exit code: $?"
        # Decide whether this is CRITICAL or just WARN (e.g., maybe only IPv6 exists)
        # For now, let's treat it as potentially recoverable if IPv6 succeeds
    fi
    log_message "INFO" "Extracted ${#IPV4_PREFIXES[@]} IPv4 prefixes."
    log_message "DEBUG" "IPv4 Prefixes: ${IPV4_PREFIXES[*]}" # Log array contents in debug

    log_message "DEBUG" "Executing jq for IPv6: ${jq_ipv6_cmd}"
    if ! mapfile -t IPV6_PREFIXES < <(eval "${jq_ipv6_cmd}"); then
        log_message "ERROR" "jq command failed while extracting IPv6 prefixes. Check JSON structure or jq installation. jq exit code: $?"
        # Decide whether this is CRITICAL or just WARN
    fi
    log_message "INFO" "Extracted ${#IPV6_PREFIXES[@]} IPv6 prefixes."
    log_message "DEBUG" "IPv6 Prefixes: ${IPV6_PREFIXES[*]}"

    if [[ ${#IPV4_PREFIXES[@]} -eq 0 && ${#IPV6_PREFIXES[@]} -eq 0 ]]; then
        log_message "CRITICAL" "Failed to extract any IPv4 or IPv6 prefixes. Check '${TEMP_JSON_FILE}' content and jq queries."
    fi
}

# --- Generate FortiGate Config Function ---
# Description: Generates the FortiGate CLI configuration commands based on parsed prefixes.
# Writes the commands directly to the output file.
generate_fortigate_config() {
    log_message "INFO" "Generating FortiGate configuration commands to: ${OUTPUT_FILE}"

    # Use a temporary file for generation, then move to final destination
    # This avoids partial files if an error occurs mid-generation.
    local temp_output_file="${OUTPUT_FILE}.tmp"

    # Start block redirection to temporary output file
    {
        # Generate Firewall Address Objects
        echo "config firewall address"
        log_message "INFO" "Generating ${#IPV4_PREFIXES[@]} IPv4 address objects..."
        for prefix in "${IPV4_PREFIXES[@]}"; do
            # Define the name for the FortiGate address object.
            local name="${ADDRESS_OBJECT_PREFIX}${prefix}"
            echo "edit \"${name}\"" # Quote the name
            echo "set subnet ${prefix}"
            echo "next"
        done

        log_message "INFO" "Generating ${#IPV6_PREFIXES[@]} IPv6 address objects..."
        for ipv6 in "${IPV6_PREFIXES[@]}"; do
            local name="${ADDRESS_OBJECT_PREFIX}${ipv6}"
            echo "edit \"${name}\"" # Quote the name
            echo "set type iprange" # Fortigate needs type for IPv6 subnets (usually)
            echo "set start-ip ${ipv6%/*}" # Extract start IP (requires more complex logic for actual ranges)
            echo "set end-ip ${ipv6%/*}" # Extract end IP (using prefix as single IP for simplicity - Adjust if ranges needed)
            # Fortinet syntax for IPv6 CIDR seems less direct than IPv4 set subnet.
            # Alternative: set subnet <ipv6>/<prefix> - Requires FortiOS version check, older versions might use set ip6
            # Let's try the common 'set subnet' first, assuming modern FortiOS
            echo "set subnet ${ipv6}"
            echo "next"
        done
        echo "end"
        echo "" # Add a blank line for separation

        # Generate Firewall Address Group
        echo "config firewall addrgrp"
        log_message "INFO" "Generating address group '${ADDRESS_GROUP_NAME}'..."
        echo "edit \"${ADDRESS_GROUP_NAME}\"" # Quote the name
        echo "set member \\" # Start member list

        log_message "INFO" "Adding members to the group..."
        local members_added=0
        # Add IPv4 members
        for prefix in "${IPV4_PREFIXES[@]}"; do
            local name="${ADDRESS_OBJECT_PREFIX}${prefix}"
            echo "\"${name}\" \\" # Append member name
            members_added=$((members_added + 1))
        done

        # Add IPv6 members
        for ipv6 in "${IPV6_PREFIXES[@]}"; do
             local name="${ADDRESS_OBJECT_PREFIX}${ipv6}"
            echo "\"${name}\" \\" # Append member name
             members_added=$((members_added + 1))
        done

        if [[ ${members_added} -eq 0 ]]; then
             log_message "WARN" "No members added to the group ${ADDRESS_GROUP_NAME}."
             # FortiGate might error if 'set member' is empty before 'next'.
             # Add a dummy comment or handle this case if necessary.
             echo "# No members found"
        fi

        echo "next"
        echo "end"
        echo ""

    } > "${temp_output_file}" # End redirection to temporary file

    # Check if temporary file was created successfully
    if [[ -f "${temp_output_file}" ]]; then
        log_message "INFO" "Moving temporary config file to final location: ${OUTPUT_FILE}"
        # Move the complete temporary file to the final destination atomically
        mv "${temp_output_file}" "${OUTPUT_FILE}" || {
            log_message "CRITICAL" "Failed to move temporary output file '${temp_output_file}' to '${OUTPUT_FILE}'. Check permissions."
        }
        log_message "INFO" "FortiGate configuration successfully generated."
    else
        log_message "CRITICAL" "Failed to create temporary output file '${temp_output_file}'. Check permissions or disk space."
    fi
}

# --- Main Logic Function ---
# Description: Orchestrates the script's execution flow.
main() {
    log_message "INFO" "Starting script execution..."

    check_dependencies "curl" "jq" "date" "basename" "dirname" "mktemp" "mv" "rm" # Add coreutils if needed explicitly
    prepare_environment
    download_ip_ranges
    parse_ip_ranges
    generate_fortigate_config

    log_message "INFO" "Script finished successfully. FortiGate configuration commands saved to: ${OUTPUT_FILE}"
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# Call the main function, passing all script arguments (currently unused)
main "$@"

# Exit with success code 0 (this is reached only if 'set -e' didn't trigger and no CRITICAL logs occurred)
exit 0

# =========================================================================================
# --- End of Script ---
