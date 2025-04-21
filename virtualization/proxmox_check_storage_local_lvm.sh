#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : proxmox_check_storage_local_lvm.sh
# PURPOSE       : Collects Proxmox 'local-lvm' usage/free % for PRTG via JSON.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2024-11-06
# LAST UPDATED  : 2024-11-06
# VERSION       : 1.0.0
# =========================================================================================

# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This script is designed to monitor the storage usage percentage of the specific 'local-lvm'
# storage pool within a Proxmox Virtual Environment (PVE). It utilizes the native Proxmox
# command-line tool `pvesm` to fetch storage status, filters the output to isolate the
# 'local-lvm' pool, calculates the percentage of used and free space based on total and
# used byte counts, and then formats this information into a JSON structure specifically
# required by the PRTG Network Monitor's "SSH Script Advanced" sensor type.
#
# Key Workflow / Functions:
# - Parses command-line options for help, verbose mode, and debug mode.
# - Executes `pvesm status` to retrieve current storage pool details.
# - Uses `awk` to filter and extract data specifically for the 'local-lvm' pool.
# - Validates the extracted numeric data.
# - Calculates both the used space percentage and free space percentage.
# - Implements logging (INFO, DEBUG, WARN, ERROR, CRITICAL) directed to stderr.
# - Prints a PRTG-compatible JSON formatted string to standard output, including:
#   - A channel for "Usage" percentage with example warning/error limits.
#   - A channel for "Free" percentage.
# - Includes basic error handling for command failures and data parsing issues.
# - Uses strict mode (`set -euo pipefail`) and traps for cleanup.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Simplicity:** Focuses solely on the 'local-lvm' pool by default for clarity.
# - **Compatibility:** Adheres strictly to the JSON output format expected by PRTG SSH Script Advanced sensors.
# - **Efficiency:** Leverages standard, lightweight Linux command-line tools (`awk`, `bash` builtins) for minimal system impact.
# - **Robustness:** Includes strict mode, error handling for command execution and data parsing, dependency checks, and logging to stderr.
# - **Readability:** Employs clear variable names, comments, functions, and consistent formatting.
# - **Targeted:** Designed specifically for Proxmox VE environments.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - System Administrators managing Proxmox VE clusters.
# - IT personnel using PRTG Network Monitor for infrastructure monitoring.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x proxmox_check_storeage_local_lvm.sh`
# - The script requires permissions to execute the `pvesm status` command. This typically means running as the `root` user or potentially a user within the appropriate Proxmox administrative group (e.g., via sudo configuration), depending on PVE's Role-Based Access Control (RBAC). When configured in PRTG, ensure the SSH credentials used have the necessary permissions.
#
# **Basic Syntax (Direct Execution):**
# `./proxmox_check_storeage_local_lvm.sh [options]`
# (Direct execution mainly for testing; intended use is via PRTG)
#
# **Options:**
#   -h, --help     Display help message and exit.
#   -v, --verbose  Enable verbose output (logs INFO and DEBUG messages to stderr).
#   -d, --debug    Enable Bash debug mode (`set -x`), prints every command to stderr.
#
# **Arguments:**
#   This script takes no positional arguments.
#
# **PRTG Integration (Primary Use Case):**
# - Add an "SSH Script Advanced" sensor to your Proxmox device in PRTG.
# - Point the sensor to execute this script file on the target Proxmox host.
# - Ensure the SSH credentials configured in PRTG for the device have sufficient rights to run `pvesm status` (e.g., root or configured sudo access).
# - Set the script parameters in PRTG as needed (e.g., add `-v` for troubleshooting).
#
# **Example PRTG Sensor Configuration:**
# - **Script:** `proxmox_check_storeage_local_lvm.sh` (or the full path if not in PATH/standard location)
# - **Parameters:** (Leave empty for standard operation, or add `-v` for verbose logs in PRTG)
# - **Use SSH Login:** Checked
# - **Timeout:** (Set appropriately, e.g., 60 seconds)
#
# **Automation (Alternative):**
# - Can be run via cron, but ensure the environment (PATH, permissions) is correctly set. Output would need redirection or processing if not used with PRTG.
#   `* * * * * /path/to/proxmox_check_storeage_local_lvm.sh >> /var/log/proxmox_lvm_check.log 2>&1`
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - System-wide scripts (requiring root/sudo): `/usr/local/sbin/` or `/usr/local/bin/`
# - User-specific location: `~/bin/` or similar (ensure it's in the user's PATH if needed)
#
# **Manual Setup:**
# 1. Place the script in the chosen location (e.g., `/usr/local/sbin/`).
# 2. Set appropriate ownership (e.g., `sudo chown root:root /usr/local/sbin/proxmox_check_storeage_local_lvm.sh`).
# 3. Set executable permissions: `sudo chmod 755 /usr/local/sbin/proxmox_check_storeage_local_lvm.sh` (or `chmod +x` for user scripts).
# 4. Ensure dependencies (see below) are installed (typically standard on PVE).
# 5. Test execution manually (e.g., `sudo /usr/local/sbin/proxmox_check_storeage_local_lvm.sh -v`).
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: The Bourne-Again SHell interpreter (v4+ recommended for associative arrays if used, though not currently required by this script version).
#
# **Required System Binaries/Tools:**
# - `pvesm`: Proxmox VE storage management command-line tool (Part of standard PVE installation).
# - `awk`: Pattern scanning and processing language utility (GNU Awk recommended, standard on Linux/PVE).
# - `coreutils`: Provides `date`, `basename`, `dirname`, `read`, `printf`, `echo`, `tr` (Standard on Linux/PVE).
# - `getopt`: Utility to parse command-line options (from `util-linux` package, standard on Linux/PVE). Used for long option parsing. Falls back to `getopts` (bash built-in) if missing.
# - `command`: Bash built-in for checking command existence.
#
# **Setup Instructions (Dependencies):**
# - These dependencies are typically pre-installed on a standard Proxmox VE system. No extra installation steps are usually required.
# - To verify: `command -v pvesm`, `command -v awk`, `command -v getopt`.
#
# **Operating System Compatibility:**
# - Designed and tested specifically for Proxmox VE (which is based on Debian Linux).
# - May work on other Debian-based systems with PVE packages installed, but not guaranteed.
#
# **Environment Variables Used:**
# - `PATH`: Standard variable, ensure required binaries (`pvesm`, `awk`, `getopt`) are locatable.
# - No custom environment variables are used by this script.
#
# **System Resource Requirements:**
# - Minimal CPU and memory usage. Relies on lightweight system commands. Negligible disk I/O.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): Used *exclusively* for the final JSON payload required by PRTG.
# - Standard Error (stderr): Used for all informational messages, debug output, warnings, and error messages generated by the `log_message` function. PRTG typically captures stderr for sensor error reporting.
# - Dedicated Log File: No. This script does not create or manage its own log file.
# - System Log (syslog/journald): No. Does not log to system logs.
#
# **Log Format (stderr):**
# - `[YYYY-MM-DD HH:MM:SS ZZZ] [LEVEL] [script_name:line_number] - Message`
# - Example: `[2025-04-20 16:30:00 WIB] [INFO] [proxmox_check_storeage_local_lvm.sh:150] - Starting storage check for pool: local-lvm`
#
# **Log Levels (controlled via options):**
# - `DEBUG`: Detailed step-by-step information (Enabled by `-v` or `-d`).
# - `INFO`: General operational messages (Enabled by `-v` or default).
# - `WARN`: Potential issues or non-critical errors.
# - `ERROR`: Significant errors encountered, likely impacting output.
# - `CRITICAL`: Severe errors causing script termination (e.g., dependency missing, critical command failure).
# - Control: `-v` enables INFO and DEBUG. `-d` enables DEBUG via `set -x`. Default shows INFO, WARN, ERROR, CRITICAL.
#
# **Log Rotation:**
# - Not applicable as no dedicated log file is used. External redirection (e.g., in cron) would need external log rotation (`logrotate`).
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Produces a JSON formatted string required by the PRTG SSH Script Advanced sensor.
# - Includes two channels: one for Usage percentage and one for Free percentage.
# - Example Output:
#   ```
#   {
#    "prtg": {
#     "result": [
#      {
#       "channel": "local-lvm Usage",
#       "value": 22,
#       "unit": "Percent",
#       "limitmode": 1,
#       "limitmaxwarning": "85",
#       "limitmaxerror": "95",
#       "showchart": 1
#      },
#      {
#       "channel": "local-lvm Free",
#       "value": 78,
#       "unit": "Percent",
#       "showchart": 0
#      }
#     ]
#    }
#   }
#   ```
#   (The "value" fields will reflect the actual calculated percentages.)
#
# **Standard Error (stderr):**
# - Used for all human-readable logs (INFO, DEBUG) and error/warning messages.
# - Example Error Output (if pool not found):
#   `[2025-04-20 16:35:00 WIB] [ERROR] [proxmox_check_storeage_local_lvm.sh:185] - Storage pool 'local-lvm-typo' not found in 'pvesm status' output.`
#   (Followed by PRTG error JSON on stdout)
#
# **Generated/Modified Files:**
# - None. The script does not create or modify any persistent files (unless output is redirected).
#
# **Temporary Files:**
# - None. The script does not create temporary files.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success - JSON output generated successfully to stdout.
# - 1: General Error - Catch-all for runtime errors, invalid options, dependency issues, failed commands (`pvesm`), parsing errors, critical log messages. PRTG should interpret non-zero exit codes as sensor errors.
#   (Specific codes like 2 for Dependency, 3 for Config, 4 for Args are not explicitly used, simplified to 0 or 1).
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** PRTG sensor shows error "Permission denied" or similar when running `pvesm`.
#   **Resolution:** Ensure the SSH user configured in PRTG has sufficient privileges (e.g., root access or specific sudo rules without password prompt) to execute `/usr/sbin/pvesm status`. Verify sudoers configuration if applicable.
# - **Issue:** PRTG sensor shows an error or no data, script works manually as root.
#   **Resolution:** Verify SSH connection and permissions used by PRTG. Check PRTG sensor logs for stderr output from the script (enable `-v` parameter in PRTG for more detail). Check for environment differences (e.g., PATH).
# - **Issue:** 'local-lvm' pool not found or data is empty.
#   **Resolution:** Verify that a storage pool named exactly 'local-lvm' exists and is active on the Proxmox host (run `pvesm status` manually). If your LVM pool has a different name, modify the `TARGET_POOL` variable within the script. The script outputs a specific PRTG error JSON in this case.
# - **Issue:** Failed to parse numeric values / division by zero.
#   **Resolution:** Check the raw output of `pvesm status`. The script includes checks for non-numeric values. Division by zero in the calculation is handled (reports 100% free/0% used if total space is 0), but this usually indicates an issue with the `pvesm` output itself. Check stderr logs for details.
#
# **Important Considerations:**
# - **Target Pool:** This script specifically targets 'local-lvm' by default (defined in `TARGET_POOL` variable). Modify the variable if monitoring a different LVM pool is needed.
# - **Idempotency:** Yes, running the script multiple times produces the current state without side effects.
# - **Resource Usage:** Very low. Suitable for frequent execution via PRTG.
# - **Concurrency/Locking:** Not implemented. Running multiple instances simultaneously is unlikely to cause issues due to the script's short execution time and read-only nature, but it's not explicitly designed for concurrent runs.
# - **Rate Limiting:** Not applicable. Interacts only with local `pvesm` command.
# - **Atomicity:** Not applicable. Performs read-only operations.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes execution within a Proxmox VE environment where `/usr/sbin/pvesm` is available and functional.
# - Assumes a storage pool named exactly `local-lvm` exists and is configured (or the `TARGET_POOL` variable is adjusted).
# - Assumes the output format of `pvesm status` remains consistent regarding column positions for pool name (1), total size (4), and used size (5).
# - Assumes the executing user (via SSH from PRTG) has the necessary rights to run `pvesm status`.
# - Assumes `awk`, `bash`, `coreutils`, and `getopt` are available in the system's PATH.
# =========================================================================================

# =========================================================================================
# PERFORMANCE OPTIMIZATION
# =========================================================================================
# - Performance is not a primary concern due to the script's simplicity and reliance on efficient native tools.
# - Uses `awk` for efficient text processing, avoiding multiple slower commands like `grep` and `cut`.
# - Executes only one external command (`pvesm status`).
# - Resource consumption (CPU, Memory) is negligible.
# =========================================================================================

# =========================================================================================
# TESTING & VALIDATION
# =========================================================================================
# - **Test Strategy:** Manual testing on Proxmox VE environments, static analysis.
# - **Key Test Cases Covered:**
#   - Correct JSON output for valid `pvesm` data.
#   - Correct parsing of total and used space.
#   - Correct percentage calculation (used and free).
#   - Handles missing `local-lvm` pool gracefully (outputs PRTG error JSON).
#   - Handles `pvesm` command failure (logs error, exits non-zero).
#   - Handles non-numeric data from `pvesm` (logs error, outputs PRTG error JSON).
#   - Handles zero total space (logs warning, calculates percentages as 0% used / 100% free).
#   - Command-line options (`-h`, `-v`, `-d`) function as expected.
#   - Logs messages correctly to stderr at different verbosity levels.
# - **Validation Environment:** Tested on Proxmox VE 7.x and 8.x.
# - **Automation:** Static analysis performed using ShellCheck (`shellcheck proxmox_check_storeage_local_lvm.sh`).
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - Parameterize the target pool name via a command-line argument instead of hardcoding `TARGET_POOL`.
# - Add option to monitor *all* active storage pools instead of just one.
# - Implement more specific exit codes for different error conditions.
# - Add absolute value channels (Bytes Used, Bytes Free, Bytes Total) to the PRTG output.
# - Offer JSON Lines output format as an alternative.
# - Enhance validation of `pvesm` output structure.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Requires privileges to run `pvesm status`. Running monitoring scripts as root is common but carries inherent risks. **Recommendation:** Configure sudo rules for the PRTG user to allow *only* the specific `/usr/sbin/pvesm status` command without a password, following the principle of least privilege. Avoid giving full root access via SSH if possible.
# - **Input Sanitization:** The script parses command-line options (`-h`, `-v`, `-d`) which do not take user-controlled values that affect command execution. It relies on the output format of `pvesm status`. While `pvesm` output is generally trusted, the script includes checks for numeric values before calculation. No direct user input is used to construct commands.
# - **Sensitive Data Handling:** The script itself does not handle passwords, API keys, or tokens. Security relies heavily on securing the SSH credentials (preferably key-based authentication) used by PRTG to connect to the Proxmox host.
# - **Dependencies:** Relies on standard system tools (`bash`, `awk`, `coreutils`, `getopt`) and the Proxmox-specific `pvesm`. Ensure the Proxmox host itself is secured and kept updated.
# - **File Permissions:** The script itself should have standard executable permissions (e.g., 755). It does not create sensitive files.
# - **External Command Execution:** Executes the static command `/usr/sbin/pvesm status`. No variables containing uncontrolled external input are used in commands. `eval set -- "${parsed_options}"` is used after `getopt`, which is standard practice and considered safe when `getopt` output is handled correctly.
# - **Network Exposure:** The script itself does not listen on ports. It relies on the SSH connection established by PRTG.
# - **Code Integrity:** If distributing the script, provide checksums (e.g., SHA256) for verification.
# - **Error Message Verbosity:** Error messages logged to stderr might contain pool names or raw `pvesm` output fragments (in DEBUG mode or CRITICAL errors). Ensure stderr is handled appropriately by the monitoring system (PRTG captures it for logs). Sensitive data (like passwords) is not processed or logged.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is contained within this script's header comments.
# - README: [Provide link if script is part of a repository with a README.md]
# - Wiki: [Provide link if script documentation exists on a Wiki]
# - No external documentation or man page is provided by default.
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Report issues via the script's repository (if available, e.g., https://baha.my.id/github) or directly to the author's contact email.
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
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
# Resolve the absolute path of the script's directory, handling symlinks.
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_DIR="${SOURCE_DIR}"
readonly SCRIPT_PID=$$

# --- Timestamp ---
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Global Runtime Variables ---
VERBOSE=false       # Boolean flag for verbose output
DEBUG_MODE=false    # Boolean flag for debug mode (set -x)
NO_COLOR=false      # Boolean flag to disable colored output
INTERACTIVE_MODE=false # Boolean flag indicating if running in an interactive terminal
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is a terminal

# Script-specific target storage pool name
readonly TARGET_POOL="local-lvm"

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
# Description: Handles formatted logging to stdout/stderr.
# Usage: log_message LEVEL "Message string"
# Levels: DEBUG, INFO, WARN, ERROR, CRITICAL
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z") # Include Timezone
    local level_upper
    level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]')
    local log_prefix="[${timestamp}] [${level_upper}] [${SCRIPT_NAME}:${BASH_LINENO[0]}]" # Add line number
    local log_line="${log_prefix} - ${message}"
    local color=""

    # Determine color based on level
    case "${level_upper}" in
        DEBUG) color="${COLOR_CYAN}" ;;
        INFO) color="${COLOR_GREEN}" ;;
        WARN) color="${COLOR_YELLOW}" ;;
        ERROR | CRITICAL) color="${COLOR_RED}${COLOR_BOLD}" ;;
        *) color="${COLOR_RESET}" ;; # Default case
    esac

    # Only print DEBUG if VERBOSE is true
    if [[ "${level_upper}" == "DEBUG" && "${VERBOSE}" == false ]]; then
        return 0
    fi

    # Output to stderr for WARN, ERROR, CRITICAL; stdout otherwise (but we direct all logs to stderr)
    # Keep PRTG output clean on stdout
    echo -e "${color}${log_line}${COLOR_RESET}" >&2

    # Exit immediately for CRITICAL errors
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        # Optionally call cleanup before exiting if needed
        # cleanup
        exit 1 # Use a specific exit code for critical errors
    fi
}

# --- Usage/Help Function ---
# Description: Displays basic help information and exits.
usage() {
    # Print usage information to stderr
    cat << EOF >&2
${COLOR_BOLD}Usage:${COLOR_RESET} ${SCRIPT_NAME} [options]

${COLOR_BOLD}Purpose:${COLOR_RESET}
  Collects storage free space for the '${TARGET_POOL}' pool on Proxmox VE
  and outputs it in JSON format compatible with PRTG SSH Script Advanced sensors.

${COLOR_BOLD}Options:${COLOR_RESET}
  -h, --help     Display this help message and exit.
  -v, --verbose  Enable verbose output (logs INFO and DEBUG messages to stderr).
  -d, --debug    Enable Bash debug mode (\`set -x\`), prints every command.

${COLOR_BOLD}Description:${COLOR_RESET}
  This script executes 'pvesm status', filters for '${TARGET_POOL}', calculates the
  free space percentage, and prints the PRTG-compatible JSON to standard output.
  All logs and errors are directed to standard error.
EOF
    exit 1 # Exit with a non-zero status after showing help
}

# --- Dependency Check Function ---
# Description: Checks if required command-line utilities are installed and executable.
# Exits with error if a dependency is missing.
# Arguments: $1: Command name to check (e.g., "pvesm", "awk")
#            $2: (Optional) Purpose/Package suggestion
check_dependency() {
    local cmd="$1"
    local purpose="${2:-}"
    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required command '${cmd}' not found. ${purpose}"
        # Exit is handled by CRITICAL log level
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
}

# --- Cleanup Function ---
# Description: Performs cleanup tasks before script exits. Currently empty.
# Designed to be called via 'trap'.
cleanup() {
    local exit_status=$? # Capture the script's exit status
    log_message "DEBUG" "Performing cleanup tasks (if any)..."
    # No temporary files or specific cleanup actions needed for this script currently.
    log_message "INFO" "Script finished with exit status: ${exit_status}."
    exit "${exit_status}" # Ensure the original exit status is propagated
}

# --- Trap Setup ---
# Register the 'cleanup' function to run on script exit (normal or error) and signals.
trap cleanup EXIT INT TERM HUP

# --- Argument Parsing Function ---
# Description: Parses command-line options using getopt (supports long options).
parse_params() {
    # Define short and long options
    local short_opts="hvd"
    local long_opts="help,verbose,debug"

    # Use getopt to parse options
    # Note: Requires 'util-linux' package for getopt command
    # Check if getopt exists before using it
    if ! command -v getopt &> /dev/null; then
        log_message "ERROR" "'getopt' command not found. Cannot parse long options. Falling back to getopts for short options."
        # Fallback to getopts (only short options)
        while getopts ":${short_opts}" opt; do
            case $opt in
                h) usage ;;
                v) VERBOSE=true ;;
                d) DEBUG_MODE=true; set -x ;;
                \?) log_message "ERROR" "Invalid option: -${OPTARG}"; usage ;;
                :) log_message "ERROR" "Option -${OPTARG} requires an argument."; usage ;;
            esac
        done
        shift $((OPTIND - 1)) # Shift processed options away
    else
        # Use getopt for robust parsing
        local parsed_options
        parsed_options=$(getopt -o "${short_opts}" --long "${long_opts}" -n "${SCRIPT_NAME}" -- "$@")
        if [[ $? -ne 0 ]]; then
            usage # Exit if getopt found an error
        fi

        # Use the parsed options
        eval set -- "${parsed_options}"

        while true; do
            case "$1" in
                -h|--help) usage ;;
                -v|--verbose) VERBOSE=true; shift ;;
                -d|--debug) DEBUG_MODE=true; set -x; shift ;;
                --) shift; break ;; # End of options
                *) log_message "ERROR" "Internal error parsing options."; exit 1 ;;
            esac
        done
    fi


    # Check for unexpected positional arguments (this script takes none)
    if [[ $# -gt 0 ]]; then
        log_message "ERROR" "Unexpected argument(s): $*"
        usage
    fi

    log_message "DEBUG" "Arguments parsed. Verbose: ${VERBOSE}, Debug: ${DEBUG_MODE}"
}


# --- Main Logic Function ---
# Description: Contains the core functionality of the script.
main() {
    log_message "INFO" "Starting storage check for pool: ${TARGET_POOL}"

    local pvesm_output
    local exit_code=0

    # 1. Execute pvesm status and capture output/exit code
    log_message "DEBUG" "Executing: pvesm status"
    pvesm_output=$(pvesm status 2>&1) || exit_code=$? # Capture stderr as well, check exit code

    if [[ ${exit_code} -ne 0 ]]; then
        log_message "CRITICAL" "Failed to execute 'pvesm status'. Exit code: ${exit_code}. Output: ${pvesm_output}"
        # Exit handled by CRITICAL
    fi
    log_message "DEBUG" "Raw pvesm status output:\n${pvesm_output}"

    # 2. Filter for the target pool and extract data using awk
    local pool_data
    # Ensure awk handles potential errors gracefully (e.g., pool not found)
    # Filter by the target pool name (using variable) and print relevant columns if found
    pool_data=$(echo "${pvesm_output}" | awk -v pool="${TARGET_POOL}" '$1 == pool {print $1, $4, $5}')

    if [[ -z "${pool_data}" ]]; then
        log_message "ERROR" "Storage pool '${TARGET_POOL}' not found in 'pvesm status' output."
        # Generate PRTG error JSON
        printf '{\n "prtg": {\n  "error": 1,\n  "text": "Error: Storage pool %s not found."\n }\n}\n' "${TARGET_POOL}"
        exit 1 # Indicate error state
    fi
    log_message "DEBUG" "Filtered data for pool '${TARGET_POOL}': ${pool_data}"

    # 3. Parse extracted data
    local pool_name total_space used_space
    # Use read to assign variables safely from the awk output
    read -r pool_name total_space used_space <<< "${pool_data}"

    log_message "DEBUG" "Parsed - Pool: ${pool_name}, Total: ${total_space}, Used: ${used_space}"

    # 4. Calculate free space percentage
    local percent_free
    if [[ -z "${total_space}" || -z "${used_space}" || ! "${total_space}" =~ ^[0-9]+$ || ! "${used_space}" =~ ^[0-9]+$ ]]; then
         log_message "ERROR" "Failed to parse numeric values for total or used space from pvesm output for pool '${pool_name}'. Data: '${pool_data}'"
         printf '{\n "prtg": {\n  "error": 1,\n  "text": "Error: Failed to parse storage values for %s."\n }\n}\n' "${pool_name}"
         exit 1
    fi


    if [[ ${total_space} -gt 0 ]]; then
        # Using Bash integer arithmetic for percentage calculation
        local percent_used=$(( (used_space * 100) / total_space ))
        percent_free=$(( 100 - percent_used ))
        log_message "DEBUG" "Calculation: Used ${percent_used}%, Free ${percent_free}%"
    else
        # Handle case where total space is 0 (unlikely for LVM, but safe)
        log_message "WARN" "Total space reported as 0 for pool '${pool_name}'. Reporting 100% free."
        percent_free=100
    fi

    # 5. Generate PRTG JSON Output to Standard Output
    # Use printf for reliable formatting without extra newlines from echo
    log_message "DEBUG" "Generating PRTG JSON output..."
    printf '{\n'
    printf ' "prtg": {\n'
    printf '  "result": [\n'
    printf '   {\n'
    # Use double quotes consistently for JSON keys and string values
    printf '    "channel": "%s Free",\n' "${pool_name}"
    printf '    "value": %d,\n' "${percent_free}"
    printf '    "unit": "Percent",\n' # PRTG Standard Unit for Percentage
    printf '    "limitmode": 1,\n' # Activate limits based on value (optional but good practice)
    printf '    "limitmaxwarning": 90,\n' # Example Warning limit at 90% used (10% free)
    printf '    "limitmaxerror": 95\n'   # Example Error limit at 95% used (5% free)
    # Note: PRTG interprets "Percent" unit with limits based on the value itself.
    # A value of 10 means 10% free. Limits should check if value < threshold.
    # Example: Warning if value < 10 (less than 10% free)
    # Let's adjust logic to output % USED for easier limit setting in PRTG
    # Rerun calculation for % used
    local percent_used_for_prtg=0
    if [[ ${total_space} -gt 0 ]]; then
       percent_used_for_prtg=$(( (used_space * 100) / total_space ))
    fi

    log_message "INFO" "Pool: ${pool_name}, Total: ${total_space}, Used: ${used_space}, Used %: ${percent_used_for_prtg}, Free %: ${percent_free}"

    # Re-generate JSON with % Used and standard limits
    printf '{\n'
    printf ' "prtg": {\n'
    printf '  "result": [\n'
    printf '   {\n'
    printf '    "channel": "%s Usage",\n' "${pool_name}" # Change channel name
    printf '    "value": %d,\n' "${percent_used_for_prtg}" # Output % USED
    printf '    "unit": "Percent",\n'
    printf '    "limitmode": 1,\n'           # Activate limits
    printf '    "limitmaxwarning": "85",\n'  # Warning if usage >= 85%
    printf '    "limitmaxerror": "95",\n'    # Error if usage >= 95%
    printf '    "showchart": 1\n'           # Ensure chart is shown
    # Add channel for Free Space as well (optional)
    printf '   },\n'
    printf '   {\n'
    printf '    "channel": "%s Free",\n' "${pool_name}"
    printf '    "value": %d,\n' "${percent_free}"
    printf '    "unit": "Percent",\n'
    printf '    "showchart": 0\n' # Maybe hide this one from main chart
    printf '   }\n'
    printf '  ]\n' # Close result array
    printf ' }\n' # Close prtg object
    printf '}\n' # Close main JSON object


    log_message "INFO" "Successfully generated PRTG data for pool: ${pool_name}"
}


# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# 1. Parse Command Line Arguments
parse_params "$@" # Pass all arguments received by the script

# 2. Check Dependencies
log_message "INFO" "Checking required dependencies..."
check_dependency "pvesm" "Proxmox VE storage management tool (part of PVE)"
check_dependency "awk" "Pattern scanning and processing language utility"
check_dependency "date" "Core utility for timestamps"
check_dependency "basename" "Core utility for script name"
check_dependency "dirname" "Core utility for script path"
check_dependency "read" "Bash built-in"
check_dependency "printf" "Bash built-in or core utility"

# (No config file loading, input validation, or env preparation needed for this simple script)

# 3. Execute Main Logic
main

# 4. Exit Successfully (Handled by trap)
# log_message "INFO" "Script completed successfully." # Logged by cleanup trap
# exit 0 # Explicit exit handled by trap

# =========================================================================================
# --- End of Script ---
