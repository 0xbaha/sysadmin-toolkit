#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : proxmox_check_vm_offline.sh
# PURPOSE       : Counts offline Proxmox VMs and outputs count for PRTG via JSON.
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
# This script queries the Proxmox VE host using the 'qm list' command to get the status
# of all registered virtual machines. It then filters this list using 'awk' to identify VMs
# that are currently in the "stopped" state. Finally, it counts these stopped VMs using 'wc'
# and formats the result into a JSON payload suitable for consumption by a PRTG
# Network Monitor custom sensor (specifically, the SSH Script Advanced sensor type).
#
# Key Workflow / Functions:
# - Sets Bash strict mode (`set -euo pipefail`) for robustness.
# - Defines helper functions for logging (`log_message`), usage (`usage`), dependency checks (`check_dependency`), argument parsing (`parse_params`), and cleanup (`cleanup` via trap).
# - Parses command-line arguments (supports `-h` for help and `-v` for verbose logging).
# - Checks for required command-line tools (`qm`, `awk`, `wc`).
# - Executes the core logic in the `main` function:
#   - Runs `qm list` to get VM statuses.
#   - Pipes the output to `awk '$3 == "stopped"'` to filter for stopped VMs.
#   - Pipes the filtered list to `wc -l` to count the number of stopped VMs.
#   - Handles potential errors during the command pipeline execution, outputting a PRTG error JSON if failure occurs.
#   - Constructs a JSON output string using `printf` conforming to the PRTG custom sensor specification.
#   - Prints the final JSON to standard output.
# - Utilizes a trap to ensure the `cleanup` function runs on script exit or interruption.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Simplicity:** The core logic focuses directly on the task using standard Unix tools.
# - **Robustness:** Incorporates Bash strict mode (`set -euo pipefail`), checks dependencies, includes basic error handling for the command pipeline, and uses `printf` for safer JSON generation.
# - **Modularity:** Uses functions for distinct tasks (logging, parsing, main logic, cleanup).
# - **Readability:** Employs clear variable names and detailed comments.
# - **Automation:** Designed for unattended execution via PRTG's SSH sensor.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - System Administrators managing Proxmox VE environments.
# - Network or System Monitoring engineers using PRTG Network Monitor.
# - Users needing a simple way to monitor the count of stopped VMs on Proxmox.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x proxmox_check_vm_offline.sh`
# - Proxmox host access: Requires sufficient privileges on the Proxmox host to execute the `qm list` command.
#   Typically, this means running as the 'root' user or a user belonging to a group with appropriate PVE permissions (e.g., `PVEAdmin` role on `/`).
#
# **Basic Syntax:**
#   Execute the script directly on the Proxmox host:
#   `./proxmox_check_vm_offline.sh [options]`
#
# **Options:**
#   -h          Display help message (extracted from this header) and exit.
#   -v          Enable verbose output (prints DEBUG level messages via `log_message`).
#
# **Common Examples:**
# 1. Run normally for PRTG:
#    `/path/to/proxmox_check_vm_offline.sh`
# 2. Run with verbose logging for debugging:
#    `/path/to/proxmox_check_vm_offline.sh -v`
# 3. Get help:
#    `/path/to/proxmox_check_vm_offline.sh -h`
#
# **PRTG Integration:**
# - Intended for use with PRTG Network Monitor's "SSH Script Advanced" sensor type.
# - Configure the sensor on PRTG:
#   - Target Device: Your Proxmox VE host IP or FQDN.
#   - Credentials: Provide SSH credentials (user/password or key) that have permission to execute `qm list` on the Proxmox host.
#   - Script: Enter the full path to this script on the Proxmox host (e.g., `/usr/local/sbin/proxmox_check_vm_offline.sh`).
#   - Parameters: Leave blank unless you need verbose logging (`-v`), which is generally not recommended for normal monitoring.
# - The script's standard output provides the JSON data PRTG expects. Standard error output (from `log_message` WARN/ERROR/CRITICAL or command failures) will be interpreted by PRTG as a sensor error message.
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - System-wide utility script: `/usr/local/sbin/` (common for admin scripts).
# - User-specific script: `~/bin/` or similar (ensure the directory is in the user's $PATH if needed).
#
# **Manual Setup:**
# 1. Place the script file in the desired location (e.g., `/usr/local/sbin/proxmox_check_vm_offline.sh`).
# 2. Set appropriate ownership (optional, depends on location/policy):
#    `sudo chown root:root /usr/local/sbin/proxmox_check_vm_offline.sh`
# 3. Set executable permissions:
#    `sudo chmod 755 /usr/local/sbin/proxmox_check_vm_offline.sh` (or `chmod u+x` for user scripts).
# 4. Ensure required dependencies (`qm`, `awk`, `wc`) are installed (typically standard on Proxmox).
# 5. Test execution manually: `/usr/local/sbin/proxmox_check_vm_offline.sh`
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: Bourne-Again SHell interpreter. Uses bash-specific features (`set -o pipefail`, `BASH_SOURCE`, `PIPESTATUS`).
#
# **Required System Binaries/Tools:**
# - `qm`: The Proxmox VE command-line tool for managing virtual machines (part of `pve-manager` package).
# - `awk`: Standard text processing utility (part of `gawk` or similar package).
# - `wc`: Standard word/line count utility (part of `coreutils`).
# - `date`: For timestamps in logging (part of `coreutils`).
# - `basename`, `dirname`, `cd`: For script path resolution (part of `coreutils`).
# - `command`: Bash built-in for checking command existence.
# - `getopts`: Bash built-in for parsing command-line options.
# - `printf`: Bash built-in used for formatted JSON output.
# - `sed`: Used by `usage` function (part of `sed` package).
# - `tr`: Used by `log_message` function (part of `coreutils`).
#
# **Operating System Compatibility:**
# - Designed specifically for Proxmox VE environments. Relies on the `qm` command.
# - Generally compatible with most modern Linux distributions where Bash and core utilities are present, but the `qm` command makes it Proxmox-specific.
#
# **Environment Variables Used:**
# - None directly read or required by the script logic itself.
# - `PATH`: Standard variable used to locate commands (`qm`, `awk`, `wc`, etc.).
#
# **System Resource Requirements:**
# - Very low: Minimal CPU, memory, and disk I/O usage. Primarily depends on the overhead of running `qm list`.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): Used for INFO and DEBUG level messages (if `-v` enabled). **Primary output (JSON) also goes to stdout.**
# - Standard Error (stderr): Used for WARN, ERROR, and CRITICAL level messages generated by the `log_message` function. PRTG typically captures stderr content as the sensor error message.
# - Dedicated Log File: No. Logging is directed to stdout/stderr only.
# - System Log (syslog/journald): No direct integration.
#
# **Log Format:**
# - `[YYYY-MM-DD HH:MM:SS ZZZ] [LEVEL] - Message` (e.g., `[2024-11-06 10:30:00 UTC] [INFO] - Starting Proxmox offline VM check...`)
#
# **Log Levels (controlled by `log_message` function):**
# - `DEBUG`: Detailed step-by-step information (Enabled by `-v`).
# - `INFO`: General operational messages (start/stop, counts).
# - `WARN`: Potential non-critical issues (Not currently used in this script).
# - `ERROR`: Significant errors likely preventing successful completion (e.g., command failure).
# - `CRITICAL`: Severe errors causing script termination (e.g., missing dependency).
# - Control: Verbosity controlled by `-v` flag (enables DEBUG). All other levels print by default to stdout (INFO) or stderr (WARN, ERROR, CRITICAL).
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Primary Output: A JSON object structured for PRTG custom sensors when successful.
#   - Example Success Output:
#     ```
#     {
#      "prtg": {
#       "result": [
#        {
#         "channel": "Offline VMs",
#         "value": 5,
#         "unit": "Count"
#        }
#       ]
#      }
#     }
#     ```
#     (Where '5' is the actual count of stopped VMs found).
# - Log Messages: INFO and DEBUG (if `-v`) messages are also sent to stdout via the `log_message` function. These should generally be ignored by PRTG when the final JSON is present and the exit code is 0.
# - Error Output (JSON): If the command pipeline fails, a specific PRTG error JSON is printed to stdout, and the script exits non-zero.
#   - Example Error JSON Output:
#     ```
#     {
#      "prtg": {
#       "error": 1,
#       "text": "Failed to execute command pipeline to count offline VMs"
#      }
#     }
#     ```
#
# **Standard Error (stderr):**
# - Log Messages: WARN, ERROR, CRITICAL messages generated by `log_message` are sent to stderr.
# - Command Errors: Any errors generated directly by `qm`, `awk`, or `wc` might also appear on stderr.
# - PRTG typically uses non-zero exit codes and/or stderr content to determine sensor error status and message.
#
# **Generated/Modified Files:**
# - None. The script does not create or modify any files.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success. Valid PRTG JSON output generated and printed to stdout.
# - 1: General Error. Used for:
#   - Invalid command-line options (`parse_params`).
#   - Critical errors detected by `log_message` (e.g., dependency missing).
#   - Failure in the main command pipeline (`qm list | awk | wc`) within `main`.
# - Non-zero (other): May occur if `set -e` triggers an exit on an unexpected command failure before explicit error handling.
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** PRTG sensor reports "Permission denied" or similar SSH/execution error.
#   **Resolution:** Verify the SSH credentials used by PRTG have permission to execute `qm list` on the Proxmox host. Ensure the user can run `qm list` manually when logged in via SSH. Check user group memberships and Proxmox roles/permissions (`/` path). Check sudo configurations if applicable (though direct execution as the correct user is preferred).
# - **Issue:** PRTG sensor reports "Script return code was not 0" or shows error message "Failed to execute command pipeline...".
#   **Resolution:** The `qm list | awk | wc` command sequence failed. Run the script manually (`/path/to/script -v`) on the Proxmox host to see detailed error messages on stderr (check exit status with `echo $?`). Common causes: `qm` command not found (PATH issue?), insufficient permissions for `qm list`, unexpected output format from `qm list` breaking `awk`.
# - **Issue:** Script outputs incorrect count (e.g., 0 when VMs are stopped).
#   **Resolution:** Run `qm list` manually on the host. Verify that stopped VMs actually have the status "stopped" in the third column. Check if the `awk` command (`awk '$3 == "stopped"'`) correctly filters the output. Proxmox updates could potentially change the `qm list` output format.
# - **Issue:** "Command not found: qm" (or awk, wc).
#   **Resolution:** Ensure the respective tools are installed and accessible via the `PATH` environment variable available to the script execution context (especially important when run via SSH or cron). Use `command -v qm` to test.
#
# **Important Considerations / Warnings:**
# - **Dependency on `qm list` format:** The script assumes the third column (`$3`) of the `qm list` output reliably indicates the VM status and that "stopped" is the exact string for offline VMs. Changes in future Proxmox versions could break this assumption.
# - **Error Reporting:** The script provides basic error handling for the main pipeline but might not catch all edge cases. Failures in underlying commands might produce stderr output that PRTG interprets as an error.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes execution occurs on a Proxmox VE host where the `qm` command is available and functional.
# - Assumes the `qm list` command output format includes the VM status in the third whitespace-delimited field.
# - Assumes the status string for a stopped VM is exactly "stopped".
# - Assumes standard tools (`awk`, `wc`, `date`, coreutils) are available in the execution environment's `PATH`.
# - Assumes the script is executed with sufficient permissions to run `qm list`.
# - Assumes network connectivity if executed remotely via SSH (e.g., by PRTG).
# - Assumes the target system uses `/bin/bash`.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Requires privileges to execute `qm list`. Does not require root if the execution user has appropriate PVE roles assigned (e.g., `PVEVMAdmin` on `/vms`). Running with the least privilege necessary is recommended.
# - **Input Sanitization:** Only accepts `-h` and `-v` flags via `getopts`. No external user-provided data is used to construct commands, minimizing injection risks.
# - **Sensitive Data Handling:** Does not handle passwords or API keys directly. Authentication is handled externally (e.g., by PRTG's SSH credential configuration).
# - **Dependencies:** Relies on standard system tools (`qm`, `awk`, `wc`, `coreutils`). Ensure these are from trusted sources (e.g., official Proxmox/Debian repositories).
# - **File Permissions:** Does not create files. Script permissions should be set appropriately (e.g., 755 or 750).
# - **External Command Execution:** Executes `qm list`, `awk`, `wc`. These are called with static arguments, not constructed from external input, making it safe from command injection via script arguments.
# - **Network Exposure:** Does not listen on any ports. Makes no outbound connections itself (SSH connection is inbound from PRTG).
# - **Error Message Verbosity:** Error messages logged to stderr might reveal internal command failures (`qm list` errors) but should not leak sensitive configuration details.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is contained within this script's header comments.
# - Use `./proxmox_check_vm_offline.sh -h` to display the USAGE section.
# - No external documentation or man page is provided.
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Report issues via the script's repository (if available at REPOSITORY link above) or directly to the author's contact email. Please include script version, Proxmox version, steps to reproduce, and relevant log output (if using `-v`).
# =========================================================================================

# =========================================================================================
# SCRIPT EXECUTION ENVIRONMENT & CONFIGURATION
# =========================================================================================

# --- Bash Strict Mode ---
# Exit immediately if a command exits with a non-zero status.
# Treat unset variables as an error during parameter expansion.
# Pipeline return status is the status of the last command to exit non-zero.
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
VERBOSE=false # Flag for verbose output
NO_COLOR=false # Flag to disable colored output
INTERACTIVE_MODE=false # Flag indicating if running in an interactive terminal
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is a terminal

# Script-specific variables
offline_vm_count=0 # Initialize count

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
# Usage: log_message LEVEL "Message string"
# Levels: DEBUG, INFO, WARN, ERROR, CRITICAL
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z")
    local level_upper
    level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]')
    local log_prefix="[${timestamp}] [${level_upper}]"
    local log_line="${log_prefix} - ${message}"
    local color=""

    case "${level_upper}" in
        DEBUG) color="${COLOR_CYAN}" ;;
        INFO) color="${COLOR_GREEN}" ;;
        WARN) color="${COLOR_YELLOW}" ;;
        ERROR) color="${COLOR_RED}" ;;
        CRITICAL) color="${COLOR_BOLD}${COLOR_RED}" ;;
    esac

    # Only print DEBUG if VERBOSE is true
    if [[ "${level_upper}" == "DEBUG" && "${VERBOSE}" == false ]]; then
        return
    fi

    # Output to stderr for WARN, ERROR, CRITICAL; stdout otherwise
    if [[ "${level_upper}" == "WARN" || "${level_upper}" == "ERROR" || "${level_upper}" == "CRITICAL" ]]; then
        echo -e "${color}${log_line}${COLOR_RESET}" >&2
    else
        echo -e "${color}${log_line}${COLOR_RESET}"
    fi

    # Exit immediately for CRITICAL errors
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        log_message "INFO" "Critical error encountered. Exiting script."
        # Consider calling cleanup function here if not using trap
        exit 1 # Use a specific exit code for critical errors if desired
    fi
}

# --- Usage/Help Function ---
# Displays help information based on header comments and exits.
usage() {
    # Extract Usage section from this script's header comments.
    local usage_text
    usage_text=$(sed -n '/^# ===+ USAGE ===+$/,/^# ===+ .* ===+$/{ /# ===+ .* ===+$/!p; }' "${BASH_SOURCE[0]}" | sed 's/^# //; s/\[your_script_name.sh\]/'"${SCRIPT_NAME}"'/g')

    cat << EOF >&2
${usage_text}

Options:
  -h, --help      Display this help message and exit.
  -v, --verbose   Enable verbose output (prints DEBUG messages).
EOF
    exit 1
}

# --- Dependency Check Function ---
# Checks if required command-line utilities are installed and executable.
check_dependency() {
    local cmd="$1"
    local install_suggestion="${2:-$cmd}"
    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required command '${cmd}' not found."
        log_message "ERROR" "Please ensure '${install_suggestion}' is installed and in the system's PATH."
        # exit 1 is handled by CRITICAL log level
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
}

# --- Cleanup Function ---
# Performs cleanup tasks before script exits (if any needed in the future).
cleanup() {
    local exit_status=$?
    log_message "DEBUG" "Performing cleanup..."
    # Add any cleanup tasks here (e.g., removing temporary files)
    log_message "DEBUG" "Cleanup finished with exit status: ${exit_status}"
    # Script exits with the original exit_status after trap completes
}

# --- Trap Setup ---
# Register 'cleanup' function to run on specific signals and script exit.
trap cleanup EXIT INT TERM HUP

# --- Argument Parsing Function ---
# Parses command-line options using getopts.
parse_params() {
    # ':' at the beginning enables silent error reporting
    while getopts ":hv" opt; do
        case $opt in
            h) usage ;;
            v) VERBOSE=true ;;
            \?) log_message "ERROR" "Invalid option: -${OPTARG}" >&2; usage ;;
            :) log_message "ERROR" "Option -${OPTARG} requires an argument." >&2; usage ;;
        esac
    done
    # Shift processed options away, leaving positional arguments (if any) in $@
    shift $((OPTIND-1))

    # Check for unexpected positional arguments (this script doesn't expect any)
    if [[ $# -gt 0 ]]; then
        log_message "ERROR" "Unexpected argument(s): $*"
        usage
    fi
    log_message "DEBUG" "Arguments parsed. Verbose: ${VERBOSE}"
}

# --- Main Logic Function ---
# Contains the core functionality of the script.
main() {
    log_message "INFO" "Starting Proxmox offline VM check..."

    # Execute the command pipeline to count stopped VMs
    log_message "DEBUG" "Executing: qm list | awk '\$3 == \"stopped\"' | wc -l"
    local output
    # Wrap command in a subshell and capture output; check exit status of pipeline
    if ! output=$(qm list | awk '$3 == "stopped"' | wc -l); then
        local pipeline_status=${PIPESTATUS[0]} # Get exit status of qm list
        if [[ $pipeline_status -ne 0 ]]; then
           log_message "ERROR" "'qm list' command failed with exit status ${pipeline_status}. Check permissions and Proxmox status."
        else
           log_message "ERROR" "Command pipeline failed. Check awk or wc execution."
        fi
        # Output a PRTG error JSON
        echo "{"
        echo " \"prtg\": {"
        echo "  \"error\": 1,"
        echo "  \"text\": \"Failed to execute command pipeline to count offline VMs\""
        echo " }"
        echo "}"
        exit 1 # Exit with error
    fi

    # Store the count; perform basic validation if needed (e.g., check if integer)
    offline_vm_count=$output
    log_message "INFO" "Found ${offline_vm_count} offline (stopped) VMs."

    # Construct the JSON output for PRTG
    log_message "DEBUG" "Generating PRTG JSON output."
    # Using printf for potentially safer/more controlled output formatting
    printf "{\n"
    printf " \"prtg\": {\n"
    printf "  \"result\": [\n"
    printf "   {\n"
    printf "    \"channel\": \"Offline VMs\",\n"
    printf "    \"value\": %d,\n" "$offline_vm_count" # Use %d for integer formatting
    printf "    \"unit\": \"Count\"\n"
    printf "   }\n"
    printf "  ]\n"
    printf " }\n"
    printf "}\n"

    log_message "INFO" "Finished Proxmox offline VM check."
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# 1. Parse Command Line Arguments
parse_params "$@"

# 2. Check Dependencies
log_message "INFO" "Checking required dependencies..."
check_dependency "qm" "Proxmox VE qm tool"
check_dependency "awk" "awk text processor"
check_dependency "wc" "wc word count tool"

# 3. Execute Main Logic
main

# 4. Exit Successfully (trap will handle cleanup)
log_message "DEBUG" "Script completed successfully."
exit 0

# =========================================================================================
# --- End of Script ---
