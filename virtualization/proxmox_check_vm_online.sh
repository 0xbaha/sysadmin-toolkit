#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : proxmox_check_vm_online.sh
# PURPOSE       : Counts online Proxmox VMs and outputs count for PRTG via JSON.
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
# This script utilizes the Proxmox Virtual Environment command-line tool `qm`
# to retrieve a list of all configured virtual machines and their statuses.
# It filters this list to identify only the VMs currently in the "running" state.
# Finally, it counts these running VMs and formats the result into a specific JSON
# structure required by PRTG for sensor data ingestion.
#
# Key Workflow / Functions:
# - Executes `qm list` to get VM status information.
# - Uses `awk` to filter for VMs with status "running".
# - Uses `wc -l` to count the number of running VMs.
# - Outputs the count in PRTG-compatible JSON format to standard output using `printf`.
# - Includes basic error handling and logging functions.
# - Uses Bash strict mode (`set -euo pipefail`) for robustness.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Simplicity:** Focuses on the core task of counting running VMs with minimal complexity.
# - **Automation:** Designed for unattended execution by monitoring systems like PRTG.
# - **Robustness:** Implements Bash strict mode and basic error checks (dependency, command failure).
# - **Readability:** Employs clear variable names and function separation.
# - **Compatibility:** Generates output specifically formatted for PRTG's SSH Script Advanced sensor.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - System Administrators managing Proxmox VE environments.
# - IT Staff using PRTG Network Monitor for infrastructure monitoring.
# - DevOps Engineers integrating Proxmox monitoring into automated workflows.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x proxmox_check_vm_online.sh`
# - Proxmox privileges: Requires sufficient privileges to execute the `qm list` command
#   on the Proxmox host. This typically means running as root or a user with an
#   appropriate role (e.g., PVEVMAdmin) assigned via Proxmox VE's Permissions panel.
#
# **Execution Context:**
# - This script is specifically designed to be executed by PRTG Network Monitor
#   using the "SSH Script Advanced" sensor type. PRTG will connect to the Proxmox
#   host via SSH (using configured credentials) and run this script.
#
# **Basic Syntax (Manual Test):**
# `./proxmox_check_vm_online.sh`
# (When run manually, it will print the JSON output to the console and log messages to stderr/stdout)
#
# **Options (Optional - Currently minimal, extend `parse_params` if needed):**
#   (This script currently does not implement command-line options, but the framework exists)
#   -h, --help     Display help (if implemented).
#   -v, --verbose  Enable verbose output (prints DEBUG logs).
#   -d, --debug    Enable Bash debug mode (`set -x`).
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - Place the script in a suitable location on the Proxmox VE host where PRTG's SSH user can access it.
# - Common locations: `/usr/local/sbin/`, `/opt/prtg/scripts/`, `~/scripts/`.
#
# **Manual Setup:**
# 1. Copy the script to the chosen location on the Proxmox VE host.
# 2. Set ownership if needed (e.g., `chown root:root /usr/local/sbin/proxmox_check_vm_online.sh`).
# 3. Set executable permissions: `chmod 755 /usr/local/sbin/proxmox_check_vm_online.sh` (adjust permissions based on security policy and location).
# 4. Ensure dependencies (bash, qm, awk, wc) are installed (standard on PVE).
# 5. Configure the PRTG "SSH Script Advanced" sensor:
#    - Point it to the script's path on the Proxmox host.
#    - Configure SSH credentials with sufficient permissions to run `qm list`.
#    - Ensure the sensor expects JSON output.
# 6. Test manually first: `sudo -u <prtg_ssh_user> /path/to/proxmox_check_vm_online.sh`
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: Bourne-Again SHell. Tested with Bash 4+.
#
# **Required System Binaries/Tools:**
# - `qm`: Proxmox VE command-line tool for managing QEMU VMs (part of `pve-qemu-kvm`).
# - `awk`: Standard Unix text processing utility (e.g., `gawk`).
# - `wc`: Standard Unix word count utility (part of `coreutils`).
# - `date`, `basename`, `dirname`, `cd`, `pwd`: Standard core utilities.
# - `command`: Bash built-in for checking command existence.
# - `printf`: Bash built-in for formatted output (safer for JSON than echo).
#
# **Operating System Compatibility:**
# - Designed and tested specifically for Proxmox Virtual Environment (PVE).
# - May not function correctly on other Linux distributions without `qm`.
#
# **Environment Variables Used:**
# - None explicitly required by the script logic itself.
# - Standard variables like `PATH` are used implicitly to find commands.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): Primarily used for the final PRTG JSON output. INFO/DEBUG logs may appear here if not running interactively or if colors are disabled.
# - Standard Error (stderr): Used for WARN, ERROR, CRITICAL log messages, and DEBUG messages when verbose mode is active. PRTG typically captures stderr for sensor error details.
# - Dedicated Log File: No. This script does not log to a separate file.
# - System Log (syslog/journald): No.
#
# **Log Format:**
# - `[YYYY-MM-DD HH:MM:SS ZZZ] [LEVEL] [script_name:PID] - Message`
#
# **Log Levels:**
# - DEBUG: Detailed info (Enabled via `VERBOSE=true`).
# - INFO: General steps (Default level).
# - WARN: Potential issues.
# - ERROR: Non-fatal errors encountered.
# - CRITICAL: Fatal errors causing script termination.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - The primary output is a JSON object formatted specifically for PRTG's SSH Script Advanced sensor.
# - It contains a single channel reporting the count of running VMs.
# - INFO/DEBUG log messages might also appear on stdout under certain conditions (see LOGGING).
#
# **Example JSON Output:**
# ```
# {
#   "prtg": {
#     "result": [
#       {
#         "channel": "Online VMs",
#         "value": 5,
#         "unit": "Count"
#       }
#     ]
#   }
# }
# ```
# (Where '5' is replaced by the actual count of running VMs found)
#
# **Standard Error (stderr):**
# - Error messages (WARN, ERROR, CRITICAL).
# - Debug messages if verbose mode is enabled (`VERBOSE=true`).
# - Bash `set -x` output if debug mode is enabled (`DEBUG_MODE=true`).
# - PRTG will typically display the contents of stderr if the script exits non-zero or if the output is not valid JSON.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success. JSON output generated and printed.
# - 1: General Error / Critical Failure (e.g., `qm list` fails, dependency missing, critical log triggered).
# - Non-zero (Bash default): May occur if `set -e` triggers on an unhandled command failure before explicit exit codes.
# PRTG will typically interpret any non-zero exit code as a sensor error state.
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** Script fails with "command not found: qm".
#   **Resolution:** Ensure the script is run on a Proxmox VE host where `qm` is installed and in the execution `$PATH` of the user running the script (e.g., the SSH user configured in PRTG).
# - **Issue:** Script returns 0 VMs or fails with permission errors (e.g., "permission denied", "command failed with exit code X").
#   **Resolution:** Verify the SSH user configured in PRTG has sufficient permissions on the Proxmox host to execute `qm list`. Add the user to an appropriate Proxmox group/role (e.g., PVEVMAdmin) or configure specific ACLs. Avoid using root if possible. Check `/var/log/auth.log` or `journalctl` on the PVE host for SSH login/permission issues.
# - **Issue:** PRTG sensor shows an error like "Invalid JSON" or "Script returned no usable data".
#   **Resolution:** Ensure the script's stdout *only* contains the final JSON object. Check for unexpected output (e.g., debugging `echo` statements, error messages printed to stdout instead of stderr). Ensure the JSON structure exactly matches the PRTG specification shown in OUTPUTS. Run the script manually on the PVE host to verify its output. Check for errors printed to stderr.
# - **Issue:** Script fails silently when run via PRTG/cron.
#   **Resolution:** Ensure the execution environment for the script runner (PRTG's SSH session, cron) has the necessary `$PATH` to find `qm`, `awk`, `wc`. Use full paths to commands (`/usr/sbin/qm`) within the script if necessary, although dependency checks should handle this. Redirect stderr to a log file for debugging if running via cron.
#
# **Important Considerations:**
# - **Idempotency:** Yes, running the script multiple times yields the same result (current count) without side effects.
# - **Resource Usage:** Very low. Primarily involves running `qm list`, `awk`, and `wc`. Negligible impact on PVE host performance.
# - **Concurrency:** Safe to run multiple instances, although not typically necessary. No locking implemented.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes execution on a functional Proxmox VE host.
# - Assumes the `qm`, `awk`, `wc`, and standard core utilities are installed and accessible via the `$PATH`.
# - Assumes the user executing the script has the necessary permissions within Proxmox VE to run `qm list`.
# - Assumes the network connection (if executed remotely via SSH by PRTG) is stable.
# - Assumes the output of `qm list` follows the standard format where the status is the third column.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** The script requires privileges to run `qm list`. Grant only the minimum necessary Proxmox VE permissions to the SSH user configured in PRTG (e.g., a dedicated monitoring user with `PVEVMAdmin` on `/vms` or just `VM.Audit`). Avoid using the `root` user for monitoring if possible.
# - **Execution Context:** As this script is designed to be run via SSH by PRTG, securing the SSH connection is paramount. Use strong authentication methods (SSH keys preferred over passwords), limit access for the SSH user, and potentially restrict the commands the SSH user can run via `authorized_keys` (`command="..."`) or sudo configurations (though direct PVE permissions are often cleaner).
# - **Command Execution:** The script executes system commands (`qm`, `awk`, `wc`). While these specific commands are standard and generally safe in this context, executing external commands always carries inherent risks. Ensure the script itself has appropriate permissions (not world-writable).
# - **Input Sanitization:** The script does not take external input beyond the output of `qm list`, reducing injection risks. No command-line arguments affecting core logic are currently implemented.
# - **Error Message Verbosity:** Error messages logged to stderr might reveal system information (e.g., command paths, PIDs). Ensure logs/stderr captured by PRTG are handled appropriately according to your security policy.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is contained within this script's header comments.
# - No external documentation or man page is provided.
# - Refer to Proxmox VE documentation for `qm` command details.
# - Refer to PRTG documentation for "SSH Script Advanced" sensor configuration.
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Report issues via the script's repository (if available) or directly to the author's contact email. Please include script version, PVE version, steps to reproduce, and any error output.
# =========================================================================================

# =========================================================================================
# SCRIPT EXECUTION ENVIRONMENT & CONFIGURATION
# =========================================================================================

# --- Bash Strict Mode ---
# -e: Exit immediately if a command exits with a non-zero status.
# -u: Treat unset variables and parameters as an error when performing parameter expansion.
# -o pipefail: The return value of a pipeline is the status of the last command to exit with a non-zero status,
#              or zero if no command exited with a non-zero status. Essential for catching errors in pipelines.
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
# Flags for controlling script behavior (can be extended with argument parsing)
VERBOSE=false
DEBUG_MODE=false
NO_COLOR=false # Flag to disable colored output
INTERACTIVE_MODE=false # Flag indicating if running in an interactive terminal
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is a terminal

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
    local log_prefix="[${timestamp}] [${level_upper}] [${SCRIPT_NAME}:${SCRIPT_PID}]"
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

    # Map script log levels to numeric values for comparison (can be adjusted via args/config later)
    declare -A log_levels=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [CRITICAL]=4)
    local current_log_level_num=${log_levels["INFO"]} # Default log level is INFO
    local message_level_num=${log_levels[${level_upper}]}

    # Adjust current log level if VERBOSE is enabled
    [[ "$VERBOSE" = true ]] && current_log_level_num=${log_levels["DEBUG"]}

    # Check if the message level is severe enough to be logged
    if [[ ${message_level_num} -ge ${current_log_level_num} ]]; then
        # Output to stderr for WARN, ERROR, CRITICAL; stdout otherwise
        if [[ "${level_upper}" == "WARN" || "${level_upper}" == "ERROR" || "${level_upper}" == "CRITICAL" ]]; then
            echo -e "${color}${log_line}${COLOR_RESET}" >&2
        else
            echo -e "${color}${log_line}${COLOR_RESET}"
        fi
    fi

    # Exit immediately for CRITICAL errors
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        log_message "INFO" "Critical error encountered. Exiting script."
        # Call cleanup if defined and needed before critical exit
        # cleanup
        exit 1 # Use a specific exit code for critical errors if desired
    fi
}


# --- Dependency Check Function ---
# Description: Checks if a command-line utility is installed and executable.
# Exits with a CRITICAL error if the dependency is missing.
# Arguments: $1: Command name to check (e.g., "qm", "awk", "wc")
#            $2: (Optional) Package name to suggest for installation
check_dependency() {
    local cmd="$1"
    local install_suggestion="${2:-$cmd}" # Use command name if package name not provided

    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required command '${cmd}' not found."
        log_message "ERROR" "Please ensure the '${install_suggestion}' tool is installed and available in the system's PATH."
        # CRITICAL log level already handles exit
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
}


# --- Cleanup Function ---
# Description: Performs cleanup tasks before script exits. Currently minimal.
# Designed to be called via 'trap'.
cleanup() {
    local exit_status=$? # Capture the script's exit status
    log_message "DEBUG" "Performing cleanup..."
    # Add cleanup tasks here if needed (e.g., removing temporary files)
    log_message "DEBUG" "Cleanup finished with exit status: ${exit_status}"
    # Note: The script will exit with the original exit_status after trap completes
}


# --- Trap Setup ---
# Register the 'cleanup' function to run on specific signals and on script exit.
# EXIT: Normal script termination or exit due to 'set -e'.
# INT: Interrupt signal (Ctrl+C).
# TERM: Termination signal (sent by `kill`).
# HUP: Hangup signal.
trap cleanup EXIT INT TERM HUP


# --- Main Logic Function ---
# Description: Contains the core functionality of the script.
main() {
    log_message "INFO" "Starting Proxmox Online VM Check execution..."

    # --- Dependency Checks ---
    log_message "INFO" "Checking required dependencies..."
    check_dependency "qm" "Proxmox VE qm tool (usually part of pve-qemu-kvm)"
    check_dependency "awk" "awk (usually part of gawk or similar package)"
    check_dependency "wc" "wc (usually part of coreutils)"
    log_message "INFO" "Dependencies check passed."

    local online_vm_count
    local qm_list_output

    # --- Get Online VM Count ---
    # This command chain performs the following steps:
    # 1. `qm list`: Executes the Proxmox command to list all VMs and their status.
    # 2. `awk '$3 == "running"'`: Filters the output to include only lines where the third field (status) is "running".
    # 3. `wc -l`: Counts the number of lines remaining, which corresponds to the number of running VMs.
    # The result is stored in 'online_vm_count'.
    # Error handling is provided by 'set -euo pipefail'. If any command in the pipeline fails, the script will exit.
    log_message "INFO" "Executing 'qm list' to find running VMs..."
    if ! qm_list_output=$(qm list); then
        log_message "ERROR" "Failed to execute 'qm list'. Check permissions and ensure Proxmox services are running."
        exit 1 # Exit with a general error status
    fi
    log_message "DEBUG" "Raw output from 'qm list':\n${qm_list_output}"

    # Process the output
    online_vm_count=$(echo "${qm_list_output}" | awk '$3 == "running"' | wc -l)
    # Validate if the count is a number (it should be, even 0)
    if ! [[ "$online_vm_count" =~ ^[0-9]+$ ]]; then
       log_message "ERROR" "Failed to parse VM count from 'qm list' output. Received: '${online_vm_count}'"
       exit 1
    fi

    log_message "INFO" "Successfully determined online VM count: ${online_vm_count}"

    # --- Generate PRTG JSON Output ---
    # The following printf commands construct a JSON object formatted specifically for PRTG's SSH Script Advanced sensor.
    # PRTG expects sensor results in a specific JSON structure. Using printf is generally safer for creating JSON than multiple echo calls.
    # - The outer structure `{"prtg": { ... }}` is required by PRTG.
    # - `"result": [ ... ]` contains an array of one or more channels.
    # - Each object within the "result" array represents a single monitoring channel.
    #   - `"channel": "Online VMs"`: Sets the name of the channel displayed in PRTG.
    #   - `"value": %d`: Provides the actual monitored value (integer).
    #   - `"unit": "Count"`: Specifies the unit for the value displayed in PRTG.
    log_message "INFO" "Generating PRTG JSON output..."
    printf '{\n'
    printf '  "prtg": {\n'
    printf '    "result": [\n'
    printf '      {\n'
    printf '        "channel": "Online VMs",\n'
    printf '        "value": %d,\n' "$online_vm_count" # Use %d for integer formatting
    printf '        "unit": "Count"\n'
    printf '      }\n'
    printf '    ]\n'
    printf '  }\n'
    printf '}\n'

    log_message "INFO" "PRTG JSON output generated successfully."
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# Execute Main Logic
main

# Explicitly exit with success code 0. The 'trap cleanup EXIT' will run automatically just before this.
log_message "INFO" "Script completed successfully."
exit 0

# =========================================================================================
# --- End of Script ---
