#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : proxmox_check_storage_data2.sh
# PURPOSE       : Collects Proxmox 'data2' pool free space for PRTG via JSON.
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
# This script queries the Proxmox VE storage manager (`pvesm`) to retrieve the status
# of storage pools. It specifically filters for the storage pool named "data2",
# extracts the total and used disk space, calculates the percentage of free space,
# and then formats this information into a JSON structure that the PRTG Network Monitor
# can directly consume through its "SSH Script Advanced" sensor type.
#
# The script incorporates strict mode (`set -euo pipefail`), basic error logging to stderr,
# dependency checking, and a standardized structure.
#
# Key Workflow / Functions:
# - Sets Bash strict mode (`set -euo pipefail`).
# - Defines global script information variables (`SCRIPT_NAME`, `SCRIPT_DIR`, `SCRIPT_PID`).
# - Defines helper functions: `log_error` (for stderr logging), `usage` (displays help),
#   `check_dependencies` (verifies required tools), `main` (core logic).
# - Parses command-line arguments (only `-h` for help is currently supported).
# - Checks for required command dependencies (`pvesm`, `awk`, `date`, etc.).
# - Executes the `main` function:
#   - Runs `pvesm status` to get storage pool information, capturing stderr.
#   - Uses `awk` to filter the output for the line corresponding to the "data2" storage pool.
#   - Handles errors if `pvesm` fails or the "data2" pool is not found, outputting PRTG error JSON.
#   - Parses the total size (bytes) and used size (bytes) from the filtered line.
#   - Validates that extracted sizes are numeric.
#   - Calculates the free space as a percentage: `100 - (used * 100 / total)`.
#   - Handles the edge case where total space is zero to prevent division by zero errors.
#   - Outputs the result as a JSON payload structured according to PRTG's requirements
#     (`{"prtg": {"result": [...]}}`) to standard output.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY (Optional)
# =========================================================================================
# - **Simplicity:** Aims for straightforward logic focused on the single task.
# - **Robustness:** Includes basic error handling for command failures and missing data.
# - **Compatibility:** Produces JSON output specifically formatted for PRTG SSH Advanced sensors.
# - **Readability:** Uses clear variable names and comments. Structured with functions.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - Proxmox VE Administrators using PRTG Network Monitor.
# - IT Staff responsible for monitoring Proxmox storage health.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x proxmox_check_storage_data2.sh`
# - Proxmox VE: The script must be run by a user with sufficient permissions to execute
#   the `pvesm status` command on the Proxmox VE host (often requires root or a user
#   in specific PVE groups, like PVEAuditor if only read access is needed).
#
# **Basic Syntax:**
#   `/path/to/proxmox_check_storage_data2.sh [options]`
#
# **Options:**
#   -h    Display help message (this usage section) and exit.
#
# **Arguments:**
#   None. The target storage pool ("data2") is hardcoded within the script.
#
# **Intended Execution (PRTG):**
# - This script is designed to be executed remotely by PRTG using the "SSH Script Advanced" sensor.
# - Place the script on the target Proxmox VE server (e.g., in `/etc/prtg/scripts/`).
#
# **Example PRTG Sensor Setup:**
# - Sensor Type: SSH Script Advanced
# - Script: `/etc/prtg/scripts/proxmox_check_storage_data2.sh` (or the full path where placed)
# - Parameters: (leave empty)
# - Authentication: Use credentials for a user that can run `pvesm status`.
# - Result Handling: Use "JSON" result handling.
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - `/usr/local/sbin/` (if requires root/specific group)
# - `/etc/prtg/scripts/` (if using PRTG standard custom script locations)
# - User home directory `~/bin/` (if run as a specific non-root user)
#
# **Manual Setup:**
# 1. Copy the script to the chosen location on the Proxmox VE server.
# 2. Set appropriate ownership (e.g., `chown root:root /usr/local/sbin/proxmox_check_storage_data2.sh`).
# 3. Set executable permissions (e.g., `chmod 750 /usr/local/sbin/proxmox_check_storage_data2.sh`).
# 4. Ensure dependencies (see below) are met.
# 5. Test run manually: `/path/to/proxmox_check_storage_data2.sh` (check JSON output and stderr for errors).
# 6. Configure the PRTG sensor.
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: The Bourne-Again SHell interpreter. Script uses bashisms (`set -eou pipefail`, `<<<`, `[[ ]]`, `read -r`).
#
# **Required System Binaries/Tools:**
# - `pvesm`: The Proxmox VE storage manager command-line tool (part of Proxmox VE).
# - `awk`: Standard Unix text processing utility (used for filtering and parsing).
# - `coreutils`: Provides `date`, `echo`, `basename`, `dirname`, `cd`.
# - `bash builtins`: `read`.
#
# **Operating System:**
# - Designed specifically for Proxmox Virtual Environment (PVE).
#
# **Environment Variables Used:**
# - None directly used by the script logic, but `PATH` is required to find commands.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): Used *exclusively* for the final JSON payload required by PRTG.
# - Standard Error (stderr): Used for all informational messages, warnings, errors, and debug output via the `log_error` function.
#                            PRTG typically captures stderr for sensor status messages/debugging.
# - Dedicated Log File: No. Logging goes to stderr.
# - System Log (syslog/journald): No.
#
# **Log Format (stderr):**
# - `[YYYY-MM-DD HH:MM:SS TZ] [ERROR] [script_name:PID] - Error message string`
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - On Success: Outputs a JSON formatted string required by the PRTG SSH Script Advanced sensor.
#   Example:
#   ```
#   {
#    "prtg": {
#     "result": [
#      {
#       "channel": "data2 Free",
#       "value": 85,
#       "unit": "%"
#      }
#     ]
#    }
#   }
#   ```
#   (Where `85` is the calculated percentage of free space)
# - On Failure (handled error): Outputs a PRTG error JSON structure.
#   Example (Pool not found):
#   ```
#   {"prtg": {"error": 1, "text": "Storage pool 'data2' not found"}}
#   ```
#   Example (pvesm failed):
#   ```
#   {"prtg": {"error": 1, "text": "Failed to execute pvesm status (Code: 127)"}}
#   ```
#
# **Standard Error (stderr):**
# - Errors, warnings, and debug messages generated by the script (using `log_error`).
# - Any direct error output from called commands like `pvesm` (if redirection is imperfect or command fails before redirection).
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success - Valid JSON output generated to stdout.
# - 1: General Error - `pvesm` command failed, target storage not found, argument parsing error, help displayed.
# - 2: Dependency Error - A required command (`pvesm`, `awk`, `date`, etc.) was not found.
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** PRTG sensor shows error "Script execution failed", "No response", or displays stderr messages.
#   **Resolution:** Check permissions for the SSH user on the Proxmox host. Ensure the user can run `pvesm status`. Verify required commands (`awk`, `date`) are in the user's `PATH`. Check Proxmox system logs or run script manually on the host to see stderr output.
# - **Issue:** PRTG shows error "Storage pool 'data2' not found".
#   **Resolution:** Verify the storage pool named "data2" exists, is active, and the name matches *exactly* (case-sensitive) using `pvesm status` on the Proxmox host.
# - **Issue:** PRTG shows "Failed to execute pvesm status (Code: X)".
#   **Resolution:** Investigate why `pvesm status` is failing. Check Proxmox services (`systemctl status pve*`), disk health, and system logs on the PVE host. The exit code (X) might give clues.
# - **Issue:** PRTG shows "Failed to parse numeric values..." on stderr.
#   **Resolution:** The output format of `pvesm status` might have changed, or the storage is reporting non-numeric values for size/used space. Check the raw output of `pvesm status`. The script will report 0% free in this case.
# - **Issue:** Incorrect percentage reported (e.g., always 0% or 100%).
#   **Resolution:** Check if `pvesm status` is reporting zero total space or zero used space for "data2". Investigate the underlying storage issue on the Proxmox host. A zero total space will result in 0% free reported by the script.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes a Bash environment (version supporting `set -euo pipefail`, `<<<`, etc.).
# - Assumes required dependencies (`pvesm`, `awk`, `coreutils`) are installed and in the execution `$PATH`.
# - Assumes the Proxmox VE storage pool named exactly "data2" exists and is configured.
# - Assumes network connectivity between PRTG probe and Proxmox host for SSH execution.
# - Assumes the SSH user configured in PRTG has execute permissions for the script and permissions to run `pvesm status`.
# - Assumes the output format of `pvesm status` includes storage name (field 1), total bytes (field 4), and used bytes (field 5).
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Requires access to run `pvesm status`, which may necessitate root or specific PVE user roles (e.g., `PVEAuditor`) configured on the Proxmox host. Use the least privilege necessary for the PRTG SSH user.
# - **Input Sanitization:** The script processes output from `pvesm status`, a system command. It does not take external input other than the `-h` flag. The storage name "data2" is hardcoded.
# - **Sensitive Data:** The script does not handle passwords, API keys, or other sensitive data directly. Authentication is managed by PRTG via SSH (use key-based authentication for better security).
# - **Dependencies:** Relies on standard system tools (`awk`, `date`) and the Proxmox-specific `pvesm`. Ensure these are from trusted sources (i.e., system package manager).
# - **Error Message Verbosity:** Error messages logged to stderr may contain system details (like PID, script name). Ensure stderr is handled appropriately by PRTG and not exposed unintentionally.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is contained within this script's header comments.
# - Run `/path/to/proxmox_check_storage_data2.sh -h` for basic usage info.
# - No external documentation or man page is provided.
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Report issues via the script's repository (if provided) or directly to the author's contact email.
# =========================================================================================

# =========================================================================================
# SCRIPT EXECUTION ENVIRONMENT & CONFIGURATION
# =========================================================================================

# --- Bash Strict Mode ---
# -e: Exit immediately if a command exits with a non-zero status.
# -u: Treat unset variables and parameters as an error during expansion.
# -o pipefail: The return value of a pipeline is the status of the last command
#              to exit with a non-zero status, or zero if none fail.
set -euo pipefail

# --- Script Information ---
# Provides the script name and the directory it resides in.
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_PID=$$

# =========================================================================================
# FUNCTION DEFINITIONS
# =========================================================================================

# --- Error Logging Function ---
# Description: Prints an error message to standard error (stderr).
# Usage: log_error "Error message string"
log_error() {
    local message="$1"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z")
    echo "[${timestamp}] [ERROR] [${SCRIPT_NAME}:${SCRIPT_PID}] - ${message}" >&2
}

# --- Usage/Help Function ---
# Description: Displays help information based on header comments and exits.
usage() {
    # Extracts the USAGE section from this script's header.
    local usage_text
    usage_text=$(sed -n '/^# ===+ USAGE ===+$/,/^# ===+ .* ===+$/{ /# ===+ .* ===+$/!p; }' "${BASH_SOURCE[0]}" | sed 's/^# //; s/\[your_script_name.sh\]/'"${SCRIPT_NAME}"'/g')
    cat << EOF >&2
${usage_text}

Options:
  -h    Display this help message and exit.
EOF
    exit 1 # Exit with a non-zero status after showing help
}

# --- Dependency Check Function ---
# Description: Checks if required command-line utilities are installed and executable.
# Exits with error if a dependency is missing.
check_dependencies() {
    local missing_deps=0
    for cmd in pvesm awk date echo read; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command '${cmd}' not found in PATH. Please ensure it is installed and accessible."
            missing_deps=1
        fi
    done
    if [[ ${missing_deps} -ne 0 ]]; then
        exit 2 # Exit code for dependency errors
    fi
}

# --- Main Logic Function ---
# Description: Contains the core functionality: fetching storage data, calculating
#              free space, and formatting the output as JSON for PRTG.
main() {
    local target_storage="data2" # Define the target storage pool name
    local output
    local pvesm_exit_code=0

    # Execute pvesm status and capture output, handle potential errors
    output=$(pvesm status 2> >(log_error "pvesm command stderr:")) || pvesm_exit_code=$?
    if [[ ${pvesm_exit_code} -ne 0 ]]; then
        log_error "Command 'pvesm status' failed with exit code ${pvesm_exit_code}."
        # Output minimal error JSON for PRTG
        echo "{\"prtg\": {\"error\": 1, \"text\": \"Failed to execute pvesm status (Code: ${pvesm_exit_code})\"}}"
        exit 1 # General error exit code
    fi

    # Filter for the target storage pool using awk
    local filtered_output
    filtered_output=$(echo "$output" | awk -v storage="$target_storage" '$1 == storage {print $1, $4, $5}') # Fields: Name, Total, Used

    # Check if the target storage pool was found
    if [[ -z "$filtered_output" ]]; then
        log_error "Storage pool '${target_storage}' not found in 'pvesm status' output."
        # Output specific error JSON for PRTG
        echo "{\"prtg\": {\"error\": 1, \"text\": \"Storage pool '${target_storage}' not found\"}}"
        exit 1 # General error exit code (or a specific one if desired)
    fi

    # Begin constructing the JSON output for PRTG.
    # IMPORTANT: Only this JSON structure should go to standard output (stdout).
    # All logs/errors must go to standard error (stderr).
    echo "{"
    echo " \"prtg\": {"
    echo "  \"result\": ["

    # Process the filtered line (should only be one line for the specific storage)
    local pool_name total_space used_space
    read -r pool_name total_space used_space <<< "$filtered_output"

    local percent_free=0 # Default value

    # Validate extracted numeric values
    if ! [[ "$total_space" =~ ^[0-9]+$ ]] || ! [[ "$used_space" =~ ^[0-9]+$ ]]; then
        log_error "Failed to parse numeric values for total/used space for pool '${pool_name}'. Got Total='${total_space}', Used='${used_space}'."
        # Fallback: report 0% free, but don't exit here, let PRTG show the channel with 0
    else
        # Calculate the percentage of free storage space, handling division by zero.
        if [[ ${total_space} -gt 0 ]]; then
            # Bash integer arithmetic: 100 - (used * 100 / total)
            percent_free=$(( 100 - (used_space * 100 / total_space) ))
        else
            log_error "Total space for storage pool '${pool_name}' reported as zero. Cannot calculate percentage. Defaulting to 0% free."
            # percent_free remains 0
        fi
    fi

    # Output the channel data in JSON format.
    echo "   {"
    # Channel name displayed in PRTG.
    echo "    \"channel\": \"${pool_name} Free\","
    # The calculated free space percentage.
    echo "    \"value\": ${percent_free},"
    # Unit for the value.
    echo "    \"unit\": \"%\""
    # Close the JSON object for this channel.
    echo "   }"

    # Close the "result" array.
    echo "  ]"
    # Close the "prtg" object.
    echo " }"
    # Close the root JSON object.
    echo "}"
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# --- Argument Parsing ---
# Simple check for -h or --help
if [[ $# -gt 0 ]]; then
    if [[ "$1" == "-h" || "$1" == "--help" ]]; then
        usage
    else
        log_error "Unknown argument: $1"
        usage
    fi
fi

# --- Check Dependencies ---
check_dependencies

# --- Execute Main Logic ---
# All setup complete, call the main function to perform the core task.
main

# --- Exit ---
# Script exits implicitly with the status of the last command (main function's JSON echo)
# or explicitly via `exit` codes within functions upon error.
# A successful run should implicitly exit 0 after the final JSON echo.

# =========================================================================================
# --- End of Script ---
