#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : proxmox_check_storage_local.sh
# PURPOSE       : Collects Proxmox 'local' pool free space for PRTG via JSON.
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
# This script retrieves the status of Proxmox VE storage pools using the native 'pvesm'
# command. It specifically filters for the storage pool named "local", extracts its total
# and used space, calculates the percentage of free space, and formats this information
# into a JSON structure suitable for consumption by a PRTG Custom SSH Sensor (Advanced).
#
# Key Workflow / Functions:
# - Sets Bash strict mode (`set -euo pipefail`) for robustness.
# - Defines utility functions (`log_error`, `check_commands`, `cleanup`).
# - Sets up a `trap` to ensure cleanup runs on exit/interrupt.
# - Executes `pvesm status` to get storage information.
# - Uses `awk` to filter and extract data specifically for the "local" storage ID.
# - Handles cases where 'local' storage might not be found, outputting a PRTG error JSON.
# - Calculates the free space percentage using Bash integer arithmetic, handling division by zero.
# - Constructs a JSON output string conforming to PRTG's required format using `printf`.
# - Outputs the JSON to standard output (stdout).
# - Logs errors to standard error (stderr) using `log_error`.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Simplicity:** Focuses on a single task (checking 'local' storage) with minimal complexity.
# - **Robustness:** Incorporates Bash strict mode (`set -euo pipefail`), dependency checks,
#   and error handling (e.g., storage not found, division by zero) with informative stderr logs.
# - **Compatibility:** Produces output directly consumable by PRTG SSH Script Advanced sensors.
# - **Efficiency:** Uses standard Linux tools (`awk`, `pvesm`) efficiently for data extraction.
# - **Automation:** Designed for unattended execution via monitoring systems like PRTG.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - Proxmox VE System Administrators
# - IT Monitoring Teams using PRTG Network Monitor
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x proxmox_check_storage_local.sh`
# - Proxmox VE permissions: The user executing this script (e.g., the PRTG probe user via SSH)
#   must have sufficient permissions to run the `pvesm status` command on the Proxmox node.
#   Typically, membership in the `PVEAuditor` group or similar is sufficient and recommended
#   over using root.
#
# **Basic Syntax:**
# The script is designed to be run without command-line options or arguments:
#   `./proxmox_check_storage_local.sh`
#
# **Options:**
#   None. This script does not accept command-line options.
#
# **Arguments:**
#   None. This script does not accept positional arguments.
#
# **Common Examples:**
# 1. Execute directly on the Proxmox host:
#    `/path/to/proxmox_check_storage_local.sh`
#
# **PRTG Integration:**
# - Deploy this script as an "SSH Script Advanced" sensor within PRTG.
# - Configure the sensor on the PRTG probe to execute this script on the target Proxmox host via SSH
#   using appropriate credentials (preferably key-based authentication for a dedicated monitoring user).
# - The script's standard output (stdout) provides the JSON data PRTG expects. PRTG will parse this JSON.
# - PRTG will typically show a sensor error if the script exits non-zero or if the JSON output
#   contains `"error": 1`.
#
# **Automation (Cron - Optional):**
# While designed for PRTG, you could run it via cron for logging, though PRTG is the intended consumer.
# Example (logging output, adjust path):
# `*/5 * * * * /usr/local/sbin/proxmox_check_storage_local.sh >> /var/log/pve_local_storage.log 2>&1`
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - Place the script on the target Proxmox VE node(s) in a suitable directory accessible
#   by the monitoring user (e.g., the user PRTG logs in as via SSH).
# - Good choices include `/usr/local/sbin/` (system-wide, requires root to place) or a
#   dedicated directory like `/opt/prtg/scripts/` (create if needed, ensure user permissions).
#
# **Manual Setup:**
# 1. Copy the script to the chosen location on the Proxmox host.
# 2. Set appropriate ownership (e.g., `chown root:root /usr/local/sbin/proxmox_check_storage_local.sh` or
#    `chown monitoringuser:monitoringgroup /opt/prtg/scripts/proxmox_check_storage_local.sh`).
# 3. Set executable permissions: `chmod 755 /usr/local/sbin/proxmox_check_storage_local.sh` or
#    `chmod 750 /opt/prtg/scripts/proxmox_check_storage_local.sh`.
# 4. Ensure dependencies (`pvesm`, `awk`, `date`, `basename`) are present (standard on PVE).
# 5. Test execution manually as the monitoring user: `sudo -u <monitoring_user> /path/to/script.sh`
#
# **Integration:**
# - **PRTG Sensor:** Add an "SSH Script Advanced" sensor in PRTG, point it to this script's
#   full path on the Proxmox host, and configure SSH credentials. No script parameters are needed.
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: The Bourne-Again SHell interpreter. Uses Bash features (`set -o pipefail`, `read`, `<<<`).
#
# **Required System Binaries/Tools:**
# - `pvesm`: The Proxmox VE storage management command-line tool (part of PVE).
# - `awk`: Standard text processing utility (provided by `gawk` or `mawk`, part of `coreutils`).
# - `coreutils`: Provides `date`, `basename`, `echo`, `read`. Essential Linux package.
# - `command`: Bash built-in used for checking command existence.
#
# **Operating System Compatibility:**
# - Designed specifically for Proxmox VE distributions (tested on PVE 7.x, 8.x).
# - May function on other Debian-based systems if `pvesm` is available, but primarily targets PVE.
#
# **Environment Variables Used:**
# - `PATH`: Standard variable, used implicitly to find commands (`pvesm`, `awk`, `date`). Ensure these
#   are in the PATH for the executing user (especially relevant for SSH sessions or cron jobs).
# - No other environment variables are directly consumed by the script logic.
#
# **System Resource Requirements:**
# - Minimal: The script is lightweight, executing only a few commands. CPU, memory, and disk usage
#   are negligible. Network usage is limited to the `pvesm` command's internal operation (if any).
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): Exclusively used for the PRTG-compatible JSON output upon success,
#   or an error JSON if 'local' storage is not found.
# - Standard Error (stderr): Used for error messages generated by the `log_error` function
#   (e.g., dependency missing, command failure, division by zero, parsing errors). PRTG
#   may capture stderr content in sensor messages on error.
# - Dedicated Log File: No. The script does not write to a dedicated log file.
# - System Log (syslog/journald): No. The script does not interact with syslog.
#
# **Log Format (stderr):**
# - `[YYYY-MM-DD HH:MM:SS ZONE] [ERROR] [script_name:PID] - Message`
# - Example: `[2025-04-20 16:30:00 WIB] [ERROR] [proxmox_check_storage_local.sh:12345] - Required command 'pvesm' not found...`
#
# **Log Levels:**
# - Only `ERROR` level messages are explicitly logged to stderr via `log_error`.
# - No configurable log levels are implemented.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - On Success: A JSON formatted string conforming to PRTG requirements.
#   - Format Example:
#     ```
#     {
#      "prtg": {
#       "result": [
#        {
#         "channel": "local Free",
#         "value": 50,
#         "unit": "%"
#        }
#       ]
#      }
#     }
#     ```
#     (Where "50" is the calculated percentage of free space for the 'local' storage pool).
# - On "Local Storage Not Found": A specific error JSON structure.
#   - Format Example:
#     ```
#     { "prtg": { "result": [], "error": 1, "text": "Storage pool local not found" } }
#     ```
#
# **Standard Error (stderr):**
# - Used exclusively for error messages (see LOGGING MECHANISM).
# - Examples: Dependency errors, `pvesm` command execution failures, parsing issues, division by zero warnings.
#
# **Generated/Modified Files:**
# - None. The script does not create, modify, or delete any files (excluding temporary system resources used by commands it calls).
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success - JSON output generated (either data or the "not found" error JSON). The script
#   considers "not found" a successful execution run, signaling the state via JSON.
# - 1: General Error - Catch-all for unexpected failures, e.g., `pvesm` command fails, parsing fails.
# - 2: Dependency Error - Required command (`pvesm`, `awk`) not found.
# - Non-zero exit codes from trapped signals (INT, TERM, HUP) via the `cleanup` function.
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** PRTG sensor shows "Script Error", "Execution Error", or similar.
#   **Resolution:**
#     1. Manually SSH to the Proxmox host *as the same user PRTG uses*.
#     2. Execute the script with its full path: `/path/to/proxmox_check_storage_local.sh`.
#     3. Check stderr for `[ERROR]` messages (e.g., command not found, permission denied from `pvesm`).
#     4. Verify script has execute permissions (`ls -l /path/to/script.sh`).
#     5. Run `pvesm status` manually as that user to check its output and permissions.
#     6. Ensure the storage pool named exactly `local` exists and is active in the `pvesm status` output.
# - **Issue:** Incorrect free space percentage reported.
#   **Resolution:**
#     1. Run `pvesm status` manually. Identify the line for `local`.
#     2. Note the Total (4th field) and Used (5th field) values in bytes.
#     3. Manually calculate `100 - (Used * 100 / Total)`. Compare with script output.
#     4. Verify the `awk` command inside the script correctly extracts these fields ($1, $4, $5).
# - **Issue:** Division by zero error in stderr log (`Total space for 'local' storage reported as 0 bytes...`).
#   **Resolution:** Check `pvesm status`. A total size of 0 for 'local' storage is unusual and indicates a PVE configuration issue. The script reports 100% free in this case but logs the anomaly.
#
# **Important Considerations:**
# - **Target Specificity:** Hardcoded to check the storage pool named exactly `local`. It will not work for other storage pools without modification.
# - **Integer Arithmetic:** Bash performs integer division for the percentage calculation. This is usually acceptable for monitoring but may differ slightly from floating-point results (e.g., 9.9% free might show as 9%).
# - **`pvesm status` Output Format:** Assumes the output format of `pvesm status` remains consistent regarding the column order (1=ID, 4=Total, 5=Used). Changes in future PVE versions could break the parsing.
# - **Idempotency:** Yes. Running the script multiple times produces the same output for the same underlying storage state. It does not change system state.
# - **Concurrency:** Safe. The script is stateless and reads system information. Running multiple instances simultaneously should not cause issues.
# - **Resource Usage:** Very low. Suitable for frequent polling by PRTG.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - The script is running on a Proxmox VE host where `pvesm` is functional.
# - The `pvesm` command is available in the system's PATH for the executing user.
# - Standard tools (`awk`, `date`, `basename`, `read`) are available and functional.
# - A storage pool with the exact identifier `local` exists and is listed in the `pvesm status` output.
# - The output format of `pvesm status` provides Storage ID, Total Bytes, and Used Bytes in columns 1, 4, and 5 respectively.
# - The user executing the script has read permissions for the `pvesm status` command output.
# =========================================================================================

# =========================================================================================
# PERFORMANCE OPTIMIZATION (Optional)
# =========================================================================================
# - Not applicable. The script performs a simple command execution and text processing sequence.
# - Performance is primarily dictated by the execution time of `pvesm status`, which is typically fast.
# - No significant optimization opportunities exist or are necessary for this script's scope.
# =========================================================================================

# =========================================================================================
# TESTING & VALIDATION (Optional)
# =========================================================================================
# - **Manual Testing:** Execute script on target PVE node as the monitoring user, verify JSON output matches `pvesm status` data. Test cases: normal usage, 'local' storage nearly full, 'local' storage nearly empty, 'local' storage temporarily unavailable (if possible).
# - **Static Analysis:** Recommended to check with `shellcheck /path/to/proxmox_check_storage_local.sh` to catch potential syntax issues or bad practices.
# - **Automated Testing:** No automated unit tests (e.g., Bats, shunit2) are provided.
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS (Optional)
# =========================================================================================
# - Parameterize storage pool name: Allow checking pools other than 'local' via a command-line argument.
# - Check multiple pools: Extend script to check and report on several or all storage pools.
# - Add additional metrics: Include total space, used space, or free space in bytes as separate channels in the JSON output.
# - Configurable warning/error thresholds: Implement logic within the script to set PRTG sensor status based on free space percentage (though PRTG's built-in limits are often preferred).
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** The script itself does not require root. The *executing user* needs permission to run `pvesm status`. **Best Practice:** Use a dedicated, non-root monitoring user (e.g., member of `PVEAuditor` group) for PRTG SSH access, granting least privilege. Avoid running PRTG sensors as root.
# - **Input Sanitization:** Not applicable. The script takes no command-line arguments or external configuration file inputs, reducing attack surface. It relies solely on the output of the system command `pvesm`.
# - **Sensitive Data Handling:** Does not handle passwords, API keys, or other credentials. SSH authentication should be handled securely by PRTG (key-based preferred).
# - **Dependencies:** Relies on standard system tools (`bash`, `awk`, `coreutils`) and the Proxmox-specific `pvesm`. Ensure these are from trusted sources (OS distribution, Proxmox). Keep the system updated.
# - **File Permissions:** Script file should have secure permissions (e.g., 750 or 755) and appropriate ownership (e.g., `root:root` or `monitoringuser:monitoringgroup`).
# - **External Command Execution:** Executes `pvesm status` and `awk`. These commands are called with static arguments, not constructed from user input, mitigating command injection risks.
# - **Network Exposure:** The script itself does not initiate network connections. `pvesm` might interact locally with PVE services.
# - **Error Message Verbosity:** Error messages logged to stderr are intended for administrators and do not contain sensitive data. They include script name, PID, and error details.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is contained within this script's header comments.
# - No external README, Wiki, or man page is provided.
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Report issues via the script's repository (if available at REPOSITORY link above) or directly to the author's contact email.
# =========================================================================================

# =========================================================================================
# SCRIPT EXECUTION ENVIRONMENT & CONFIGURATION
# =========================================================================================

# --- Bash Strict Mode ---
# Exit immediately if a command exits with a non-zero status. Prevents errors from snowballing.
set -e
# Treat unset variables and parameters as an error during expansion. Catches typos and unset variables.
set -u
# The return value of a pipeline is the status of the last command to exit with a non-zero status,
# or zero if no command exited with a non-zero status. Ensures pipeline failures are detected.
set -o pipefail

# --- Script Information ---
# Script name derived reliably from invocation path, handles symlinks.
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
# Process ID of the current script instance. Useful for logging/debugging.
readonly SCRIPT_PID=$$

# --- Global Variables ---
# This script currently does not require external configuration or global state variables beyond defaults.

# =========================================================================================
# FUNCTION DEFINITIONS
# =========================================================================================

# --- Error Logging Function ---
# Description: Logs a standardized error message to standard error (stderr).
# Includes timestamp, script name, PID for context.
# Usage: log_error "Descriptive error message"
log_error() {
    # Capture the error message passed as the first argument.
    local message="$1"
    # Get the current timestamp in a standard format, including timezone.
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z")
    # Print the formatted error message to stderr.
    echo "[${timestamp}] [ERROR] [${SCRIPT_NAME}:${SCRIPT_PID}] - ${message}" >&2
}

# --- Dependency Check Function ---
# Description: Checks if required command-line utilities are installed and executable.
# Iterates through provided command names and verifies their existence in the system's PATH.
# Exits the script with status code 2 (Dependency Error) if any command is missing.
# Usage: check_commands command1 [command2 ...]
check_commands() {
    # Loop through all arguments passed to the function (command names).
    for cmd in "$@"; do
        # 'command -v' checks if the command exists (built-in, alias, function, or file in PATH).
        # Redirect output to /dev/null to suppress command path output on success.
        if ! command -v "$cmd" &> /dev/null; then
            # Log a critical error if the command is not found.
            log_error "Required command '${cmd}' not found in PATH. Please ensure it is installed and accessible."
            # Exit the script with code 2, indicating a missing dependency.
            exit 2
        fi
    done
}

# --- Cleanup Function ---
# Description: Performs cleanup tasks before the script exits.
# This function is executed automatically via the 'trap' command on exit or signal.
# Currently empty as no temporary files or resources are created, but provides a hook for future needs.
# Usage: Automatically called by trap.
cleanup() {
    # Capture the exit status of the command that triggered the trap (or 0 if exiting normally).
    local exit_status=$?
    # Add cleanup actions here if the script creates temporary files, lock files, background processes, etc.
    # Example: rm -f /tmp/myfile.$$
    # Keep cleanup actions simple and robust, as they might run during error conditions.
    # Exit the script with the original exit status that triggered the cleanup.
    exit ${exit_status}
}

# --- Trap Setup ---
# Register the 'cleanup' function to be executed automatically on:
# EXIT: Normal script termination (end of script or explicit 'exit' command).
# INT: Interrupt signal (usually Ctrl+C).
# TERM: Termination signal (usually from 'kill' command).
# HUP: Hangup signal.
# This ensures cleanup happens regardless of how the script terminates.
trap cleanup EXIT INT TERM HUP

# --- Main Logic Function ---
# Description: Contains the core workflow of the script:
# 1. Check dependencies.
# 2. Retrieve storage data for the 'local' pool using 'pvesm'.
# 3. Parse the retrieved data.
# 4. Calculate the percentage of free space.
# 5. Generate and output the monitoring data in PRTG-compatible JSON format.
# Usage: Called once in the script execution flow.
main() {
    # Declare local variables used within this function.
    local pvesm_output
    local pool_name total_space used_space percent_free

    # --- 1. Check Dependencies ---
    # Ensure required external commands are available before proceeding.
    check_commands pvesm awk

    # --- 2. Retrieve Storage Data ---
    # Attempt to run 'pvesm status' and filter for the 'local' storage pool.
    # Extract the pool name ($1), total bytes ($4), and used bytes ($5).
    # If the pipeline fails (e.g., pvesm command error), 'set -e' will trigger script exit via trap.
    if ! pvesm_output=$(pvesm status | awk '$1 == "local" {print $1, $4, $5}'); then
        # This part might not be reached if 'set -e' is active and the command fails,
        # but provides clarity if 'set -e' were disabled for specific error handling.
        log_error "Failed to execute 'pvesm status' or process its output."
        exit 1 # Exit with a general error code.
    fi

    # Check if the 'local' storage pool was found by awk. If not, pvesm_output will be empty.
    if [[ -z "${pvesm_output}" ]]; then
        # Log the issue to stderr for system administrators.
        log_error "Storage pool 'local' not found in 'pvesm status' output."
        # Output a specific JSON structure that PRTG can interpret as an error state
        # for the sensor, rather than making the script itself fail.
        # Includes "error": 1 flag and descriptive text.
        echo '{ "prtg": { "result": [], "error": 1, "text": "Storage pool local not found" } }'
        # Exit the script successfully (status 0) because the script ran correctly,
        # but the monitored item was not found. PRTG will show the error based on the JSON.
        exit 0
    fi

    # --- 3. Parse Extracted Data ---
    # Use 'read' to safely assign the space-separated fields from pvesm_output to variables.
    read -r pool_name total_space used_space <<< "${pvesm_output}"

    # --- 4. Calculate Free Space Percentage ---
    # Validate that the extracted total and used space values are non-negative integers.
    if ! [[ "${total_space}" =~ ^[0-9]+$ ]] || ! [[ "${used_space}" =~ ^[0-9]+$ ]]; then
         log_error "Failed to parse numeric values for total ('${total_space}') or used ('${used_space}') space from pvesm output."
         exit 1 # Exit with a general error code.
    fi

    # Calculate percentage, handling the case where total_space might be 0.
    if [[ ${total_space} -gt 0 ]]; then
        # Standard percentage calculation using Bash integer arithmetic.
        # Calculates used percentage first, then subtracts from 100.
        percent_free=$(( 100 - (used_space * 100 / total_space) ))
    else
        # If total space is zero, define free space percentage as 100% (or 0% could also be valid).
        # Log this edge case as an error for visibility.
        percent_free=100
        log_error "Total space for 'local' storage reported as 0 bytes. Reporting 100% free."
    fi

    # --- 5. Generate PRTG JSON Output ---
    # Use 'printf' to construct the JSON output string. This is generally safer and more
    # controllable than multiple 'echo' commands, especially regarding quoting and newlines.
    # The format string defines the JSON structure, with placeholders (%s for string, %d for decimal integer).
    # The subsequent arguments fill these placeholders. The double percent '%%' prints a literal '%'.
    printf '{
 "prtg": {
  "result": [
   {
    "channel": "%s Free",
    "value": %d,
    "unit": "%%"
   }
  ]
 }
}' "${pool_name}" "${percent_free}"

    # Add a final newline character to the standard output.
    # While printf doesn't add one by default, it's good practice for command-line tools.
    echo ""
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# Execute the main logic function, which orchestrates all the script's tasks.
main

# If the script reaches this point, 'main' has completed successfully.
# The 'trap cleanup EXIT' command ensures the cleanup function runs and the script
# exits with status 0. No explicit 'exit 0' is needed here.

# =========================================================================================
# --- End of Script ---
