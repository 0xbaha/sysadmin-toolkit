#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : check_storage_speed.sh
# PURPOSE       : Checks drive type, measures R/W speed, generates CSV report.
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
# This script checks all storage devices (HDD or SSD) on the server and attempts
# to measure the read and write speed using the `dd` command where possible.
# It identifies the device type (HDD/SSD) by checking the rotational flag in sysfs.
# If all existing mount points for a device are unsuitable (e.g., read-only, insufficient space),
# the script will attempt to create a temporary directory, mount the device directly,
# perform the tests, and then clean up the temporary mount.
# The results, including device name, type, write speed, and read speed,
# are saved to a CSV file with a timestamp in its name. Errors and execution details
# are logged to a separate file (`storage_check_errors.log`).
#
# Key Functions:
# - Detect block storage devices using `lsblk`.
# - Determine device type (HDD/SSD) via `/sys/block/<device>/queue/rotational`. # Corrected path
# - Check for required command-line tools (`lsblk`, `dd`, `grep`, `awk`, `mount`, etc.) and attempt installation via `apt-get` if missing.
# - Check for sufficient permissions (requires root/sudo).
# - Identify suitable writable mount points with sufficient space for testing (checks device and partition mounts).
# - If needed, create a temporary mount point (e.g., `/mnt/temp_<device>_<PID>`) for testing. # Updated path example
# - Perform write speed test using `dd` with `if=/dev/zero` and `oflag=direct`.
# - Perform read speed test using `dd` with `of=/dev/null` and `iflag=direct`.
# - Clean up temporary test files (`.testfile_storage_speed_<PID>`) and mount points. # Updated file example
# - Log execution progress and errors to `storage_check_errors.log` (configurable via LOG_FILE variable).
# - Output results to a timestamped CSV file (e.g., `storage_speed_report_YYYY-MM-DD_HH-MM-SS.csv`).
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Automation:** Aims to automatically test all relevant block devices found.
# - **Robustness:** Includes checks for root permissions, required dependencies, mount point writability, and available space. Uses logging for diagnostics. Implements `set -euo pipefail`.
# - **Flexibility:** Attempts temporary mounting if existing mount points are unsuitable. Checks device and partition mounts.
# - **Clarity:** Outputs results clearly to both console (with colors if interactive) and a structured CSV file. Uses verbose logging.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - System Administrators
# - DevOps Engineers
# - IT Support Teams
# - Performance Analysts
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x check_storage_speed.sh`
# - Requires root/sudo privileges for mounting devices, potentially installing packages (`apt-get`), accessing sysfs, and potentially writing to `/mnt`.
#
# **Basic Syntax:**
# `sudo ./check_storage_speed.sh`
#
# **Options:**
# - None currently implemented via command-line flags. Configuration via internal variables (LOG_DIR, REPORT_DIR, DD parameters).
#
# **Arguments:**
# - None.
#
# **Common Examples:**
# 1. Basic execution:
#    `sudo ./check_storage_speed.sh`
#
# **Advanced Execution (e.g., Cron or Systemd):**
# - Example cron job running weekly Sunday at 2 AM:
#   `0 2 * * 0 /path/to/check_storage_speed.sh > /var/log/storage_speed_check.cron.log 2>&1`
#   (Ensure the script path is correct, `sudo` is handled if needed, and cron environment has necessary permissions/PATH).
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - Place the script in a standard administrative directory, e.g., `/usr/local/sbin/` or `/opt/scripts/`.
#
# **Manual Setup:**
# 1. Place the script in the chosen location.
# 2. Set ownership if needed (e.g., `sudo chown root:root /usr/local/sbin/check_storage_speed.sh`).
# 3. Make the script executable (`sudo chmod +x /usr/local/sbin/check_storage_speed.sh`).
# 4. Ensure all dependencies are met (see below). Script attempts auto-install via `apt-get`.
# 5. Run manually with `sudo`.
#
# **Integration:**
# - **Cron Job:** Configure a cron job for scheduled execution. Ensure correct path and permissions. Redirect output appropriately.
# - **Systemd Service/Timer:** Can be integrated for more complex scheduling or dependency management.
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: The Bourne-Again SHell interpreter.
#
# **Required System Binaries/Tools:**
# - `lsblk`: To list block devices and their mount points. (Package: `util-linux`)
# - `dd`: To measure read/write speed. (Package: `coreutils`)
# - `grep`: For pattern searching (uses `-P` for Perl regex). (Package: `grep`)
# - `awk`: For text processing (parsing `df` output). (Package: `gawk` preferred)
# - `mount`: To mount devices temporarily. (Package: `util-linux`)
# - `umount`: To unmount temporary mounts. (Package: `util-linux`)
# - `mkdir`: To create temporary mount directories. (Package: `coreutils`)
# - `rmdir`: To remove temporary mount directories. (Package: `coreutils`)
# - `touch`: To test writability. (Package: `coreutils`)
# - `rm`: To remove test files. (Package: `coreutils`)
# - `df`: To check available disk space. (Package: `coreutils`)
# - `cat`: To read device type information from sysfs. (Package: `coreutils`)
# - `date`: For timestamping logs and output files. (Package: `coreutils`)
# - `basename`: Used internally for SCRIPT_NAME. (Package: `coreutils`)
# - `dirname`: Used internally for SCRIPT_DIR. (Package: `coreutils`)
# - `sort`: Used internally for sorting mount points. (Package: `coreutils`)
# - `sed`: Used internally for parsing `df` output. (Package: `sed` or part of `coreutils`)
# - `command`: Bash built-in.
# - `sudo` (if not run as root): Used internally for `apt-get` operations.
# - `apt-get` (Optional, for auto-install): Package manager used if dependencies are missing on Debian/Ubuntu systems.
#
# **Setup Instructions (if needed):**
# - The script attempts to install missing tools using `sudo apt-get install -y --no-install-recommends <package(s)>` on Debian/Ubuntu systems.
# - On other distributions (e.g., RHEL/CentOS/Fedora), install dependencies manually using `yum` or `dnf`:
#   `sudo yum install util-linux coreutils grep gawk mount procps-ng sed` (adjust package names as needed).
# - Check tool availability: `command -v lsblk && command -v dd && ...`
#
# **Operating System Compatibility:**
# - Designed primarily for Debian-based Linux distributions (like Ubuntu) due to `apt-get` usage for dependency installation.
# - Should work on most Linux systems with the required tools installed and standard `/sysfs` structure for device type detection. Adjust `check_and_install_requirements` function if needed for other package managers.
#
# **Environment Variables Used:**
# - `EUID`: Checked for root permissions.
# - `BASH_SOURCE`: Used to determine script path.
# - Standard variables like `PATH`.
#
# **System Resource Requirements:**
# - CPU/Memory: Generally low, but `dd` can consume significant CPU and I/O resources during tests, potentially impacting system performance.
# - Disk Space: Requires ~1GB (configurable via `DD_COUNT`/`DD_BLOCK_SIZE` constants) of free space on each successfully tested filesystem for the temporary test file. Requires minimal space for the script, log, and report files.
# - Disk I/O: High during `dd` tests.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Dedicated Log File: Yes. Path defined by `LOG_FILE` variable (Default: `./storage_check_errors.log`).
# - Standard Output (stdout): General progress messages, final summary, results per device (uses colors if interactive).
# - Standard Error (stderr): Error messages, warnings (uses colors if interactive).
#
# **Log Format:**
# - File Format: `[YYYY-MM-DD HH:MM:SS] [LEVEL] - Message`
# - Stdout/Stderr Format: Similar, but with ANSI colors if interactive.
#
# **Log Levels Implemented:**
# - `DEBUG`: Detailed internal steps (not shown by default).
# - `INFO`: General operational messages, start/stop, main steps.
# - `WARN`: Potential issues, non-critical errors (e.g., cannot write to mount point, insufficient space).
# - `ERROR`: Significant errors impacting a specific device test or setup (e.g., mount failure, dd failure, dependency missing).
# - `CRITICAL`: Severe errors causing script termination (e.g., permissions error, cannot create report file).
#
# **Log Control:**
# - Logging to file enabled by default (`LOG_TO_FILE=true`).
# - Log file path configured via `LOG_FILE` variable.
# - Verbosity not controlled by command-line flag in this version; DEBUG messages are logged to file but not usually shown on console.
#
# **Log Rotation:**
# - Not handled by the script. Use external tools like `logrotate`.
# - Example `logrotate` config (`/etc/logrotate.d/check_storage_speed`):
#   ```
#   /path/to/storage_check_errors.log {
#       weekly
#       rotate 4
#       compress
#       delaycompress
#       missingok
#       notifempty
#       create 0640 root adm # Adjust path and permissions as needed
#   }
#   ```
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Progress messages indicating which device is being processed.
# - Per-device results summary (e.g., "Device: /dev/sda | Storage Type: SSD | Speeds (Write,Read): 450.1 MB/s,480.2 MB/s").
# - Final summary message indicating completion and paths to report/log files.
#
# **Standard Error (stderr):**
# - Initial permission error message if not run as root.
# - Warnings (e.g., "Mount point ... not writable", "Insufficient space...", "Failed to unmount...").
# - Error messages (e.g., "Failed to mount...", "Failed to measure write speed...").
# - Critical error messages before exit.
# - Output uses ANSI colors if terminal is interactive and NO_COLOR is false.
#
# **Generated/Modified Files:**
# - Report File: Timestamped CSV file (e.g., `storage_speed_report_YYYY-MM-DD_HH-MM-SS.csv`). Path defined by `REPORT_FILE`.
#   - Columns: `Device,Storage Type,Write Speed,Read Speed`. Contains "N/A" if tests failed.
# - Log File: Detailed execution log (e.g., `storage_check_errors.log`). Path defined by `LOG_FILE`.
# - Temporary Test File: Hidden file created on tested mount point (e.g., `/mnt/temp_sda_12345/.testfile_storage_speed_12345`). Deleted after test.
# - Temporary Mount Directory: Created in `/mnt/` if temporary mounting is needed (e.g., `/mnt/temp_sda_12345`). Removed after test (if unmount succeeds).
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success (script completed execution, report generated).
# - 1: General/Unspecified Error (often triggered by `set -e`) or Specific Error (e.g., insufficient permissions, dependency install failure, critical mount failure, cannot create report). Individual device test failures log errors and report "N/A" but don't typically cause non-zero exit unless no devices could be tested or a critical setup step failed.
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** "Error: This script requires root privileges..."
#   **Resolution:** Run using `sudo ./check_storage_speed.sh`.
# - **Issue:** "CRITICAL ... Required command '...' not found." or "ERROR: 'apt-get' not found..."
#   **Resolution:** Manually install the missing tool(s) using the system's package manager (see DEPENDENCIES). Verify `$PATH`.
# - **Issue:** "N/A" speeds reported for a device.
#   **Resolution:** Check the log file (`storage_check_errors.log`). Common causes:
#     - No writable mount points found for the device or its partitions.
#     - Insufficient free space (<1GB default) on tested mount points.
#     - `dd` command failed (check log for `dd` output).
#     - Temporary mount attempt failed (check log for `mount` errors, verify filesystem on device using `lsblk -f`).
#     - Device is inherently read-only (e.g., CD-ROM reported as block device).
# - **Issue:** Incorrect device type (HDD/SSD/Unknown) reported.
#   **Resolution:** Verify `/sys/block/<device>/queue/rotational`. Some virtualized, USB, or RAID controllers might not report this accurately.
# - **Issue:** Script hangs or takes excessively long.
#   **Resolution:** `dd` tests on large/slow drives take time (proportional to `DD_COUNT`). Monitor system I/O (`iostat`, `iotop`). Check for underlying storage issues (`dmesg`, `smartctl`). Consider reducing `DD_COUNT` if necessary.
# - **Issue:** "Failed to unmount..." or "Failed to remove temporary directory...".
#   **Resolution:** Check log file. The mount point might still be busy (`lsof | grep /mnt/temp...`). Manual cleanup (`sudo umount /mnt/...`, `sudo rmdir /mnt/...`) might be needed.
#
# **Important Considerations / Warnings:**
# - **Requires Root:** Essential for mounting, package installation, sysfs access.
# - **Performance Impact:** `dd` tests generate significant I/O load. Run during low-usage periods on production systems.
# - **Test File Size:** Creates a ~1GB file by default. Ensure sufficient free space exists on filesystems being tested.
# - **Benchmark Accuracy:** `dd` provides a basic sequential I/O benchmark. Results are indicative and can vary based on load, filesystem, caching (though `direct` flags mitigate this), etc. Not a substitute for comprehensive storage benchmarking tools (like `fio`).
# - **Temporary Mounts:** Assumes the device contains a filesystem mountable by the kernel without specific options. May fail on devices without filesystems or with exotic types.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Running on a Linux system with `bash`.
# - Standard core utilities and required tools are available or installable via `apt-get` (or manually).
# - `/sysfs` provides device rotational status at the standard path.
# - Executed with `root` privileges (`EUID=0`).
# - `/mnt/` directory exists and is writable by root for creating temporary mount points.
# - Block devices listed by `lsblk -dno NAME` are the primary targets for testing. Associated partition mount points are also considered.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Requires `root`. Necessary for core functions. Run with `sudo`.
# - **Input Sanitization:** Device names obtained from `lsblk` are used in paths/commands. Assumes `lsblk` output is safe. Mount points from `lsblk` are also used. Temporary file/directory names include PID for uniqueness.
# - **Sensitive Data Handling:** Does not handle passwords or API keys.
# - **Dependencies:** Relies on standard system tools. `apt-get` usage assumes trusted repositories.
# - **File Permissions:** Log/Report files created likely as root:root (default umask). Temporary dirs/files created as root. Consider `umask` if specific permissions are needed.
# - **External Command Execution:** Executes system commands (`lsblk`, `dd`, `mount`, `apt-get`, etc.). Commands are generally static or use variables derived from trusted system sources (`lsblk`). `sudo apt-get install` involves running external package manager commands.
# - **Resource Usage:** High I/O during `dd`. Run responsibly.
# - **Code Integrity:** Verify script source if obtained externally (e.g., `sha256sum`).
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is contained within this script's header comments.
# - No external documentation or man page is provided.
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Report issues via the script's repository (https://baha.my.id/github) or directly to the author's contact email.
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

# --- Script Information ---
readonly SCRIPT_VERSION="1.9" # From original header, kept for consistency
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_DIR="${SOURCE_DIR}"
readonly SCRIPT_PID=$$

# --- Timestamp ---
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")

# --- Global Runtime Variables ---
# Configuration Defaults
INTERACTIVE_MODE=false # Boolean flag indicating if running in an interactive terminal
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is a terminal
NO_COLOR=false # Set to true to disable colors if needed

# Default Paths and Files
DEFAULT_LOG_DIR="${SCRIPT_DIR}" # Log directory default
DEFAULT_REPORT_DIR="${SCRIPT_DIR}" # Report directory default

# Runtime variables
LOG_DIR="${DEFAULT_LOG_DIR}"
REPORT_DIR="${DEFAULT_REPORT_DIR}"
LOG_FILE="${LOG_DIR}/storage_check_errors.log" # Default log file path
REPORT_FILE="${REPORT_DIR}/storage_speed_report_${SCRIPT_RUN_TIMESTAMP}.csv" # Timestamped report file

# dd Test Parameters (Constants)
readonly DD_BLOCK_SIZE="1M" # Block size for dd command
readonly DD_COUNT=1024 # Number of blocks to write/read (1024 * 1M = 1GB)
readonly REQUIRED_SPACE_MB=1024 # Required space in MB for the test file. Matches DD_COUNT * DD_BLOCK_SIZE (in MB)

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
# Description: Appends log messages with a timestamp to the designated log file.
# Usage: log_message LEVEL "Message"
# Levels: INFO, WARN, ERROR, DEBUG (Only shown if VERBOSE=true, not implemented here)
# Note: Simplified version inspired by template, kept close to original functionality.
log_message() {
    local level="${1:-INFO}" # Default level is INFO
    local message="${2:-}"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_line="[${timestamp}] [${level^^}] - ${message}"

    # Append to log file, ensuring directory exists (best effort)
    mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
    if [[ -w "$(dirname "${LOG_FILE}")" ]]; then
        echo "${log_line}" >> "${LOG_FILE}"
    elif [[ -z ${LOG_DIR_WRITE_WARN_SENT+x} ]]; then # Check if warning already sent
        echo -e "${COLOR_YELLOW}[${timestamp}] [WARN] - Cannot write to log directory $(dirname "${LOG_FILE}"). Logging to file may fail.${COLOR_RESET}" >&2
        LOG_DIR_WRITE_WARN_SENT=true # Prevent repeating warning
        # Try logging anyway, might work if file exists but dir check failed
        echo "${log_line}" >> "${LOG_FILE}" 2>/dev/null || true
    fi
}

# --- Initial Log Setup ---
# Description: Initializes the log file, overwriting or creating it.
setup_logging() {
    mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
    if echo "Starting log for ${SCRIPT_NAME} (PID: ${SCRIPT_PID}) at $(date)" > "${LOG_FILE}"; then
        log_message "INFO" "Log file initialized at ${LOG_FILE}."
    else
        echo -e "${COLOR_RED}ERROR: Failed to initialize log file ${LOG_FILE}. Please check permissions.${COLOR_RESET}" >&2
        # Optionally exit if logging is critical
        # exit 1
    fi
}

# --- Cleanup Function ---
# Description: Performs cleanup tasks before script exits. Called via 'trap'.
# Currently only logs the exit status. Temporary mounts are cleaned within test_device_speed.
cleanup() {
    local exit_status=$? # Capture the script's exit status
    log_message "INFO" "Script exiting with status: ${exit_status}."
    exit ${exit_status} # Ensure script exits with the original status
}

# --- Trap Setup ---
# Register the 'cleanup' function to run on specific signals and on script exit.
trap cleanup EXIT INT TERM HUP

# --- Permissions Check Function ---
# Description: Verifies if the script is executed with root privileges (UID 0). Exits if not.
check_permissions() {
    log_message "INFO" "Checking script execution permissions."
    if [ "$EUID" -ne 0 ]; then
        log_message "ERROR" "Script requires root privileges."
        echo -e "${COLOR_RED}Error: This script requires root privileges to perform all actions.${COLOR_RESET}" >&2
        echo -e "${COLOR_YELLOW}Please run the script as root or with sudo: 'sudo ./${SCRIPT_NAME}'${COLOR_RESET}" >&2
        exit 1 # Exit with status 1 indicating a permissions error.
    fi
    log_message "INFO" "Root privileges check passed."
}

# --- Dependency Check and Installation Function ---
# Description: Checks for required command-line tools. If a tool is missing,
#              attempts installation using apt-get (Debian/Ubuntu). Logs status.
check_and_install_requirements() {
    log_message "INFO" "Checking for required command-line tools."
    local requirements=("lsblk" "dd" "grep" "awk" "mount" "umount" "mkdir" "rmdir" "touch" "rm" "df" "cat" "date")
    local missing_reqs=()
    local req # Declare local variable

    for req in "${requirements[@]}"; do
        if ! command -v "$req" &> /dev/null; then
            log_message "WARN" "Missing requirement: ${req}"
            missing_reqs+=("$req")
        else
            log_message "DEBUG" "Requirement found: ${req}" # DEBUG level implies it won't show by default
        fi
    done

    if [ ${#missing_reqs[@]} -gt 0 ]; then
        log_message "INFO" "Attempting to install missing requirements: ${missing_reqs[*]}"
        # Check if apt-get exists before trying to use it
        if command -v apt-get &> /dev/null; then
            # Attempt to update package list first (optional, but good practice)
            log_message "INFO" "Running 'apt-get update'..."
            if sudo apt-get update -qq; then
                log_message "INFO" "Package list updated successfully."
            else
                log_message "WARN" "'apt-get update' failed. Installation might use outdated package versions."
            fi

            # Install missing packages
            # Construct package names (often same as command, but not always)
            # Assuming package names match command names for this example
            # Use a more robust mapping if needed (e.g., mount -> util-linux)
            local packages_to_install=("${missing_reqs[@]}") # Basic assumption
            # Refine package list if known mappings exist:
            declare -A cmd_to_pkg=( ["lsblk"]="util-linux" ["mount"]="util-linux" ["umount"]="util-linux" ["df"]="coreutils" ["touch"]="coreutils" ["rm"]="coreutils" ["mkdir"]="coreutils" ["rmdir"]="coreutils" ["cat"]="coreutils" ["date"]="coreutils" ["grep"]="grep" ["awk"]="gawk" ["dd"]="coreutils" )
            local install_list=()
            local pkg
            for req in "${missing_reqs[@]}"; do
                pkg="${cmd_to_pkg[$req]:-$req}" # Use mapping or fallback to command name
                # Avoid adding duplicates like util-linux multiple times
                if [[ ! " ${install_list[*]} " =~ " ${pkg} " ]]; then
                    install_list+=("$pkg")
                fi
            done

            log_message "INFO" "Attempting to install packages: ${install_list[*]}"
            if sudo apt-get install -y --no-install-recommends "${install_list[@]}"; then
                 log_message "INFO" "Successfully installed missing requirements."
                 # Re-verify commands after installation
                 for req in "${missing_reqs[@]}"; do
                     if ! command -v "$req" &> /dev/null; then
                         log_message "ERROR" "Failed to find command '${req}' even after attempting package installation. Please install manually."
                         # Decide whether to exit or continue
                         # exit 1
                     fi
                 done
            else
                 log_message "ERROR" "Failed to install required packages: ${install_list[*]}. Please install them manually."
                 exit 1 # Exit if essential tools cannot be installed
            fi
        else
            log_message "ERROR" "'apt-get' not found. Cannot automatically install missing requirements: ${missing_reqs[*]}. Please install them manually."
            exit 1 # Exit if dependencies are missing and cannot be auto-installed
        fi
    else
        log_message "INFO" "All required tools are installed."
    fi
}


# --- Device Type Check Function ---
# Description: Determines if a block device is HDD, SSD, or Unknown via sysfs rotational flag.
# Arguments: $1: Device name (e.g., sda, nvme0n1).
# Returns: "HDD", "SSD", or "Unknown" via stdout.
check_device_type() {
    local device=$1
    local rotational_flag_path="/sys/block/$device/queue/rotational"
    local device_type="Unknown" # Default value

    log_message "DEBUG" "Checking device type for ${device} at ${rotational_flag_path}"
    if [ -r "$rotational_flag_path" ]; then
        local type_value
        type_value=$(cat "$rotational_flag_path" 2>/dev/null)
        if [ "$type_value" == "1" ]; then
            device_type="HDD"
        elif [ "$type_value" == "0" ]; then
            device_type="SSD"
        else
            log_message "WARN" "Unknown rotational value '${type_value}' for device ${device}."
            device_type="Unknown"
        fi
    else
        log_message "WARN" "Cannot determine type for device ${device}, rotational flag not found or unreadable at ${rotational_flag_path}."
        device_type="Unknown"
    fi
    echo "${device_type}"
    log_message "DEBUG" "Device ${device} determined as: ${device_type}"
}


# --- Temporary Mount Function ---
# Description: Creates a temporary directory and mounts a block device onto it.
# Arguments: $1: Device name (e.g., sda).
# Returns: Path to the temporary mount point via stdout on success.
# Returns exit code 1 on failure.
mount_device_temporarily() {
    local device=$1
    # Define a unique temporary mount point path based on the device name and script PID
    local temp_mount_point="/mnt/temp_${device}_${SCRIPT_PID}"

    log_message "INFO" "Attempting to create temporary mount point: ${temp_mount_point}"
    if ! mkdir -p "$temp_mount_point"; then
        log_message "ERROR" "Failed to create temporary directory ${temp_mount_point} for device ${device}."
        return 1 # Return failure
    fi

    log_message "INFO" "Attempting to mount /dev/${device} to ${temp_mount_point}"
    # Attempt to mount the block device (/dev/device_name).
    # Redirects stderr to log file to capture mount errors.
    if mount "/dev/$device" "$temp_mount_point" 2>> "${LOG_FILE}"; then
        log_message "INFO" "Successfully mounted /dev/${device} to ${temp_mount_point}"
        echo "$temp_mount_point"
        return 0 # Return success.
    else
        log_message "ERROR" "Failed to mount /dev/${device} to ${temp_mount_point}. Check filesystem type, device status, and log file for mount errors."
        # Attempt to clean up the created directory if mounting failed.
        rmdir "$temp_mount_point" 2>/dev/null || log_message "WARN" "Could not remove empty temp dir ${temp_mount_point} after failed mount."
        return 1 # Return failure.
    fi
}

# --- Mount Cleanup Function ---
# Description: Unmounts a device from its temporary mount point and removes the directory.
# Arguments: $1: Path to the temporary mount point.
cleanup_mount() {
    local mount_point=$1
    log_message "INFO" "Attempting to unmount temporary mount point: ${mount_point}"
    # Attempt to unmount the filesystem. Redirect errors to log.
    if umount "$mount_point" 2>> "${LOG_FILE}"; then
        log_message "INFO" "Successfully unmounted ${mount_point}."
        # Attempt to remove the (now empty) temporary directory. Redirect errors to log.
        if rmdir "$mount_point" 2>> "${LOG_FILE}"; then
            log_message "INFO" "Successfully removed temporary directory ${mount_point}."
        else
            log_message "WARN" "Failed to remove temporary directory ${mount_point}. It might not be empty or permissions are wrong. Check log."
        fi
    else
        # Log failure if unmounting did not succeed. The directory will not be removed.
        log_message "ERROR" "Failed to unmount ${mount_point}. It might be busy or other errors occurred. Check log."
    fi
}

# --- Speed Test Function (on Mount Point) ---
# Description: Measures write/read speeds on a mount point using dd.
# Arguments: $1: Device name (for logging).
#            $2: Mount point path.
# Returns: "WriteSpeed,ReadSpeed" string via stdout on success.
# Returns exit code 1 on failure (not writable, insufficient space, dd error).
test_speed_on_mount_point() {
    local device=$1
    local mount_point=$2
    # Use a more specific and unique filename including PID
    local test_file_path="${mount_point}/.testfile_storage_speed_${SCRIPT_PID}"
    local write_speed="N/A"
    local read_speed="N/A"
    local result_code=1 # Default to failure

    log_message "INFO" "Starting speed test for /dev/${device} on mount point ${mount_point}"

    # Check 1: Mount point exists and is a directory
    if [ ! -d "$mount_point" ]; then
        log_message "ERROR" "Mount point ${mount_point} does not exist or is not a directory for device ${device}."
        echo "${write_speed},${read_speed}"
        return ${result_code}
    fi

    # Check 2: Mount point is writable
    if ! touch "${mount_point}/.__writable_test_${SCRIPT_PID}" 2>/dev/null; then
        log_message "WARN" "Mount point ${mount_point} for device ${device} is not writable. Skipping test here."
        echo "${write_speed},${read_speed}"
        return ${result_code}
    else
        # Clean up the temporary file immediately after the check.
        rm -f "${mount_point}/.__writable_test_${SCRIPT_PID}"
        log_message "DEBUG" "Writability check passed for ${mount_point}"
    fi

    # Check 3: Sufficient free space
    # Uses 'df -BM' to get sizes in Megabytes, extracts available space (4th field) from the relevant line (NR==2).
    local available_space
    available_space=$(df -BM "$mount_point" | awk 'NR==2 {print $4}' | sed 's/M//' 2>/dev/null) || available_space=0
    if [ -z "$available_space" ] || [ "$available_space" -lt ${REQUIRED_SPACE_MB} ]; then
        log_message "WARN" "Insufficient space on ${mount_point} for device ${device}: ${available_space:-0} MB available, requires ${REQUIRED_SPACE_MB} MB. Skipping test here."
        echo "${write_speed},${read_speed}"
        return ${result_code}
    fi
    log_message "DEBUG" "Sufficient space check passed for ${mount_point} (${available_space}MB available)"

    # --- Perform Write Test ---
    log_message "INFO" "Testing write speed for /dev/${device} at ${mount_point} (File: ${test_file_path}, Size: ${DD_COUNT}x${DD_BLOCK_SIZE})"
    # Capture dd output (stderr) to extract speed
    local write_output
    write_output=$(dd if=/dev/zero of="${test_file_path}" bs=${DD_BLOCK_SIZE} count=${DD_COUNT} oflag=direct 2>&1) || true # Use || true to prevent exit on dd failure
    # Extract speed (e.g., "150.5 MB/s" or "150 MB/s")
    write_speed=$(echo "$write_output" | grep -oP '\d+(\.\d+)?\s+MB/s' | head -n 1)

    if [ -z "$write_speed" ]; then
         log_message "ERROR" "Failed to measure write speed for ${device} on ${mount_point}. dd output included in next log line."
         log_message "DEBUG" "dd write output: ${write_output}" # Log full output for debugging
         rm -f "${test_file_path}" 2>/dev/null # Clean up potentially partially written file
         echo "N/A,N/A"
         return 1
    fi
    log_message "INFO" "Write speed on ${mount_point} for ${device}: ${write_speed}"

    # --- Perform Read Test ---
    log_message "INFO" "Testing read speed for /dev/${device} at ${mount_point}"
    # Ensure kernel buffers are flushed before read test for more accurate 'direct' read measurement.
    # sync # Uncomment if buffer effects are suspected despite iflag=direct

    local read_output
    read_output=$(dd if="${test_file_path}" of=/dev/null bs=${DD_BLOCK_SIZE} count=${DD_COUNT} iflag=direct 2>&1) || true # Use || true
    read_speed=$(echo "$read_output" | grep -oP '\d+(\.\d+)?\s+MB/s' | head -n 1)

    # Clean up the test file immediately after reading.
    rm -f "${test_file_path}"
    log_message "INFO" "Cleaned up test file ${test_file_path}"

    if [ -z "$read_speed" ]; then
         log_message "ERROR" "Failed to measure read speed for ${device} on ${mount_point}. dd output included in next log line."
         log_message "DEBUG" "dd read output: ${read_output}"
         # Return write speed but N/A for read speed if write succeeded
         echo "${write_speed},N/A"
         return 1 # Indicate partial success/failure
    fi
    log_message "INFO" "Read speed on ${mount_point} for ${device}: ${read_speed}"

    # If both tests succeeded
    result_code=0
    echo "${write_speed},${read_speed}"
    return ${result_code}
}

# --- Device Speed Test Orchestrator Function ---
# Description: Orchestrates speed testing for a device, trying existing mounts first, then temporary mount if needed.
# Arguments: $1: Device name (e.g., sda).
# Returns: Speed result string ("WriteSpeed,ReadSpeed" or "N/A,N/A") via echo.
# Returns exit code 0 on success, 1 on failure (no suitable test location found/worked).
test_device_speed() {
    local device=$1
    local speed_result="N/A,N/A" # Default result if tests fail
    local overall_result_code=1 # Default to failure

    # Get a list of current mount points for the raw device and its partitions.
    # lsblk -no MOUNTPOINT /dev/device - lists mountpoint of the device itself
    # lsblk -no MOUNTPOINT /dev/device?* - lists mountpoints of partitions (sda1, sda2 etc)
    # Combine, sort unique, filter empty lines.
    log_message "INFO" "Looking for existing mount points for /dev/${device} and its partitions."
    local mount_points
    mount_points=$( (lsblk -no MOUNTPOINT "/dev/$device" 2>/dev/null; lsblk -no MOUNTPOINT "/dev/${device}"?* 2>/dev/null) | grep -v '^$' | sort -u || true )

    local tested_on_existing=false # Flag

    # Try testing on existing mount points first
    if [ -n "$mount_points" ]; then
        log_message "INFO" "Device /dev/${device} or its partitions appear mounted at: ${mount_points}. Attempting tests..."
        local mount_point # Declare local variable
        for mount_point in $mount_points; do
            log_message "INFO" "Trying existing mount point ${mount_point} for device ${device}."
            # Call the function to test speed on this specific mount point. Capture its output and exit code.
            local test_output
            test_output=$(test_speed_on_mount_point "$device" "$mount_point")
            local test_exit_code=$?

            if [ $test_exit_code -eq 0 ]; then
                log_message "INFO" "Speed test successful on existing mount point ${mount_point} for device ${device}."
                speed_result="$test_output"
                overall_result_code=0 # Mark as success
                tested_on_existing=true
                break # Exit loop once a working mount point is found
            else
                log_message "INFO" "Speed test failed or mount point ${mount_point} unsuitable for device ${device}. Trying next..."
            fi
        done
    else
        log_message "INFO" "Device /dev/${device} and its partitions have no existing mount points listed by lsblk."
    fi

    # If no existing mount point worked, attempt a temporary mount of the base device
    if [ "$tested_on_existing" = false ]; then
        log_message "INFO" "No suitable existing mount point found or tested successfully for /dev/${device}. Attempting temporary mount."
        local temp_mount_point
        temp_mount_point=$(mount_device_temporarily "$device")
        local mount_exit_code=$?

        if [ $mount_exit_code -eq 0 ] && [ -n "$temp_mount_point" ]; then
            log_message "INFO" "Temporary mount successful at ${temp_mount_point}. Testing speed..."
            local test_output
            test_output=$(test_speed_on_mount_point "$device" "$temp_mount_point")
            local test_exit_code=$?

            # Clean up the temporary mount regardless of test success/failure.
            cleanup_mount "$temp_mount_point"

            if [ $test_exit_code -eq 0 ]; then
                log_message "INFO" "Speed test successful on temporary mount for device ${device}."
                speed_result="$test_output"
                overall_result_code=0 # Mark as success
            else
                log_message "ERROR" "Speed test failed on temporary mount for device ${device}."
                # speed_result remains "N/A,N/A"
            fi
        else
            log_message "ERROR" "Temporary mount failed for /dev/${device}. Cannot perform speed test via this method."
            # speed_result remains "N/A,N/A"
        fi
    fi

    # Echo the final result (either successful speeds or "N/A,N/A")
    echo "$speed_result"
    return ${overall_result_code}
}


# --- Main Logic Function ---
# Description: Contains the core orchestration logic of the script.
main() {
    log_message "INFO" "Starting main script execution..."

    # Prepare Report File
    log_message "INFO" "Preparing report file: ${REPORT_FILE}"
    # Create the CSV file and write the header row.
    if echo "Device,Storage Type,Write Speed,Read Speed" > "${REPORT_FILE}"; then
        log_message "INFO" "Created output report file with headers: ${REPORT_FILE}"
    else
        log_message "CRITICAL" "Failed to create or write header to report file: ${REPORT_FILE}. Check permissions."
        exit 1 # Cannot proceed without report file
    fi

    # Get list of block devices (disks, not partitions)
    log_message "INFO" "Detecting block devices..."
    local devices
    devices=$(lsblk -dno NAME)
    log_message "INFO" "Detected block devices: ${devices}"

    # Loop through each detected device
    local device # Declare local variable
    for device in $devices; do
        echo -e "${COLOR_BLUE}--- Processing device: /dev/${device} ---${COLOR_RESET}"
        log_message "INFO" "--- Processing /dev/${device} ---"

        # Determine device type
        local storage_type
        storage_type=$(check_device_type "$device")
        log_message "INFO" "Storage type determined for /dev/${device}: ${storage_type}"

        # Test device speed
        local speed_result
        speed_result=$(test_device_speed "$device")
        local test_exit_code=$? # Capture the exit code of the test orchestrator

        # Log and Report results
        if [ $test_exit_code -eq 0 ]; then
            log_message "INFO" "Successfully tested /dev/${device}. Results: ${speed_result}"
            # Append results to CSV
            echo "/dev/${device},${storage_type},${speed_result}" >> "${REPORT_FILE}"
            # Display results to console
            echo -e "${COLOR_GREEN}Device: /dev/${device} | Storage Type: ${storage_type} | Speeds (Write,Read): ${speed_result}${COLOR_RESET}"
        else
            log_message "ERROR" "Failed to test speed for /dev/${device}. All attempts exhausted or failed."
            # Append "N/A" results to CSV
            echo "/dev/${device},${storage_type},N/A,N/A" >> "${REPORT_FILE}"
            # Display failure status to console
            echo -e "${COLOR_YELLOW}Device: /dev/${device} | Storage Type: ${storage_type} | Write Speed: N/A | Read Speed: N/A (Testing failed or skipped)${COLOR_RESET}"
        fi
         echo -e "${COLOR_BLUE}--------------------------------------${COLOR_RESET}" # Separator for console output
    done

    # Final notification
    echo "====================================================="
    echo -e "${COLOR_BOLD}${COLOR_GREEN}Storage speed check complete.${COLOR_RESET}"
    echo -e "Report saved to: ${COLOR_CYAN}${REPORT_FILE}${COLOR_RESET}"
    echo -e "Check ${COLOR_CYAN}${LOG_FILE}${COLOR_RESET} for detailed logs and errors."
    echo "====================================================="
    log_message "INFO" "Script finished. Report saved to ${REPORT_FILE}"
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# 1. Setup Logging
setup_logging

# 2. Check Permissions
check_permissions

# 3. Check Dependencies (and install if possible)
check_and_install_requirements

# 4. Execute Main Logic
main

# 5. Exit Successfully
# The 'trap cleanup EXIT' will handle logging the final exit status (should be 0 here).
# Explicit exit 0 is handled by the trap calling 'exit $exit_status' where status is 0 if main completed.
# No 'exit 0' needed here because of the trap.

# =========================================================================================
# --- End of Script ---
