#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : reset_homes.sh
# PURPOSE       : Automates resetting user home directories in /home for consistency.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2024-11-05
# LAST UPDATED  : 2024-11-05
# VERSION       : 1.0.0
# =========================================================================================

# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This script provides a mechanism to reset the home directories of regular users located
# within the /home directory. It iterates through each entry in /home, identifies directories
# corresponding to regular users (typically UID >= 1000), forcefully removes their contents,
# recreates the home directory with strict permissions (700), sets correct ownership,
# and optionally restores a basic set of standard subdirectories (e.g., Desktop, Downloads, Documents).
#
# The primary use case is environments requiring a consistent, clean user state after
# each session or reboot, akin to a "Deep Freeze" setup, often found in computer labs,
# kiosks, or public access computers. It ensures that user-generated data and settings
# from a previous session are wiped clean before the next session begins.
#
# Key Workflow:
# - Iterates through all items in `/home/*`.
# - Checks if an item is a directory.
# - Extracts the directory name as a potential username.
# - Retrieves the UID for the username using the `id` command.
# - Skips the entry if UID lookup fails or if the UID is below `MIN_UID_THRESHOLD` (default 1000).
# - Forcefully removes the user's home directory (`rm -rf`).
# - Recreates the home directory (`mkdir`).
# - Sets ownership to the user and their primary group (`chown user:user`).
# - Sets permissions to owner-only access (`chmod 700`).
# - Optionally creates standard subdirectories (Desktop, Downloads, etc.) and sets their ownership.
#
# !! EXTREME CAUTION !! This script performs destructive actions (`rm -rf`) and will
# permanently delete all data within the targeted user home directories without prompting
# for confirmation. Ensure backups are in place and the script's logic, scope, and
# configuration (like MIN_UID_THRESHOLD) are fully understood before deployment.
# Test thoroughly in a non-production environment.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Targeted Reset**: Focuses only on regular user accounts (UID >= `MIN_UID_THRESHOLD`),
#   avoiding critical system accounts or accounts below the threshold whose home directories
#   might reside elsewhere or should not be touched.
# - **Security Focused**: Recreates home directories with restrictive permissions (700 - owner only),
#   ensuring privacy between users. Assumes a user-private group scheme (UPG).
# - **Robustness**: Includes checks to only process actual directories within `/home`. Uses `set -euo pipefail`
#   for stricter error handling. Logs actions and errors via the `log_message` function.
# - **Simplicity**: Aims for straightforward logic using standard Unix commands for easier
#   understanding, modification, and maintenance. Avoids complex external dependencies.
# - **Automation**: Designed for unattended execution, typically via system startup (systemd) or
#   shutdown hooks, requiring no user interaction.
# - **Configurability**: Key parameters like `MIN_UID_THRESHOLD` and `CREATE_STANDARD_DIRS` are
#   defined as variables near the top for easy adjustment.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - System Administrators managing Linux labs, public workstations, kiosks, or multi-user environments
#   where periodic user home directory resets are required for security, privacy, or consistency.
# - IT Support Teams deploying standardized desktop environments that need stateless user sessions.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x reset_homes.sh` (or `chmod 700 reset_homes.sh`)
# - File system access: Read/write access within `/home`, ability to create/delete directories.
# - Elevated privileges: Requires `root` privileges (run via `sudo`) due to file ownership changes (`chown`),
#   permissions modifications (`chmod`), and unrestricted deletion (`rm -rf`) within `/home`.
#   Root privileges are validated at the start of the script.
#
# **Basic Syntax:**
#   The script takes no command-line options or arguments. Configuration is done via internal variables.
#   `sudo /path/to/reset_homes.sh`
#
# **Options:**
#   None. Script configuration is managed via variables within the script file itself:
#   - `MIN_UID_THRESHOLD`: Set the minimum UID to consider for reset (Default: 1000).
#   - `CREATE_STANDARD_DIRS`: Set to `true` or `false` to control creation of standard subdirs (Default: `true`).
#   - `LOG_LEVEL`: Control verbosity (DEBUG, INFO, WARN, ERROR, CRITICAL) (Default: "INFO").
#   - `LOG_TO_FILE`: Set to `true` and define `LOG_FILE` path to enable file logging.
#   - `VERBOSE`: Set to `true` for detailed output (equivalent to `LOG_LEVEL="DEBUG"`).
#
# **Arguments:**
#   None.
#
# **Common Examples:**
# 1. Direct execution with sudo (using internal defaults):
#    `sudo ./reset_homes.sh`
#
# 2. Execution from a specific path:
#    `sudo /usr/local/sbin/reset_homes.sh`
#
# 3. Running with debug logging redirected to a file for troubleshooting:
#    (Modify `LOG_LEVEL="DEBUG"` and potentially `LOG_TO_FILE=true`, `LOG_FILE="/var/log/reset_homes.log"` inside the script)
#    `sudo ./reset_homes.sh`
#    Or without modifying script, redirect all output:
#    `sudo ./reset_homes.sh > /var/log/reset_homes_stdout.log 2> /var/log/reset_homes_stderr.log`
#
# **Advanced Execution (Automation):**
# - **Systemd Service:** Create a service unit (e.g., `reset-homes.service`) to run the
#   script during the boot process (e.g., `After=local-fs.target`, `RequiresMountsFor=/home`, `Before=systemd-user-sessions.service`).
#   See INSTALLATION section for an example unit.
# - **Cron Job:** Can be scheduled with `@reboot` in the root user's crontab, though systemd
#   is generally preferred for boot-time tasks for better dependency management.
#   `@reboot /usr/local/sbin/reset_homes.sh >> /var/log/reset_homes.log 2>&1`
#
# **WARNING:** Test thoroughly in a non-production environment before deploying, especially
# when automating execution. Incorrect usage, misconfiguration, or modification can lead to
# significant, irreversible data loss.
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - System-wide scripts (requiring root): `/usr/local/sbin/` (preferred for admin scripts).
#
# **Manual Setup:**
# 1. Place the script in the chosen location (e.g., `/usr/local/sbin/reset_homes.sh`).
# 2. Set appropriate ownership: `sudo chown root:root /usr/local/sbin/reset_homes.sh`
# 3. Set secure executable permissions: `sudo chmod 700 /usr/local/sbin/reset_homes.sh` (owner read/write/execute only).
# 4. Verify required dependencies are installed (see DEPENDENCIES section - usually standard).
# 5. Review and adjust internal configuration variables (`MIN_UID_THRESHOLD`, etc.) as needed.
# 6. Perform a test run manually in a safe environment: `sudo /usr/local/sbin/reset_homes.sh`.
# 7. If using file logging, ensure the log directory exists and has appropriate permissions, or that the script can create it.
#
# **Integration (Example: Systemd Service):**
# - Create a unit file, e.g., `/etc/systemd/system/reset-homes.service`:
#   ```
#   [Unit]
#   Description=Reset User Home Directories at Boot
#   Documentation=man:reset_homes.sh # Assuming you create a man page or refer back to script
#   DefaultDependencies=no
#   RequiresMountsFor=/home
#   After=local-fs.target
#   Before=systemd-user-sessions.service getty.target graphical.target shutdown.target # Ensure it runs before user sessions start
# [Service]
#   Type=oneshot
# Specify User and Group if not running as root, though root is required by script logic
# User=root
# Group=root
#   ExecStart=/usr/local/sbin/reset_homes.sh
#   RemainAfterExit=yes # Useful for oneshot services that establish a state
#   StandardOutput=journal # Log stdout to journald
#   StandardError=journal # Log stderr to journald
# [Install]
#   WantedBy=multi-user.target # Or adjust depending on when it should run (e.g., before graphical login)
#   ```
# - Reload systemd: `sudo systemctl daemon-reload`
# - Enable the service to run on boot: `sudo systemctl enable reset-homes.service`
# - Start the service immediately (for testing): `sudo systemctl start reset-homes.service`
# - Check status/logs: `sudo systemctl status reset-homes.service`, `sudo journalctl -u reset-homes.service`
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: The Bourne-Again SHell interpreter (Version >= 4.x recommended for features like `declare -A`). Uses bashisms (`set -euo pipefail`, `[[ ]]`, etc.).
#
# **Required System Binaries/Tools:**
# - `coreutils`: Provides fundamental tools used: `basename`, `id`, `rm`, `mkdir`, `chown`, `chmod`, `date`, `echo`, `dirname`, `cd`, `pwd`, `tr`.
# - `command`: Bash built-in used for checking command existence.
# - `sed`: Used within `log_message` function (optional config loading placeholder uses it too).
#
# **Setup Instructions:**
# - These utilities are standard components of virtually all modern Linux distributions (Debian, Ubuntu, Fedora, CentOS, RHEL, Arch, etc.). No special installation steps are typically required.
# - Check availability (optional): `command -v id`, `command -v rm`, etc.
#
# **Operating System Compatibility:**
# - Designed primarily for: Linux distributions using a standard `/home/<username>` structure and POSIX utilities.
# - Known compatibility issues: May require adjustments for macOS (different `sed`/`id` flags potentially) or highly non-standard Linux setups. Not designed for Windows.
# - Windows Subsystem for Linux (WSL): Likely works on WSL2 if the Linux distribution meets requirements.
#
# **Environment Variables Used:**
# - `NO_COLOR`: If set (e.g., `export NO_COLOR=true`), disables colored output in logs.
# - `PATH`: Standard variable; ensures required binaries (`id`, `rm`, etc.) are locatable. Script uses standard paths, should not normally be an issue.
# - Does not rely on custom environment variables for configuration.
#
# **System Resource Requirements:**
# - CPU: Minimal. Primarily short bursts for file system operations.
# - Memory: Minimal. Bash script overhead is low.
# - Disk I/O: Can be significant during the `rm -rf` phase if user directories are large. Generally fast for typical reset scenarios (deleting and creating mostly empty directories).
# - Disk Space: Requires negligible space for the script itself. Log file space depends on verbosity and frequency of execution.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): Used for INFO and DEBUG level messages by default.
# - Standard Error (stderr): Used for WARN, ERROR, and CRITICAL level messages. Also used for `set -x` output if enabled.
# - Dedicated Log File: Optional. Controlled by `LOG_TO_FILE=true` and `LOG_FILE="/path/to/log"`. If enabled, messages (without color codes) are appended to this file.
# - System Log (syslog/journald): Not directly implemented, but can be achieved by:
#     - Running via systemd with `StandardOutput=journal` `StandardError=journal` (see INSTALLATION example).
#     - Piping output to `logger`: `sudo ./reset_homes.sh | logger -t reset_homes`
#     - Modifying `log_message` to use `logger` command internally.
#
# **Log Format (Default stdout/stderr/file):**
# `[YYYY-MM-DD HH:MM:SS ZONE] [LEVEL] [script_name.sh:LINE_NUMBER] - Message`
# Example: `[2025-04-20 18:00:00 WIB] [INFO] [reset_homes.sh:350] - Starting home directory reset process...`
#
# **Log Levels:**
# - `DEBUG`: Very detailed step-by-step information (e.g., "Processing entry X", "Executing command Y"). Enabled if `LOG_LEVEL="DEBUG"` or `VERBOSE=true`.
# - `INFO`: General operational messages (start/stop, user being reset, completion). Default level.
# - `WARN`: Potential issues or non-critical errors (e.g., failed to get UID for a directory, failed to create optional subdir).
# - `ERROR`: Significant errors likely preventing reset for a specific user (e.g., `mkdir`/`chown`/`chmod` failed after `rm`). Script continues to next user.
# - `CRITICAL`: Severe errors causing script termination (e.g., running without root, `/home` missing, `rm -rf` fails).
# - Control: Set the `LOG_LEVEL` variable inside the script. Only messages at this level or higher are shown/logged.
#
# **Log Rotation (if using a dedicated file):**
# - Handled by script?: No.
# - External Recommendation: Use standard system tools like `logrotate`. Create a config file in `/etc/logrotate.d/reset_homes` to manage rotation (daily/weekly, size, compression, retention).
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Normal Operation (`LOG_LEVEL="INFO"`): Prints INFO messages (start, finish, user being reset).
# - Verbose/Debug Operation (`LOG_LEVEL="DEBUG"`): Prints INFO and DEBUG messages (detailed steps, commands being run).
#
# **Standard Error (stderr):**
# - Errors: Prints WARN, ERROR, CRITICAL messages.
# - Debug Mode (`set -x`): If uncommented, prints every command executed, prefixed with `+`.
#
# **Generated/Modified Files:**
# - **Primary Effect:** The script fundamentally alters the contents of the `/home` directory by:
#     - **DELETING** contents of user home directories matching the criteria.
#     - **RECREATING** these home directories as empty.
#     - **MODIFYING** ownership (`chown`) and permissions (`chmod`) of these directories.
#     - Optionally **CREATING** standard subdirectories (Desktop, Downloads, etc.) within each reset home directory.
# - Log File: If `LOG_TO_FILE=true`, appends logs to the path specified in `LOG_FILE`.
# - Temporary Files: None used by default.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success - Script completed its loop. Note: Errors resetting *individual* users (logged as ERROR/WARN) may occur, but the script will still exit 0 if it finishes the loop.
# - 1: General/Critical Error - Typically corresponds to CRITICAL log messages (e.g., not root, `/home` missing, `rm -rf` failure). The script terminates immediately via `log_message "CRITICAL"` or `set -e`.
# - Other non-zero: Could occur if a command fails unexpectedly and `set -e` triggers exit before specific logging.
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** Home directory not reset for a specific user.
#   **Resolution:** Enable DEBUG logging (`LOG_LEVEL="DEBUG"` or `VERBOSE=true`). Check logs for messages about skipping the user (UID below threshold? Not a directory? `id -u` failed?). Verify the user's UID (`id -u <username>`) against `MIN_UID_THRESHOLD`. Ensure their home is directly under `/home`.
# - **Issue:** Errors logged related to `rm`, `mkdir`, `chown`, or `chmod`.
#   **Resolution:** Confirm the script is running as root (`log_message "CRITICAL"` checks this early). Check filesystem health (`dmesg`, `fsck`). Ensure `/home` is mounted read-write. Verify the username extracted corresponds to a valid system user/group (for `chown`). Check for immutable flags (`lsattr`).
# - **Issue:** System accounts (UID < 1000) are being processed unexpectedly.
#   **Resolution:** Verify the `MIN_UID_THRESHOLD` variable in the script. Check its value against your system's convention (usually defined in `/etc/login.defs` as `UID_MIN`). Adjust the variable if necessary.
# - **Issue:** Script fails silently when run via cron or systemd.
#   **Resolution:** Check system logs (`journalctl -u <service_name>` for systemd, or cron logs in `/var/log/syslog` or similar). Ensure the execution environment has necessary PATH. Use full paths to commands within the script if needed (though standard paths are generally fine). Redirect output explicitly in cron if not using systemd logging (`>> /var/log/reset_homes.log 2>&1`).
#
# **Important Considerations / Warnings:**
# - **DATA DESTRUCTION**: **CRITICAL:** The `rm -rf` command is irreversible and bypasses any trash mechanism. **ALL DATA** in the targeted home directories (`/home/<user>/*`) **WILL BE PERMANENTLY LOST.** This is the script's primary function but carries extreme risk if misconfigured or run accidentally.
# - **BACKUPS**: **ESSENTIAL:** Implement and verify a robust backup strategy for all data within `/home` *before* deploying this script. This script provides *no* recovery capability. Data loss due to misconfiguration is a real possibility.
# - **UID THRESHOLD**: The default `MIN_UID_THRESHOLD=1000` assumes standard Linux user UID allocation. **Verify** this against your system's `/etc/login.defs` (`UID_MIN`) and adjust the script variable if your regular users start at a different UID (e.g., 500 on older systems).
# - **EXCLUSIONS**: The script resets *all* user directories found in `/home` with a UID >= `MIN_UID_THRESHOLD`. It **does not** automatically exclude specific users (e.g., an administrative user whose home is in `/home` and has UID >= 1000). Manual exclusions must be added to the loop logic if needed (e.g., `if [[ "$username" == "admin_user_to_keep" ]]; then log_message "INFO" "Skipping explicitly excluded user: $username"; continue; fi`).
# - **NFS/REMOTE HOMES**: This script is designed for local filesystems. Running it on `/home` directories mounted via NFS, Samba/CIFS, etc., may be **unsafe or ineffective**. Filesystem operations could be slow, permissions handling complex, and `rm -rf` might have unintended consequences on the remote server or cause partial failures. Test with extreme caution in such environments, or avoid using it.
# - **ERROR HANDLING ROBUSTNESS**: Uses `set -euo pipefail` and logs errors. If `rm -rf` fails critically, the script exits. If `mkdir/chown/chmod` fail for a user, an ERROR is logged, and the script continues to the next user, potentially leaving that specific user's home in an inconsistent state (e.g., missing, wrong permissions). For higher assurance, more sophisticated transactionality/rollback logic would be needed, significantly increasing complexity.
# - **IDEMPOTENCY**: Running the script multiple times is technically idempotent in the sense that the *end state* (empty home dirs with correct perms) is the same. However, it performs destructive `rm -rf` actions each time, which is unnecessary work and potentially risky if run concurrently or interrupted. It's designed to be run once per desired reset cycle (e.g., once on boot).
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - User home directories targeted for reset reside directly under the `/home` directory (e.g., `/home/user1`, `/home/user2`). Does not search recursively or handle other locations like `/var/home`.
# - The script is executed with `root` privileges.
# - Regular user accounts intended for reset have UIDs greater than or equal to `MIN_UID_THRESHOLD`.
# - A User Private Group (UPG) scheme is generally in use, where each user's primary group has the same name as the username (relevant for `chown "$username:$username"`). If not, `chown` might need adjustment.
# - The underlying filesystem for `/home` is a standard Linux filesystem (ext4, xfs, btrfs, etc.) supporting POSIX permissions and ownership.
# - Core Unix utilities (`basename`, `id`, `rm`, `mkdir`, `chown`, `chmod`, `date`, etc.) are available in the system's `$PATH` and function as expected on a POSIX-compliant system.
# =========================================================================================

# =========================================================================================
# PERFORMANCE OPTIMIZATION (Optional)
# =========================================================================================
# **Benchmarks:** Not formally benchmarked. Performance primarily depends on disk I/O speed and the number/size of directories being deleted.
# **Resource Consumption Profile:** Generally low CPU/memory. Disk I/O is the main factor, potentially high during `rm -rf` on large directories.
# **Optimization Notes:**
# - Uses standard core utilities which are generally efficient.
# - Avoids unnecessary forks where possible (e.g., uses Bash built-ins like `[[ ]]`).
# - The loop processes users sequentially. Parallelization (e.g., using `&` with careful job management or `xargs -P`) could speed up processing on systems with many users and fast I/O, but adds complexity and potential risks if not managed properly. Current sequential approach is simpler and safer.
# - Bottleneck is likely disk I/O during deletion.
# =========================================================================================

# =========================================================================================
# TESTING & VALIDATION (Optional)
# =========================================================================================
# **Test Strategy:** Primarily manual testing in controlled environments (VMs, test servers).
# **Key Test Cases:**
# - Run as non-root (should fail with CRITICAL error).
# - Run on a system with users having UIDs both below and above `MIN_UID_THRESHOLD`.
# - Run with non-directory files present in `/home` (should be skipped).
# - Run with directories in `/home` that don't match valid usernames (should be skipped with WARN).
# - Test with `CREATE_STANDARD_DIRS=true` and `false`.
# - Test different `LOG_LEVEL` settings.
# - **CRITICAL:** Test impact on a system with sample user data to confirm deletion occurs as expected.
# - Test integration with chosen automation method (systemd, cron).
# **Validation Tools:**
# - `ShellCheck` (Highly Recommended): Run `shellcheck reset_homes.sh` to catch potential syntax errors, quoting issues, and common pitfalls.
# - Manual inspection of logs and filesystem state after runs.
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - Add an explicit exclusion list (e.g., read from a config file or array) for usernames/UIDs never to reset.
# - Implement locking (e.g., `flock`) to prevent concurrent runs if deployed in a way that might allow it.
# - Make configuration parameters (Threshold, Dirs) configurable via command-line arguments (`getopts`) or an external config file.
# - Option to copy skeleton files (from `/etc/skel`) into the newly created home directory.
# - More granular error handling: Potentially attempt to continue resetting permissions even if `mkdir` failed (though current logic prevents this), or offer options on failure.
# - Add dry-run mode (`--dry-run`) that logs actions that *would* be taken without actually deleting/modifying anything.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Requires `root` privileges. This is necessary for `rm -rf /home/*` and `chown`/`chmod`. Grants the script maximum power over user data. **Restrict access to the script file itself** (e.g., `chmod 700`, `chown root:root`).
# - **Input Sanitization:** No direct external input via arguments. Relies on `basename` for username extraction from directory paths found via `/home/*`. While generally safe, extremely unusual directory names with special characters in `/home` could theoretically cause issues, though coreutils are robust. `id -u` is used with the extracted name.
# - **Sensitive Data Handling:** The script's purpose is to **DELETE** data, potentially including sensitive user data. It does not handle passwords or API keys itself. The main security risk is **accidental or malicious execution leading to data loss**.
# - **Dependencies:** Relies on standard, trusted core Unix utilities (`rm`, `mkdir`, `id`, etc.). Keep the OS updated to patch vulnerabilities in these tools.
# - **File Permissions:** Explicitly sets recreated home directories to `700` (owner `rwx`, group/other no access), a secure default. Standard subdirectories get default permissions based on `umask` but are owned by the user.
# - **External Command Execution:** Executes standard utilities (`rm`, `mkdir`, `chown`, `chmod`, `id`, `basename`) with paths derived from `/home/*`. Variables holding paths/usernames are double-quoted (`"$user_home"`, `"$username"`) to prevent word splitting and globbing issues.
# - **Code Integrity:** If obtained from untrusted sources, verify integrity using checksums (e.g., SHA256) against a known good copy. Malicious modification could be catastrophic.
# - **Data Deletion Risk:** **Paramount concern.** Accidental execution, incorrect `MIN_UID_THRESHOLD`, or failure to implement necessary exclusions can lead to **irreversible loss of critical user data.** Careful configuration, thorough testing, and strict access control are mandatory. Use of automation (cron, systemd) requires extra caution.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is contained within this script's header comments.
# - External documentation: None by default. Consider creating a README.md if part of a larger project/repository.
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha (Baharuddin Aziz)
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Submit via repository issues tracker if available (e.g., https://baha.my.id/github/issues), otherwise contact the author.
# - Feature Requests: Submit via repository or contact the author.
# =========================================================================================

# =========================================================================================
# SCRIPT EXECUTION ENVIRONMENT & CONFIGURATION
# =========================================================================================

# --- Bash Strict Mode ---
# -e: Exit immediately if a command exits with a non-zero status.
# -u: Treat unset variables and parameters as an error when performing parameter expansion.
# -o pipefail: The return value of a pipeline is the status of the last command to exit
#              with a non-zero status, or zero if no command exited with non-zero status.
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
# Configuration Defaults (can be adjusted here)
MIN_UID_THRESHOLD=1000 # Minimum UID for user accounts to be reset (prevents system accounts)
CREATE_STANDARD_DIRS=true # Set to false to skip creating Desktop, Downloads, Documents

# Runtime variables
LOG_LEVEL="INFO" # Default log level (DEBUG, INFO, WARN, ERROR, CRITICAL)
LOG_TO_FILE=false # Default: No dedicated log file, use redirection if needed
LOG_FILE="" # Placeholder, can be set if LOG_TO_FILE=true
VERBOSE=false # Set to true for more detailed output (maps to DEBUG level)

# --- Color Definitions (Optional) ---
# Define ANSI escape codes for colored output, checking if NO_COLOR is set or if not interactive.
INTERACTIVE_MODE=false
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is a terminal
NO_COLOR=false # Set to true to disable colors manually

if [[ "${NO_COLOR}" == false && "${INTERACTIVE_MODE}" == true ]]; then
    COLOR_RESET='\033[0m'; COLOR_RED='\033[0;31m'; COLOR_GREEN='\033[0;32m'; COLOR_YELLOW='\033[0;33m'; COLOR_CYAN='\033[0;36m'; COLOR_BOLD='\033[1m'
else
    COLOR_RESET=""; COLOR_RED=""; COLOR_GREEN=""; COLOR_YELLOW=""; COLOR_CYAN=""; COLOR_BOLD=""
fi

# =========================================================================================
# FUNCTION DEFINITIONS
# =========================================================================================

# --- Logging Function ---
log_message() {
    local level="$1"
    local message="$2"
    local timestamp; timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z")
    local level_upper; level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]')
    local log_prefix="[${timestamp}] [${level_upper}] [${SCRIPT_NAME}:${BASH_LINENO[0]}]"
    local log_line="${log_prefix} - ${message}"
    local color=""

    declare -A log_levels=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [CRITICAL]=4)
    local current_log_level_num=${log_levels[${LOG_LEVEL^^}]}
    local message_level_num=${log_levels[${level_upper}]}

    # Set verbosity automatically if DEBUG level is chosen
    [[ "${LOG_LEVEL^^}" == "DEBUG" ]] && VERBOSE=true

    # Decide color
    case "${level_upper}" in DEBUG) color="${COLOR_CYAN}";; INFO) color="${COLOR_GREEN}";; WARN) color="${COLOR_YELLOW}";; ERROR) color="${COLOR_RED}";; CRITICAL) color="${COLOR_BOLD}${COLOR_RED}";; esac

    # Only log if message level is >= current log level
    if [[ ${message_level_num} -ge ${current_log_level_num} ]]; then
        # Output to stderr for WARN/ERROR/CRITICAL, stdout otherwise
        if [[ "${level_upper}" == "WARN" || "${level_upper}" == "ERROR" || "${level_upper}" == "CRITICAL" ]]; then
            echo -e "${color}${log_line}${COLOR_RESET}" >&2
        else
            # Only print DEBUG if VERBOSE is true
            if [[ "${level_upper}" == "DEBUG" && "${VERBOSE}" == false ]]; then : # Do nothing
            else echo -e "${color}${log_line}${COLOR_RESET}"; fi
        fi

        # Append to log file if enabled and possible
        if [[ "${LOG_TO_FILE}" == true && -n "${LOG_FILE}" ]]; then
            if [[ -w "$(dirname "${LOG_FILE}")" ]] || mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null; then
                # Strip color codes for file logging
                echo "${log_prefix} - ${message}" >> "${LOG_FILE}"
            else
                if [[ -z ${LOG_DIR_WRITE_WARN_SENT+x} ]]; then
                    echo -e "${COLOR_YELLOW}[${timestamp}] [WARN] [${SCRIPT_NAME}:${BASH_LINENO[0]}] - Cannot write to log directory $(dirname "${LOG_FILE}"). Logging to file disabled.${COLOR_RESET}" >&2
                    declare -g LOG_DIR_WRITE_WARN_SENT=true # Use declare -g to set global flag
                fi
            fi
        fi
    fi

    # Exit immediately for CRITICAL errors after logging
    if [[ "${level_upper}" == "CRITICAL" ]]; then exit 1; fi
}

# --- Usage/Help Function ---
usage() {
    # Extract the Usage section from this script's header comments.
    local usage_text; usage_text=$(sed -n '/^# ===+ USAGE ===+$/,/^# ===+ .* ===+$/{ /# ===+ .* ===+$/!p; }' "${BASH_SOURCE[0]}" | sed 's/^# //; s/reset_homes.sh/'"${SCRIPT_NAME}"'/g')
    cat << EOF >&2
${usage_text}
This script does not accept command-line arguments.
Configuration is handled by variables at the top of the script.
EOF
    exit 1
}

# --- Dependency Check Function ---
check_dependency() {
    local cmd="$1"
    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required command '${cmd}' not found. Please ensure core utilities are installed."
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
}

# --- Cleanup Function ---
cleanup() {
    local exit_status=$?
    log_message "DEBUG" "Performing cleanup..."
    # No temporary files/dirs used in this script currently. Add cleanup here if needed in future.
    log_message "INFO" "Script finished with exit status: ${exit_status}"
    exit ${exit_status} # Ensure script exits with the original status
}

# --- Trap Setup ---
# Register 'cleanup' on EXIT, INT, TERM, HUP. cleanup() handles the final exit.
trap cleanup EXIT INT TERM HUP

# --- Argument Parsing Function ---
# This script doesn't take arguments, but includes the function for structural consistency.
parse_params() {
    if [[ "$#" -gt 0 ]]; then
        log_message "WARN" "This script does not accept command-line arguments. Ignoring: $*"
        usage # Show help if arguments are provided
    fi
    log_message "DEBUG" "No command-line arguments to parse."
}

# --- Configuration Loading Function ---
# This script doesn't use external config files, but includes function for structure.
load_config() {
    log_message "DEBUG" "No external configuration file to load. Using internal defaults."
    # Placeholder for future config file loading if needed
}

# --- Input Validation Function ---
validate_inputs() {
    log_message "INFO" "Validating inputs and environment..."

    # Check if running as root
    if [[ "$(id -u)" -ne 0 ]]; then
        log_message "CRITICAL" "This script must be run as root (or with sudo)."
    fi
    log_message "DEBUG" "Root privilege check passed."

    # Validate UID Threshold (simple integer check)
    if ! [[ "${MIN_UID_THRESHOLD}" =~ ^[0-9]+$ ]]; then
        log_message "CRITICAL" "Invalid MIN_UID_THRESHOLD setting: '${MIN_UID_THRESHOLD}'. Must be an integer."
    fi
    log_message "DEBUG" "MIN_UID_THRESHOLD is set to ${MIN_UID_THRESHOLD}."

    # Check if /home exists and is a directory
    if [[ ! -d "/home" ]]; then
         log_message "CRITICAL" "The /home directory does not exist or is not accessible."
    fi
     log_message "DEBUG" "/home directory exists."

    log_message "INFO" "Input validation passed."
}

# --- Preparation Function ---
prepare_environment() {
    log_message "INFO" "Preparing execution environment..."
    # Nothing specific needed for this script (like temp dirs)
    log_message "INFO" "Environment preparation complete."
}

# --- Main Logic Function ---
main() {
    log_message "INFO" "Starting home directory reset process..."

    # Iterate through all entries (files and directories) directly under the /home directory.
    # The pattern /home/* expands to a list of paths like /home/user1, /home/user2, etc.
    # Using find is safer for unusual filenames than a raw glob, but glob is simpler here.
    for user_home in /home/*; do
        local username uid exit_code

        log_message "DEBUG" "Processing entry: ${user_home}"

        # Check if the current entry is actually a directory. If not (e.g., it's a file
        # directly in /home), skip to the next iteration. This prevents errors.
        if [[ ! -d "$user_home" ]]; then
            log_message "DEBUG" "Skipping non-directory entry: ${user_home}"
            continue # Skip this entry and proceed to the next item in /home/*
        fi

        # Extract the last component of the path, assumed to be the username.
        # Example: If user_home is "/home/alice", `basename` returns "alice".
        username=$(basename "$user_home")
        if [[ -z "$username" ]]; then
             log_message "WARN" "Could not extract username from path: ${user_home}. Skipping."
             continue
        fi
        log_message "DEBUG" "Extracted username: ${username}"

        # Retrieve the User ID (UID) for the extracted username.
        # The `id -u` command looks up the user's numeric UID.
        # Use a subshell with error checking rather than relying solely on 2>/dev/null.
        if ! uid=$(id -u "$username" 2>/dev/null); then
            exit_code=$?
            log_message "WARN" "Could not get UID for username '${username}' (Exit code: ${exit_code}). Directory might not correspond to a valid user. Skipping."
            continue
        fi
        log_message "DEBUG" "Found UID ${uid} for username ${username}"

        # Check if the UID meets the threshold. UIDs below the threshold are typically
        # reserved for system accounts (like root, daemon, bin) which should not be reset.
        if [[ "$uid" -lt ${MIN_UID_THRESHOLD} ]]; then
            log_message "INFO" "Skipping user '${username}' (UID ${uid}) - Below threshold ${MIN_UID_THRESHOLD}."
            continue
        fi

        log_message "INFO" "Resetting home directory for user '${username}' (UID ${uid}) at path: ${user_home}"

        # --- DANGER ZONE ---
        # Forcefully and recursively remove the entire contents of the user's home directory.
        # `rm` is the remove command.
        # `-r` (recursive) means delete directories and their contents.
        # `-f` (force) means ignore non-existent files and arguments, never prompt for confirmation.
        # WARNING: This command permanently deletes data without confirmation. Ensure the target is correct.
        log_message "WARN" "Executing: rm -rf \"${user_home}\""
        if ! rm -rf "$user_home"; then
             # If rm fails, it's a serious issue (permissions, filesystem error?) - stop the script.
             log_message "CRITICAL" "Failed to remove directory '${user_home}'. Filesystem issue or permissions problem? Aborting."
             # Critical log message handles exit
        fi
        log_message "DEBUG" "Successfully removed ${user_home}"

        # Recreate the user's home directory as an empty directory.
        log_message "DEBUG" "Executing: mkdir \"${user_home}\""
        if ! mkdir "$user_home"; then
             log_message "ERROR" "Failed to recreate directory '${user_home}' after deletion. Skipping further steps for this user."
             continue # Skip chown/chmod for this user
        fi
        log_message "DEBUG" "Successfully recreated directory ${user_home}"

        # Set the owner and group of the newly created home directory to the user.
        # `chown user:group path` changes ownership. Using "$username":"$username"
        # sets both the user owner and the group owner to the username. This assumes
        # a user-private group scheme where each user has a primary group with the same name.
        log_message "DEBUG" "Executing: chown \"${username}:${username}\" \"${user_home}\""
        if ! chown "$username:$username" "$user_home"; then
            log_message "ERROR" "Failed to set ownership for '${user_home}' to '${username}:${username}'. Check user/group existence and permissions. Skipping chmod."
            continue # Skip chmod if chown failed
        fi
        log_message "DEBUG" "Successfully set ownership for ${user_home}"

        # Set the permissions of the home directory to 700.
        # `chmod` changes file mode bits. 700 means: Owner(rwx), Group(---), Others(---).
        # This restricts access to the home directory exclusively to the owner.
        log_message "DEBUG" "Executing: chmod 700 \"${user_home}\""
        if ! chmod 700 "$user_home"; then
             log_message "ERROR" "Failed to set permissions (700) for '${user_home}'. Check permissions."
             # Continue anyway, as the directory exists, but log the error.
        fi
        log_message "DEBUG" "Successfully set permissions for ${user_home}"

        # Optional: Create standard subdirectories within the user's home directory.
        if [[ "${CREATE_STANDARD_DIRS}" == true ]]; then
            log_message "DEBUG" "Creating standard subdirectories..."
            local std_dirs=("Desktop" "Downloads" "Documents" "Pictures" "Music" "Videos" "Templates" "Public") # Common standard dirs
            for dir in "${std_dirs[@]}"; do
                local full_path="${user_home}/${dir}"
                log_message "DEBUG" "Executing: mkdir \"${full_path}\""
                if ! mkdir "${full_path}"; then
                    log_message "WARN" "Failed to create subdirectory '${full_path}'. Skipping ownership change for this dir."
                    continue
                fi
                log_message "DEBUG" "Executing: chown \"${username}:${username}\" \"${full_path}\""
                if ! chown "$username:$username" "${full_path}"; then
                    log_message "WARN" "Failed to set ownership for subdirectory '${full_path}'."
                fi
                 # Default permissions from mkdir (controlled by umask) are usually fine here.
            done
            log_message "DEBUG" "Finished creating standard subdirectories."
        fi

        log_message "INFO" "Successfully reset home directory for user '${username}'."

    # End of the loop for processing entries in /home
    done

    log_message "INFO" "Home directory reset process finished."
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================
# 1. Parse Command Line Arguments (Does nothing in this script)
parse_params "$@"

# 2. Load Configuration File (Does nothing in this script)
load_config

# 3. Validate Inputs and Configuration (Checks root, /home, threshold)
validate_inputs

# 4. Check Dependencies (Checks coreutils: id, basename, rm, mkdir, chown, chmod)
log_message "INFO" "Checking required dependencies..."
check_dependency "id"
check_dependency "basename"
check_dependency "rm"
check_dependency "mkdir"
check_dependency "chown"
check_dependency "chmod"
log_message "DEBUG" "All core dependencies found."

# 5. Prepare Environment (Does nothing in this script)
prepare_environment

# 6. Execute Main Logic (The core reset loop)
main

# 7. Exit Successfully (Handled by trap)
# The 'trap cleanup EXIT' will run automatically. The main function reaching its end
# without 'set -e' triggering an exit means success. cleanup() preserves exit status 0.
# An explicit `exit 0` is added by the trap handler if no error occurred.

# =========================================================================================
# --- End of Script ---
