#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : buster_apt_setup_imagemagick.sh
# PURPOSE       : Standardizes Debian 10 APT repos, cleans sources, installs pkg.
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
# This script performs system maintenance focused on the APT package management system
# on Debian 10 (Buster). It aims to create a consistent and clean repository state
# by overwriting the main sources list, removing known problematic or unwanted
# repository configurations (like backports, specific mirrors, or duplicate entries),
# ensuring the necessary GPG key for the Spotify repository is present, and finally
# updating the package list and installing the 'imagemagick' package suite.
# It utilizes Bash strict mode (`set -euo pipefail`), includes dependency checks,
# root privilege validation, and provides structured logging messages to stdout/stderr.
#
# Key Workflow / Functions:
# - Enables Bash strict mode (`set -euo pipefail`).
# - Defines constants for paths, patterns, and keys.
# - Implements a `log_message` function for structured output (INFO, WARN, ERROR, CRITICAL).
# - Checks for root privileges using `check_root`.
# - Checks for required command dependencies using `check_dependency`.
# - Overwrites `/etc/apt/sources.list` with standard Debian Buster repository definitions.
# - Uses `find` and `grep -q` to safely locate files containing 'buster-backports' or
#   'mirror.poliwangi.ac.id' within `/etc/apt/` and removes them using `rm -f`.
# - Removes `/etc/apt/sources.list.d/google-chrome-beta.list` if a stable version list also exists.
# - Adds the Spotify GPG public key (ID: 6224F9941A8AA6D1) using `apt-key` (with deprecation warning).
# - Cleans the local APT package cache using `apt-get clean`.
# - Updates the APT package index using `apt-get update -y`.
# - Installs the `imagemagick` package using `apt-get install -y imagemagick`.
# - Exits with status 0 on success, or 1 on CRITICAL errors detected by `log_message`.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Simplicity:** Aims for a straightforward, sequential execution flow for its specific task.
# - **Robustness:** Incorporates strict mode (`set -euo pipefail`), explicit checks for root privileges
#   and dependencies, and basic error handling via logging levels (CRITICAL logs cause exit).
# - **Readability:** Uses clear variable names, comments, and a structured logging function.
# - **Specificity:** Hardcoded for Debian 10 (Buster) and predefined cleanup/installation tasks.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - System Administrators managing Debian 10 (Buster) systems.
# - Users needing to standardize APT repositories and install ImageMagick on Buster.
# - Personnel managing systems (e.g., "PC SOC") where these specific cleanup steps are required.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x buster_apt_setup_imagemagick.sh`
# - File system access: Requires root privileges to read/write `/etc/apt/`, manage keys,
#   run `apt-get`, and potentially create temporary files in `/tmp`.
# - Network access: Required for `apt-key` (keyserver) and `apt-get` (repositories).
# - Elevated privileges: **Requires `sudo` or root privileges** for almost all operations.
#
# **Basic Syntax:**
# `sudo ./buster_apt_setup_imagemagick.sh`
#
# **Options:**
# - None implemented. (Future improvement could add `-v` for verbose debug logs).
#
# **Arguments:**
# - None implemented.
#
# **Common Examples:**
# 1. Execute the script with root privileges:
#    `sudo ./buster_apt_setup_imagemagick.sh`
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - System-wide scripts requiring root: `/usr/local/sbin/`
# - User scripts (if adapted not to need root for all steps): `~/bin/` or `~/.local/bin/`
#
# **Manual Setup:**
# 1. Place the script in the chosen location (e.g., `/usr/local/sbin/`).
# 2. Set appropriate ownership: `sudo chown root:root /usr/local/sbin/buster_apt_setup_imagemagick.sh`
# 3. Set executable permissions: `sudo chmod 750 /usr/local/sbin/buster_apt_setup_imagemagick.sh` (owner rwx, group rx)
# 4. Ensure all dependencies are met (see below).
# 5. Run the script: `sudo /usr/local/sbin/buster_apt_setup_imagemagick.sh`
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: Version >= 4 recommended for `mapfile`/associative arrays if used later (not current). `set -o pipefail` needs Bash.
#
# **Required System Binaries/Tools:**
# - `coreutils`: Provides `cat`, `rm`, `basename`, `dirname`, `mktemp`, `date`, `tr`, `echo`.
# - `grep`: Used for searching file content (`grep -q`).
# - `find`: Used for locating files based on content search.
# - `xargs`: Used with find/rm (though simplified implementation might use loop).
# - `apt-get`: For package management (update, install, clean). Preferred over `apt` for scripting.
# - `apt-key`: For managing APT keys (Note: Deprecated).
# - `command`: Bash built-in for checking command existence.
#
# **Setup Instructions (Standard Tools):**
# - These tools are typically pre-installed on Debian systems. If missing:
#   `sudo apt update && sudo apt install -y coreutils grep findutils xargs apt dpkg`
#
# **Operating System Compatibility:**
# - Designed specifically for: Debian 10 (Buster).
# - Known compatibility issues: Will likely fail or misconfigure repositories on other Debian/Ubuntu versions or different Linux distributions due to hardcoded repository names and paths.
#
# **Environment Variables Used:**
# - `EUID`: Checked for root privileges.
# - `PATH`: Standard variable, assumes required binaries are locatable.
# - (No custom environment variables are used or expected).
#
# **System Resource Requirements:**
# - CPU/Memory: Minimal usage during configuration/cleanup. Moderate during `apt-get update/install`.
# - Disk Space: Requires space for `imagemagick` and its dependencies (~hundreds of MBs). Requires small space for APT lists and potentially temporary files in `/tmp`.
# - Network: Required bandwidth for downloading GPG key, package lists, and packages.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): INFO and DEBUG (if VERBOSE=true) messages.
# - Standard Error (stderr): WARN, ERROR, and CRITICAL messages.
# - Dedicated Log File: No (Not implemented in this version).
# - System Log (syslog/journald): No.
#
# **Log Format:**
# - `[YYYY-MM-DD HH:MM:SS TZ] [LEVEL] - Message`
# - Example: `[2025-04-20 18:30:00 WIB] [INFO] - Starting main script execution...`
#
# **Log Levels:**
# - `DEBUG`: Detailed step tracing (Currently only active if `VERBOSE=true` is manually set).
# - `INFO`: General operational messages, start/stop, steps completed.
# - `WARN`: Potential issues, non-critical errors (e.g., deprecated `apt-key` usage, failure to clean cache).
# - `ERROR`: Significant errors likely preventing task completion (e.g., failed key add, failed package install).
# - `CRITICAL`: Severe errors causing script termination via `exit 1` (e.g., not root, missing dependency, failed file write, failed apt update).
# - Control: Log level filtering is basic (only DEBUG hidden by default). No command-line control implemented.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Prints INFO/DEBUG level status messages from the `log_message` function.
#
# **Standard Error (stderr):**
# - Prints WARN, ERROR, CRITICAL level messages from the `log_message` function.
# - May also display error messages directly from underlying commands (`apt-get`, `apt-key`, `rm`, etc.) if they fail and `set -e` triggers exit before the script logs it.
#
# **Generated/Modified Files:**
# - `/etc/apt/sources.list`: Overwritten with standard Buster repositories.
# - Files within `/etc/apt/`: Files matching specified patterns (`buster-backports`,
#   `mirror.poliwangi.ac.id`, `google-chrome-beta.list`) may be deleted.
# - APT Keyring: Modified by `apt-key` to add the Spotify key.
# - APT Cache (`/var/cache/apt/archives/`): Cleaned by `apt-get clean`.
# - Temporary Files: May create temporary files via `mktemp` in `/tmp` during file searching; these should be cleaned up automatically.
# - System State: `imagemagick` package and its dependencies will be installed or updated.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success - Script completed all steps (may include non-critical WARN/ERROR messages logged).
# - 1: Critical Error - Script exited prematurely due to a CRITICAL level log message (e.g., failed check, failed critical command). Also default exit code from `set -e` if a command fails unexpectedly.
# - Other non-zero: Possible if underlying commands exit with specific codes not explicitly handled before `set -e` terminates the script.
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** "Permission Denied" errors / "must be run as root".
#   **Resolution:** Ensure the script is executed using `sudo`.
# - **Issue:** `apt-key`/`apt-get` commands fail (network errors, GPG errors, hash sum mismatch).
#   **Resolution:** Check network connectivity (`ping deb.debian.org`). Verify DNS (`resolvectl query deb.debian.org`). Check system time is accurate (for SSL/TLS). Try `apt-get clean` manually. Ensure configured repositories are accessible and GPG keys haven't expired.
# - **Issue:** Script deletes an important configuration file accidentally.
#   **Resolution:** Restore `/etc/apt/` from backup. **Crucially, BACK UP `/etc/apt/` before running this script.** Review the patterns (`BACKPORTS_PATTERN`, `UNWANTED_MIRROR_PATTERN`) for accuracy.
# - **Issue:** "Required command 'X' not found".
#   **Resolution:** Install the missing package using `sudo apt-get install package-providing-X`.
#
# **Important Considerations / Warnings:**
# - **CRITICAL: DATA MODIFICATION/DELETION RISK**
#   This script performs destructive actions with minimal prompting:
#     - It **overwrites** the entire `/etc/apt/sources.list` file. All previous content is lost.
#     - It uses `rm -f` to delete files found via `find`/`grep` within `/etc/apt/`. While `find` is safer than `grep | xargs` for filenames, an incorrect pattern could still lead to unintended deletion.
#     **=> BACK UP THE `/etc/apt/` DIRECTORY BEFORE RUNNING THIS SCRIPT <=**
# - **Hardcoded Configuration:** Specifically tailored for Debian 10 (Buster). Not suitable for other systems without modification.
# - **`apt-key` Deprecation:** Uses the `apt-key` command which is deprecated due to security concerns regarding global key management. The modern approach involves managing keys individually in `/etc/apt/trusted.gpg.d/`. Consider migrating this step manually.
# - **Idempotency:** Mostly idempotent (rerunning should yield the same state), but `apt-key adv` might repeatedly try to add the key (harmlessly), and `apt-get install` will update ImageMagick if a newer version is available. File removals only happen if the files exist.
# - **Error Handling Scope:** Uses `set -e` and CRITICAL logs for major failures. Some non-critical command failures (like `apt-get clean`, `rm` in some cases) are logged as WARN/ERROR but may not stop execution unless `set -e` catches them first.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - The script is being executed on a Debian 10 (Buster) system.
# - The script is executed with root privileges (EUID=0).
# - The system has reliable network connectivity to reach `deb.debian.org`, `security.debian.org`, and `keyserver.ubuntu.com`.
# - Standard command-line utilities (coreutils, findutils, grep, apt-get, apt-key, etc.) are installed and available in the system `$PATH`.
# - The `/tmp` directory is writable for creating temporary files.
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - Replace deprecated `apt-key` with modern key management (downloading key to `/etc/apt/trusted.gpg.d/`).
# - Add command-line arguments (`getopts`) for verbosity (`-v`), dry-run (`-n`), skipping steps.
# - Make OS version detection and repository configuration more dynamic or configurable.
# - Implement optional logging to a file.
# - Enhance error handling for specific `apt-get` or file operation failures.
# - Add a proper `cleanup` function using `trap` for temporary files (though `mktemp` handles this reasonably well).
# - Integrate with `shellcheck` for static analysis during development/CI.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Requires root privileges. Grants extensive system access. Execute with caution.
# - **Input Sanitization:** Does not take external user input for commands, reducing command injection risks. Relies on predefined constants.
# - **Sensitive Data Handling:** Does not handle passwords or API keys.
# - **Dependencies:** Relies on standard system tools and APT infrastructure. Keep the underlying system patched. `apt-key` usage is a known security smell (see deprecation notes).
# - **File Permissions:** Modifies system files in `/etc/apt/`. Creates temporary files in `/tmp` using `mktemp` (which uses secure permissions).
# - **External Command Execution:** Executes system commands (`cat`, `find`, `grep`, `rm`, `apt-key`, `apt-get`). These are core system functions but run with root privileges.
# - **`rm -f`:** Forced removal of files based on `find`/`grep` output carries inherent risk if patterns are imprecise or match unintended files in `/etc/apt/`. The use of `find` is safer for parsing filenames than `grep | xargs`.
# - **Network Exposure:** Connects to Debian repositories and Ubuntu keyserver over standard protocols (HTTP/HTTPS, HKP). Ensure network path is secure if necessary.
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
# - Bug Reports/Issues: Report issues via the script's repository (if available at REPOSITORY link) or directly to the author's contact email.
# =========================================================================================

# =========================================================================================
# SCRIPT EXECUTION ENVIRONMENT & CONFIGURATION
# =========================================================================================

# --- Bash Strict Mode ---
# -e: Exit immediately if a command exits with a non-zero status.
# -u: Treat unset variables and parameters as an error when performing parameter expansion.
# -o pipefail: The return value of a pipeline is the status of the last command to exit
#              with a non-zero status, or zero if none exited non-zero.
set -euo pipefail

# --- Debug Mode ---
# Uncomment the following line for debugging (prints each command before execution):
# set -x

# --- Script Information ---
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
# Resolve the absolute path of the script's directory
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_DIR="${SOURCE_DIR}"
readonly SCRIPT_PID=$$

# --- Timestamp ---
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Global Runtime Variables ---
# Define constants for easier maintenance
readonly SOURCES_LIST_PATH="/etc/apt/sources.list"
readonly APT_SOURCES_D_PATH="/etc/apt/sources.list.d"
readonly APT_DIR="/etc/apt"
readonly CHROME_BETA_LIST="${APT_SOURCES_D_PATH}/google-chrome-beta.list"
readonly CHROME_STABLE_LIST="${APT_SOURCES_D_PATH}/google-chrome.list"
readonly SPOTIFY_KEY_ID="6224F9941A8AA6D1"
readonly SPOTIFY_KEYSERVER="keyserver.ubuntu.com"
readonly BACKPORTS_PATTERN="buster-backports"
readonly UNWANTED_MIRROR_PATTERN="mirror.poliwangi.ac.id"
readonly REQUIRED_PACKAGES=("imagemagick")

# Flags
VERBOSE=false # Set via arguments if implemented
NO_COLOR=false # Set via arguments if implemented
INTERACTIVE_MODE=false # Auto-detected
[[ -t 1 ]] && INTERACTIVE_MODE=true

# --- Color Definitions (Optional) ---
if [[ "${NO_COLOR}" == false && "${INTERACTIVE_MODE}" == true ]]; then
    COLOR_RESET='\033[0m'; COLOR_RED='\033[0;31m'; COLOR_GREEN='\033[0;32m'
    COLOR_YELLOW='\033[0;33m'; COLOR_BLUE='\033[0;34m'; COLOR_CYAN='\033[0;36m'
    COLOR_BOLD='\033[1m'
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
    local level="$1"; local message="$2"; local timestamp; local level_upper
    timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z")
    level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]')
    local log_prefix="[${timestamp}] [${level_upper}]"; local log_line="${log_prefix} - ${message}"
    local color=""

    case "${level_upper}" in
        DEBUG) color="${COLOR_CYAN}" ;; INFO) color="${COLOR_GREEN}" ;;
        WARN) color="${COLOR_YELLOW}" ;; ERROR|CRITICAL) color="${COLOR_RED}${COLOR_BOLD}" ;;
    esac

    # Output to stderr for WARN/ERROR/CRITICAL, stdout otherwise
    if [[ "${level_upper}" == "WARN" || "${level_upper}" == "ERROR" || "${level_upper}" == "CRITICAL" ]]; then
        echo -e "${color}${log_line}${COLOR_RESET}" >&2
    elif [[ "${level_upper}" != "DEBUG" || "${VERBOSE}" == true ]]; then
        echo -e "${color}${log_line}${COLOR_RESET}"
    fi

    # Exit immediately for CRITICAL errors
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        log_message "INFO" "Critical error encountered. Exiting script."
        exit 1
    fi
}

# --- Check Root Privilege Function ---
# Exits if the script is not run as root.
check_root() {
    log_message "INFO" "Checking for root privileges..."
    if [[ "${EUID}" -ne 0 ]]; then
        log_message "CRITICAL" "This script must be run as root (e.g., using sudo)."
    fi
    log_message "INFO" "Root privileges check passed."
}

# --- Dependency Check Function ---
# Exits with error if a required command is missing.
check_dependency() {
    local cmd="$1"
    log_message "DEBUG" "Checking for command: ${cmd}"
    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required command '${cmd}' not found. Please install it."
    fi
}

# --- Remove Files By Pattern Function ---
# Safely finds and removes files matching a pattern within a directory.
remove_files_by_pattern() {
    local search_dir="$1"
    local pattern="$2"
    local description="$3" # e.g., "buster-backports"
    local found_files

    log_message "INFO" "Searching for files containing '${pattern}' in '${search_dir}'..."

    # Use find instead of grep for safer filename handling (handles spaces, special chars)
    # -type f: only find files
    # -exec grep -q: quietly search inside each file for the pattern
    # -print: print the filename if grep finds the pattern
    # Use a temporary file to store found files for logging/deletion
    local tmp_file
    tmp_file=$(mktemp)

    # Find files containing the pattern and store the list
    find "${search_dir}" -type f -exec grep -q "${pattern}" {} \; -print > "${tmp_file}"

    found_files=$(cat "${tmp_file}")

    if [[ -n "${found_files}" ]]; then
        log_message "WARN" "Found files related to ${description} scheduled for removal:"
        # Log files before deleting (indent for readability)
        while IFS= read -r file; do
             log_message "WARN" "  - ${file}"
        done <<< "${found_files}"

        log_message "INFO" "Attempting to remove identified ${description} files..."
        # Use xargs with the temp file, handle potential errors during removal
        # Use --no-run-if-empty to avoid running rm if no files were found
        # Use -0 with find -print0 and xargs -0 if filenames might contain newlines (safer)
        # For simplicity here, assuming standard filenames without newlines:
        xargs rm -f < "${tmp_file}" || log_message "ERROR" "Failed to remove one or more ${description} files. Check permissions or errors above."

        log_message "INFO" "${description} related files removed."
    else
        log_message "INFO" "No files containing '${pattern}' found in '${search_dir}'. No removal needed."
    fi
    rm -f "${tmp_file}" # Clean up temporary file
}

# --- Main Logic Function ---
main() {
    log_message "INFO" "Starting main script execution: APT setup for Debian Buster..."

    # === Step 1: Configure Standard Debian Buster Repositories ===
    log_message "INFO" "Step 1: Configuring ${SOURCES_LIST_PATH} with standard Debian Buster repositories..."
    log_message "WARN" "This will overwrite any existing content in ${SOURCES_LIST_PATH}."
    # Using temporary file for atomicity (write to temp, then move) is safer,
    # but for simplicity, direct write is used here as in the original script.
    # Ensure the command succeeds. `set -e` handles exit, log explicit success/failure.
    if cat << EOL > "${SOURCES_LIST_PATH}"; then
# Debian Buster Official Repositories
deb http://deb.debian.org/debian/ buster main contrib non-free
deb-src http://deb.debian.org/debian/ buster main contrib non-free
# Security Updates
deb http://security.debian.org/debian-security buster/updates main contrib non-free
deb-src http://security.debian.org/debian-security buster/updates main contrib non-free
# Buster Updates
deb http://deb.debian.org/debian/ buster-updates main contrib non-free
deb-src http://deb.debian.org/debian/ buster-updates main contrib non-free
EOL
        log_message "INFO" "Successfully updated ${SOURCES_LIST_PATH}."
    else
        log_message "CRITICAL" "Failed to write to ${SOURCES_LIST_PATH}. Check permissions or disk space."
    fi

    # === Step 2: Remove Specific Unwanted Repository References ===
    log_message "INFO" "Step 2: Removing specific unwanted repository references..."
    remove_files_by_pattern "${APT_DIR}" "${BACKPORTS_PATTERN}" "buster-backports"
    remove_files_by_pattern "${APT_DIR}" "${UNWANTED_MIRROR_PATTERN}" "unwanted mirror (${UNWANTED_MIRROR_PATTERN})"

    # === Step 3: Deduplicate Google Chrome Sources ===
    log_message "INFO" "Step 3: Checking for duplicate Google Chrome repository entries..."
    if [[ -f "${CHROME_BETA_LIST}" && -f "${CHROME_STABLE_LIST}" ]]; then
        log_message "WARN" "Both stable and beta Google Chrome lists found. Removing beta list: ${CHROME_BETA_LIST}"
        rm -f "${CHROME_BETA_LIST}" || log_message "ERROR" "Failed to remove ${CHROME_BETA_LIST}. Check permissions."
        log_message "INFO" "Removed duplicate Google Chrome beta list."
    else
        log_message "INFO" "No duplicate Google Chrome lists found."
    fi

    # === Step 4: Add Spotify Repository GPG Key ===
    log_message "INFO" "Step 4: Adding Spotify repository GPG key (ID: ${SPOTIFY_KEY_ID})..."
    log_message "WARN" "Using deprecated 'apt-key'. Consider managing keys in ${APT_DIR}/trusted.gpg.d/ manually."
    apt-key adv --keyserver "${SPOTIFY_KEYSERVER}" --recv-keys "${SPOTIFY_KEY_ID}" || {
        log_message "ERROR" "Failed to add Spotify key using apt-key. Check network or keyserver status."
        # Decide if this is critical. For this script, maybe just an error.
    }
    log_message "INFO" "Spotify key addition process completed (check for errors above)."

    # === Step 5: Clean APT Package Cache ===
    log_message "INFO" "Step 5: Cleaning up APT package cache..."
    apt-get clean || log_message "WARN" "Failed to clean APT cache. This may not be critical."
    log_message "INFO" "APT cache cleaned."

    # === Step 6: Update Package Lists and Install ImageMagick ===
    log_message "INFO" "Step 6: Updating package lists and installing required packages..."
    log_message "INFO" "Running apt-get update..."
    # Use apt-get for better script stability over apt
    apt-get update -y || log_message "CRITICAL" "Failed to update APT package lists. Check network and repository configuration (${SOURCES_LIST_PATH})."
    log_message "INFO" "APT package lists updated successfully."

    log_message "INFO" "Installing required package(s): ${REQUIRED_PACKAGES[*]}..."
    apt-get install -y "${REQUIRED_PACKAGES[@]}" || {
        log_message "ERROR" "Failed to install one or more required packages: ${REQUIRED_PACKAGES[*]}."
        log_message "ERROR" "Check APT errors above. Manual installation might be required."
        # Consider if this failure should be critical depending on script's goal
    }
    log_message "INFO" "Package installation process completed (check for errors above)."

    log_message "INFO" "Main script execution finished."
}


# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# 1. Check for Root Privileges
check_root

# 2. Check Dependencies
log_message "INFO" "Checking required dependencies..."
check_dependency "cat"
check_dependency "grep"
check_dependency "find" # Added for safer file searching
check_dependency "xargs"
check_dependency "rm"
check_dependency "apt-key"
check_dependency "apt-get" # Changed from apt for stability
check_dependency "date"
check_dependency "mktemp" # Added for temporary file usage

# Argument Parsing would go here if implemented (e.g., parse_params "$@")

# 3. Execute Main Logic
main

# 4. Exit Successfully
log_message "INFO" "${SCRIPT_NAME} completed successfully."
exit 0

# =========================================================================================
# --- End of Script ---
