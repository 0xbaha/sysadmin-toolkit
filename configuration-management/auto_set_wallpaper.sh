#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : auto_set_wallpaper.sh
# PURPOSE       : Standardizes backgrounds & displays hostname on Cinnamon desktops.
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
# This script automates the process of setting a standardized desktop wallpaper on Linux
# systems running the Cinnamon desktop environment (e.g., Linux Mint, LMDE). It ensures
# that all users logging into the machine see a consistent background image featuring the
# system's hostname. This aids in quick system identification, especially in environments
# with multiple similar machines.
#
# Key Functions / Workflow:
# - Dependency Check & Installation: Checks for the required 'ImageMagick' toolkit (specifically the 'convert' command).
#   If not found, it attempts to install it using the 'apt' package manager.
# - Environment Compatibility Check: Verifies that the 'gsettings' command can interact with
#   Cinnamon desktop background settings ('org.cinnamon.desktop.background picture-uri'), confirming compatibility.
# - Shared Directory Management: Creates a shared directory ('/shared/wallpapers' by default)
#   to store the generated wallpaper, making it accessible to all users. Sets appropriate permissions.
# - Wallpaper Generation: Creates a 1920x1080 black wallpaper using ImageMagick's 'convert', overlaying
#   the system's current hostname in large, centered, white text.
# - User Autostart Configuration: Iterates through user directories in '/home'. For each user,
#   it creates a '.desktop' autostart entry in '~/.config/autostart/'. This entry runs a
#   'gsettings' command upon user login to apply the generated wallpaper.
#
# The script requires root privileges (sudo) for package installation, shared directory creation,
# and modifying user autostart configurations.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Robustness**: Includes checks for essential dependencies (ImageMagick, gsettings compatibility)
#   and attempts automatic installation of ImageMagick. Includes basic error handling and exit codes
#   for critical steps. Uses `set -euo pipefail` for stricter error checking.
# - **Automation**: Designed primarily for a one-time setup. It configures automatic wallpaper
#   application for all detected users via standard desktop autostart entries, eliminating manual
#   configuration per user or per login.
# - **User-Agnostic**: Automatically detects user home directories under /home and sets up
#   the autostart mechanism individually, ensuring the wallpaper applies regardless of
#   which standard user logs into the Cinnamon desktop.
# - **Simplicity**: Leverages standard Linux commands and widely available tools (ImageMagick, gsettings, coreutils)
#   for broad compatibility within its target environment (Debian-based systems with Cinnamon).
# - **Centralized Wallpaper**: Stores the single generated wallpaper image in a shared location
#   ('/shared/wallpapers') to avoid duplication across user home directories and simplify updates if needed.
# - **Readability**: Uses functions for distinct tasks, clear variable names, and extensive comments.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - Linux System Administrators managing fleets of workstations or servers with graphical logins.
# - IT Support Teams responsible for desktop configuration, standardization, and branding.
# - Lab Managers needing easy visual identification of machines.
# - Anyone needing to automatically set a dynamic (hostname-based) wallpaper for all
#   users on a shared Linux Mint or other Cinnamon-based system.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: Must be run with root privileges using `sudo`. This is required for:
#   - Installing software packages ('imagemagick') via 'apt'.
#   - Creating/managing directories outside the user's home (e.g., '/shared/wallpapers').
#   - Creating directories and files within *other users'* home directories (specifically '~/.config/autostart').
# - File system access: Read access to `/home/`, write access to `/shared/` (to create `/shared/wallpapers`), write access to user `~/.config/` dirs.
# - Network access: Outbound HTTPS/HTTP access may be needed by `apt` to download packages if ImageMagick is not installed.
# - Elevated privileges: Requires `sudo` for `apt`, `mkdir`, `chmod`, `chown` operations outside the user's home or in other users' homes.
#
# **Basic Syntax:**
# `sudo bash /path/to/auto_set_wallpaper.sh`
# or if in PATH or current directory (and executable: `chmod +x auto_set_wallpaper.sh`):
# `sudo ./auto_set_wallpaper.sh`
#
# **Options:**
# - None. The script does not accept any command-line flags or options.
#
# **Arguments:**
# - None. The script does not accept any command-line arguments. It automatically
#   detects the system hostname and user directories under /home.
#
# **Common Examples:**
# 1. Execute from the directory where the script is saved:
#    `sudo ./auto_set_wallpaper.sh`
#
# 2. Execute using the full path (if placed in /usr/local/sbin):
#    `sudo bash /usr/local/sbin/auto_set_wallpaper.sh`
#
# **Advanced Execution (Automation):**
# - Cron Job: Generally **not recommended** or needed. The script sets up user-level autostart which handles wallpaper application on login. Running via cron would be redundant.
# - Systemd Service: Not applicable for the intended setup mechanism (user autostart).
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - System-wide scripts (requiring root): `/usr/local/sbin/` (Common for locally installed admin scripts)
# - Custom scripts directory: `/opt/scripts/`
#
# **Manual Setup:**
# 1. Copy the script to the chosen location (e.g., `sudo cp auto_set_wallpaper.sh /usr/local/sbin/`).
# 2. Set appropriate ownership: `sudo chown root:root /usr/local/sbin/auto_set_wallpaper.sh`.
# 3. Set executable permissions: `sudo chmod 700 /usr/local/sbin/auto_set_wallpaper.sh` (Owner RWX, Group/Other no access).
# 4. Install required dependencies (Script attempts auto-install of ImageMagick, see DEPENDENCIES).
# 5. Run the script **once** with `sudo` (e.g., `sudo /usr/local/sbin/auto_set_wallpaper.sh`).
#
# **Integration:**
# - No systemd service or cron job is typically required as the script configures user-level autostart via `.desktop` files.
# - Configuration Management (Ansible, etc.): Deploy the script file and execute it once on target machines.
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: The Bourne-Again SHell interpreter (Version >= 4.x recommended for features like `mapfile`). Uses bashisms.
#
# **Required System Binaries/Tools:**
# - `coreutils`: Provides `basename`, `cat`, `chmod`, `chown`, `date`, `dirname`, `echo`, `mkdir`, `printf`, `pwd`, `tee`, `tr`.
# - `hostname`: Retrieves the system hostname.
# - `apt`: (Debian/Ubuntu specific) Package manager used to potentially install `imagemagick`.
# - `sudo`: Executes commands with elevated privileges.
# - `imagemagick`: Provides `convert` for image generation. (Script attempts auto-install via `apt`).
# - `gsettings`: Part of GLib/GNOME libs. Interacts with desktop settings schemas (specifically `org.cinnamon.desktop.background`).
# - `command`: Bash built-in for checking command existence.
# - `dbus-launch`: Used to ensure `gsettings` can connect to a D-Bus session when run via `sudo` during the check. (Package: `dbus-x11` or similar).
#
# **Setup Instructions:**
# - Core utilities, `hostname`, `sudo`, `gsettings`, `dbus-launch` are typically pre-installed on Debian-based systems with Cinnamon.
# - The script attempts `sudo apt update && sudo apt install -y imagemagick` if `convert` is missing. Manual installation (`sudo apt install imagemagick`) may be needed if this fails (e.g., due to network issues or repo problems).
# - Check availability: `command -v convert`, `command -v gsettings`, etc.
#
# **Operating System Compatibility:**
# - Designed primarily for: **Debian-based Linux distributions** (e.g., Debian, Ubuntu, Linux Mint, LMDE) using the `apt` package manager.
# - Requires the **Cinnamon Desktop Environment** to be installed and active for users. Compatibility is verified by checking access to `org.cinnamon.desktop.background picture-uri`.
# - May require adjustments for non-Debian systems (package manager, paths) or other desktop environments.
#
# **Environment Variables Used:**
# - `EUID`: Checked to ensure script is run as root.
# - `HOME`: Used implicitly by `sudo -u` and path expansion (`~`).
# - `DISPLAY`, `DBUS_SESSION_BUS_ADDRESS`: May be relevant for `gsettings` functioning, handled by `dbus-launch` during the check.
#
# **System Resource Requirements:**
# - Minimal. Requires disk space for the ImageMagick package (~50-100MB if installed) and the single small wallpaper image file (~few KB).
# - CPU/Memory usage is negligible, occurring only during the brief execution of the script (especially `apt install` and `convert`).
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): Used for informational messages (INFO level), progress updates, success confirmation. Colorized if interactive terminal.
# - Standard Error (stderr): Used for error messages (ERROR, CRITICAL levels) and warnings (WARN level). Colorized if interactive terminal. DEBUG messages also go here if enabled (not currently enabled by default).
# - Dedicated Log File: No. Logs are only sent to stdout/stderr.
# - System Log (syslog/journald): No.
#
# **Log Format:**
# - `[YYYY-MM-DD HH:MM:SS ZONE] [LEVEL] - Message` (e.g., `[2025-04-17 15:30:00 UTC] [INFO] - Starting script execution...`)
#
# **Log Levels (Implemented):**
# - `DEBUG`: Detailed internal steps (Use `log_message DEBUG "..."`). Not shown by default.
# - `INFO`: General operational messages, progress.
# - `WARN`: Potential issues, non-critical errors.
# - `ERROR`: Significant errors likely impacting success.
# - `CRITICAL`: Severe errors causing script termination (via `exit 1` in `log_message`).
# - Control: Log level filtering is basic (only DEBUG is suppressed unless VERBOSE=true, which isn't implemented via args yet).
#
# **Log Rotation:**
# - Not applicable. Logging is transient to stdout/stderr. Redirect output if persistence is needed: `sudo ./auto_set_wallpaper.sh > script.log 2>&1`.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Normal Operation: Prints INFO messages confirming checks passed, actions taken (creating folders/files, generating wallpaper), and final success message. Colorized.
#
# **Standard Error (stderr):**
# - Errors: Prints ERROR and CRITICAL messages indicating failures (dependency missing, install failed, command failed, permission denied). Colorized.
# - Warnings: Prints WARN messages for non-critical issues (e.g., failed to set permissions on generated file but continuing). Colorized.
# - Debug Output: Would appear here if `VERBOSE=true` were implemented and enabled.
#
# **Generated/Modified Files:**
# - **Wallpaper Image:** `${SHARED_FOLDER}/${OUTPUT_FILENAME}` (Default: `/shared/wallpapers/fullscreen_hostname_dark.png`). This PNG image file contains the hostname text. Permissions set to `644` (Owner RW, Group R, Other R).
# - **Shared Directory:** `${SHARED_FOLDER}` (Default: `/shared/wallpapers/`). Created if it doesn't exist. Permissions set to `777` (World RWE - see Security Considerations).
# - **Autostart Entries:** `/home/USERNAME/.config/autostart/set_hostname_wallpaper.desktop` (created within each detected user's home directory). These files trigger the wallpaper setting on login via `gsettings`. Permissions set to `644` and owned by the respective user.
# - **Temporary Files:** None explicitly created or managed. `apt` and `convert` might use system temporary space.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success - Script completed. Wallpaper generated, autostart entries attempted for all detected users (individual user setup failures result in WARN, not exit 1).
# - 1: General/Critical Error - Used for various failures causing script termination, including:
#   - Not run as root.
#   - Failed to retrieve hostname.
#   - Critical dependency missing (coreutils, etc.).
#   - Failed to install/verify ImageMagick.
#   - `gsettings` incompatibility detected.
#   - Failed to create the shared folder.
#   - Failed to generate the wallpaper image.
#   - Other unexpected errors due to `set -e`.
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** "CRITICAL: This script must be run as root..."
#   **Resolution:** Execute the script using `sudo`: `sudo ./auto_set_wallpaper.sh`.
# - **Issue:** "ERROR: Failed to install 'imagemagick'..."
#   **Resolution:** Check network connectivity. Run `sudo apt update` manually. Try `sudo apt install imagemagick` manually to see detailed errors. Check repository sources (`/etc/apt/sources.list`).
# - **Issue:** "ERROR: gsettings check failed..."
#   **Resolution:** Confirm the system is running Cinnamon desktop environment. Ensure `gsettings` works manually (e.g., `gsettings list-schemas`). Check D-Bus status (`systemctl status dbus`).
# - **Issue:** "ERROR: Failed to create shared folder..." or "ERROR: ImageMagick 'convert' command failed..."
#   **Resolution:** Check permissions on the parent directory (e.g., `/shared/` requires root write access). Check for sufficient disk space (`df -h`). Verify ImageMagick installed correctly (`convert --version`).
# - **Issue:** "ERROR: Failed to set up autostart for user..."
#   **Resolution:** Verify permissions on the user's home directory (`ls -ld /home/USERNAME`) and their `.config` directory (`ls -ld /home/USERNAME/.config`). Ensure the user exists and the home directory structure is standard.
# - **Issue:** Wallpaper doesn't apply after login (Script ran successfully).
#   **Resolution:** Log in as the user. Check autostart file exists: `ls ~/.config/autostart/set_hostname_wallpaper.desktop`. Check its contents (`cat ...`). Verify the path in `Exec=` is correct and points to the existing image. Run the `Exec=` command manually in the user's terminal: `gsettings set org.cinnamon.desktop.background picture-uri 'file:///shared/wallpapers/fullscreen_hostname_dark.png'`. Check session logs (`~/.xsession-errors` or journalctl) for errors related to autostart.
#
# **Important Considerations / Warnings:**
# - **Root Requirement:** This script *must* be run as root (`sudo`). Exercise caution.
# - **File Permissions (`/shared/wallpapers`):** Creates the directory with `777` (World RWE) permissions for simplicity. This is potentially insecure. Consider changing `SHARED_FOLDER_PERMS` to `755` (Owner RWE, Group RE, Other RE) if only root needs to write the wallpaper and users only need read access. The wallpaper file itself is `644` (Owner RW, Others R), which is generally appropriate.
# - **User Configuration Modification:** The script modifies user configuration by adding files to `~/.config/autostart`. While the `.desktop` file created is benign (just sets wallpaper via `gsettings`), be aware it automatically alters settings for all detected users in `/home`.
# - **Idempotency:** The script is mostly idempotent. Re-running it will regenerate the wallpaper (no harm if hostname is same) and overwrite the existing autostart files (no functional change). It won't endlessly create new files or cause errors on re-run (unless underlying permissions change).
# - **Error Scope:** A failure during setup for one specific user (e.g., bad home dir permissions) will log an ERROR but will *not* stop the script from attempting setup for other users (currently logged as WARN at the end). Critical failures (dependencies, wallpaper generation) will stop the script via `exit 1`.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - The script is executed on a Debian-based Linux distribution (e.g., Debian, Ubuntu, Linux Mint, LMDE) using `apt`.
# - The Cinnamon desktop environment is installed and is the active/default graphical session for users who should see the wallpaper.
# - Standard user home directories are located directly under `/home` (e.g., `/home/user1`, `/home/user2`). It does not scan other locations like `/root` or network homes mounted elsewhere.
# - The system has network access if ImageMagick needs to be downloaded and installed via `apt`.
# - The script is executed with `sudo` or directly as the root user (EUID 0).
# - The desired wallpaper resolution is 1920x1080 (hardcoded in `WALLPAPER_WIDTH_DEFAULT`/`WALLPAPER_HEIGHT_DEFAULT`).
# - `dbus-launch` is available for the root gsettings check.
# =========================================================================================

# =========================================================================================
# PERFORMANCE OPTIMIZATION
# =========================================================================================
# - Performance is generally not a significant factor for this script's intended use (one-time setup).
# - Resource Consumption Profile:
#   - CPU: Low, brief spike during `convert` or `apt install`.
#   - Memory: Low, moderate spike during `apt install`.
#   - Disk I/O: Moderate during `apt install`, low otherwise (reading `/home`, writing small files).
#   - Network: Required only if `apt install` runs.
# - Optimization Notes: Uses standard, efficient tools. No parallel processing implemented as the user loop is typically fast.
# =========================================================================================

# =========================================================================================
# TESTING & VALIDATION
# =========================================================================================
# - **Test Strategy:** Manual testing is recommended before production deployment. No automated tests (Bats, shunit2) included. Static analysis via ShellCheck is recommended.
# - **Key Test Cases Covered (Manual):**
#   - Run on a system *without* ImageMagick installed (verify auto-install works).
#   - Run on a system *with* ImageMagick already installed.
#   - Run on a system *not* running Cinnamon (verify gsettings check fails and exits).
#   - Verify wallpaper file is created correctly in `/shared/wallpapers` with correct content/permissions.
#   - Verify autostart files are created for all expected users in `/home/*/.config/autostart/` with correct content/ownership/permissions.
#   - Log in as different users to confirm the wallpaper is applied correctly after setup.
#   - Test with user home directories having varied permissions (e.g., unreadable `.config`) to check error handling.
#   - Re-run the script to check for idempotency (should complete successfully without unwanted side effects).
# - **Validation Environment:** [Specify OS/versions tested, e.g., Tested on Linux Mint 21.3 Cinnamon, Bash 5.1.16, ImageMagick 6.9.11].
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - Add command-line options (`getopts`/`getopt`) to customize:
#   - Output wallpaper path/filename (`-o FILE`).
#   - Shared folder location (`-d DIR`).
#   - Wallpaper resolution (`-s WxH`).
#   - Font size (`-p SIZE`), color (`-f COLOR`), type (`-F FONT`).
#   - Background color (`-b COLOR`) or use a base image.
#   - Permissions for shared folder (`--perms MODE`).
#   - Add `-v`/`--verbose` flag for DEBUG level logging.
# - Implement support for other Desktop Environments (e.g., GNOME, MATE, XFCE) by detecting the DE (`XDG_CURRENT_DESKTOP`) and using appropriate settings commands/keys.
# - Add more robust error handling (e.g., option to exit immediately if *any* user setup fails).
# - Implement a `--cleanup` or `--uninstall` option to remove generated files and autostart entries.
# - Check available disk space before attempting image generation.
# - Allow configuration via a config file (`/etc/auto_wallpaper.conf`?).
# - Add locking mechanism (`flock`) to prevent concurrent executions if needed (unlikely for this script).
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Requires root (`sudo`) access. This grants extensive permissions. **Only run trusted scripts as root.** Needed for `apt`, creating `/shared/wallpapers`, and writing to other users' `~/.config` directories.
# - **Input Sanitization:** No external input is taken via command-line arguments, reducing risk. The `HOSTNAME` variable is from the system's `hostname` command; while unlikely to be malicious, `convert -annotate` is generally robust against unusual characters. Variables for paths/colors are hardcoded or derived internally.
# - **Sensitive Data Handling:** No passwords, API keys, or other sensitive data are handled or required.
# - **Dependencies:** Relies on standard OS tools (`apt`, `gsettings`, `coreutils`) and `imagemagick`. Ensure these are sourced from trusted OS repositories. Keep the system (especially `imagemagick`) updated as vulnerabilities can occur.
# - **File Permissions:**
#   - `/shared/wallpapers` directory created with `777` (World RWE) by default via `SHARED_FOLDER_PERMS`. **This is overly permissive.** Consider changing `SHARED_FOLDER_PERMS` to `755` (Owner RWE, Group RE, Other RE) for better security.
#   - Wallpaper file (`$OUTPUT_PATH`) permissions set to `644` (Owner RW, Group R, Other R), which is appropriate.
#   - Autostart `.desktop` files are created as the target user (via `sudo -u` and `tee`) and permissions set to `644`, which is appropriate and secure. Ownership is also verified/set using `sudo chown`.
# - **External Command Execution:** Executes `hostname`, `apt`, `convert`, `gsettings`, `mkdir`, `chmod`, `chown`, `tee`, `dbus-launch`. These are standard system commands. Variables used (like `${HOSTNAME}`, `${OUTPUT_PATH}`) are quoted to prevent injection issues in most contexts. `gsettings` execution via `.desktop` file runs as the logged-in user.
# - **Network Exposure:** Network access used only by `apt` if `imagemagick` installation is needed. Ensure `apt` sources are secure.
# - **Code Integrity:** If downloading the script, verify its integrity using checksums (e.g., SHA256) if provided by the source: `sha256sum auto_set_wallpaper.sh`.
# - **Error Message Verbosity:** Current error messages do not intentionally leak sensitive data. Path information is included, which is standard for diagnosing issues.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is contained within this script's header comments.
# - No external documentation (README, Wiki, man page) is provided.
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha (Baharuddin Aziz)
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Report issues via the script's repository (if available: https://baha.my.id/github) or directly to the author's contact email.
# - Feature Requests: Submit via repository issues or email.
# =========================================================================================

# =========================================================================================
# SCRIPT EXECUTION ENVIRONMENT & CONFIGURATION
# =========================================================================================

# --- Bash Strict Mode ---
# -e: Exit immediately if a command exits with a non-zero status.
# -u: Treat unset variables and parameters as an error when performing parameter expansion.
# -o pipefail: The return value of a pipeline is the status of the last command to exit with a non-zero status,
#              or zero if no command exited with a non-zero status.
set -euo pipefail

# --- Debug Mode ---
# Uncomment the following line for detailed command execution tracing:
# set -x

# --- Script Information ---
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_PID=$$

# --- Timestamp ---
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Global Configuration Variables (Constants) ---
# These define the core settings for the wallpaper and paths. Modify as needed.
readonly SHARED_FOLDER_DEFAULT="/shared/wallpapers"
readonly OUTPUT_FILENAME_DEFAULT="fullscreen_hostname_dark.png"
readonly WALLPAPER_WIDTH_DEFAULT="1920"
readonly WALLPAPER_HEIGHT_DEFAULT="1080"
readonly WALLPAPER_BG_COLOR_DEFAULT="black"
readonly FONT_COLOR_DEFAULT="white"
readonly FONT_SIZE_DEFAULT="200"
readonly SHARED_FOLDER_PERMS="777" # Permissions for the shared directory (Consider 755 for security)
readonly WALLPAPER_FILE_PERMS="644" # Permissions for the generated wallpaper file

# --- Runtime Variables ---
# These variables hold the actual values used during script execution.
# They are initialized from defaults but could potentially be overridden by future argument parsing.
SHARED_FOLDER="${SHARED_FOLDER_DEFAULT}"
OUTPUT_FILENAME="${OUTPUT_FILENAME_DEFAULT}"
WALLPAPER_WIDTH="${WALLPAPER_WIDTH_DEFAULT}"
WALLPAPER_HEIGHT="${WALLPAPER_HEIGHT_DEFAULT}"
WALLPAPER_BG_COLOR="${WALLPAPER_BG_COLOR_DEFAULT}"
FONT_COLOR="${FONT_COLOR_DEFAULT}"
FONT_SIZE="${FONT_SIZE_DEFAULT}"

# Derived Runtime Variables
OUTPUT_PATH="${SHARED_FOLDER}/${OUTPUT_FILENAME}"
HOSTNAME="" # Will be populated by get_hostname function

# Flags
VERBOSE=false # Set to true via future argument parsing if needed
NO_COLOR=false # Set to true via future argument parsing if needed
INTERACTIVE_MODE=false
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is a terminal

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
# Description: Handles formatted logging to stdout/stderr.
# Usage: log_message LEVEL "Message string" (e.g., log_message INFO "Starting...")
log_message() {
    local level="$1"; local message="$2"; local timestamp; timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z")
    local level_upper; level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]')
    local log_prefix="[${timestamp}] [${level_upper}]"
    local log_line="${log_prefix} - ${message}"
    local color=""

    case "${level_upper}" in
        DEBUG) color="${COLOR_CYAN}" ;;
        INFO) color="${COLOR_GREEN}" ;;
        WARN) color="${COLOR_YELLOW}" ;;
        ERROR|CRITICAL) color="${COLOR_RED}${COLOR_BOLD}" ;;
        *) color="${COLOR_RESET}" ;; # Default for other levels or direct echo usage
    esac

    # Output to stderr for WARN, ERROR, CRITICAL; stdout otherwise
    if [[ "${level_upper}" == "WARN" || "${level_upper}" == "ERROR" || "${level_upper}" == "CRITICAL" ]]; then
        echo -e "${color}${log_line}${COLOR_RESET}" >&2
    else
        # Print INFO and other levels to stdout
        echo -e "${color}${log_line}${COLOR_RESET}"
    fi

    # Exit immediately for CRITICAL errors
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        log_message "ERROR" "Critical error encountered. Exiting script."
        exit 1 # Use a general error code
    fi
}

# --- Ensure Root Function ---
# Description: Checks if the script is run with root privileges (EUID 0). Exits if not.
ensure_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        log_message "CRITICAL" "This script must be run as root (or using sudo)."
        # exit 1 handled by CRITICAL log level
    fi
    log_message "DEBUG" "Root privileges check passed (EUID: ${EUID})."
}

# --- Dependency Check Function ---
# Description: Checks if required command-line utilities are installed and executable.
# Arguments: $1: Command name (e.g., "convert")
#            $2: (Optional) Package name for installation suggestion
check_dependency() {
    local cmd="$1"
    local install_suggestion="${2:-$cmd}"
    if ! command -v "$cmd" &> /dev/null; then
        log_message "ERROR" "Required command '${cmd}' not found."
        log_message "ERROR" "Please install the '${install_suggestion}' package or ensure '${cmd}' is in the system PATH."
        return 1 # Return error status
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
    return 0 # Return success status
}

# --- Get Hostname Function ---
# Description: Retrieves the system hostname and stores it in the global HOSTNAME variable.
get_hostname() {
    log_message "DEBUG" "Attempting to retrieve hostname..."
    if ! HOSTNAME=$(hostname); then
        log_message "CRITICAL" "Failed to retrieve hostname using the 'hostname' command."
        # exit 1 handled by CRITICAL log level
    fi
    if [[ -z "${HOSTNAME}" ]]; then
        log_message "CRITICAL" "Retrieved hostname is empty."
        # exit 1 handled by CRITICAL log level
    fi
    log_message "INFO" "System hostname retrieved: ${HOSTNAME}"
}

# --- Install ImageMagick Function ---
# Description: Checks for 'convert' command and installs 'imagemagick' via apt if missing.
install_imagemagick() {
    log_message "INFO" "Checking for ImageMagick ('convert' command)..."
    if ! command -v convert &> /dev/null; then
        log_message "WARN" "ImageMagick ('convert' command) not found. Attempting installation..."
        log_message "INFO" "Updating package lists (apt update)..."
        if ! sudo apt update; then
            log_message "ERROR" "Failed to update package lists ('apt update'). Please check network and repository configuration."
            return 1 # Indicate failure
        fi
        log_message "INFO" "Installing 'imagemagick' package..."
        if ! sudo apt install -y imagemagick; then
            log_message "ERROR" "Failed to install 'imagemagick'. Please check apt logs and try manually."
            return 1 # Indicate failure
        fi
        log_message "INFO" "ImageMagick installed successfully."
    else
        log_message "INFO" "ImageMagick ('convert' command) is already installed."
    fi
    return 0 # Indicate success
}

# --- Verify gsettings Compatibility Function ---
# Description: Checks if gsettings can access Cinnamon background schema.
verify_gsettings() {
    local cinnamon_schema="org.cinnamon.desktop.background"
    local cinnamon_key="picture-uri"
    log_message "INFO" "Checking gsettings compatibility with Cinnamon schema '${cinnamon_schema}'..."
    # Run gsettings as the 'root' user to check general accessibility.
    # Specific user checks happen implicitly when the autostart runs.
    if sudo -u root dbus-launch gsettings get "${cinnamon_schema}" "${cinnamon_key}" &> /dev/null; then
        log_message "INFO" "gsettings check passed. Compatible with Cinnamon desktop schema."
        return 0 # Indicate success
    else
        log_message "ERROR" "gsettings check failed. Could not access '${cinnamon_schema} ${cinnamon_key}'."
        log_message "ERROR" "Ensure Cinnamon desktop is installed, running, and gsettings/D-Bus are functional."
        return 1 # Indicate failure
    fi
}

# --- Setup Shared Folder Function ---
# Description: Creates the shared wallpaper directory if it doesn't exist and sets permissions.
setup_shared_folder() {
    log_message "INFO" "Checking shared folder: ${SHARED_FOLDER}"
    if [[ ! -d "${SHARED_FOLDER}" ]]; then
        log_message "INFO" "Shared folder does not exist. Creating..."
        # Create the directory including parent directories if needed (-p).
        if ! sudo mkdir -p "${SHARED_FOLDER}"; then
            log_message "ERROR" "Failed to create shared folder: ${SHARED_FOLDER}. Check permissions for parent directory."
            return 1
        fi
        log_message "INFO" "Setting permissions (${SHARED_FOLDER_PERMS}) on: ${SHARED_FOLDER}"
        # Set permissions (Consider 755 instead of 777 for better security).
        if ! sudo chmod "${SHARED_FOLDER_PERMS}" "${SHARED_FOLDER}"; then
             log_message "ERROR" "Failed to set permissions (${SHARED_FOLDER_PERMS}) on ${SHARED_FOLDER}."
             return 1
        fi
        log_message "INFO" "Shared folder created successfully at ${SHARED_FOLDER} with permissions ${SHARED_FOLDER_PERMS}."
    else
        log_message "INFO" "Shared folder already exists at ${SHARED_FOLDER}."
        # Optional: Verify/reset permissions even if it exists?
        # log_message "INFO" "Verifying permissions (${SHARED_FOLDER_PERMS}) on existing folder..."
        # sudo chmod "${SHARED_FOLDER_PERMS}" "${SHARED_FOLDER}" || log_message "WARN" "Could not set permissions on existing folder ${SHARED_FOLDER}."
    fi
    return 0 # Indicate success
}

# --- Generate Wallpaper Function ---
# Description: Uses ImageMagick 'convert' to create the wallpaper image with the hostname.
generate_wallpaper() {
    log_message "INFO" "Generating wallpaper with hostname '${HOSTNAME}'..."
    log_message "DEBUG" "Wallpaper settings: Size=${WALLPAPER_WIDTH}x${WALLPAPER_HEIGHT}, BG=${WALLPAPER_BG_COLOR}, Font Size=${FONT_SIZE}, Font Color=${FONT_COLOR}"
    log_message "DEBUG" "Output path: ${OUTPUT_PATH}"

    # Use 'convert' to generate the image. Quote variables, especially HOSTNAME.
    if ! convert \
        -size "${WALLPAPER_WIDTH}x${WALLPAPER_HEIGHT}" \
        "xc:${WALLPAPER_BG_COLOR}" \
        -gravity Center \
        -pointsize "${FONT_SIZE}" \
        -fill "${FONT_COLOR}" \
        -annotate +0+0 "${HOSTNAME}" \
        "${OUTPUT_PATH}"; then
        log_message "ERROR" "ImageMagick 'convert' command failed to generate the wallpaper."
        log_message "ERROR" "Check ImageMagick installation, font availability, and write permissions for '${SHARED_FOLDER}'."
        return 1 # Indicate failure
    fi

    log_message "INFO" "Setting permissions (${WALLPAPER_FILE_PERMS}) on generated wallpaper: ${OUTPUT_PATH}"
    if ! sudo chmod "${WALLPAPER_FILE_PERMS}" "${OUTPUT_PATH}"; then
         log_message "WARN" "Failed to set permissions (${WALLPAPER_FILE_PERMS}) on ${OUTPUT_PATH}. Proceeding anyway."
         # Don't necessarily fail the whole script for this, but log a warning.
    fi
    log_message "INFO" "Wallpaper generated successfully: ${OUTPUT_PATH}"
    return 0 # Indicate success
}

# --- Setup User Autostart Function ---
# Description: Creates the .desktop autostart entry for a specific user.
# Arguments: $1: Username
#            $2: User's home directory path
setup_user_autostart() {
    local username="$1"
    local user_home="$2"
    local autostart_dir="${user_home}/.config/autostart"
    local desktop_entry="${autostart_dir}/set_hostname_wallpaper.desktop" # Use a more descriptive filename

    log_message "INFO" "Setting up autostart for user '${username}' in '${user_home}'..."

    # Check if the user's .config directory exists, create if not (owned by user)
    if [[ ! -d "${user_home}/.config" ]]; then
        log_message "INFO" "Creating .config directory for user '${username}'..."
        if ! sudo -u "${username}" mkdir -p "${user_home}/.config"; then
            log_message "ERROR" "Failed to create directory '${user_home}/.config' for user '${username}'. Check permissions."
            return 1 # Failed for this user
        fi
        # Explicitly set ownership if needed, though `sudo -u` should handle it.
        # sudo chown "${username}:${username}" "${user_home}/.config"
    fi


    # Ensure the autostart directory exists, create if not (owned by user)
    if [[ ! -d "${autostart_dir}" ]]; then
        log_message "INFO" "Creating autostart directory for user '${username}'..."
        if ! sudo -u "${username}" mkdir -p "${autostart_dir}"; then
            log_message "ERROR" "Failed to create autostart directory '${autostart_dir}' for user '${username}'. Check permissions."
            return 1 # Failed for this user
        fi
        # Explicitly set ownership if needed
        # sudo chown "${username}:${username}" "${autostart_dir}"
    fi

    # Create the .desktop file content using a Here Document
    local desktop_content
    # Note: Using `file://${OUTPUT_PATH}` for the gsettings URI format.
    # Using escaped quotes within the Exec line for robustness.
    mapfile -t desktop_content << EOL
[Desktop Entry]
Type=Application
Name=Set Custom Hostname Wallpaper
Comment=Automatically sets the desktop wallpaper to show the system hostname
Exec=gsettings set org.cinnamon.desktop.background picture-uri "'file://${OUTPUT_PATH}'"
Hidden=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
EOL

    log_message "INFO" "Creating/updating autostart file: ${desktop_entry}"
    # Use sudo -u to write the file as the target user, ensuring correct ownership.
    # Use printf to safely handle the array content.
    if ! printf "%s\n" "${desktop_content[@]}" | sudo -u "${username}" tee "${desktop_entry}" > /dev/null; then
        log_message "ERROR" "Failed to create or write to autostart file '${desktop_entry}' for user '${username}'."
        return 1 # Failed for this user
    fi

    # Explicitly set permissions on the .desktop file (should be owned by user already)
    if ! sudo chmod 644 "${desktop_entry}"; then
        log_message "WARN" "Failed to set permissions (644) on autostart file '${desktop_entry}'. Please check manually."
    fi
    # Explicitly verify/set ownership (redundant if tee worked as expected, but safe)
    if ! sudo chown "${username}:${username}" "${desktop_entry}"; then
         log_message "WARN" "Failed to set ownership for autostart file '${desktop_entry}'. Please check manually."
    fi

    log_message "INFO" "Successfully configured autostart for user '${username}'."
    return 0 # Success for this user
}

# --- Cleanup Function ---
# Description: Performs cleanup tasks before script exits. Currently empty.
cleanup() {
    local exit_status=$?
    log_message "DEBUG" "Running cleanup function with exit status: ${exit_status}"
    # Add cleanup tasks here if needed (e.g., remove temporary files)
    log_message "DEBUG" "Cleanup finished."
    exit ${exit_status} # Ensure script exits with the original status
}

# --- Trap Setup ---
# Register the 'cleanup' function to run on script EXIT, INT, TERM, HUP signals.
trap cleanup EXIT INT TERM HUP


# --- Main Logic Function ---
# Description: Orchestrates the primary tasks of the script.
main() {
    log_message "INFO" "Starting script execution: ${SCRIPT_NAME} (PID: ${SCRIPT_PID})"

    # Step 0: Ensure running as root
    ensure_root

    # Step 0.1: Get Hostname
    get_hostname # Populates the global HOSTNAME variable

    # Step 1: Check Core Dependencies (fail fast if essential tools are missing)
    local dependencies_ok=true
    check_dependency "hostname" || dependencies_ok=false
    check_dependency "convert" "imagemagick" # Suggest package name
    # Check 'gsettings' dependency more thoroughly later, after confirming Cinnamon env.
    check_dependency "mkdir" "coreutils" || dependencies_ok=false
    check_dependency "chmod" "coreutils" || dependencies_ok=false
    check_dependency "chown" "coreutils" || dependencies_ok=false
    check_dependency "basename" "coreutils" || dependencies_ok=false
    check_dependency "cat" "coreutils" || dependencies_ok=false
    check_dependency "tee" "coreutils" || dependencies_ok=false
    check_dependency "apt" "apt" || dependencies_ok=false
    check_dependency "sudo" "sudo" || dependencies_ok=false
    check_dependency "dbus-launch" "dbus-x11" || dependencies_ok=false # Needed for gsettings check as root

    if [[ "${dependencies_ok}" == false ]]; then
         log_message "CRITICAL" "One or more critical dependencies are missing. Cannot continue."
    fi

    # Step 2: Ensure ImageMagick is installed
    install_imagemagick || log_message "CRITICAL" "ImageMagick installation/verification failed."

    # Step 3: Verify gsettings/Cinnamon compatibility
    verify_gsettings || log_message "CRITICAL" "gsettings compatibility check failed. Is Cinnamon installed and running?"

    # Step 4: Set up the shared folder
    setup_shared_folder || log_message "CRITICAL" "Failed to set up the shared wallpaper folder."

    # Step 5: Generate the wallpaper image
    generate_wallpaper || log_message "CRITICAL" "Failed to generate the wallpaper image."

    # Step 6: Configure autostart for users in /home
    log_message "INFO" "Scanning /home for user directories to configure autostart..."
    local user_setup_errors=0
    for user_home_dir in /home/*; do
        if [[ -d "${user_home_dir}" ]]; then
            local current_username
            current_username=$(basename "${user_home_dir}")

            # Basic sanity check - skip common non-user dirs like 'lost+found' or if username is empty
            if [[ -z "${current_username}" || "${current_username}" == "lost+found" ]]; then
                 log_message "DEBUG" "Skipping non-user directory: ${user_home_dir}"
                 continue
            fi

            # Check if it looks like a valid user home (e.g., contains .profile or similar) - optional
            # if [[ ! -f "${user_home_dir}/.profile" && ! -f "${user_home_dir}/.bashrc" ]]; then
            #     log_message "DEBUG" "Skipping directory that might not be a user home: ${user_home_dir}"
            #     continue
            # fi

            if ! setup_user_autostart "${current_username}" "${user_home_dir}"; then
                log_message "ERROR" "Failed to set up autostart for user '${current_username}'."
                ((user_setup_errors++))
            fi
        else
             log_message "DEBUG" "Skipping non-directory item in /home: ${user_home_dir}"
        fi
    done

    if [[ ${user_setup_errors} -gt 0 ]]; then
        log_message "WARN" "${user_setup_errors} error(s) occurred during user autostart configuration. Please review logs."
        # Decide if this should be a critical failure or just a warning. Currently warning.
    else
        log_message "INFO" "User autostart configuration scan complete."
    fi

    log_message "INFO" "Script finished successfully."
    # Trap will handle exit 0
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================
# Call the main function to start the script's execution.
main "$@" # Pass any script arguments to main (though none are currently used)

# The 'trap cleanup EXIT' ensures cleanup runs and the script exits with the correct code (0 here).
# Explicit exit 0 is technically redundant due to the trap on EXIT.
# exit 0

# =========================================================================================
# --- End of Script ---
