#!/bin/bash
# SPDX-FileCopyrightText: © 2025 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : python_web_env_setup.sh
# PURPOSE       : Automates Python web env setup with tools on Debian/Ubuntu via PPA.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2025-04-22
# LAST UPDATED  : 2025-04-22
# VERSION       : 1.0.0
# =========================================================================================

# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This script streamlines the process of preparing a Debian or Ubuntu system for Python web
# development and deployment. It installs a user-specified Python 3 version using the
# reliable Deadsnakes PPA and includes essential tools commonly used in web environments.

# Key Workflow / Functions:
# - Parses command-line arguments to get the desired Python version (required).
# - Validates inputs, including checking for required root privileges.
# - Checks for core dependencies like `apt` and `add-apt-repository`.
# - Updates the system's package list (`apt update`).
# - Ensures `software-properties-common` is installed to manage PPAs.
# - Adds the `ppa:deadsnakes/ppa` repository.
# - Updates the package list again after adding the PPA.
# - Installs the specified Python 3 version (e.g., `python3.11`, `python3.11-dev`, `python3.11-venv`).
# - Installs a set of base system packages useful for web development:
#   - `build-essential`, `git`, `curl`, `wget`
#   - `nginx` (web server/reverse proxy)
#   - `postgresql` and `libpq-dev` (database and client library headers)
#   - `libssl-dev`, `libffi-dev` (common C library dependencies for Python packages)
#   - `supervisor` (process control system)
#   - `pipx` (for installing Python CLI tools in isolated environments)
# - Provides clear logging output for each step.
# - Outputs final instructions and recommendations, emphasizing the use of virtual environments (`venv`) for project dependencies.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Automation:** Reduces manual steps required to set up a consistent Python environment.
# - **Robustness:** Includes strict mode (`set -euo pipefail`), checks for root privileges and essential commands, and basic input validation. Uses PPA for reliable access to multiple Python versions.
# - **Clarity:** Provides informative logging for each step using a dedicated `log_message` function.
# - **Best Practices:** Installs `*-dev` and `*-venv` packages alongside Python, includes `pipx`, and strongly recommends using `venv` for project dependencies rather than system-wide pip installs.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - Developers setting up new machines or virtual environments for Python web projects.
# - System Administrators configuring servers for hosting Python web applications.
# - DevOps Engineers automating infrastructure setup.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x python_web_env_setup.sh`
# - Elevated privileges: Requires `sudo` or root privileges to run `apt`, `add-apt-repository`, and install system packages. This is necessary for system-wide configuration changes.

# **Basic Syntax:**
# `sudo ./python_web_env_setup.sh -p <python_version> [options]`

# **Options:**
# -p, --python VERSION   Specify the Python 3 version to install (e.g., 3.10, 3.11). REQUIRED.
# -v, --verbose          Enable verbose output (DEBUG level logging).
# --no-color           Disable colored output in logs.
# -h, --help             Display this help message and exit.

# **Arguments:**
# - None. The Python version is specified via the mandatory `-p` option.

# **Common Examples:**
# 1. Set up environment with Python 3.11:
#    `sudo ./python_web_env_setup.sh -p 3.11`

# 2. Set up environment with Python 3.10 and verbose logging:
#    `sudo ./python_web_env_setup.sh -p 3.10 -v`

# **Advanced Execution (Automation):**
# - Can be used in automated provisioning scripts (e.g., cloud-init, Ansible, Dockerfile build steps). Ensure the `-y` flag used with `apt` is acceptable.
# - Example cron job (less common for setup, but possible):
#   `0 1 * * * /path/to/python_web_env_setup.sh -p 3.11 >> /var/log/env_setup.log 2>&1`
#   (Ensure non-interactive execution is fully handled).
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - System-wide utility (requires root): `/usr/local/sbin/`
# - Project-specific tool: Within a project's `scripts/` directory.

# **Manual Setup:**
# 1. Place the script in the chosen location (e.g., `/usr/local/sbin/`).
# 2. Set ownership (if system-wide): `sudo chown root:root /usr/local/sbin/python_web_env_setup.sh`
# 3. Set executable permissions: `sudo chmod 750 /usr/local/sbin/python_web_env_setup.sh` (or `chmod +x` for user/project scope).
# 4. Ensure dependencies are met (standard Debian/Ubuntu tools, see below).
# 5. Run with `sudo` and the required `-p` option: `sudo /usr/local/sbin/python_web_env_setup.sh -p 3.11`
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: Uses Bash-specific features (strict mode, arrays, `getopt`, `[[ ]]`).

# **Required System Binaries/Tools:**
# - `apt`: Debian/Ubuntu package manager.
# - `software-properties-common`: Provides `add-apt-repository`.
# - `add-apt-repository`: For adding the Deadsnakes PPA.
# - `getopt`: External utility for parsing long command-line options.
# - `coreutils`: Provides `basename`, `dirname`, `date`, `echo`, `tr`, `cat`, etc.
# - `grep`: Used implicitly by checks (if any, mostly handled by command return codes).
# - `curl` / `wget`: Needed by `apt` and `add-apt-repository` for downloading package info/keys.
# - `gpg`: Used implicitly by `apt` and `add-apt-repository` for key management.

# **Setup Instructions (Standard Tools):**
# - Most dependencies (`apt`, `coreutils`, `grep`, `gpg`, `curl`/`wget`) are standard on Debian/Ubuntu.
# - `software-properties-common` and `getopt` are explicitly installed or checked by the script or standard package dependencies. If missing, can be installed via:
#   `sudo apt update && sudo apt install -y software-properties-common apt-utils util-linux` (`getopt` is part of `util-linux`).

# **Operating System Compatibility:**
# - Designed primarily for: Debian and Ubuntu-based Linux distributions that are supported by the Deadsnakes PPA (check PPA page for current compatibility).
# - Known compatibility issues: Will not work on non-Debian/Ubuntu systems. May fail on EOL OS versions or architectures not supported by the PPA.

# **Environment Variables Used:**
# - `PATH`: Standard variable, assumes required binaries are locatable.
# - `DEBIAN_FRONTEND=noninteractive`: Set implicitly by `apt install -y` to avoid prompts.

# **System Resource Requirements:**
# - Network: Requires internet access to download PPA info, GPG keys, and system packages.
# - Disk Space: Requires space for downloaded packages and the installed size of Python, build tools, Nginx, PostgreSQL dev files, etc. (can be several hundred MB).
# - CPU/Memory: Moderate usage during `apt update` and package installation.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): `INFO` and `DEBUG` level messages (progress, steps).
# - Standard Error (stderr): `WARN`, `ERROR`, `CRITICAL` level messages, and `DEBUG` output if `-v` is used.
# - Dedicated Log File: No. Logging can be redirected using shell operators (`>`, `>>`, `2>&1`).

# **Log Format:**
# - `[YYYY-MM-DD HH:MM:SS Z] [LEVEL] - Message` (e.g., `[2025-04-22 16:30:00 WIB] [INFO] - Updating package lists...`)
# - Color-coded by level if terminal supports it and `--no-color` is not used.

# **Log Levels (Implemented via `log_message` function):**
# - `DEBUG`: Detailed step info (Enabled by `-v` or `--verbose`).
# - `INFO`: General operational messages (default level).
# - `WARN`: Potential issues or important notices.
# - `ERROR`: Significant errors encountered, but script might attempt to continue (though `set -e` usually stops it).
# - `CRITICAL`: Severe errors causing script termination via `exit 1`.
# - Control: Log level defaults to `INFO`, set to `DEBUG` via `-v`.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Normal Operation: Prints `INFO` messages tracking script progress (adding PPA, installing packages).
# - Final Instructions: Prints guidance on creating and using Python virtual environments (`venv`).

# **Standard Error (stderr):**
# - Errors: Prints `ERROR` and `CRITICAL` messages (e.g., failed apt commands, missing PPA, permission issues).
# - Warnings: Prints `WARN` messages (e.g., reminders about pip usage).
# - Debug/Verbose Output: Prints detailed `DEBUG` messages if `-v` is used.

# **Generated/Modified Files:**
# - System package database cache (`/var/lib/apt/lists/`).
# - APT sources: Adds `/etc/apt/sources.list.d/deadsnakes-ubuntu-ppa-*.list` (or similar).
# - APT keys: May add Deadsnakes PPA key to `/etc/apt/trusted.gpg.d/`.
# - Installs system packages into standard locations (`/usr/bin/`, `/usr/lib/`, `/usr/include/`, etc.).
# - Does NOT create project-specific files or directories.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success - Script completed all tasks successfully.
# - 1: General Error - Usually triggered by `log_message CRITICAL` or `set -e` on command failure (e.g., `apt` failure, validation failure).
# - Other non-zero codes may be emitted by failed external commands (`apt`, `add-apt-repository`, `getopt`) if `set -e` is bypassed or trap logic interferes.

# **Potential Issues & Troubleshooting:**
# - **Issue:** "Permission denied" or "Are you root?".
#   **Resolution:** Run the script with `sudo`.
# - **Issue:** "add-apt-repository: command not found".
#   **Resolution:** Script attempts to install `software-properties-common`. If that fails, check `apt` sources or network. Install manually: `sudo apt update && sudo apt install software-properties-common`.
# - **Issue:** "Failed to add PPA" or "apt update" fails after adding PPA.
#   **Resolution:** Check network connection/firewall. Verify the OS version is supported by Deadsnakes PPA. Check for conflicting APT sources.
# - **Issue:** "Unable to locate package pythonX.Y".
#   **Resolution:** Ensure the specified Python version (e.g., 3.11) is available in the Deadsnakes PPA for your OS version. Double-check the version format `-p 3.11`. Ensure `apt update` ran successfully after adding the PPA.
# - **Issue:** `apt install` fails for other packages.
#   **Resolution:** Review `apt` error messages. Check network, disk space, and potential package conflicts.

# **Important Considerations / Warnings:**
# - **[Root Privileges Required]:** Modifies system package lists and installs software globally. Must be run with `sudo`.
# - **[System Modification]:** Installs numerous system packages and adds an external PPA. Understand the implications for system state and security.
# - **[External Dependency]:** Relies entirely on the Deadsnakes PPA being available, correct, and trustworthy.
# - **[Idempotency]:** Designed to be mostly idempotent. Re-running `apt install -y` for already installed packages is generally safe and quick. Adding the PPA again is also safe.
# - **[Concurrency]:** Do not run concurrently with other `apt` processes due to dpkg locking.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes a Debian or Ubuntu-based Linux distribution compatible with the Deadsnakes PPA.
# - Assumes the system architecture (e.g., amd64) is supported by the PPA and requested packages.
# - Assumes standard core utilities (`bash`, `apt`, `coreutils`, etc.) are installed and functional.
# - Assumes internet connectivity is available to reach Canonical/Debian repositories and `ppa.launchpad.net`.
# - Assumes the script is executed with `sudo` or root privileges.
# - Assumes the Python version string provided via `-p` is valid and available in the PPA.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Requires root (`sudo`) for package management (`apt`, `add-apt-repository`). Justification: System-wide software installation.
# - **Input Sanitization:** Python version input (`-p`) is validated for basic format (`3.X`) but relies on `apt` to handle the actual package name construction and validation against available packages. No complex command construction from input.
# - **Sensitive Data Handling:** Does not handle passwords, API keys, or other sensitive data.
# - **Dependencies:** Relies on standard system tools (`apt`, `bash`, etc.) and the external Deadsnakes PPA. Trust in the PPA maintainers and Launchpad infrastructure is required. Connections use HTTPS where appropriate via `apt`.
# - **File Permissions:** Modifies system files/directories (`/etc/apt/`, `/var/lib/apt/`, package installation paths) using `apt`, which manages permissions according to package definitions.
# - **External Command Execution:** Executes standard, trusted system commands (`apt`, `add-apt-repository`, `getopt`). Does not dynamically build commands from untrusted input.
# - **Network Exposure:** Makes outbound HTTPS connections via `apt` and `add-apt-repository` to official repositories and Launchpad PPA.
# - **Code Integrity:** Users should obtain the script from a trusted source or review it before execution with `sudo`.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is within this script's header comments.
# - Deadsnakes PPA: https://launchpad.net/~deadsnakes/+archive/ubuntu/ppa
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: [Your Name / Team Name]
# - Contact: [Your Email / Contact Method]
# - Bug Reports/Issues: [Link to repository issues or contact method]
# =========================================================================================

# =========================================================================================
# SCRIPT EXECUTION ENVIRONMENT & CONFIGURATION
# =========================================================================================

# --- Bash Strict Mode ---
# Exit on error, treat unset variables as errors, pipelines fail on first error
set -euo pipefail

# --- Debug Mode ---
# Uncomment the following line for debugging (prints each command before execution)
# set -x

# --- Script Information ---
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_PID=$$

# --- Timestamp ---
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Global Runtime Variables ---
VERBOSE=false
NO_COLOR=false
INTERACTIVE_MODE=false
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is a terminal

# Script-specific Defaults
PYTHON_VERSION_DEFAULT="" # No default, must be specified
PYTHON_VERSION=""         # Will be set by arguments
LOG_LEVEL="INFO"          # Default log level

# Base system packages - Python packages added dynamically
readonly BASE_SYSTEM_PACKAGES=(
    build-essential           # Basic C/C++ build tools (gcc, make, etc.)
    git                       # Version control system
    nginx                     # Web server / Reverse proxy
    postgresql                # PostgreSQL database server
    libpq-dev                 # Development headers for PostgreSQL (needed by psycopg2)
    curl                      # Utility for transferring data with URLs
    wget                      # Utility for non-interactive network downloads
    libssl-dev                # Development libraries for Secure Sockets Layer
    libffi-dev                # Development libraries for Foreign Function Interface
    supervisor                # Process control system (for running apps)
    software-properties-common # Needed for add-apt-repository
    pipx                      # Install Python CLI tools in isolated environments
    # Note: python3-pip is handled separately or via get-pip.py if needed.
    # Note: Gunicorn recommended via pipx install gunicorn
)

# --- Color Definitions (Optional) ---
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

    declare -A log_levels=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [CRITICAL]=4)
    local current_log_level_num=${log_levels[${LOG_LEVEL^^}]}
    local message_level_num=${log_levels[${level_upper}]}

    if [[ ${message_level_num} -ge ${current_log_level_num} ]]; then
        local target_stream=1 # Default to stdout
        if [[ "${level_upper}" == "WARN" || "${level_upper}" == "ERROR" || "${level_upper}" == "CRITICAL" ]]; then
            target_stream=2 # stderr for errors/warnings
        fi

        # Only print DEBUG if VERBOSE is true
        if [[ "${level_upper}" == "DEBUG" && "${VERBOSE}" == false ]]; then
             : # Do nothing
        else
             echo -e "${color}${log_line}${COLOR_RESET}" >&${target_stream}
        fi
    fi

    if [[ "${level_upper}" == "CRITICAL" ]]; then
        log_message "INFO" "Critical error encountered. Exiting script."
        exit 1 # Exit on critical errors
    fi
}

# --- Usage/Help Function ---
usage() {
    cat << EOF >&2
Usage: ${SCRIPT_NAME} -p <python_version> [-h] [-v] [--no-color]

Sets up a Python development and deployment environment on Debian/Ubuntu systems.

Requires root privileges (run with sudo).

Options:
  -p, --python VERSION   Specify the Python 3 version to install (e.g., 3.10, 3.11). REQUIRED.
  -v, --verbose          Enable verbose output (DEBUG level logging).
  --no-color           Disable colored output.
  -h, --help             Display this help message and exit.

Example:
  sudo ./${SCRIPT_NAME} -p 3.11
EOF
    exit 1
}

# --- Dependency Check Function ---
check_dependency() {
    local cmd="$1"
    local install_suggestion="${2:-$cmd}"
    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required command '${cmd}' not found."
        log_message "ERROR" "Please install the '${install_suggestion}' package or ensure it's in your PATH."
        # Exit handled by CRITICAL log level
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
}

# --- Cleanup Function ---
cleanup() {
    local exit_status=$?
    log_message "DEBUG" "Performing cleanup..."
    # Add any cleanup tasks here (e.g., removing temp files)
    log_message "INFO" "Script exiting with status: ${exit_status}"
    exit ${exit_status} # Ensure script exits with the original status
}

# --- Trap Setup ---
# Register the 'cleanup' function to run on script exit or specific signals
trap cleanup EXIT INT TERM HUP

# --- Argument Parsing Function ---
parse_params() {
    # Use getopt for long options support
    local options
    options=$(getopt -o hvp: --long help,verbose,python:,no-color -n "${SCRIPT_NAME}" -- "$@")
    if [[ $? -ne 0 ]]; then
        usage
    fi

    eval set -- "$options"

    while true; do
        case "$1" in
            -h|--help) usage ;;
            -v|--verbose) VERBOSE=true; LOG_LEVEL="DEBUG"; shift ;;
            -p|--python) PYTHON_VERSION="$2"; shift 2 ;;
            --no-color) NO_COLOR=true; shift ;;
            --) shift; break ;; # End of options
            *) log_message "ERROR" "Internal error parsing options."; exit 1 ;;
        esac
    done

    # Check for leftover arguments (this script expects none)
    if [[ $# -gt 0 ]]; then
        log_message "ERROR" "Unexpected argument(s): $*"
        usage
    fi
}

# --- Input Validation Function ---
validate_inputs() {
    log_message "INFO" "Validating inputs..."

    # Check for root privileges
    if [[ $EUID -ne 0 ]]; then
        log_message "CRITICAL" "This script must be run with root privileges (use sudo)."
    fi
    log_message "DEBUG" "Sudo privileges check passed."

    # Validate required Python version argument
    if [[ -z "${PYTHON_VERSION}" ]]; then
        log_message "CRITICAL" "Python version is required. Use the -p or --python option."
    fi

    # Basic validation for Python version format (e.g., 3.10, 3.11)
    if ! [[ "${PYTHON_VERSION}" =~ ^3\.[0-9]+$ ]]; then
        log_message "CRITICAL" "Invalid Python version format: '${PYTHON_VERSION}'. Please use format like '3.10', '3.11'."
    fi
    log_message "DEBUG" "Python version '${PYTHON_VERSION}' format check passed."

    log_message "INFO" "Input validation passed."
}

# --- Environment Preparation ---
prepare_environment() {
    log_message "INFO" "Preparing execution environment..."

    # Check essential dependencies needed before proceeding
    check_dependency "apt" "apt (Debian/Ubuntu package manager)"
    log_message "DEBUG" "Detected apt package manager."

    log_message "INFO" "Environment preparation complete."
}


# --- Main Logic Function ---
main() {
    log_message "INFO" "Starting Python Development & Deployment Environment Setup for Python ${PYTHON_VERSION}..."

    # 1. Update package lists
    log_message "INFO" "Updating package lists..."
    if apt update -y; then
        log_message "INFO" "Package lists updated successfully."
    else
        log_message "CRITICAL" "Failed to update package lists. Check network/repository configuration."
    fi

    # 2. Ensure software-properties-common (needed for PPA)
    log_message "INFO" "Ensuring 'software-properties-common' is installed..."
    if apt install -y software-properties-common; then
        log_message "INFO" "'software-properties-common' is installed."
    else
        log_message "CRITICAL" "Failed to install 'software-properties-common'. Cannot add PPA."
    fi
    check_dependency "add-apt-repository" "software-properties-common"

    # 3. Add Deadsnakes PPA
    log_message "INFO" "Adding deadsnakes PPA for Python versions..."
    if add-apt-repository -y ppa:deadsnakes/ppa; then
        log_message "INFO" "Deadsnakes PPA added successfully."
        log_message "INFO" "Updating package lists again after adding PPA..."
        if apt update -y; then
            log_message "INFO" "Package lists updated successfully after PPA add."
        else
            log_message "CRITICAL" "Failed to update package lists after adding PPA."
        fi
    else
        # Provide a more helpful error if PPA add fails
        log_message "ERROR" "Failed to add deadsnakes PPA."
        log_message "ERROR" "This might happen on unsupported OS versions or network issues."
        log_message "CRITICAL" "Cannot proceed without the PPA."
    fi

    # 4. Construct Python package names
    local python_pkg="python${PYTHON_VERSION}"
    local python_dev_pkg="python${PYTHON_VERSION}-dev"
    local python_venv_pkg="python${PYTHON_VERSION}-venv"

    # Combine base packages and specific Python packages
    local system_packages=("${BASE_SYSTEM_PACKAGES[@]}" "${python_pkg}" "${python_dev_pkg}" "${python_venv_pkg}")

    # 5. Install System Packages
    log_message "INFO" "Installing essential system packages including ${python_pkg}..."
    local packages_to_install
    packages_to_install=$(IFS=" "; echo "${system_packages[*]}")
    log_message "DEBUG" "Attempting to install: ${packages_to_install}"

    if apt install -y ${packages_to_install}; then
        log_message "INFO" "System packages installed successfully."
    else
        log_message "ERROR" "Failed to install one or more system packages."
        log_message "CRITICAL" "Check if Python version '${PYTHON_VERSION}' is available in the PPA and review apt output above."
    fi

        # 6. Final Information
    log_message "INFO" "====================================================================="
    log_message "INFO" " System Preparation Script Completed! "
    log_message "INFO" "====================================================================="

    # Use echo -e for better readability of the final summary block, removing log prefixes
    echo -e "\n${COLOR_GREEN}Your system should now have the basic tools:${COLOR_RESET}"
    echo -e " - Python ${PYTHON_VERSION} (including -dev and -venv packages from deadsnakes PPA)"
    echo -e " - Standard Build tools, git, nginx, postgresql-dev, supervisor, pipx, etc."

    # Use WARN color for important notes, but directly via echo
    echo -e "\n${COLOR_YELLOW}${COLOR_BOLD}VERY IMPORTANT - Using Pip with Python ${PYTHON_VERSION}:${COLOR_RESET}"
    echo -e "${COLOR_YELLOW} - The system 'pip3' (if installed separately) likely manages packages for the system's default Python.${COLOR_RESET}"
    echo -e "${COLOR_YELLOW} - To install packages specifically for Python ${PYTHON_VERSION}, you MUST use a virtual environment.${COLOR_RESET}"

    # Use a different color for next steps/commands
    echo -e "\n${COLOR_BLUE}Next Steps for Your Project:${COLOR_RESET}"
    echo -e " 1. Create environment: ${COLOR_CYAN}${python_pkg} -m venv path/to/your/venv${COLOR_RESET}"
    echo -e " 2. Activate environment: ${COLOR_CYAN}source path/to/your/venv/bin/activate${COLOR_RESET}"
    echo -e " 3. Install packages: ${COLOR_CYAN}pip install <package_name>${COLOR_RESET}  # <-- This pip uses Python ${PYTHON_VERSION}"
    echo -e " 4. Deactivate when done: ${COLOR_CYAN}deactivate${COLOR_RESET}"

    echo -e "\n${COLOR_BLUE}Other Next Steps:${COLOR_RESET}"
    echo -e " - Install global tools cleanly (like Gunicorn): ${COLOR_CYAN}pipx install gunicorn${COLOR_RESET}"
    echo -e " - Configure Nginx, Supervisor, PostgreSQL (users/databases), etc. per project requirements."

    # Note about pipx path
    echo -e "\n${COLOR_YELLOW}Note: If pipx commands don't work in your user shell, you might need to run 'pipx ensurepath' and restart your shell.${COLOR_RESET}\n"

    # Note: The final "Script completed successfully." message below this will still use log_message

}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# 1. Parse Command Line Arguments
parse_params "$@"

# 2. Validate Inputs and Configuration (includes root check)
validate_inputs

# 3. Prepare Environment (includes essential dependency checks)
prepare_environment

# 4. Execute Main Logic
main

# 5. Exit Successfully (handled by trap)
log_message "INFO" "Script completed successfully."

# =========================================================================================
# --- End of Script ---
