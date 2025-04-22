#!/bin/bash
# SPDX-FileCopyrightText: © 2025 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : manage_py_env.sh
# PURPOSE       : Manages Python virtual environment setup within a project.
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
# This script streamlines the management of a Python virtual environment ('venv') for a
# development project. It assumes the user has already *activated* the virtual
# environment before running the script.
#
# Key Workflow / Functions:
# - Verifies that a virtual environment (checked via $VIRTUAL_ENV) is currently active. Exits if not.
# - Checks if the configured Python executable (default: python3) and the 'pip' module
#   are available within the active venv. Attempts to bootstrap pip using 'ensurepip' if missing.
# - Locates the 'requirements.txt' file (or configured alternative).
# - If 'requirements.txt' is missing, it offers to install 'pipreqs' (if not present in venv)
#   and generate the file based on project imports, ignoring the venv directory.
# - Prompts the user to install/update packages listed in 'requirements.txt' using 'pip install -r'.
# - Prompts the user whether to run 'pipreqs' again to update/overwrite the 'requirements.txt'
#   file based on the current project code.
# - Uses colored logging for different message levels (DEBUG, INFO, WARN, ERROR, CRITICAL).
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - Python Developers managing project dependencies.
# - DevOps Engineers setting up development or CI/CD environments.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Prerequisite:** ACTIVATE YOUR PYTHON VIRTUAL ENVIRONMENT FIRST!
# Example: `source .venv/bin/activate` (assuming default venv name '.venv')
#
# **Permissions:**
# - Script execution: `chmod +x manage_py_env.sh`
# - File system access: Read/Write access within the project directory (for requirements.txt)
#                     and the virtual environment directory (for pip installs).
# - Network access: Required by pip to download packages and potentially by pipreqs.
#
# **Basic Syntax:**
# `./manage_py_env.sh [options]`
#
# **Options:**
# -h             Display help message (extracted from this header) and exit.
# -v             Enable verbose output (logs DEBUG messages).
# # -d           Enable Bash debug mode (`set -x`) - handled manually via set -x below.
#
# **Arguments:**
# None currently supported. Operates on the current directory by default.
#
# **Common Examples:**
# 1. Activate venv and run with default settings:
#    `source .venv/bin/activate && ./manage_py_env.sh`
#
# 2. Activate venv and run with verbose logging:
#    `source .venv/bin/activate && ./manage_py_env.sh -v`
#
# 3. Get help (can be run without activating venv):
#    `./manage_py_env.sh -h`
#
# **Automation:**
# - Primarily designed for interactive use due to confirmation prompts.
# - Could be part of a larger setup script if prompts are handled or bypassed (requires modification).
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# - Place the script in the root directory of your Python project, alongside where your
#   `.venv` directory and `requirements.txt` file would typically reside.
# - Make it executable: `chmod +x manage_py_env.sh`
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: Bourne-Again SHell interpreter (standard Linux/macOS/WSL).
#
# **Required System Binaries/Tools:**
# - `coreutils`: Provides `basename`, `dirname`, `date`, `cat`, `mkdir`, `touch`, `tr`, `head`, `grep`.
# - `python3` (or configured PYTHON_EXECUTABLE_DEFAULT): Needed to *create* virtual environments
#   and usually expected within them. Must be in the system PATH.
# - `pip` (Python Package Installer): Expected to be available *within* the activated venv.
#   The script attempts to install it via `ensurepip` if missing in the venv.
# - `pipreqs`: Optional, but needed for automatic generation/update of requirements.txt.
#   The script will offer to install `pipreqs` into the venv using pip if it's missing
#   and generation/update is requested.
# - `getopts`: Bash built-in for argument parsing.
# - `command`: Bash built-in for checking command existence.
#
# **Setup Instructions:**
# - Ensure Python 3 is installed on the system: `python3 --version`
# - Create a virtual environment if one doesn't exist: `python3 -m venv .venv`
# - Activate the virtual environment before running this script: `source .venv/bin/activate`
# - `pipreqs` will be handled by the script if needed and confirmed by the user.
#
# **Operating System Compatibility:**
# - Designed primarily for Linux distributions (Ubuntu, CentOS, Fedora, etc.) and macOS.
# - Should work on Windows Subsystem for Linux (WSL).
#
# **Environment Variables Used:**
# - `VIRTUAL_ENV`: Checked to confirm a virtual environment is active. Set automatically by venv activation.
# - `PATH`: Standard variable used to find executables (`python3`, `pipreqs` etc.).
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): INFO and DEBUG messages (DEBUG only if -v is used).
# - Standard Error (stderr): WARN, ERROR, CRITICAL messages, help text (`-h`). Specific command examples during errors.
# - Dedicated Log File: No by default (LOG_TO_FILE=false). Can be enabled by setting LOG_TO_FILE=true
#   and ensuring DEFAULT_LOG_DIR is writable. Path: './logs/manage_py_env_[timestamp].log' (by default)
#
# **Log Format:**
# - Console: `[YYYY-MM-DD HH:MM:SS TZ] [LEVEL] - Message` (Colored)
# - File (if enabled): `[YYYY-MM-DD HH:MM:SS TZ] [LEVEL] - Message` (No color)
#
# **Log Levels:**
# - DEBUG: Detailed step-by-step info (Enabled by `-v`).
# - INFO: General operational messages (Default level).
# - WARN: Potential issues or user skips.
# - ERROR: Significant errors encountered.
# - CRITICAL: Severe errors causing script termination.
# - Control: `-v` flag sets level to DEBUG. Otherwise uses `LOG_LEVEL` variable (default: INFO).
#
# **Log Rotation:**
# - Not handled by the script. Use external tools like `logrotate` if long-term file logging is enabled.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Normal Operation: Status messages (INFO), verbose details (DEBUG).
# - User Prompts: Asks for confirmation (`read -p`) before installing packages or updating files.
# **Standard Error (stderr):**
# - Errors: Prints error messages (ERROR, CRITICAL) and warnings (WARN).
# - Help Text: Prints usage information when `-h` is used.
# - Specific Instructions: Prints example commands (e.g., how to activate venv) if prerequisites fail.
# **Generated/Modified Files:**
# - `requirements.txt` (or configured REQUIREMENTS_FILE): May be generated or updated (overwritten) using `pipreqs` if confirmed by the user.
# - Log File: Created in `logs/` directory if `LOG_TO_FILE` is true.
# - Temporary Files: Not currently used. Cleanup trap is in place for future use.
# - Installed Packages: Modifies the Python virtual environment by installing/updating packages via pip.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success.
# - 1: General Error (often triggered by `log_message CRITICAL` or `set -e`).
# - 4: Invalid command-line option/argument (via `usage` function from `getopts`).
# - Other non-zero codes may be returned by failed external commands (`pip`, `pipreqs`, `python`).
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** "SCRIPT ABORTED: Python virtual environment not active."
#   **Resolution:** Activate the virtual environment *before* running the script (e.g., `source .venv/bin/activate`). Create one (`python3 -m venv .venv`) if it doesn't exist.
# - **Issue:** "Could not find 'python3' within the active virtual environment" or "'pip' module not found".
#   **Resolution:** The activated venv might be corrupted or wasn't created correctly. Try recreating it. Ensure the correct Python version was used to create the venv.
# - **Issue:** "'pipreqs' failed during file generation" or "Failed to install 'pipreqs'".
#   **Resolution:** Check network connectivity. Check permissions in the venv directory. Ensure pip is working correctly within the venv. Check pipreqs output for specific errors.
# - **Issue:** "Failed to install packages using pip from 'requirements.txt'".
#   **Resolution:** Check network connectivity. Check the syntax of your `requirements.txt`. Check pip's output for specific package conflicts or build errors.
#
# **Important Considerations / Warnings:**
# - **CRITICAL:** This script REQUIRES an active virtual environment. Running it outside may lead to unexpected behavior or errors if checks fail.
# - **Modification:** Installs packages into the active venv using `pip`.
# - **Overwrite Risk:** Running `pipreqs` to generate/update `requirements.txt` WILL OVERWRITE the existing file if `--force` is used (as implemented for updates). Review changes carefully.
# - **Interactive:** Relies on user prompts (`read -p`) for confirmation before modifying actions (installing, updating requirements).
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes a Bash (v4+) environment with standard core utilities.
# - Assumes Python 3 (or configured executable) is installed system-wide.
# - Assumes the user knows how to create and activate a Python virtual environment.
# - Assumes the script is executed AFTER the target virtual environment has been activated.
# - Assumes the script is run from the project's root directory or context where `.venv` and `requirements.txt` should reside.
# - Assumes write permissions within the project directory and the virtual environment.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Runs as the user who executes it. Does not require root/sudo unless file permissions prevent writing to the project/venv dirs.
# - **Input Sanitization:** Basic checks for options via `getopts`. Relies on external tools (`pip`, `pipreqs`) to handle file paths and package names. No dynamic command execution based on user file content.
# - **Sensitive Data Handling:** Does not handle passwords or API keys.
# - **Dependencies:** Relies on `python`, `pip`, `pipreqs`. Ensure these are from trusted sources. `pip install` downloads and executes code from PyPI – inherent risk.
# - **File Permissions:** Uses standard user permissions for creating/modifying `requirements.txt` and potentially log files. Venv package installation depends on venv permissions.
# - **Network Exposure:** Connects to PyPI (via pip/pipreqs) to download packages/check versions. Ensure network policies allow this.
# =========================================================================================

# =========================================================================================
# SCRIPT EXECUTION ENVIRONMENT & CONFIGURATION
# =========================================================================================

# --- Script Information ---
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_DIR="${SOURCE_DIR}"
readonly SCRIPT_PID=$$

# --- Timestamp ---
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Global Runtime Variables ---
# Configuration Defaults (can be overridden)
PROJECT_DIR_DEFAULT="."
REQUIREMENTS_FILE_DEFAULT="requirements.txt"
PYTHON_EXECUTABLE_DEFAULT="python3"
VENV_DIR_DEFAULT=".venv"

# Runtime flags
VERBOSE=false
DEBUG_MODE=false # Set via 'set -x' if needed, or a -d flag could be added
DRY_RUN=false # Add functionality if needed
NO_COLOR=false
INTERACTIVE_MODE=false
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is a terminal

# Default Paths
DEFAULT_LOG_DIR="${SCRIPT_DIR}/logs"
DEFAULT_LOG_FILE="${DEFAULT_LOG_DIR}/${SCRIPT_NAME%.sh}_${SCRIPT_RUN_TIMESTAMP}.log"
DEFAULT_TMP_DIR_BASE="/tmp"

# Script-specific runtime variables (populated later)
PROJECT_DIR="${PROJECT_DIR_DEFAULT}"
REQUIREMENTS_FILE="${REQUIREMENTS_FILE_DEFAULT}"
PYTHON_EXECUTABLE="${PYTHON_EXECUTABLE_DEFAULT}"
VENV_DIR="${VENV_DIR_DEFAULT}" # Used primarily for checking/ignoring

# Populated runtime variables
PYTHON_VENV_PATH="" # Path to python inside the venv
REQUIREMENTS_PATH="" # Full path to requirements file
TEMP_DIR="" # For temporary files if needed by mktemp

# Logging config
LOG_FILE="${DEFAULT_LOG_FILE}"
LOG_TO_FILE=false # Set to true if file logging is desired
LOG_LEVEL="INFO" # Default log level (DEBUG, INFO, WARN, ERROR, CRITICAL)

# --- Color Definitions (Optional) ---
if [[ "${NO_COLOR}" == false && "${INTERACTIVE_MODE}" == true ]]; then
    COLOR_RESET='\033[0m'; COLOR_RED='\033[0;31m'; COLOR_GREEN='\033[0;32m';
    COLOR_YELLOW='\033[0;33m'; COLOR_BLUE='\033[0;34m'; COLOR_CYAN='\033[0;36m';
    COLOR_BOLD='\033[1m';
else
    COLOR_RESET=""; COLOR_RED=""; COLOR_GREEN=""; COLOR_YELLOW="";
    COLOR_BLUE=""; COLOR_CYAN=""; COLOR_BOLD="";
fi

# =========================================================================================
# FUNCTION DEFINITIONS
# =========================================================================================

# --- Logging Function ---
log_message() {
    local level="$1"; local message="$2"; local timestamp;
    timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z"); local level_upper;
    level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]');
    local log_prefix="[${timestamp}] [${level_upper}]";
    local log_line="${log_prefix} - ${message}"; local color="";
    case "${level_upper}" in
        DEBUG) color="${COLOR_CYAN}" ;; INFO) color="${COLOR_GREEN}" ;;
        WARN) color="${COLOR_YELLOW}" ;; ERROR) color="${COLOR_RED}" ;;
        CRITICAL) color="${COLOR_BOLD}${COLOR_RED}" ;;
    esac
    declare -A log_levels=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [CRITICAL]=4);
    local current_log_level_num=${log_levels[${LOG_LEVEL^^}]};
    local message_level_num=${log_levels[${level_upper}]};
    if [[ ${message_level_num} -ge ${current_log_level_num} ]]; then
        if [[ "${level_upper}" == "WARN" || "${level_upper}" == "ERROR" || "${level_upper}" == "CRITICAL" ]]; then
            echo -e "${color}${log_line}${COLOR_RESET}" >&2;
        else
            if [[ "${level_upper}" == "DEBUG" && "${VERBOSE}" == false ]]; then : # Skip DEBUG if not VERBOSE
            else echo -e "${color}${log_line}${COLOR_RESET}"; fi;
        fi;
        if [[ "${LOG_TO_FILE}" == true ]]; then
            mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true;
            if [[ -w "$(dirname "${LOG_FILE}")" ]]; then
                echo "${log_prefix} - ${message}" >> "${LOG_FILE}";
            else
                if [[ -z ${LOG_DIR_WRITE_WARN_SENT+x} ]]; then
                   echo -e "${COLOR_YELLOW}[${timestamp}] [WARN] - Cannot write to log directory $(dirname "${LOG_FILE}"). Logging to file disabled.${COLOR_RESET}" >&2;
                   LOG_DIR_WRITE_WARN_SENT=true; LOG_TO_FILE=false;
                fi;
            fi;
        fi;
    fi;
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        log_message "INFO" "Critical error encountered. Exiting script.";
        # Cleanup is handled by trap
        exit 1; # Exit on CRITICAL
    fi;
}

# --- Usage/Help Function ---
usage() {
    # Basic usage message - Adapt if arguments are added
    cat << EOF >&2
Usage: ${SCRIPT_NAME}

  This script manages a Python virtual environment within the current project.
  It requires an *active* virtual environment before running.

  Key Functions:
    - Checks for an active virtual environment (default: ${VENV_DIR_DEFAULT}).
    - Ensures Python (${PYTHON_EXECUTABLE_DEFAULT}) and pip are available within the venv.
    - Finds or generates (using pipreqs) a requirements file (default: ${REQUIREMENTS_FILE_DEFAULT}).
    - Installs dependencies from the requirements file (with confirmation).
    - Optionally updates the requirements file using pipreqs (with confirmation).

  Configuration (defaults can be changed at the top of the script):
    PROJECT_DIR:        ${PROJECT_DIR_DEFAULT}
    REQUIREMENTS_FILE:  ${REQUIREMENTS_FILE_DEFAULT}
    PYTHON_EXECUTABLE:  ${PYTHON_EXECUTABLE_DEFAULT}
    VENV_DIR:           ${VENV_DIR_DEFAULT}

  Options:
    -h: Display this help message and exit.
    -v: Enable verbose output (logs DEBUG messages).
EOF
    exit 1
}

# --- Dependency Check Function ---
check_dependency() {
    local cmd="$1"; local install_suggestion="${2:-$cmd}";
    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required base command '${cmd}' not found."
        log_message "ERROR" "Please install '${install_suggestion}' or ensure it's in your PATH."
        # CRITICAL log handles exit
    fi;
    log_message "DEBUG" "Dependency check passed for base command: ${cmd}";
}

# --- Cleanup Function ---
cleanup() {
    local exit_status=$?;
    log_message "INFO" "Performing cleanup..."
    if [[ -n "${TEMP_DIR:-}" && -d "${TEMP_DIR}" ]]; then
        log_message "DEBUG" "Removing temporary directory: ${TEMP_DIR}";
        rm -rf "${TEMP_DIR}" || log_message "WARN" "Failed to remove temporary directory: ${TEMP_DIR}";
    fi;
    log_message "INFO" "Cleanup finished with exit status: ${exit_status}";
    # Script exits with original exit_status after trap completes
}

# --- Trap Setup ---
trap cleanup EXIT INT TERM HUP

# --- Argument Parsing Function ---
parse_params() {
    while getopts ":hv" opt; do
        case $opt in
            h) usage ;;
            v) VERBOSE=true; LOG_LEVEL="DEBUG" ;; # Enable verbose logging
            \?) log_message "ERROR" "Invalid option: -${OPTARG}"; usage ;;
            :) log_message "ERROR" "Option -${OPTARG} requires an argument."; usage ;;
        esac
    done
    shift $((OPTIND-1))
    # Handle positional arguments if any are added later
    # if [[ $# -gt 0 ]]; then log_message "ERROR" "Unexpected argument(s): $*"; usage; fi
    log_message "DEBUG" "Arguments parsed. Verbose: ${VERBOSE}";
}

# --- Input Validation Function ---
validate_inputs() {
    log_message "INFO" "Validating inputs and environment..."

    # 1. VIRTUAL ENVIRONMENT CHECK (Critical Prerequisite)
    if [[ -z "${VIRTUAL_ENV:-}" ]]; then
        log_message "ERROR" "------------------------------------------------------------------"
        log_message "ERROR" " SCRIPT ABORTED: Python virtual environment not active."
        log_message "ERROR" "------------------------------------------------------------------"
        local script_path="${BASH_SOURCE[0]}"
        local venv_path_relative="${VENV_DIR}" # Relative path check

        # Get timestamp and construct the error prefix string for manual use
        local timestamp; timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z")
        local error_prefix_str="[${timestamp}] [ERROR] - "

        # --- Case 1: Venv directory doesn't exist ---
        if [[ ! -d "${venv_path_relative}" ]]; then
            log_message "ERROR" "Virtual environment directory ('${venv_path_relative}') not found."
            log_message "ERROR" "" # Blank line for spacing
            log_message "ERROR" "You need to create the virtual environment first."
            log_message "ERROR" "Please run the following command in your terminal:"
            # **MODIFIED LINE:** Print prefix in red, command in default color, to stderr
            echo -e "${COLOR_RED}${error_prefix_str}${COLOR_RESET}${PYTHON_EXECUTABLE} -m venv ${venv_path_relative}" >&2
            log_message "ERROR" "" # Blank line
            log_message "ERROR" "After creating, activate it and re-run this script using:"
            # **MODIFIED LINE:** Print prefix in red, command in default color, to stderr
            echo -e "${COLOR_RED}${error_prefix_str}${COLOR_RESET}source \"${venv_path_relative}/bin/activate\" && \"${script_path}\" \"$@\"" >&2
            log_message "ERROR" "" # Blank line
        else
        # --- Case 2: Venv directory exists but is not active ---
            log_message "ERROR" "The virtual environment directory ('${venv_path_relative}') exists, but it's not active."
            log_message "ERROR" "" # Blank line
            log_message "ERROR" "Activate the environment first, then re-run the script."
            log_message "ERROR" "Please run the following command in your terminal:"
            # **MODIFIED LINE:** Print prefix in red, command in default color, to stderr
            echo -e "${COLOR_RED}${error_prefix_str}${COLOR_RESET}source \"${venv_path_relative}/bin/activate\" && \"${script_path}\" \"$@\"" >&2
            log_message "ERROR" "" # Blank line
        fi

        # Use CRITICAL level to ensure exit after logging messages
        log_message "CRITICAL" "Virtual environment setup required before script execution."
    fi
    # Use default expansion ${VAR:-} to safely expand even if set -u is picky.
    log_message "INFO" "Active virtual environment detected: ${VIRTUAL_ENV:-}"

    # Validate PROJECT_DIR exists
    if [[ ! -d "${PROJECT_DIR}" ]]; then
         log_message "CRITICAL" "Project directory '${PROJECT_DIR}' not found."
    fi

    REQUIREMENTS_PATH="${PROJECT_DIR}/${REQUIREMENTS_FILE}"
    log_message "DEBUG" "Requirements file path set to: ${REQUIREMENTS_PATH}"

    log_message "INFO" "Input validation passed."
}

# --- Environment Preparation Function ---
prepare_environment() {
    log_message "INFO" "Preparing execution environment..."
    # Example: Create a temporary directory if needed
    # TEMP_DIR=$(mktemp -d "${DEFAULT_TMP_DIR_BASE}/${SCRIPT_NAME}.XXXXXX")
    # log_message "DEBUG" "Created temporary directory: ${TEMP_DIR}"
    # Ensure log directory exists if logging to file
    if [[ "${LOG_TO_FILE}" == true ]]; then
        mkdir -p "$(dirname "${LOG_FILE}")" || log_message "WARN" "Could not create log directory: $(dirname "${LOG_FILE}")"
        touch "${LOG_FILE}" || log_message "WARN" "Could not touch log file: ${LOG_FILE}"
    fi
    log_message "INFO" "Environment preparation complete."
}

# --- Specific Task Functions ---

# Function to provide advice when system pip install is discouraged
attempt_system_pip_install_advice() {
    log_message "ERROR" "Attempting system-wide pip installation is discouraged when using virtual environments."
    log_message "ERROR" "'ensurepip' failed even within the venv: ${VIRTUAL_ENV}"
    log_message "ERROR" "This might indicate a problem with the Python installation used to create the venv, or the venv itself."
    log_message "ERROR" "Consider recreating the virtual environment (delete '${VENV_DIR}' and run '${PYTHON_EXECUTABLE} -m venv ${VENV_DIR}' again)."
    log_message "ERROR" "If issues persist, check your base Python installation's integrity."
    # Note: No exit here, allows the calling function to decide the next step (usually exit)
}

# Function to Check/Install pipreqs
check_and_install_pipreqs() {
    local python_exe_path="$1" # Pass the venv python path
    log_message "INFO" "Checking for 'pipreqs' command within venv..."

    # Check if pipreqs exists *and* is inside the venv path
    local pipreqs_path
    if command -v pipreqs &> /dev/null; then
         pipreqs_path=$(command -v pipreqs)
         if [[ "$pipreqs_path" == "${VIRTUAL_ENV}"* ]]; then
             log_message "INFO" "'pipreqs' command found in venv: ${pipreqs_path}"
             return 0 # Available in venv
         else
             log_message "WARN" "'pipreqs' command found, but seems to be outside the current venv (${pipreqs_path})."
             read -p "Install 'pipreqs' into the current venv '${VIRTUAL_ENV}' for consistency? (y/N): " confirm_reinstall
             if [[ "$(echo "$confirm_reinstall" | tr '[:upper:]' '[:lower:]')" =~ ^(y|yes)$ ]]; then
                  : # Fall through to installation logic below
             else
                 log_message "INFO" "Using external 'pipreqs'. Note this may have unexpected behavior."
                 return 0 # User opted to use external one
             fi
         fi
    fi

    log_message "WARN" "'pipreqs' not found in venv or reinstall requested."
    read -p "Attempt to install 'pipreqs' into the active venv using pip? (y/N): " confirm_install
    if [[ "$(echo "$confirm_install" | tr '[:upper:]' '[:lower:]')" =~ ^(y|yes)$ ]]; then
        log_message "INFO" "Attempting to install pipreqs into the venv..."
        if "${python_exe_path}" -m pip install pipreqs; then
            log_message "INFO" "'pipreqs' installed successfully into the venv." [1]
            # Verify command is now in venv path
            if command -v pipreqs &> /dev/null && [[ "$(command -v pipreqs)" == "${VIRTUAL_ENV}"* ]]; then
                log_message "INFO" "'pipreqs' command is now available in venv."
                return 0 # Success
            else
                log_message "ERROR" "'pipreqs' installed, but command not found in venv PATH. Check venv activation or PATH."
                return 1 # Failure post-install
            fi
        else
            log_message "ERROR" "Failed to install 'pipreqs' using pip into the venv."
            return 1 # Failure during install
        fi
    else
        log_message "INFO" "Skipping 'pipreqs' installation."
        return 1 # Not available and install skipped
    fi
}

# Function to Generate requirements.txt using pipreqs
generate_requirements_file() {
    local req_path="$1"
    local proj_dir="$2"
    log_message "INFO" "Attempting to generate '${req_path}' using pipreqs..."

    if [[ ! -d "${proj_dir}" ]]; then
        log_message "ERROR" "Project directory '${proj_dir}' not found for generation."
        return 1;
    fi

    log_message "DEBUG" "Running: pipreqs \"${proj_dir}\" --encoding=utf-8 --ignore \"${VENV_DIR}\" --savepath \"${req_path}\""
    if pipreqs "${proj_dir}" --encoding=utf-8 --ignore "${VENV_DIR}" --savepath "${req_path}"; then
        log_message "INFO" "Successfully generated '${req_path}' using pipreqs."
        # Check if it was actually created (pipreqs might succeed but create nothing if no imports)
        if [[ ! -f "${req_path}" ]]; then
            log_message "WARN" "pipreqs reported success, but '${req_path}' was not created. It might be empty if no requirements were found."
            # Create an empty file for consistency
            touch "${req_path}" || { log_message "ERROR" "Failed to touch empty requirements file: ${req_path}"; return 1; }
            log_message "INFO" "Created empty '${req_path}'."
        fi
        return 0 # Success
    else
        log_message "ERROR" "'pipreqs' failed during file generation. Check pipreqs output above."
        return 1 # Failure
    fi
}

# --- Main Logic Function ---
main() {
    log_message "INFO" "Starting main script execution..."
    log_message "INFO" "Project Dir: ${PROJECT_DIR}, Requirements File: ${REQUIREMENTS_FILE}, Python Exec: ${PYTHON_EXECUTABLE}"

    # 2. PREREQUISITE CHECKS (Python & Pip in Venv) - Runs after venv active check in validate_inputs
    log_message "INFO" "Performing prerequisite checks within the virtual environment..."
    PYTHON_VENV_PATH=$(command -v "${PYTHON_EXECUTABLE}")

    if [[ -z "$PYTHON_VENV_PATH" || ! "$PYTHON_VENV_PATH" == "${VIRTUAL_ENV}"* ]]; then
        log_message "CRITICAL" "Could not find '${PYTHON_EXECUTABLE}' within the active virtual environment (${VIRTUAL_ENV}). Check venv activation or the PYTHON_EXECUTABLE config."
    fi
    log_message "INFO" "Using Python from venv: ${PYTHON_VENV_PATH} ($(${PYTHON_VENV_PATH} --version))"

    log_message "INFO" "Checking for pip module associated with '${PYTHON_VENV_PATH}'..."
    if ! "${PYTHON_VENV_PATH}" -m pip --version &> /dev/null; then
        log_message "WARN" "'pip' module not found for the venv's Python."
        log_message "INFO" "Attempting to install/bootstrap pip within the venv using 'ensurepip'..."
        if "${PYTHON_VENV_PATH}" -m ensurepip --upgrade; then
            log_message "INFO" "Successfully installed/upgraded pip using ensurepip within the venv."
            if ! "${PYTHON_VENV_PATH}" -m pip --version &> /dev/null; then
                 log_message "CRITICAL" "'ensurepip' seemed successful, but pip module still not found. Check venv integrity."
            fi
            log_message "INFO" "Pip is now available in venv: $(${PYTHON_VENV_PATH} -m pip --version | head -n 1)"
        else
            log_message "ERROR" "Attempt using 'ensurepip' failed even within the venv."
            attempt_system_pip_install_advice # Provides error messages and advice
            log_message "CRITICAL" "Failed to ensure pip is available in the virtual environment."
        fi
    else
        log_message "INFO" "Found pip in venv: $(${PYTHON_VENV_PATH} -m pip --version | head -n 1)"
    fi

    # 3. FIND OR GENERATE requirements.txt
    log_message "INFO" "Checking for requirements file: ${REQUIREMENTS_PATH}"
    if [[ ! -f "${REQUIREMENTS_PATH}" ]]; then
        log_message "WARN" "Requirements file '${REQUIREMENTS_PATH}' not found."
        log_message "INFO" "Attempting to generate it using 'pipreqs'."

        # Check/Install pipreqs BEFORE attempting generation
        if ! check_and_install_pipreqs "${PYTHON_VENV_PATH}"; then
            log_message "ERROR" "Cannot generate requirements file because 'pipreqs' is not available and could not be installed."
            log_message "CRITICAL" "Please create '${REQUIREMENTS_PATH}' manually or fix the pipreqs installation."
        fi

        # Attempt generation
        if ! generate_requirements_file "${REQUIREMENTS_PATH}" "${PROJECT_DIR}"; then
            log_message "CRITICAL" "Failed to generate '${REQUIREMENTS_PATH}'. Cannot proceed."
        fi
        # Generation succeeded or created empty file, REQUIREMENTS_PATH now points to the file
    else
        log_message "INFO" "Found existing requirements file: ${REQUIREMENTS_PATH}"
    fi

    # 4. INSTALL REQUIREMENTS FROM FILE
    log_message "INFO" "Checking requirements listed in '${REQUIREMENTS_PATH}'..."
    if ! grep -qE '^[^#[:space:]]' "${REQUIREMENTS_PATH}"; then
        log_message "INFO" "'${REQUIREMENTS_PATH}' is empty or contains no active requirements. Skipping installation."
    else
        log_message "INFO" "Requirements found in '${REQUIREMENTS_PATH}'."
        # Consider adding 'pip list --outdated' or similar checks here if desired.
        # log_message "INFO" "Comparing listed requirements with installed packages..."

        read -p "Do you want to install/update packages from '${REQUIREMENTS_PATH}' into the venv? (y/N): " confirm_install
        if [[ "$(echo "$confirm_install" | tr '[:upper:]' '[:lower:]')" =~ ^(y|yes)$ ]]; then
            log_message "INFO" "Attempting to install packages from ${REQUIREMENTS_PATH} into the venv..."
            if "${PYTHON_VENV_PATH}" -m pip install -r "${REQUIREMENTS_PATH}"; then
                log_message "INFO" "Successfully installed/updated packages from '${REQUIREMENTS_PATH}' into the venv."
            else
                log_message "ERROR" "Failed to install packages using pip from '${REQUIREMENTS_PATH}'. Check pip output above."
                # Decide if this is critical or just an error
                log_message "CRITICAL" "Installation from requirements file failed."
            fi
        else
            log_message "INFO" "Installation from '${REQUIREMENTS_PATH}' skipped by user."
        fi
    fi

    # 5. UPDATE requirements.txt (Optional)
    log_message "INFO" "------------------------------------------------------------------"
    log_message "INFO" "Environment setup based on '${REQUIREMENTS_PATH}' is complete (or skipped)."
    read -p "Do you want to run 'pipreqs' now to update '${REQUIREMENTS_PATH}' based on current code? (y/N): " confirm_update
    if [[ "$(echo "$confirm_update" | tr '[:upper:]' '[:lower:]')" =~ ^(y|yes)$ ]]; then
        log_message "INFO" "Checking 'pipreqs' availability again before update..."
        # Check/Install pipreqs again, in case it wasn't installed/available earlier
        if ! check_and_install_pipreqs "${PYTHON_VENV_PATH}"; then
            log_message "ERROR" "Cannot update requirements file because 'pipreqs' is not available and could not be installed."
            log_message "WARN" "Skipping update step."
        else
            log_message "INFO" "Running 'pipreqs --force' to update '${REQUIREMENTS_PATH}'..."
            # Use --force to overwrite existing file
            if pipreqs "${PROJECT_DIR}" --force --encoding=utf-8 --ignore "${VENV_DIR}" --savepath "${REQUIREMENTS_PATH}"; then
                log_message "INFO" "Successfully updated '${REQUIREMENTS_PATH}' based on current project code."
                # Display content if not empty
                if [[ -s "${REQUIREMENTS_PATH}" ]]; then
                    log_message "INFO" "--- New Content of ${REQUIREMENTS_FILE} ---"
                    # Use cat within echo/log to avoid issues with formatting/colors
                    echo -e "${COLOR_BLUE}" # Example color for file content
                    cat "${REQUIREMENTS_PATH}"
                    echo -e "${COLOR_RESET}"
                    log_message "INFO" "---------------------------------"
                else
                    log_message "INFO" "'${REQUIREMENTS_PATH}' is now empty after update."
                fi
            else
                # Don't make this critical, as the main install likely worked
                log_message "ERROR" "'pipreqs --force' failed during update. Check output. The file might be in an inconsistent state."
            fi
        fi
    else
        log_message "INFO" "Skipping update of '${REQUIREMENTS_PATH}'."
    fi

    log_message "INFO" "Main execution logic finished."
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# 1. Parse Command Line Arguments
parse_params "$@"

# 2. Load Configuration File (Optional - Function exists but not used by default)
# load_config

# 3. Check Base Dependencies (Not venv specific yet)
check_dependency "${PYTHON_EXECUTABLE}" # Check if the base python command exists

# 4. Validate Inputs (Includes the critical Venv Active Check)
validate_inputs

# 5. Prepare Environment (e.g., create temp dirs, log dirs)
prepare_environment

# 6. Execute Main Logic (Checks inside venv, installs, generates)
main

# 7. Exit Successfully (trap will run cleanup)
log_message "INFO" "Script completed successfully."
exit 0

# =========================================================================================
# --- End of Script ---