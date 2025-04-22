#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME  : dos2unix_git_repo.sh
# PURPOSE      : Convert line endings of all Git-tracked files to Unix (LF) format.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2025-04-22
# LAST UPDATED  : 2025-04-22
# VERSION       : 1.0.0
# -----------------------------------------------------------------------------------------
# WARNING      : Modifies files in place. Ensure you have committed or backed up
#                any important changes before running.
# =========================================================================================

# =========================================================================================
# SCRIPT EXECUTION ENVIRONMENT & CONFIGURATION
# =========================================================================================

# --- Bash Strict Mode ---
set -euo pipefail

# --- Script Information ---
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_PID=$$

# --- Global Runtime Variables ---

# Configuration Defaults
VERBOSE=false
DEBUG_MODE=false # Not used actively here, but kept for template consistency
NO_COLOR=false
INTERACTIVE_MODE=false
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is a terminal

# Determine default processors, allow override via -P
DEFAULT_PROCESSORS=1
if command -v nproc &> /dev/null; then
  DEFAULT_PROCESSORS=$(nproc)
fi

DEFAULT_BATCH_SIZE=50 # Default batch size for xargs, allow override via -n

# Runtime variables populated by defaults or arguments
PROCESSORS=${DEFAULT_PROCESSORS}
BATCH_SIZE=${DEFAULT_BATCH_SIZE}

# --- Color Definitions ---
if [[ "${NO_COLOR}" == false && "${INTERACTIVE_MODE}" == true ]]; then
    COLOR_RESET='\033[0m'; COLOR_RED='\033[0;31m'; COLOR_GREEN='\033[0;32m';
    COLOR_YELLOW='\033[0;33m'; COLOR_CYAN='\033[0;36m'; COLOR_BOLD='\033[1m';
else
    COLOR_RESET=""; COLOR_RED=""; COLOR_GREEN=""; COLOR_YELLOW=""; COLOR_CYAN=""; COLOR_BOLD="";
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
    local log_prefix="[${timestamp}] [${level_upper}]"
    local log_line="${log_prefix} - ${message}"
    local color=""

    case "${level_upper}" in
        DEBUG) [[ "${VERBOSE}" == false ]] && return 0; color="${COLOR_CYAN}" ;; # Only show if verbose
        INFO) color="${COLOR_GREEN}" ;;
        WARN) color="${COLOR_YELLOW}" ;;
        ERROR|CRITICAL) color="${COLOR_RED}${COLOR_BOLD}" ;; # Make errors bold red
    esac

    # Output to stderr for WARN/ERROR/CRITICAL, stdout otherwise
    if [[ "${level_upper}" =~ ^(WARN|ERROR|CRITICAL)$ ]]; then
        echo -e "${color}${log_line}${COLOR_RESET}" >&2
    else
        echo -e "${color}${log_line}${COLOR_RESET}"
    fi

    # Exit immediately for CRITICAL errors
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        log_message "INFO" "Critical error encountered. Exiting script."
        exit 1
    fi
}

# --- Usage/Help Function ---
usage() {
    # Minimal usage based on original script's purpose + new flags
    cat << EOF >&2
Usage: ${SCRIPT_NAME} [options]

Runs dos2unix recursively on all files currently tracked by Git in the repository,
ensuring consistent LF line endings. WARNING: Modifies files in place.

Options:
  -h, --help          Display this help message and exit.
  -v, --verbose       Enable verbose output (shows DEBUG messages).
  -P NUM              Number of parallel 'dos2unix' processes to run (Default: ${DEFAULT_PROCESSORS}, detected via nproc if available).
  -n NUM              Number of files to process per 'dos2unix' batch (Default: ${DEFAULT_BATCH_SIZE}).
  --no-color          Disable colored output.

EOF
    exit 1
}

# --- Dependency Check Function ---
check_dependency() {
    local cmd="$1"
    local install_suggestion="${2:-$cmd}"
    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required command '${cmd}' not found."
        log_message "ERROR" "Please install the '${install_suggestion}' package (e.g., using apt, dnf, brew)."
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
}

# --- Cleanup Function ---
cleanup() {
    local exit_status=$?
    log_message "DEBUG" "Performing cleanup (if any)..."
    # No specific temp files to clean in this version
    log_message "DEBUG" "Cleanup finished with exit status: ${exit_status}"
    exit ${exit_status} # Ensure script exits with the original status
}

# --- Trap Setup ---
trap cleanup EXIT INT TERM HUP

# --- Argument Parsing Function ---
parse_params() {
    # Use getopt for long options (--help, --no-color)
    local options
    options=$(getopt -o hvP:n: --long help,verbose,no-color -n "$SCRIPT_NAME" -- "$@")
    if [ $? -ne 0 ]; then
        usage
    fi
    eval set -- "$options" # Set positional parameters to getopt output

    while true; do
        case "$1" in
            -h|--help) usage ;;
            -v|--verbose) VERBOSE=true; shift ;;
            -P)
                PROCESSORS="$2"
                # Basic validation: Check if it's a positive integer
                if ! [[ "$PROCESSORS" =~ ^[1-9][0-9]*$ ]]; then
                    log_message "ERROR" "Invalid number for -P: '$PROCESSORS'. Must be a positive integer."
                    usage
                fi
                shift 2 ;;
            -n)
                BATCH_SIZE="$2"
                 # Basic validation: Check if it's a positive integer
                if ! [[ "$BATCH_SIZE" =~ ^[1-9][0-9]*$ ]]; then
                    log_message "ERROR" "Invalid number for -n: '$BATCH_SIZE'. Must be a positive integer."
                    usage
                fi
                shift 2 ;;
            --no-color)
                NO_COLOR=true
                # Redefine colors to empty strings if --no-color is parsed
                COLOR_RESET=""; COLOR_RED=""; COLOR_GREEN=""; COLOR_YELLOW=""; COLOR_CYAN=""; COLOR_BOLD="";
                shift ;;
            --) # End of options
                shift
                break ;;
            *) # Should not happen with getopt error checking
                log_message "ERROR" "Internal error parsing options."
                usage ;;
        esac
    done

    # Check for unexpected positional arguments
    if [[ $# -gt 0 ]]; then
        log_message "ERROR" "Unexpected argument(s): $*"
        usage
    fi

    log_message "DEBUG" "Arguments parsed. Verbose: ${VERBOSE}, Processors: ${PROCESSORS}, Batch Size: ${BATCH_SIZE}, No Color: ${NO_COLOR}"
}

# --- Input Validation / Safety Check ---
validate_inputs() {
    log_message "INFO" "Validating environment..."
    if ! git rev-parse --is-inside-work-tree &> /dev/null; then
      log_message "CRITICAL" "This script must be run from within a Git repository."
    fi
    log_message "DEBUG" "Running inside a Git repository."
    # Validation for PROCESSORS and BATCH_SIZE happens during parsing
    log_message "INFO" "Validation passed."
}

# --- Main Logic Function ---
main() {
    log_message "INFO" "Starting dos2unix conversion for files tracked by Git..."
    log_message "INFO" "Processing files in batches of ${BATCH_SIZE} using ${PROCESSORS} parallel process(es)."

    # Core execution logic from the original script
    # Uses variables set by parse_params (PROCESSORS, BATCH_SIZE)
    if git ls-files -z | xargs -0 -r -n "${BATCH_SIZE}" -P "${PROCESSORS}" dos2unix; then
        log_message "INFO" "dos2unix conversion completed successfully for Git-tracked files."
    else
        # xargs returns non-zero if *any* invocation of dos2unix fails
        log_message "ERROR" "One or more files may have failed conversion during the dos2unix process. Check 'dos2unix' output above for details."
        # Don't use CRITICAL here, as some files might have succeeded. Allow script to exit via trap.
        exit 1 # Indicate partial or full failure
    fi
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# 1. Parse Command Line Arguments
parse_params "$@"

# 2. Validate Inputs / Environment
validate_inputs

# 3. Check Dependencies
log_message "INFO" "Checking required dependencies..."
check_dependency "git" "git"
check_dependency "dos2unix" "dos2unix"
# Only check nproc if it was used for default PROCESSORS calculation
if [[ "${PROCESSORS}" -eq "${DEFAULT_PROCESSORS}" && "${DEFAULT_PROCESSORS}" -gt 1 ]]; then
    check_dependency "nproc" "coreutils" # nproc is usually part of coreutils
fi

# 4. Execute Main Logic
main

# 5. Exit Successfully (cleanup trap handles final exit)
log_message "INFO" "Script finished."
exit 0 # Explicitly exit with success code (trap will still run)

# =========================================================================================
# --- End of Script ---

