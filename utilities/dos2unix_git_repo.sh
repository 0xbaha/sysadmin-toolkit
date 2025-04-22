#!/bin/bash
# SPDX-FileCopyrightText: © 2025 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : dos2unix_git_repo.sh
# PURPOSE       : Convert line endings of all Git-tracked files to Unix (LF) format.
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
# This script automates the conversion of line endings for text files within a Git
# repository from DOS/Windows format (CRLF - Carriage Return Line Feed) to Unix format
# (LF - Line Feed). It ensures consistency, which is crucial for scripts, configuration
# files, and source code, especially in cross-platform development environments.
#
# Key Workflow / Functions:
# - Checks for required dependencies (`git`, `dos2unix`, optionally `nproc`).
# - Verifies that the script is run from within a Git working directory.
# - Uses `git ls-files -z` to reliably list all files currently tracked by Git,
#   respecting `.gitignore` and excluding files in the `.git` directory. The `-z`
#   option ensures correct handling of filenames containing spaces or special characters.
# - Pipes the null-terminated list of files to `xargs -0`.
# - Uses `xargs` to execute the `dos2unix` command on the files in batches (`-n`)
#   and potentially in parallel (`-P`) for efficiency.
# - `dos2unix` modifies the files in place, converting CRLF to LF.
# - Provides informative log messages regarding progress and errors using a
#   structured logging function.
# - Supports command-line options for verbose output, parallel processing, batch size,
#   and disabling color.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Simplicity:** Acts as a convenient wrapper around standard, well-tested Unix utilities
#   (`git`, `xargs`, `dos2unix`).
# - **Robustness:** Uses `set -euo pipefail` for stricter error handling. Employs
#   `git ls-files -z | xargs -0` for safe handling of all possible Git-tracked filenames.
#   Includes dependency checks and validates the execution environment.
# - **Safety:** Specifically targets only files tracked by Git, reducing the risk of
#   accidentally converting binary files or files outside the repository's scope
#   (respects `.gitignore`). Includes a clear warning about in-place modification.
# - **Efficiency:** Leverages `xargs -P` to optionally parallelize `dos2unix` execution,
#   speeding up the process in repositories with many files on multi-core systems.
# - **Readability:** Follows a structured template with clear function separation,
#   comments, and consistent logging.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - Developers working on projects across different operating systems (Windows, Linux, macOS).
# - System Administrators maintaining scripts or configurations within Git repositories.
# - DevOps Engineers ensuring consistent file formats in CI/CD pipelines or deployments.
# - Anyone needing to enforce Unix line endings within a Git project.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x dos2unix_git_repo.sh`
# - File system access: Requires read and write permissions for the files tracked by Git
#   within the current repository that need conversion.
# - Execution context: Must be run from within a directory managed by Git.
#
# **Basic Syntax:**
# `./dos2unix_git_repo.sh [options]`
# (Run from the root or any subdirectory of the Git repository)
#
# **Options:**
#   -h, --help          Display the help message and exit.
#   -v, --verbose       Enable verbose output (shows DEBUG messages).
#   -P NUM              Number of parallel 'dos2unix' processes to run (Default: detected via nproc, fallback 1).
#   -n NUM              Number of files to process per 'dos2unix' batch (Default: 50).
#   --no-color          Disable colored output.
#
# **Common Examples:**
# 1. Convert all Git-tracked files using default settings:
#    `./utilities/dos2unix_git_repo.sh`
#
# 2. Convert files using 4 parallel processes and verbose output:
#    `./utilities/dos2unix_git_repo.sh -v -P 4`
#
# 3. Get help:
#    `./utilities/dos2unix_git_repo.sh --help`
#
# **Automation (Example):**
# - Git pre-commit hook: Can be integrated as a pre-commit hook to ensure files
#   staged for commit have Unix line endings. Add a call to this script in
#   `.git/hooks/pre-commit`. Be mindful of performance impact on commits.
#   (Note: Hooks require careful implementation to only process staged files if desired).
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - Within the Git repository itself, e.g., in a `utilities/` or `scripts/` directory.
# - System-wide (less common for repo-specific tasks): `/usr/local/bin/` or `~/bin/`.
#
# **Manual Setup:**
# 1. Place the script in the chosen location (e.g., `./utilities/dos2unix_git_repo.sh`).
# 2. Set executable permissions: `chmod +x ./utilities/dos2unix_git_repo.sh`.
# 3. Install required dependencies (see DEPENDENCIES section below, usually `git` and `dos2unix`).
# 4. Navigate to your Git repository's directory in the terminal.
# 5. Run the script: `./utilities/dos2unix_git_repo.sh`
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: Assumes Bash v4+ for features like associative arrays in logging (though core logic may work on older versions).
#
# **Required System Binaries/Tools:**
# - `git`: Used to list tracked files (`git ls-files`) and verify repository context (`git rev-parse`). (Any recent version).
# - `dos2unix`: The core utility for converting line endings. (Install if missing).
# - `coreutils`: Provides `basename`, `dirname`, `date`, `tr`, `mktemp` (if used later), `nproc` (optional). Standard on most systems.
# - `xargs`: Used to build and execute `dos2unix` commands efficiently. Standard.
# - `command`: Bash built-in for checking command existence.
# - `getopt`: External utility for parsing long command-line options (GNU version recommended).
#
# **Setup Instructions (if dependencies are not standard):**
# - Example installation (Debian/Ubuntu):
#   `sudo apt update && sudo apt install -y dos2unix git`
# - Example installation (RHEL/CentOS/Fedora):
#   `sudo dnf update && sudo dnf install -y dos2unix git`
# - Example installation (macOS using Homebrew):
#   `brew install dos2unix` (git is usually pre-installed or via Xcode Command Line Tools)
#
# **Operating System Compatibility:**
# - Designed primarily for: Linux distributions, macOS, Windows Subsystem for Linux (WSL).
# - Should work on most Unix-like systems where Bash and the required dependencies are available.
#
# **Environment Variables Used:**
# - `PATH`: Standard variable, ensure `git`, `dos2unix`, `xargs`, `nproc` are locatable.
#
# **System Resource Requirements:**
# - CPU: Low, but can utilize multiple cores if `-P` > 1 is used.
# - Memory: Low. `dos2unix` and `xargs` are generally memory-efficient.
# - Disk I/O: Can be significant during conversion, especially with many large files. Depends on disk speed.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): INFO and DEBUG messages (DEBUG only if `-v` is used).
# - Standard Error (stderr): WARN, ERROR, and CRITICAL messages.
# - Dedicated Log File: No dedicated log file is created by default.
# - System Log (syslog/journald): No integration by default.
#
# **Log Format:**
# - `[YYYY-MM-DD HH:MM:SS TZ] [LEVEL] - Message` (e.g., `[2025-04-22 21:30:00 WIB] [INFO] - Starting conversion...`)
#
# **Log Levels:**
# - `DEBUG`: Detailed step-by-step information (Enabled by `-v, --verbose`).
# - `INFO`: General operational messages, start/stop, success.
# - `WARN`: Potential issues encountered (e.g., `nproc` not found).
# - `ERROR`: Non-critical errors (e.g., some files failed conversion via `xargs`).
# - `CRITICAL`: Severe errors causing script termination (e.g., missing dependencies, not in Git repo).
# - Control: Log level verbosity controlled by `-v`. CRITICAL errors always shown and cause exit.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Normal Operation: Prints INFO and DEBUG (if verbose) status messages.
#
# **Standard Error (stderr):**
# - Errors: Prints WARN, ERROR, and CRITICAL messages.
# - Help Message: Printed via `usage()` function on `-h` or invalid options.
#
# **Generated/Modified Files:**
# - **Git-tracked files:** The primary effect is modifying text files tracked by Git *in place* to use LF line endings. Binary files are typically skipped by `dos2unix` automatically.
# - No other report files, log files, or temporary files are created by default.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success - Script completed, and the `xargs dos2unix` pipeline reported success.
# - 1: General Error - Default exit code for errors caught by `set -e` or if `xargs` reports any `dos2unix` invocation failed. Also used for argument/usage errors via `usage()`. CRITICAL log messages also typically lead to exit 1.
# - Specific codes could be added (e.g., 2 for missing dependency), but current implementation relies on CRITICAL log messages followed by exit 1.
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** "ERROR: Required command 'dos2unix' not found."
#   **Resolution:** Install `dos2unix` using your system's package manager (see DEPENDENCIES).
# - **Issue:** "CRITICAL: This script must be run from within a Git repository."
#   **Resolution:** Change directory (`cd`) into the Git repository before running the script.
# - **Issue:** "Permission denied" errors during conversion.
#   **Resolution:** Ensure the user running the script has write permissions for the files within the repository. Check file ownership and permissions (`ls -l`).
# - **Issue:** Script converts binary files unintentionally.
#   **Resolution:** `dos2unix` usually skips binary files automatically. If specific files *must* be excluded, consider modifying the script or using Git attributes (`*.bin -text`).
#
# **Important Considerations / Warnings:**
# - **[CRITICAL WARNING: Modifies Files In Place]**
#   This script directly modifies files within your Git working directory using `dos2unix`.
#   **THERE IS NO AUTOMATIC UNDO.** Ensure you have committed any desired changes *before*
#   running this script, or have a clean working directory (`git status`). It is highly
#   recommended to review the changes (`git diff`) after running the script before committing.
# - **[Idempotency]:** Yes. Running the script multiple times on files that already have LF endings
#   will have no further effect ( `dos2unix` won't change them again).
# - **[Concurrency/Locking]:** Safe to run multiple instances only if they operate on *different*
#   Git repositories. Running multiple instances within the *same* repository simultaneously
#   could lead to race conditions if they process the same files; no locking is implemented.
#   The internal parallelism via `xargs -P` is safe.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes a Bash (v4+ recommended) environment with access to standard core utilities.
# - Assumes required dependencies (`git`, `dos2unix`, `xargs`, `getopt`) are installed and in `$PATH`.
# - Assumes the script is executed from within a functional Git working directory.
# - Assumes the user executing the script has read and write permissions for the files
#   tracked by Git within the repository.
# - Assumes `dos2unix` behaves typically (skips binary files, converts CRLF/CR to LF).
# =========================================================================================

# =========================================================================================
# PERFORMANCE OPTIMIZATION
# =========================================================================================
# **Optimization Notes:**
# - Uses `git ls-files -z` and `xargs -0` for efficient and safe filename handling, avoiding
#   issues with special characters and the overhead of loops for simple cases.
# - Leverages `xargs -P ${PROCESSORS}` to parallelize the `dos2unix` calls across multiple
#   CPU cores, significantly speeding up conversion in repositories with many files.
# - Uses `xargs -n ${BATCH_SIZE}` to process files in batches, potentially reducing the
#   overhead of invoking `dos2unix` many times for very small files compared to `-n 1`.
# **Potential Bottleneck:** Disk I/O can become a bottleneck if converting a very large
# number of files or very large individual files, especially on slower storage.
# =========================================================================================

# =========================================================================================
# TESTING & VALIDATION
# =========================================================================================
# **Test Strategy:**
# - Primarily manual testing in various scenarios (different OS, repositories with mixed
#   line endings, repositories with special filenames).
# - Static analysis using `shellcheck` is highly recommended (`shellcheck dos2unix_git_repo.sh`).
# **Validation Environment:**
# - Tested OS: [Specify OS versions where tested, e.g., Ubuntu 22.04, macOS Sonoma, WSL2 Ubuntu]
# - Tested Bash Version(s): [e.g., 5.1.16]
# - Tested Dependencies: [e.g., dos2unix 7.4.3, git 2.34.1]
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - Add options to include/exclude specific file paths or patterns (e.g., `--exclude '*.pdf'`).
# - Add option to only process files staged in Git (`git diff --cached --name-only -z`).
# - Implement more specific exit codes for different failure types.
# - Add a `--dry-run` option to list files that *would* be converted without modifying them.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Typically requires only standard user privileges, sufficient to
#   read/write files within the target Git repository. Does not require root/sudo.
# - **Input Sanitization:** Command-line options (`-P`, `-n`) are validated to be integers.
#   File paths are sourced directly and safely from `git ls-files -z` and passed via `xargs -0`,
#   mitigating risks associated with special characters in filenames.
# - **Sensitive Data Handling:** Does not handle passwords, API keys, or other sensitive data.
# - **Dependencies:** Relies on standard, widely used system utilities (`git`, `dos2unix`, `coreutils`, `xargs`).
#   Users should ensure these are obtained from trusted sources (system package manager).
# - **File Permissions:** Modified files retain their original permissions. The script itself
#   should have execute permission (`chmod +x`).
# - **External Command Execution:** Executes `git`, `dos2unix`, `nproc` safely. Does not construct
#   commands dynamically from potentially unsafe user input beyond filenames (handled by `-z`/`-0`).
# - **Code Integrity:** Users cloning the repository should verify the script's source if obtained
#   from untrusted channels. Consider providing checksums for tagged releases.
# - **CRITICAL WARNING:** The primary security consideration is the **in-place modification** of
#   repository files. Users must understand this and use version control practices (commit changes,
#   review diffs) accordingly.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is embedded within this script's header comments.
# - README: Refer to the main `README.md` of the repository: [Link to your README, e.g., https://github.com/0xbaha/sysadmin-toolkit/blob/main/README.md]
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Report via the script's repository or directly to the author.
# - Feature Requests: Submit via GitHub Issues.
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

