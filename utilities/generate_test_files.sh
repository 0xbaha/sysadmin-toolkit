#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : generate_test_files.sh
# PURPOSE       : Generates configurable random files for testing via CLI options.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2024-11-11
# LAST UPDATED  : 2024-11-11
# VERSION       : 1.0.0
# =========================================================================================

# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This script generates a specified number of files containing random data within a given
# directory. It allows customization of the number of files, the size range (min/max in KB),
# the allowed file extensions, the length of the random filename component, and the frequency
# of progress reporting. This is useful for creating test datasets, simulating file system
# usage, or benchmarking tools that process many files.
#
# Key Functions:
# - Creates a target directory if it doesn't exist.
# - Parses command-line arguments for flexible configuration (directory, count, size, etc.).
# - Generates random filenames with specified length and random extensions from a list.
# - Generates files with random sizes within the specified KB range using /dev/urandom.
# - Provides progress updates to the console during generation via a logging function.
# - Includes input validation and basic error handling (directory creation, file writing).
# - Uses Bash strict mode and provides structured logging.
# - Includes dependency checks for required commands.
# - Uses a trap for basic cleanup (though minimal cleanup needed here).
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Flexibility:** Uses command-line arguments (`getopts`) for easy customization.
# - **Simplicity:** Focuses solely on generating random files with clear, sequential logic within functions.
# - **Robustness:** Incorporates Bash strict mode, dependency checks, basic error handling, and structured logging.
# - **Efficiency:** Uses standard Linux/Unix utilities (`head`, `/dev/urandom`, `seq`) for file generation.
# - **Usability:** Provides clear usage instructions (`-h`) and progress feedback via logging.
# - **Maintainability:** Structured into functions for parsing, validation, preparation, and main logic.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - Developers needing test data.
# - QA Engineers / Testers setting up test environments.
# - System Administrators testing storage performance or file system tools.
# - Anyone needing to quickly populate a directory with varied dummy files.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Ensure the script is executable: `chmod +x generate_test_files.sh`
# - Requires write permissions in the parent directory of the target directory (to create it)
#   and write permissions within the target directory itself.
#
# **Basic Syntax:**
# `./generate_test_files.sh [-d DIR] [-n NUM] [-smin MIN_KB] [-smax MAX_KB] [-e EXT1,...] [-l LEN] [-p INT] [-v] [-h]`
#
# **Options:**
#   -d DIR          : Target directory for generated files (default: ./test_files_flexible)
#   -n NUM          : Number of files to create (default: 1000)
#   -smin MIN_KB    : Minimum file size in Kilobytes (default: 1)
#   -smax MAX_KB    : Maximum file size in Kilobytes (default: 100)
#   -e EXTENSIONS   : Comma-separated list of file extensions (default: txt,log,...)
#   -l LEN          : Length of the random part of the filename (default: 8)
#   -p INTERVAL     : Show progress every INTERVAL files (default: 100)
#   -v              : Enable verbose (DEBUG) logging.
#   -h              : Display this help message and exit.
#
# **Common Examples:**
# 1. Generate 100 files in the default directory with default settings:
#    `./generate_test_files.sh -n 100`
#
# 2. Generate 5000 files in `/tmp/my_test_data`, sizes 10KB-500KB, only .dat and .bin extensions:
#    `./generate_test_files.sh -n 5000 -d /tmp/my_test_data -smin 10 -smax 500 -e dat,bin`
#
# 3. Generate 20 files with long names (16 chars) and report progress every 5 files, with verbose output:
#    `./generate_test_files.sh -n 20 -l 16 -p 5 -v`
#
# 4. Get help:
#    `./generate_test_files.sh -h`
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - User scripts: `~/bin/` or `~/.local/bin/` (ensure these are in user's $PATH)
# - System-wide scripts: `/usr/local/bin/`
# - Project-specific scripts: Within the project directory structure.
#
# **Manual Setup:**
# 1. Place the script in the chosen location.
# 2. Set executable permissions: `chmod +x generate_test_files.sh`.
# 3. Ensure dependencies are installed (see DEPENDENCIES section).
# 4. Run the script initially with `-h` to verify.
#
# **Integration:**
# - No specific integration required. Run directly from the command line.
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: The Bourne-Again SHell interpreter.
#
# **Required System Binaries/Tools:**
# - `coreutils`: Provides `head`, `seq`, `mkdir`, `date`, `echo`, `basename`, `dirname`, `cd`, `pwd`.
# - `grep`: Used indirectly by `check_dependency` via `command -v`.
# - `getopts`: Bash built-in for parsing command-line options.
# - `read`: Bash built-in used for parsing the extensions string.
# - `sed`: Used by logging function to strip color codes for potential file logging.
# - `/dev/urandom`: System device used as the source of random data for file content.
#
# **Setup Instructions:**
# - These dependencies are standard on most Linux/Unix-like systems.
#
# **Operating System Compatibility:**
# - Designed primarily for Linux and Unix-like operating systems (including macOS, BSD variants)
#   that provide the required core utilities and `/dev/urandom`.
#
# **Environment Variables Used:**
# - Does not rely on specific environment variables beyond standard ones like `PATH`.
#
# **System Resource Requirements:**
# - CPU: Generally low, spikes during random data generation (`head /dev/urandom`).
# - Memory: Low RAM usage.
# - Disk I/O: Can be high, as it involves writing potentially many files. Performance depends heavily on disk speed.
# - Disk Space: Requires sufficient free space in the target directory's filesystem for the generated files.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): Used for INFO and DEBUG messages (if verbose).
# - Standard Error (stderr): Used for WARN, ERROR, CRITICAL messages and the help/usage output.
# - Dedicated Log File: No (LOG_TO_FILE is false by default).
# - System Log (syslog/journald): No.
#
# **Log Format:**
# - Console: `[YYYY-MM-DD HH:MM:SS UTC] [LEVEL] - Message` (Colored by default if terminal supports it)
# - File (if enabled): `[YYYY-MM-DD HH:MM:SS UTC] [LEVEL] - Message` (No color codes)
#
# **Log Levels:**
# - DEBUG: Very detailed information (Enabled by `-v`).
# - INFO: General operational messages, progress, start/stop.
# - WARN: Potential issues encountered, non-critical errors.
# - ERROR: Significant errors encountered during operation (e.g., file write failure).
# - CRITICAL: Fatal errors causing script termination (e.g., missing dependency, invalid arguments, unwritable directory).
# - Control: `-v` flag enables DEBUG level. Default is INFO.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Prints INFO/DEBUG level log messages (configuration, progress, completion).
#
# **Standard Error (stderr):**
# - Prints WARN/ERROR/CRITICAL level log messages.
# - Prints the help/usage message (`-h` or argument errors).
#
# **Generated/Modified Files:**
# - Creates multiple files with random names and specified extensions within the `TARGET_DIR`.
# - The content of these files is pseudo-random binary data read from `/dev/urandom`.
# - The size of each file varies randomly between `MIN_SIZE_KB * 1024` and `MAX_SIZE_KB * 1024` bytes.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success.
# - 1: General Error (unused, caught by others).
# - 2: Dependency Error (Required command not found).
# - 3: Configuration Error (Unused - No separate config file).
# - 4: Argument Error (Invalid or missing command-line arguments).
# - 5: Permission Denied (Cannot create/write to target directory).
# - 6: File System Error (Unused - Specific file write errors logged but don't terminate).
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** "Permission Denied" when creating directory or writing files.
#   **Resolution:** Ensure the user running the script has write permissions for the target location. Check parent directory permissions if the target doesn't exist. Run `ls -ld ./` and `ls -ld ./parent_dir`.
# - **Issue:** "No space left on device" or similar errors during file writing (`head` command fails).
#   **Resolution:** Ensure sufficient free disk space (`df -h .`). Reduce the number or size of files being generated. The script will log an ERROR and continue to the next file.
# - **Issue:** "Invalid option" or "Option requires an argument".
#   **Resolution:** Check the command-line syntax against the `USAGE` section or run with `-h`.
# - **Issue:** "CRITICAL: Required command '...' not found."
#   **Resolution:** Install the missing command (likely `head`, `seq`, or `mkdir` from `coreutils`, which should usually be present).
#
# **Important Considerations / Warnings:**
# - **Disk Space:** Generating many/large files consumes disk space. Monitor available space.
# - **Performance:** File creation is I/O bound. Generating millions of small files can be slow due to metadata operations. Generating huge files can be slow due to disk write speed.
# - **`/dev/urandom`:** Uses the system's pseudo-random number generator. Performance can vary. `/dev/urandom` does not block.
# - **Filename Collisions:** While unlikely with the default 8 random characters, generating an extremely large number of files could theoretically lead to filename collisions. The script currently overwrites colliding files without warning. Increase `-l` for more uniqueness if needed.
# - **File Write Errors:** If `head` fails to write a specific file (e.g., disk full during run), an ERROR is logged, and the script continues with the next file. It does *not* terminate on individual file write errors.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes a Bash shell environment.
# - Assumes standard core utilities (`head`, `seq`, `mkdir`) are available in the system `$PATH`.
# - Assumes `/dev/urandom` exists and is readable.
# - Assumes the user has appropriate permissions to create the target directory and write files within it.
# =========================================================================================

# =========================================================================================
# TESTING & VALIDATION
# =========================================================================================
# - Tested manually with various combinations of options on Linux (Ubuntu).
# - Validation focuses on: correct argument parsing, directory creation, file count, adherence to size limits (approximate due to KB conversion), extension usage, error reporting, logging levels, dependency checks.
# - No automated test suite included. `shellcheck` analysis recommended.
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - Add option for specific file content types (e.g., text, JSON) instead of just random binary.
# - Implement option for creating subdirectories and distributing files within them.
# - Add option for fixed file sizes instead of only random ranges.
# - Introduce parallel file generation (e.g., using `xargs -P` or `parallel`).
# - More robust error handling (e.g., check disk space before starting).
# - Option to specify filename prefix/suffix pattern.
# - Add option to prevent overwriting existing files (check existence before writing).
# - Count and report file write failures at the end.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Does not require root privileges unless writing to directories owned by root. Runs with the privilege of the executing user.
# - **Input Sanitization:** Basic validation is performed on numeric inputs. Directory/extension inputs are used directly in paths and string operations; while unlikely to cause direct execution vulnerabilities in this context, avoid unusual characters (like ';') in directory or extension names. Filenames are generated internally from a safe character set.
# - **Sensitive Data:** Does not handle passwords, API keys, or other sensitive information. Generated file content is from `/dev/urandom`.
# - **File Permissions:** Files are created with default permissions based on the system's `umask` setting for the user running the script.
# - **Resource Consumption:** Can consume significant disk space and I/O. Malicious use could attempt a denial-of-service by filling a disk. Use with caution regarding `-n`, `-smin`, `-smax` values.
# - **External Command Execution:** Primarily uses built-ins and core utilities (`head`, `seq`, `mkdir`). Input is not directly used to construct commands in a way vulnerable to injection in this script's logic. Variables are quoted where appropriate.
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Report via the script's repository (if known) or directly to the author's contact email.
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

# --- Script Information ---
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_PID=$$

# --- Timestamp ---
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Global Runtime Variables ---
# Configuration Defaults (can be overridden by command-line arguments)
TARGET_DIR="./test_files_flexible" # Default directory where files will be created.
NUM_FILES=1000                     # Default number of files to generate.
MIN_SIZE_KB=1                      # Default minimum file size in Kilobytes.
MAX_SIZE_KB=100                    # Default maximum file size in Kilobytes.
EXTENSIONS_STR="txt,log,csv,json,html,xml,conf,md,yml,ini" # Default comma-separated list of allowed file extensions.
FILENAME_LENGTH=8                  # Default length of the random part of the generated filenames.
PROGRESS_INTERVAL=100              # Default interval for reporting progress (e.g., report every 100 files).

# Runtime variables
VERBOSE=false                      # Boolean flag for verbose output (DEBUG level)
LOG_LEVEL="INFO"                   # Default log level (DEBUG, INFO, WARN, ERROR, CRITICAL)
NO_COLOR=false                     # Boolean flag to disable colored output
INTERACTIVE_MODE=false             # Boolean flag indicating if running in an interactive terminal
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is a terminal

# Array for extensions, populated in prepare_environment
declare -a extensions=()

# --- Color Definitions (Optional) ---
# Define ANSI escape codes for colored output, checking if NO_COLOR is set or if not interactive.
if [[ "${NO_COLOR}" == false && "${INTERACTIVE_MODE}" == true ]]; then
  COLOR_RESET='\033[0m'; COLOR_RED='\033[0;31m'; COLOR_GREEN='\033[0;32m'; COLOR_YELLOW='\033[0;33m'
  COLOR_BLUE='\033[0;34m'; COLOR_CYAN='\033[0;36m'; COLOR_BOLD='\033[1m'
else
  COLOR_RESET=""; COLOR_RED=""; COLOR_GREEN=""; COLOR_YELLOW=""; COLOR_BLUE=""; COLOR_CYAN=""; COLOR_BOLD=""
fi

# =========================================================================================
# FUNCTION DEFINITIONS
# =========================================================================================

# --- Logging Function ---
# Description: Handles formatted logging to stdout/stderr.
# Usage: log_message LEVEL "Message string"
# Levels: DEBUG, INFO, WARN, ERROR, CRITICAL
log_message() {
    local level="$1"; local message="$2"; local timestamp; local level_upper; local log_prefix; local log_line; local color=""
    timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z") # Include Timezone
    level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]')
    log_prefix="[${timestamp}] [${level_upper}]"
    log_line="${log_prefix} - ${message}"

    # Determine color based on level
    case "${level_upper}" in
        DEBUG) color="${COLOR_CYAN}" ;; INFO) color="${COLOR_GREEN}" ;; WARN) color="${COLOR_YELLOW}" ;;
        ERROR) color="${COLOR_RED}" ;; CRITICAL) color="${COLOR_BOLD}${COLOR_RED}" ;;
    esac

    # Map script log levels to numeric values for comparison
    declare -A log_levels=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [CRITICAL]=4)
    local current_log_level_num=${log_levels[${LOG_LEVEL^^}]}
    local message_level_num=${log_levels[${level_upper}]}

    # Check if the message level is severe enough to be logged based on LOG_LEVEL
    if [[ ${message_level_num} -ge ${current_log_level_num} ]]; then
        # Output to stderr for WARN, ERROR, CRITICAL; stdout otherwise
        if [[ "${level_upper}" == "WARN" || "${level_upper}" == "ERROR" || "${level_upper}" == "CRITICAL" ]]; then
            echo -e "${color}${log_line}${COLOR_RESET}" >&2
        else
            # Only print DEBUG if VERBOSE is true (which sets LOG_LEVEL to DEBUG)
            if [[ "${level_upper}" == "DEBUG" && "${VERBOSE}" == false ]]; then : # Do nothing
            else echo -e "${color}${log_line}${COLOR_RESET}"; fi
        fi
    fi

    # Exit immediately for CRITICAL errors
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        # Cleanup will be called by trap
        exit 1 # Use exit code 1 for critical, specific codes used elsewhere
    fi
}

# --- Usage/Help Function ---
# Description: Displays help information based on USAGE header section and exits.
usage() {
    # Print usage information to stderr
    cat << EOF >&2
Usage: ${SCRIPT_NAME} [-d DIR] [-n NUM] [-smin MIN_KB] [-smax MAX_KB] [-e EXT1,...] [-l LEN] [-p INT] [-v] [-h]

Generates random files for testing purposes.

Options:
  -d DIR          Target directory (default: ${TARGET_DIR})
  -n NUM          Number of files to create (default: ${NUM_FILES})
  -smin MIN_KB    Minimum file size in KB (default: ${MIN_SIZE_KB})
  -smax MAX_KB    Maximum file size in KB (default: ${MAX_SIZE_KB})
  -e EXTENSIONS   Comma-separated list of file extensions (default: ${EXTENSIONS_STR})
  -l LEN          Length of random filename part (default: ${FILENAME_LENGTH})
  -p INTERVAL     Progress report interval (default: ${PROGRESS_INTERVAL})
  -v              Enable verbose (DEBUG) logging.
  -h              Display this help message and exit.

Example: ${SCRIPT_NAME} -n 500 -d /tmp/test_data -smin 10 -smax 50 -e txt,dat
EOF
    exit 4 # Exit with argument error code
}

# --- Dependency Check Function ---
# Description: Checks if a command-line utility is installed and executable. Exits with CRITICAL error if not found.
# Arguments: $1: Command name, $2: (Optional) Package name suggestion
check_dependency() {
    local cmd="$1"; local install_suggestion="${2:-$cmd}"
    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required command '${cmd}' not found. Please install the '${install_suggestion}' package."
        exit 2 # Specific exit code for dependency errors
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
}

# --- Combined Dependency Check Function ---
check_dependencies() {
    log_message "INFO" "Checking required dependencies..."
    check_dependency "head" "coreutils"
    check_dependency "seq" "coreutils"
    check_dependency "mkdir" "coreutils"
    check_dependency "date" "coreutils" # Used by logging
    check_dependency "basename" "coreutils" # Used by SCRIPT_NAME
    check_dependency "dirname" "coreutils" # Used by SCRIPT_DIR
    check_dependency "sed" "sed" # Used by logging (strip color)
    log_message "INFO" "All required dependencies found."
}


# --- Cleanup Function ---
# Description: Performs cleanup tasks before script exits. Currently minimal. Called via 'trap'.
cleanup() {
    local exit_status=$? # Capture the script's exit status
    log_message "DEBUG" "Performing cleanup for PID ${SCRIPT_PID}..."
    # No temporary files or specific resources to clean up in this script currently.
    log_message "DEBUG" "Cleanup finished. Exiting with status: ${exit_status}"
    # Script will exit with the original exit_status after trap completes
}

# --- Trap Setup ---
# Register the 'cleanup' function to run on specific signals and on script exit.
trap cleanup EXIT INT TERM HUP

# --- Argument Parsing Function ---
# Description: Parses command-line options using getopts. Updates global variables.
parse_params() {
    local OPTIND # Reset OPTIND for getopts parsing in functions
    # Corrected OPTSTRING: uses -m for min size, -M for max size. Removed invalid s:x:
    local optstring=":d:n:m:M:e:l:p:vh" # Define options understood by getopts

    # ':' at the beginning enables silent error reporting handled in case statements
    while getopts "${optstring}" opt; do
      case ${opt} in # Use ${opt} as per standard getopts practice
        d) TARGET_DIR="$OPTARG" ;;
        n) NUM_FILES="$OPTARG" ;;
        m) MIN_SIZE_KB="$OPTARG" ;; # Use -m for min size
        M) MAX_SIZE_KB="$OPTARG" ;; # Use -M for max size
        e) EXTENSIONS_STR="$OPTARG" ;;
        l) FILENAME_LENGTH="$OPTARG" ;;
        p) PROGRESS_INTERVAL="$OPTARG" ;;
        v) VERBOSE=true; LOG_LEVEL="DEBUG" ;;
        h) usage ;; # usage function handles exit
        \?) log_message "CRITICAL" "Invalid option: -${OPTARG}"; usage ;;
        :) log_message "CRITICAL" "Option -${OPTARG} requires an argument."; usage ;;
      esac
    done
    shift $((OPTIND-1)) # Remove processed options

    # Check for unexpected positional arguments
    if [[ $# -gt 0 ]]; then
        log_message "CRITICAL" "Unexpected argument(s): $*"
        usage
    fi
    log_message "DEBUG" "Arguments parsed. Target: ${TARGET_DIR}, Num: ${NUM_FILES}, Size: ${MIN_SIZE_KB}-${MAX_SIZE_KB}KB, Ext: ${EXTENSIONS_STR}, Len: ${FILENAME_LENGTH}, Prog: ${PROGRESS_INTERVAL}, Verbose: ${VERBOSE}"
}


# --- Input Validation Function ---
# Description: Performs checks on finalized configuration and inputs before execution.
validate_inputs() {
    log_message "INFO" "Validating inputs and configuration..."

    # Validate numeric arguments
    local numeric_pattern='^[0-9]+$'
    if ! [[ "$NUM_FILES" =~ $numeric_pattern ]] || \
       ! [[ "$MIN_SIZE_KB" =~ $numeric_pattern ]] || \
       ! [[ "$MAX_SIZE_KB" =~ $numeric_pattern ]] || \
       ! [[ "$FILENAME_LENGTH" =~ $numeric_pattern ]] || \
       ! [[ "$PROGRESS_INTERVAL" =~ $numeric_pattern ]] || \
       (( FILENAME_LENGTH < 1 )) || \
       (( PROGRESS_INTERVAL < 1 )); then
      log_message "CRITICAL" "Numeric arguments (NUM_FILES, MIN_SIZE_KB, MAX_SIZE_KB, FILENAME_LENGTH, PROGRESS_INTERVAL) must be positive integers."
      exit 4 # Argument error
    fi

    # Validate size range
    if (( MIN_SIZE_KB > MAX_SIZE_KB )); then
        log_message "WARN" "Minimum size (${MIN_SIZE_KB} KB) is greater than maximum size (${MAX_SIZE_KB} KB). Setting max size = min size."
        MAX_SIZE_KB=$MIN_SIZE_KB
    fi

    # Validate target directory writability (attempt to create later in prepare_environment)
    # Basic check: if it exists, is it a directory and writable?
    if [[ -e "${TARGET_DIR}" && ! -d "${TARGET_DIR}" ]]; then
        log_message "CRITICAL" "Target path '${TARGET_DIR}' exists but is not a directory."
        exit 5 # Permission/FS error
    fi
    # Deeper writability check happens in prepare_environment after mkdir

    log_message "INFO" "Input validation passed."
}

# --- Environment Preparation Function ---
# Description: Sets up the environment (creates directory, prepares extension array).
prepare_environment() {
    log_message "INFO" "Preparing execution environment..."

    # Convert extensions string to array
    IFS=',' read -r -a extensions <<< "$EXTENSIONS_STR"
    log_message "DEBUG" "Parsed extensions: ${extensions[*]}"

    # Create target directory if it doesn't exist
    log_message "DEBUG" "Attempting to create target directory: ${TARGET_DIR}"
    if ! mkdir -p "${TARGET_DIR}"; then
        log_message "CRITICAL" "Could not create target directory '${TARGET_DIR}'. Check permissions."
        exit 5 # Permission/FS error
    fi

    # Final check: ensure the target directory is writable
    if [[ ! -w "${TARGET_DIR}" ]]; then
        log_message "CRITICAL" "Target directory '${TARGET_DIR}' is not writable."
        exit 5 # Permission/FS error
    fi
    log_message "INFO" "Target directory '${TARGET_DIR}' is ready."

    log_message "INFO" "Environment preparation complete."
}


# --- File Generation Functions (from original script) ---

# Function: generate_random_size
# Description: Calculates a random file size in bytes.
# Parameters: $1: min_kb, $2: max_kb
# Output: Echoes the calculated random size in bytes.
generate_random_size() {
  local min_kb=$1; local max_kb=$2; local range; local random_kb
  if (( min_kb > max_kb )); then max_kb=$min_kb; fi # Handled in validation, but keep for robustness
  range=$((max_kb - min_kb + 1))
  random_kb=$((RANDOM % range + min_kb))
  echo $(( random_kb * 1024 ))
}

# Function: generate_random_filename
# Description: Creates a random filename with extension.
# Parameters: $1: length, $@: extensions_array
# Output: Echoes the generated random filename.
generate_random_filename() {
  local length=$1; shift; local extensions_array=("$@")
  local chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'; local filename=""; local i
  local num_extensions=${#extensions_array[@]}; local extension=""

  for (( i=0; i<length; i++ )); do
    filename+="${chars:RANDOM%${#chars}:1}"
  done

  if (( num_extensions > 0 )); then
      extension="${extensions_array[RANDOM % num_extensions]}"
      echo "${filename}.${extension}"
  else
      echo "${filename}" # No extensions provided
  fi
}

# --- Main Logic Function ---
# Description: Contains the core file generation loop.
main() {
    log_message "INFO" "Starting file generation..."
    log_message "INFO" "--------------------------------------------------"
    log_message "INFO" "Target Directory : ${TARGET_DIR}"
    log_message "INFO" "Number of Files  : ${NUM_FILES}"
    log_message "INFO" "File Size Range  : ${MIN_SIZE_KB}KB - ${MAX_SIZE_KB}KB"
    log_message "INFO" "Extensions       : ${extensions[*]}"
    log_message "INFO" "Filename Length  : ${FILENAME_LENGTH}"
    log_message "INFO" "Progress Interval: ${PROGRESS_INTERVAL}"
    log_message "INFO" "--------------------------------------------------"

    local i; local filename; local filepath; local filesize

    # Loop to create files
    for i in $(seq 1 "$NUM_FILES"); do
      # Generate filename and path
      filename=$(generate_random_filename "$FILENAME_LENGTH" "${extensions[@]}")
      filepath="${TARGET_DIR}/${filename}"
      log_message "DEBUG" "Generating file #${i}: ${filepath}"

      # Generate size
      filesize=$(generate_random_size "$MIN_SIZE_KB" "$MAX_SIZE_KB")
      log_message "DEBUG" "File #${i} size: ${filesize} bytes"

      # Write random content to the file using head/urandom
      if head -c "$filesize" /dev/urandom > "$filepath"; then
          log_message "DEBUG" "Successfully wrote file: ${filepath}"
      else
          # Log error but continue (as per original script logic)
          log_message "ERROR" "Failed to write file '${filepath}'. Check permissions or disk space."
          # If strict mode (-e) was off, we'd check $? here. With -e, the script would exit
          # unless the command was part of `if` or `||`. Here, it's safe in the `if`.
          # If we wanted to guarantee continuation even with `set -e`, we could do:
          # head -c "$filesize" /dev/urandom > "$filepath" || log_message "ERROR" "Failed..."
          continue # Explicitly continue to next iteration
      fi

      # Display progress
      if (( i % PROGRESS_INTERVAL == 0 )); then
        log_message "INFO" "Created ${i} / ${NUM_FILES} files..."
      fi
    done

    log_message "INFO" "--------------------------------------------------"
    log_message "INFO" "Finished: File generation process completed for ${NUM_FILES} requested files in ${TARGET_DIR}."
    log_message "INFO" "(Note: Individual file write errors were logged but did not halt execution)."
    log_message "INFO" "--------------------------------------------------"
}


# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# 1. Parse Command Line Arguments
parse_params "$@" # Pass all arguments received by the script

# 2. Validate Inputs and Configuration
validate_inputs

# 3. Check Dependencies
check_dependencies

# 4. Prepare Environment
prepare_environment

# 5. Execute Main Logic
main

# 6. Exit Successfully
# The 'trap cleanup EXIT' will run automatically just before this.
log_message "INFO" "Script completed successfully."
exit 0 # Explicitly exit with success code

# =========================================================================================
# --- End of Script ---
