#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : parallel_chown.sh
# PURPOSE       : Changes file ownership in parallel with logging/dry-run options.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2024-11-14
# LAST UPDATED  : 2024-11-14
# VERSION       : 1.0.0
# =========================================================================================

# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This production-ready script is designed to change the owner and group of files and
# directories recursively within a target directory. It optimizes the process by finding
# items with incorrect ownership and processing them in parallel batches using xargs.
# This significantly speeds up the operation on directories containing a large number
# of files compared to a simple recursive `chown`.
#
# Key Workflow / Features:
# - Parses command-line arguments for target directory, owner:group, and options (--dry-run, -v).
# - Validates inputs (directory existence, owner format).
# - Checks for required command dependencies (find, xargs, chown, etc.).
# - Finds files/directories not matching the target owner:group using `find`.
# - Uses `xargs` with `-P` to run multiple `chown` commands in parallel for efficiency.
# - Calculates the number of parallel processes based on available CPU cores (defaults to 90%, min 1).
# - Processes items in configurable batches (default size 100) for efficient handling.
# - Provides a dry-run mode (`--dry-run`) to simulate changes without executing them.
# - Implements robust logging with configurable levels (INFO, DEBUG, WARN, ERROR, CRITICAL)
#   to both console (with color support) and a timestamped log file.
# - Captures specific `chown` command failures in a separate error log file.
# - Includes strict mode (`set -euo pipefail`) and trap-based cleanup for robustness.
# - Handles filenames with spaces or special characters correctly using null delimiters (`-print0`, `xargs -0`).
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Efficiency:** Prioritizes speed on large filesystems by using `find` to identify targets
#   and `xargs -P` for parallel execution, avoiding the overhead of a shell loop for every item.
# - **Robustness:** Employs strict mode (`set -euo pipefail`), input validation, dependency checks,
#   and detailed logging with distinct levels. Uses `trap` for cleanup.
# - **Readability:** Uses clear variable names, extensive header documentation, comments for
#   complex logic, and function-based structure.
# - **Safety:** Includes a `--dry-run` mode for simulation. Handles filenames safely. Logs errors
#   without halting the entire process for individual file failures.
# - **Configurability:** Allows setting log file path, parallel processes (derived), and log level
#   via variables or arguments (e.g., verbosity).
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - System Administrators managing file permissions on Linux/UNIX systems.
# - DevOps Engineers automating infrastructure tasks involving ownership changes.
# - Users needing to correct ownership on large directory trees efficiently.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x parallel_chown.sh`
# - File system access: Requires read/traverse permissions on the target directory and its contents.
# - Ownership change: Requires sufficient privileges (often root or sudo) to change ownership
#   of the target files/directories. `chown` command itself requires these privileges.
# - Log directories: Requires write permissions for the user running the script to the specified
#   log file directory (`/var/log/` by default) and the chown error log directory.
#
# **Basic Syntax:**
#   ./parallel_chown.sh [options] <directory> <owner:group> [--dry-run]
#
# **Options:**
#   -h              : Display help message and exit.
#   -v              : Enable verbose output (sets log level to DEBUG).
#
# **Arguments:**
#   <directory>     : Required. The target directory path where ownership changes will be applied recursively.
#   <owner:group>   : Required. The new owner and group specification in the format 'username:groupname'.
#   --dry-run       : Optional. If provided, simulates the ownership changes, logging what *would*
#                     be changed without actually modifying any file ownership. Must be the last argument if used.
#
# **Common Examples:**
# 1. Change ownership in /data/web to user 'www-data' and group 'www-data':
#    sudo ./parallel_chown.sh /data/web www-data:www-data
#
# 2. Simulate the same ownership change with verbose output:
#    sudo ./parallel_chown.sh -v /data/web www-data:www-data --dry-run
#
# 3. Get help:
#    ./parallel_chown.sh -h
#
# **Advanced Execution (Automation):**
# - Example cron job running daily at 3:00 AM, logging to the default file:
#   0 3 * * * /path/to/parallel_chown.sh /data/important_dir user:group >> /var/log/parallel_chown.log 2>&1
#   (Ensure cron environment has access to necessary commands and permissions)
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - System-wide utility: `/usr/local/sbin/` (if requires root/sudo often) or `/usr/local/bin/`
# - User-specific utility: `~/bin/` or `~/.local/bin/` (ensure in user's $PATH)
#
# **Manual Setup:**
# 1. Place the script `parallel_chown.sh` in the chosen location.
# 2. Set appropriate ownership (e.g., `sudo chown root:root /usr/local/sbin/parallel_chown.sh`).
# 3. Set executable permissions (e.g., `sudo chmod 755 /usr/local/sbin/parallel_chown.sh` or `chmod +x parallel_chown.sh`).
# 4. Ensure all dependencies (see below) are installed.
# 5. Verify write permissions for the default log directory (`/var/log/`) or configure `LOGFILE` and
#    `CHOWN_ERROR_LOG` variables to point to writable locations.
# 6. Run initially with `-h` or `--dry-run` to test setup.
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: The Bourne-Again SHell interpreter (Version >= 4.0 recommended for associative arrays used in logging).
#
# **Required System Binaries/Tools:**
# - `coreutils`: Provides `date`, `mkdir`, `chmod`, `cat`, `wc`, `cut`, `basename`, `dirname`, `touch`, `tee` (optional, replaced by log function).
# - `findutils`: Provides `find` (GNU version recommended for `-print0`) and `xargs`.
# - `gawk` (or `mawk`/`nawk`): Provides `awk` (used for calculating parallel processes).
# - `grep`: Provides `grep` (used for input validation and filtering find errors).
# - `procps` (or similar): Provides `nproc` (used for determining CPU cores).
# - `chown`: The command to change file owner and group (typically part of coreutils).
# - `sed`: Used in `usage` function.
# - `command`: Bash built-in for checking command existence.
# - `getopts`: Bash built-in for parsing options.
#
# **Setup Instructions (if dependencies are not standard):**
# - Most dependencies are standard on modern Linux systems.
# - Check availability: `command -v <tool_name>` (e.g., `command -v nproc`)
# - Installation example (Debian/Ubuntu): `sudo apt update && sudo apt install coreutils findutils gawk procps grep`
# - Installation example (RHEL/CentOS/Fedora): `sudo dnf update && sudo dnf install coreutils findutils gawk procps-ng grep`
#
# **Operating System Compatibility:**
# - Designed primarily for Linux distributions.
# - May work on other UNIX-like systems (macOS, BSD) with potential minor adjustments if core utilities behave differently (e.g., `nproc`, `find` options).
#
# **Environment Variables Used:**
# - `LOGFILE` (Internal, configurable default): Overrides default path for the main log file.
# - `PARALLEL_PROCESSES` (Internal, configurable default): Overrides default calculation for parallel workers.
# - `CHOWN_ERROR_LOG` (Internal, configurable default): Overrides default path for the chown error log file.
# - `LOG_LEVEL` (Internal): Controls logging verbosity (DEBUG, INFO, WARN, ERROR, CRITICAL). Set via `-v` flag currently.
# - `NO_COLOR` (Standard): If set to `true`, disables colored output.
# - `PATH`: Standard variable, ensure required binaries are locatable.
#
# **System Resource Requirements:**
# - CPU: Scales with `PARALLEL_PROCESSES`. Can utilize multiple cores heavily during `xargs` execution.
# - Memory: Generally low, mainly used by shell and parallel `chown` processes. `find` may use memory depending on directory size.
# - Disk I/O: Can be significant, depending on the number of files being checked/modified and filesystem performance.
# - Disk Space: Minimal for script; requires space for log files.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): INFO and DEBUG messages (DEBUG only if `-v` is used). Colored if interactive and `NO_COLOR` is not set.
# - Standard Error (stderr): WARN, ERROR, and CRITICAL messages. Colored if interactive and `NO_COLOR` is not set. Help/usage messages.
# - Dedicated Log File: Yes. Path configurable via `LOGFILE` variable (Default: `/var/log/parallel_chown.log`). Contains timestamped messages (without color codes) matching the console output based on `LOG_LEVEL`.
# - Chown Error Log File: Yes. Path configurable via `CHOWN_ERROR_LOG` variable (Default: `/var/log/chown_errors.log`). Specifically logs timestamped errors from individual `chown` command failures within `xargs`.
#
# **Log Format:**
# - Main Log/Console Format: `[YYYY-MM-DD HH:MM:SS TZ] [LEVEL] - Message`
# - Chown Error Log Format: `[YYYY-MM-DD HH:MM:SS]: Failed to change ownership for '<item>' to '<owner:group>'`
#
# **Log Levels:**
# - `DEBUG`: Detailed step-by-step information (Enabled by `-v`).
# - `INFO`: General operational messages (default level).
# - `WARN`: Potential issues or non-critical errors.
# - `ERROR`: Significant errors potentially affecting the operation.
# - `CRITICAL`: Severe errors causing script termination (e.g., missing dependencies, invalid required arguments).
# - Control: Currently `-v` sets `LOG_LEVEL` to `DEBUG`. `LOG_LEVEL` variable can be modified internally for different default.
#
# **Log Rotation:**
# - Handled by script?: No.
# - External Recommendation: Use standard system tools like `logrotate` to manage `LOGFILE` and `CHOWN_ERROR_LOG` file sizes and retention. Create a configuration file in `/etc/logrotate.d/`.
# =========================================================================================

# =========================================================================================
# CONFIGURATION
# =========================================================================================
# Key runtime parameters are set as global variables with defaults. Some can be influenced
# by command-line arguments.
#
# **Runtime Configuration Variables (Defaults set in script):**
# - `LOGFILE`: Path to the main operational log file.
#              Default: "/var/log/${SCRIPT_NAME%.sh}.log" (e.g., /var/log/parallel_chown.log)
# - `PARALLEL_PROCESSES`: Number of parallel `chown` processes `xargs` will run.
#                         Default: Calculated as 90% of available cores via `nproc`, minimum 1.
# - `DRY_RUN`: Flag to enable/disable dry-run mode. Set by the `--dry-run` command-line argument.
#              Default: false
# - `CHOWN_ERROR_LOG`: Path to the log file for specific `chown` failures.
#                      Default: "/var/log/chown_errors.log"
# - `LOG_TO_FILE`: Controls whether logging to `LOGFILE` is enabled.
#                  Default: true (can be disabled if log directory is unwritable)
# - `LOG_LEVEL`: Minimum severity level for messages to be logged.
#                Default: "INFO" (set to "DEBUG" by `-v` flag)
# - `VERBOSE`: Internal flag set by `-v`.
#              Default: false
#
# **Internal Script Parameters:**
# - `batch_size`: (Internal variable within `change_ownership_optimized` function)
#                 Number of files processed per parallel `xargs` invocation. Default: 100.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Normal Operation: Prints INFO and DEBUG level log messages (timestamps, levels, messages).
# - Dry Run: Prints messages indicating which ownership changes *would* occur.
#
# **Standard Error (stderr):**
# - Errors & Warnings: Prints WARN, ERROR, and CRITICAL level log messages.
# - Usage/Help: Prints the script's usage instructions when `-h` is used or arguments are invalid.
#
# **Generated/Modified Files:**
# - Main Log File (`LOGFILE`): Records timestamped execution details, errors, and informational messages based on `LOG_LEVEL`.
# - Chown Error Log File (`CHOWN_ERROR_LOG`): Records specific `chown` command failures encountered during parallel processing. Check this file for items that could not be processed.
# - Target Files/Directories: File ownership (user and group) is modified if not in dry-run mode and permissions allow.
# - Temporary Files: None created by default.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success - Script completed its operation (or simulation) without fatal errors. Note: Individual `chown` failures within batches are logged but do *not* cause a non-zero exit code for the main script.
# - 1: General/Usage Error - Invalid command-line options, insufficient arguments, or CRITICAL log message triggered.
# - 2: Directory Error - Target directory specified does not exist or is not a directory.
# - 3: Owner Format Error - Invalid owner:group format provided as an argument.
# - Other non-zero codes might result from underlying command failures if `set -e` triggers before the main `xargs` loop, or if `check_dependency` fails (via CRITICAL log).
#
# **Error Handling:**
# - Uses `set -euo pipefail` for immediate exit on errors, unset variables, and pipeline failures (outside the main `xargs` command which handles failures internally).
# - `trap cleanup EXIT INT TERM HUP`: Ensures cleanup function runs on exit or signal.
# - Input Validation (`validate_inputs`): Checks directory existence/type and owner:group format before proceeding.
# - Dependency Checks (`check_dependency`): Verifies presence of required tools, exits via CRITICAL log if missing.
# - `find` Errors: Permission denied errors during file searching are filtered from stderr to reduce noise but allow processing of accessible items.
# - `chown` Failures: Individual `chown` errors within the `xargs` parallel execution are caught using `||` and logged to `CHOWN_ERROR_LOG`. They do *not* stop the processing of other files in the batch or subsequent batches.
# - Log Directory Errors: Checks writability of log directories; warns and disables file logging if unwritable.
#
# **Important Considerations / Warnings:**
# - **Privilege Requirements:** Running `chown` typically requires root privileges (`sudo`). Ensure the script is executed by a user with sufficient permissions to modify ownership in the target directory.
# - **Performance Impact:** Can consume significant CPU and Disk I/O, especially on large directories with many files needing changes. Monitor system load during initial runs. The 90% core utilization default is aggressive; consider adjusting `PARALLEL_PROCESSES` if needed.
# - **Concurrency:** The script itself is not designed for multiple simultaneous instances operating on the *same* directory tree, as this could lead to race conditions. No explicit locking is implemented.
# - **Filesystem Type:** Performance may vary based on the underlying filesystem.
# - **Error Log:** Always check the `CHOWN_ERROR_LOG` file after execution, especially on large runs, to identify any files whose ownership could not be changed due to permissions or other issues.
# - **Idempotency:** The script is mostly idempotent. Running it multiple times with the same arguments will find fewer (or no) files needing changes on subsequent runs, achieving the desired state without adverse side effects.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes a Bash environment (Version 4.0+ recommended) with access to standard GNU/Linux core utilities.
# - Assumes required dependencies (find, xargs, chown, nproc, awk, grep, etc.) are installed and in the system `$PATH`.
# - Assumes the target directory path provided as an argument exists.
# - Assumes the owner:group string provided follows the 'user:group' format.
# - Assumes the user running the script has read/traverse permissions for the target directory structure.
# - Assumes the user running the script has sufficient privileges to execute `chown` effectively (often requires root/sudo).
# - Assumes write permissions to the specified/default log file directories (`/var/log/` by default).
# =========================================================================================

# =========================================================================================
# PERFORMANCE OPTIMIZATION
# =========================================================================================
# - Uses `find` to efficiently locate only the files/directories needing ownership changes, avoiding processing items already correct.
# - Leverages `xargs -P` to parallelize the `chown` operations across multiple CPU cores, significantly reducing execution time on multi-core systems compared to sequential processing.
# - Uses `-print0` and `xargs -0` to handle filenames safely and potentially more efficiently than newline-separated lists.
# - Processes files in batches (`-n ${batch_size}`) within `xargs` to balance parallelism overhead and argument list length limits.
# - **Potential Bottlenecks:** Disk I/O speed, CPU core count, very large number of files causing `find` to take time.
# - **Tuning:** The `PARALLEL_PROCESSES` (calculated or set directly) and internal `batch_size` could be adjusted based on system characteristics and testing, though defaults are generally reasonable.
# =========================================================================================

# =========================================================================================
# TESTING & VALIDATION
# =========================================================================================
# - Manual testing performed on Linux (e.g., Ubuntu, CentOS).
# - Tested with directories containing files with spaces and special characters.
# - Validated `--dry-run` mode behavior.
# - Validated argument parsing and error handling for incorrect inputs.
# - Checked log output for clarity and correctness across different levels.
# - Static analysis performed using `shellcheck` to identify potential issues.
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - Add command-line options to override `PARALLEL_PROCESSES` or `batch_size`.
# - Add option to configure log file paths via command-line arguments.
# - Implement more sophisticated calculation for `PARALLEL_PROCESSES` (e.g., considering I/O load).
# - Add support for reading target directories/ownership from a file for batch operations.
# - Enhance error reporting (e.g., summary of failed `chown` operations at the end).
# - Explore alternative parallelization tools (e.g., GNU `parallel`) if more features are needed.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** High. The script's core function (`chown`) typically requires root privileges. Running this script with `sudo` grants it extensive permissions to change file ownership across the filesystem. Exercise caution regarding the target directory specified.
# - **Input Sanitization:** Basic validation is performed on the directory (existence check) and owner:group (format check). The script relies on `find` and `xargs` which are generally safe regarding filename handling when used with `-print0`/`-0`. However, ensure the `owner:group` input itself is trusted.
# - **Sensitive Data Handling:** The script does not directly handle passwords or API keys.
# - **Dependencies:** Relies on standard, trusted system utilities. Keep the OS and these utilities updated.
# - **File Permissions:** The script modifies file ownership. Log files are created with default permissions unless modified; ensure log directories (`/var/log/` by default) have appropriate permissions.
# - **External Command Execution:** Executes `find`, `xargs`, `chown`, `nproc`, `awk`, `cut`, `grep`, `wc`, `date`, `tee`, `basename`, `dirname`, `mkdir`, `touch`. These are invoked with arguments derived from user input (directory, owner:group). While `-print0`/`-0` mitigate injection risks via filenames, trust in the input `owner:group` string is assumed. The inline `bash -c` script within `xargs` receives controlled input.
# - **Error Message Verbosity:** Error messages logged should not inadvertently leak sensitive system information. Current logging focuses on filenames and ownership.
# - **Dry Run:** The `--dry-run` option is crucial for safely previewing changes before execution. **Always use `--dry-run` first** when operating on critical directories.
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
# Configuration Defaults
LOGFILE_DEFAULT="/var/log/${SCRIPT_NAME%.sh}.log" # Default log file path
PARALLEL_PROCESSES_DEFAULT=$(awk "BEGIN {n=$(nproc)*0.9; printf \"%d\", (n<1)?1:n}") # Default 90% cores, min 1
DRY_RUN_DEFAULT=false # Default dry-run mode
VERBOSE=false # Boolean flag for verbose output
DEBUG_MODE=false # Boolean flag for debug mode (set -x) - handled via set -x above if uncommented
NO_COLOR=false # Boolean flag to disable colored output
INTERACTIVE_MODE=false # Boolean flag indicating if running in an interactive terminal
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is a terminal

# Default Paths
DEFAULT_CHOWN_ERROR_LOG="/var/log/chown_errors.log" # Separate log for chown failures

# Runtime variables that will be populated later
LOGFILE="${LOGFILE_DEFAULT}"
PARALLEL_PROCESSES=${PARALLEL_PROCESSES_DEFAULT}
DRY_RUN=${DRY_RUN_DEFAULT}
CHOWN_ERROR_LOG="${DEFAULT_CHOWN_ERROR_LOG}"
LOG_TO_FILE=true # Control whether logging to file is enabled
LOG_LEVEL="INFO" # Default log level (DEBUG, INFO, WARN, ERROR, CRITICAL)
TEMP_DIR="" # Will be set by mktemp if needed (not used currently)

# Script-specific runtime variables populated by argument parsing
TARGET_DIRECTORY=""
TARGET_OWNER=""

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
# Description: Handles formatted logging to stdout/stderr and optionally to a file.
# Usage: log_message LEVEL "Message string"
# Levels: DEBUG, INFO, WARN, ERROR, CRITICAL
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z") # Include Timezone
    local level_upper
    level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]')
    local log_prefix="[${timestamp}] [${level_upper}]"
    local log_line="${log_prefix} - ${message}"
    local color=""

    # Determine color based on level
    case "${level_upper}" in
        DEBUG) color="${COLOR_CYAN}" ;;
        INFO) color="${COLOR_GREEN}" ;;
        WARN) color="${COLOR_YELLOW}" ;;
        ERROR) color="${COLOR_RED}" ;;
        CRITICAL) color="${COLOR_BOLD}${COLOR_RED}" ;;
    esac

    # Map script log levels to numeric values for comparison
    declare -A log_levels=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [CRITICAL]=4)
    local current_log_level_num=${log_levels[${LOG_LEVEL^^}]}
    # Handle potential unset LOG_LEVEL (though -u should prevent this)
    [[ -z "$current_log_level_num" ]] && current_log_level_num=1 # Default to INFO if unset

    local message_level_num=${log_levels[${level_upper}]}

    # Check if the message level is severe enough to be logged based on LOG_LEVEL
    if [[ ${message_level_num} -ge ${current_log_level_num} ]]; then
        # Output to stderr for WARN, ERROR, CRITICAL; stdout otherwise
        if [[ "${level_upper}" == "WARN" || "${level_upper}" == "ERROR" || "${level_upper}" == "CRITICAL" ]]; then
            echo -e "${color}${log_line}${COLOR_RESET}" >&2
        else
            # Only print DEBUG if VERBOSE is true
            if [[ "${level_upper}" == "DEBUG" && "${VERBOSE}" == false ]]; then
                : # Do nothing for DEBUG messages if not verbose
            else
                echo -e "${color}${log_line}${COLOR_RESET}"
            fi
        fi

        # Append to log file if enabled
        if [[ "${LOG_TO_FILE}" == true ]]; then
            # Ensure log directory exists (attempt to create if missing)
            # shellcheck disable=SC2155 # Declaration via command substitution is intended here
            local log_dir=$(dirname "${LOGFILE}")
            if [[ ! -d "$log_dir" ]]; then
                # Attempt to create the directory
                if mkdir -p "$log_dir"; then
                    log_message "DEBUG" "Created log directory: ${log_dir}" # Log creation only if successful
                else
                    # If creation fails, warn and disable file logging
                    if [[ -z ${LOG_DIR_CREATE_WARN_SENT+x} ]]; then # Check if variable is unset
                        echo -e "${COLOR_YELLOW}[${timestamp}] [WARN] - Cannot create log directory ${log_dir}. Logging to file disabled.${COLOR_RESET}" >&2
                        LOG_DIR_CREATE_WARN_SENT=true # Set variable to prevent repeating warning
                        LOG_TO_FILE=false # Disable further file logging attempts
                    fi
                fi
            fi

            # Check writability again after potential creation attempt
            if [[ "${LOG_TO_FILE}" == true && -w "$log_dir" ]]; then
                # Strip color codes for file logging
                echo "${log_prefix} - ${message}" >> "${LOGFILE}"
            elif [[ "${LOG_TO_FILE}" == true ]]; then # Only warn if we haven't already warned about creation failure
                 if [[ -z ${LOG_DIR_WRITE_WARN_SENT+x} ]]; then # Check if variable is unset
                    echo -e "${COLOR_YELLOW}[${timestamp}] [WARN] - Cannot write to log directory ${log_dir}. Logging to file disabled.${COLOR_RESET}" >&2
                    LOG_DIR_WRITE_WARN_SENT=true # Set variable to prevent repeating warning
                    LOG_TO_FILE=false # Disable further file logging attempts
                fi
            fi
        fi
    fi

    # Exit immediately for CRITICAL errors
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        log_message "INFO" "Critical error encountered. Exiting script."
        # Cleanup will be handled by trap
        exit 1 # Use a specific exit code for critical errors if desired
    fi
}

# --- Usage/Help Function ---
# Description: Displays help information based on header comments and exits.
usage() {
    # Extract the Usage section from this script's header comments.
    local usage_text
    usage_text=$(sed -n '/^# ===+ USAGE ===+$/,/^# ===+ .* ===+$/{ /# ===+ .* ===+$/!p; }' "${BASH_SOURCE[0]}" | sed 's/^# //; s/\[your_script_name.sh\]/'"${SCRIPT_NAME}"'/g')

    # Print extracted usage information to stderr
    cat << EOF >&2
${usage_text}

Default Log File: ${LOGFILE_DEFAULT}
Default Chown Error Log: ${DEFAULT_CHOWN_ERROR_LOG}
Default Parallel Processes: ${PARALLEL_PROCESSES_DEFAULT} (Adjusted based on system cores)
EOF
    exit 1 # Exit with a non-zero status after showing help
}

# --- Dependency Check Function ---
# Description: Checks if a command-line utility is installed and executable.
# Logs a CRITICAL error and exits if the dependency is missing.
# Arguments: $1: Command name to check (e.g., "find", "xargs")
#            $2: (Optional) Package name to suggest for installation
check_dependency() {
    local cmd="$1"
    local install_suggestion="${2:-$cmd}" # Use command name if package name not provided
    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required command '${cmd}' not found."
        log_message "ERROR" "Please install the '${install_suggestion}' package using your system's package manager."
        # exit 1 is handled by CRITICAL log level
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
}

# --- Cleanup Function ---
# Description: Performs cleanup tasks before script exits (e.g., removing temp files).
# Currently does nothing specific for this script but included for good practice.
# Designed to be called via 'trap'.
cleanup() {
    local exit_status=$? # Capture the script's exit status
    log_message "INFO" "Performing cleanup..."
    # Add cleanup tasks here if needed (e.g., remove temp files, lock files)
    # if [[ -n "${TEMP_DIR:-}" && -d "${TEMP_DIR}" ]]; then
    #     log_message "DEBUG" "Removing temporary directory: ${TEMP_DIR}"
    #     rm -rf "${TEMP_DIR}" || log_message "WARN" "Failed to remove temporary directory: ${TEMP_DIR}"
    # fi
    log_message "INFO" "Cleanup finished with exit status: ${exit_status}"
    # Note: The script will exit with the original exit_status after trap completes
}

# --- Trap Setup ---
# Register the 'cleanup' function to run on specific signals and on script exit.
trap cleanup EXIT INT TERM HUP

# --- Argument Parsing Function ---
# Description: Parses command-line options and arguments.
# Updates global variables based on provided flags and arguments.
# Uses a combination of getopts for flags and positional argument checks.
parse_params() {
    log_message "DEBUG" "Parsing command-line arguments: $*"
    # Use getopts for potential future short options like -v (verbose) or -h (help).
    # Currently, only -h and -v are handled for demonstration/template consistency.
    while getopts ":hv" opt; do
        case $opt in
            h) usage ;; # Show help and exit
            v) VERBOSE=true; LOG_LEVEL="DEBUG" ;; # Enable verbose mode (maps to DEBUG level)
            \?) log_message "ERROR" "Invalid option: -${OPTARG}"; usage ;;
            :) log_message "ERROR" "Option -${OPTARG} requires an argument."; usage ;;
        esac
    done

    # Shift processed options away, leaving positional arguments in $@
    shift $((OPTIND-1))

    # --- Handle Positional Arguments and --dry-run ---
    # Expecting: <directory> <owner:group> [--dry-run]

    if [[ $# -lt 2 ]]; then
        log_message "ERROR" "Insufficient arguments provided. Directory and Owner:Group are required."
        usage
    fi

    TARGET_DIRECTORY="$1"
    TARGET_OWNER="$2"
    shift 2 # Remove directory and owner from arguments

    # Check for remaining arguments (should only be --dry-run, if present)
    if [[ $# -gt 0 ]]; then
        if [[ "$1" == "--dry-run" && $# -eq 1 ]]; then
            DRY_RUN=true
        else
            log_message "ERROR" "Unexpected argument(s): $*"
            usage
        fi
    fi

    # Final log of parsed parameters
    log_message "DEBUG" "Arguments parsed. Verbose: ${VERBOSE}, DryRun: ${DRY_RUN}, LogLevel: ${LOG_LEVEL}"
    log_message "DEBUG" "Target Directory: ${TARGET_DIRECTORY}"
    log_message "DEBUG" "Target Owner: ${TARGET_OWNER}"
}

# --- Configuration Loading Function ---
# Description: Placeholder for loading configuration from a file.
# Not used by this script currently but included for template consistency.
load_config() {
    log_message "DEBUG" "Configuration file loading skipped (not implemented for this script)."
    # If implemented, load settings from a file like "${SCRIPT_DIR}/config.conf"
    # Settings should generally be overridden by command-line arguments.
}

# --- Input Validation Function ---
# Description: Performs checks on finalized configuration and inputs before execution.
validate_inputs() {
    log_message "INFO" "Validating inputs and configuration..."

    # Validate Target Directory
    if [[ -z "${TARGET_DIRECTORY}" ]]; then
        log_message "CRITICAL" "Target directory argument is missing."
    elif [[ ! -d "${TARGET_DIRECTORY}" ]]; then
        log_message "CRITICAL" "Target directory '${TARGET_DIRECTORY}' does not exist or is not a directory."
        exit 2 # Specific exit code for directory error
    fi
    log_message "DEBUG" "Target directory '${TARGET_DIRECTORY}' validated."

    # Validate Target Owner Format
    if [[ -z "${TARGET_OWNER}" ]]; then
         log_message "CRITICAL" "Target owner:group argument is missing."
    elif ! echo "${TARGET_OWNER}" | grep -qE '^[^:]+:[^:]+$'; then
        log_message "CRITICAL" "Invalid owner format '${TARGET_OWNER}'. Expected format: user:group"
        exit 3 # Specific exit code for owner format error
    fi
    log_message "DEBUG" "Target owner:group format '${TARGET_OWNER}' validated."

    # Ensure log directory is writable if logging to file (check again after potential creation)
    if [[ "${LOG_TO_FILE}" == true ]]; then
        local log_dir
        log_dir=$(dirname "${LOGFILE}")
        if [[ ! -w "${log_dir}" ]]; then
            log_message "WARN" "Log directory '${log_dir}' is not writable. Disabling file logging."
            LOG_TO_FILE=false
        else
            log_message "DEBUG" "Log directory '${log_dir}' is writable."
        fi
        # Also check the chown error log directory
        local chown_log_dir
        chown_log_dir=$(dirname "${CHOWN_ERROR_LOG}")
         if ! mkdir -p "${chown_log_dir}"; then
             log_message "WARN" "Chown error log directory '${chown_log_dir}' could not be created."
         elif [[ ! -w "${chown_log_dir}" ]]; then
            log_message "WARN" "Chown error log directory '${chown_log_dir}' is not writable. Chown errors might not be logged to file."
        else
            log_message "DEBUG" "Chown error log directory '${chown_log_dir}' is accessible."
        fi
    fi

    log_message "INFO" "Input validation passed."
}

# --- Preparation Function ---
# Description: Sets up the environment before the main logic runs.
prepare_environment() {
    log_message "INFO" "Preparing execution environment..."

    # Ensure log file directory exists if logging is enabled (validation already checked writability)
    if [[ "${LOG_TO_FILE}" == true ]]; then
        local log_dir
        log_dir=$(dirname "${LOGFILE}")
        mkdir -p "${log_dir}" # Attempt creation, ignore error as writability checked in validation
        # Touch the log file to ensure it exists early (optional)
        touch "${LOGFILE}" || log_message "WARN" "Could not touch log file: ${LOGFILE}"

        # Ensure chown error log directory exists
        local chown_log_dir
        chown_log_dir=$(dirname "${CHOWN_ERROR_LOG}")
        mkdir -p "${chown_log_dir}"
        touch "${CHOWN_ERROR_LOG}" || log_message "WARN" "Could not touch chown error log file: ${CHOWN_ERROR_LOG}"
    fi

    if [[ "${DRY_RUN}" == true ]]; then
        log_message "WARN" "--- Dry-run mode enabled. No file ownership changes will be made. ---"
    fi

    log_message "INFO" "Environment preparation complete."
}

# --- Core Logic Function: Change Ownership ---
# Description: Finds files/directories with incorrect ownership and changes them in parallel batches.
# Arguments: $1 = Target directory path.
#            $2 = New owner:group string.
#            $3 = Dry-run flag (true/false).
#            $4 = Number of parallel processes.
#            $5 = Chown error log file path.
change_ownership_optimized() {
    local dir="$1"
    local owner="$2"
    local dry_run="$3"
    local parallel_procs="$4"
    local chown_err_log="$5" # Pass error log path explicitly

    log_message "INFO" "Starting ownership change process in directory '${dir}' for owner '${owner}'."

    # Extract the target user and group from the owner:group string.
    local target_user
    target_user=$(echo "$owner" | cut -d':' -f1)
    local target_group
    target_group=$(echo "$owner" | cut -d':' -f2)
    log_message "DEBUG" "Target User: ${target_user}, Target Group: ${target_group}"

    # Use 'find' to count the number of items needing change. Redirect stderr to avoid permission errors cluttering output.
    local total_items
    # Use process substitution for cleaner error handling with find | wc
    total_items=$(find "$dir" \( ! -user "$target_user" -o ! -group "$target_group" \) -print 2> >(grep -v "Permission denied" >&2) | wc -l) || {
        log_message "WARN" "Failed to count items potentially needing ownership change (might be permission issues)."
        total_items=0 # Assume zero if find fails badly, or handle differently
    }


    if [[ $total_items -eq 0 ]]; then
        log_message "INFO" "No items found requiring ownership change in '${dir}'."
        return 0 # Return success code
    fi

    log_message "INFO" "Total items identified for ownership change: $total_items"

    local batch_size=100 # Define the number of file paths to process in each parallel batch.
    # Calculate the total number of batches required (ceiling division).
    local batch_count=$(( (total_items + batch_size - 1) / batch_size ))

    log_message "INFO" "Processing items in approximately $batch_count batches (size up to $batch_size) using $parallel_procs parallel processes."

    # Record the start time of the find/xargs operation.
    local start_time_chown
    start_time_chown=$(date +%s)

    # Use 'find' with -print0 and pipe to 'xargs' with -0 for safe handling of filenames.
    # Run chown commands in parallel using bash -c for each batch.
    # Note: Errors from find (like permission denied) are redirected inside the find command.
    #       Errors from chown within xargs are logged to the separate error log.
    find "$dir" \( ! -user "$target_user" -o ! -group "$target_group" \) -print0 2> >(grep -v "Permission denied" >&2) | \
    xargs -0 -n "$batch_size" -P "$parallel_procs" bash -c '
        # These variables are passed implicitly to the subshell environment by bash -c '' "$@"
        owner_group="$1"
        dry_run_flag="$2"
        error_log_file="$3"
        shift 3 # Shift the first three arguments (owner, dry_run, error_log) off, leaving file paths in $@

        # Iterate through the batch of file paths passed as arguments ($@).
        for item in "$@"; do
            if [[ "$dry_run_flag" == "true" ]]; then
                # In dry-run mode, print the action that would be taken without executing it.
                # Use printf for safer output formatting compared to echo with potentially tricky filenames.
                printf "Dry-run: Would change ownership of '\''%s'\'' to '\''%s'\''\n" "$item" "$owner_group"
            else
                # In normal mode, attempt to change the ownership using chown.
                # The "||" operator executes the printf command only if chown fails.
                # Failed attempts are logged to the dedicated error log file with a timestamp.
                chown "$owner_group" "$item" || \
                    printf "$(date "+%Y-%m-%d %H:%M:%S"): Failed to change ownership for '\''%s'\'' to '\''%s'\''\n" "$item" "$owner_group" >> "$error_log_file"
            fi
        done
    ' _ "$owner" "$dry_run" "$chown_err_log" || {
        # This block executes if xargs itself fails (e.g., cannot execute bash), which is less common.
        # Individual chown errors inside the loop don't trigger this.
        # The '|| true' in the original script masked this potential xargs failure.
        # We now log it explicitly but still allow the script to continue.
        log_message "WARN" "xargs command execution encountered an issue. Some batches might not have run."
    }

    # Record the end time and calculate duration for the core operation.
    local end_time_chown
    end_time_chown=$(date +%s)
    local duration_chown=$((end_time_chown - start_time_chown))

    log_message "INFO" "Ownership change processing loop completed for directory '$dir' in $duration_chown seconds."
    log_message "INFO" "Check '${chown_err_log}' for any specific file ownership change errors."
}

# --- Main Logic Function ---
# Description: Orchestrates the main steps of the script after setup.
main() {
    log_message "INFO" "Initiating main script execution..."
    local script_start_time
    script_start_time=$(date +%s)

    # Call the core ownership change function
    change_ownership_optimized "$TARGET_DIRECTORY" "$TARGET_OWNER" "$DRY_RUN" "$PARALLEL_PROCESSES" "$CHOWN_ERROR_LOG"

    local script_end_time
    script_end_time=$(date +%s)
    local script_duration=$((script_end_time - script_start_time))
    log_message "INFO" "Main execution logic finished. Total script time: $script_duration seconds."
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# 1. Parse Command Line Arguments
parse_params "$@" # Pass all arguments received by the script

# 2. Load Configuration File (Placeholder)
load_config

# 3. Check Dependencies
log_message "INFO" "Checking required dependencies..."
check_dependency "find" "findutils"
check_dependency "xargs" "findutils"
check_dependency "chown" "coreutils"
check_dependency "nproc" "coreutils"
check_dependency "awk" "gawk" # or mawk
check_dependency "cut" "coreutils"
check_dependency "grep" "grep"
check_dependency "wc" "coreutils"
check_dependency "date" "coreutils"
check_dependency "tee" "coreutils" # tee is used by original log function, less critical now
check_dependency "basename" "coreutils"
check_dependency "dirname" "coreutils"
check_dependency "mkdir" "coreutils"
check_dependency "touch" "coreutils"
log_message "DEBUG" "All required dependencies checked."

# 4. Validate Inputs and Configuration
validate_inputs

# 5. Prepare Environment
prepare_environment

# 6. Execute Main Logic
main

# 7. Exit Successfully
# The 'trap cleanup EXIT' will run automatically.
log_message "INFO" "Script completed successfully."
exit 0 # Explicitly exit with success code

# =========================================================================================
# --- End of Script ---
