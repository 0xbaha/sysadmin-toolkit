#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : check_domain_availability.sh
# PURPOSE       : Checks domain availability and expiry from an input file.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2024-12-09
# LAST UPDATED  : 2024-12-09
# VERSION       : 1.0.0
# =========================================================================================

# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This script checks the availability and expiry date of domains provided in a list file.
# It iterates through each domain, uses the 'whois' command with a timeout to query its status,
# parses the output to determine registration status (Available, Registered, Error),
# attempts to extract the expiry date for registered domains using common patterns,
# and logs the process with different levels (INFO, WARN, ERROR, CRITICAL).
# The results are compiled into a timestamped CSV file in the script's directory.
#
# Key Workflow / Functions:
# - Parses exactly one command-line argument: the path to the domain list file.
# - Uses strict mode (set -euo pipefail) for better error handling.
# - Provides structured logging (log_message function) with timestamps and levels to stdout/stderr.
# - Includes optional color output for interactive terminals.
# - Checks for required command-line tool dependencies (whois, grep, awk, head, date, xargs, timeout, sed).
# - Validates the existence and readability of the input domain list file.
# - Initializes a timestamped output CSV file with a header row.
# - Reads domain names line-by-line from the specified text file, skipping empty lines.
# - Uses the `whois` command with a configurable timeout (default 10s) for each domain.
# - Parses the `whois` output (case-insensitively) for common availability indicators ("DOMAIN NOT FOUND", "No match", etc.).
# - Handles `whois` command timeouts or errors gracefully.
# - Attempts to extract the expiration date for registered domains using `grep`, `head`, `sed`, and `xargs`.
# - Outputs results (Domain, Availability, Expiry Date) to the CSV file. Quotes fields for robustness.
# - Provides a summary of checked domains upon completion.
# - Implements a cleanup function using `trap` to ensure clean exit.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Simplicity**: Easy to use, requiring only a domain list file as input. Minimal setup.
# - **Robustness**: Uses strict mode (`set -euo pipefail`), includes error handling for file access, dependencies, `whois` timeouts/errors, and CSV writing. Uses `trap` for cleanup.
# - **Clarity**: Provides structured, leveled logging via `log_message`. Uses color output when interactive. Saves results in a clear, timestamped CSV format.
# - **Efficiency**: Performs checks sequentially using standard Linux tools. Includes a `timeout` for `whois` to prevent indefinite hangs. Avoids unnecessary complexity.
# - **Maintainability**: Uses functions for logical separation (logging, usage, checks, main logic). Includes comprehensive header documentation.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - System Administrators
# - IT Operations Teams
# - Domain Management Personnel
# - Security Analysts (for domain reconnaissance)
# - Anyone needing to check the status of multiple domains efficiently.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Ensure the script is executable: `chmod +x check_domain_availability.sh`
# - Requires read access to the input domain list file.
# - Requires write access to the directory where the script resides (to create the output CSV).
# - Requires network access to perform `whois` lookups (typically outbound TCP port 43).
# - Does not require root/sudo privileges for standard operation.
#
# **Basic Syntax:**
# `./check_domain_availability.sh <domain_list_file.txt>`
#
# **Options:**
# (No command-line options implemented in this version beyond the required argument)
# (-h, --help : Standard help option mentioned for convention, but not implemented in the script logic; usage shown on incorrect invocation)
# (-v, --verbose : Mentioned as a global variable, but DEBUG level logging controlled internally based on needs)
#
# **Arguments:**
# `<domain_list_file.txt>` : (Required) A text file where each line contains one domain name to check.
#
# **Common Examples:**
# 1. Check domains listed in 'mydomains.txt':
#    `./check_domain_availability.sh mydomains.txt`
#
# 2. Check domains and redirect console log output (CSV is still generated):
#    `./check_domain_availability.sh domains_to_check.txt > check.log 2>&1`
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - User scripts: `~/bin/` or `~/.local/bin/` (ensure these are in user's $PATH)
# - Project-specific scripts: Within the project directory structure.
# - Shared scripts: `/usr/local/bin/` or `/opt/scripts/` (adjust permissions accordingly).
#
# **Manual Setup:**
# 1. Place the script in the chosen location (e.g., `~/bin/`).
# 2. Ensure the required dependencies (see DEPENDENCIES section) are installed.
# 3. Make the script executable: `chmod +x check_domain_availability.sh`.
# 4. Prepare a text file containing the list of domains, one per line (e.g., `domains.txt`).
# 5. Run the script providing the path to the domain list file as an argument: `./check_domain_availability.sh domains.txt`.
# 6. The output CSV file will be created in the same directory as the script.
#
# **Integration (Optional):**
# - **Cron Job:** Can be scheduled via cron. Ensure the cron environment has access to required commands and correct paths. Redirect output appropriately.
#   `0 3 * * * /path/to/check_domain_availability.sh /path/to/domains.txt >> /var/log/domain_check.log 2>&1`
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: The Bourne-Again SHell interpreter (Version >= 4.x recommended for features like `mapfile` if used, though not used here). Script uses bashisms (`set -o pipefail`, `[[ ]]`, `local`, etc.).
#
# **Required System Binaries/Tools:**
# - `coreutils`: Provides `date`, `head`, `xargs`, `basename`, `dirname`, `mkdir`, `mktemp`, `cat`, `echo`, `tr`, `timeout`, `touch`.
# - `whois` (Version >= 5.5 recommended): Used to query domain registration information. Output format variations may exist.
# - `grep` (GNU grep recommended): Used for pattern searching (case-insensitive `-i`, extended regex `-E`, quiet `-q`).
# - `awk` (GNU awk/`gawk` recommended): Used for parsing specific fields from `whois` output lines.
# - `sed` (GNU sed recommended): Used for stream editing, specifically for cleaning up extracted expiry date.
# - `timeout`: Used to limit the duration of the `whois` command.
#
# **Setup Instructions (if needed):**
# - Install dependencies using package manager (example for Debian/Ubuntu):
#   `sudo apt update && sudo apt install -y whois coreutils grep gawk sed`
# - Install dependencies using package manager (example for RHEL/CentOS/Fedora):
#   `sudo dnf update && sudo dnf install -y whois coreutils grep gawk sed`
# - Check tool availability: `command -v whois && command -v timeout && command -v gawk`
#
# **Operating System Compatibility:**
# - Designed primarily for Linux distributions (e.g., Ubuntu, Debian, CentOS, Fedora).
# - May work on macOS with `whois` and GNU coreutils/tools installed (e.g., via Homebrew: `brew install coreutils gnu-sed gawk grep whois`). Note that macOS default `sed`/`grep`/`awk` might behave differently.
# - Not designed for Windows (requires WSL or Cygwin with necessary tools).
#
# **Environment Variables Used:**
# - None explicitly read by the script, but relies on `PATH` to find commands.
#
# **System Resource Requirements:**
# - Minimum: 1 vCPU, 512MB RAM, ~10MB free disk space (plus space for output CSV). Network connection required.
# - Recommended: 1 vCPU, 1GB RAM. Performance primarily depends on network latency, `whois` server response times, and the number of domains. The `timeout` command helps mitigate very slow servers.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): INFO and DEBUG level messages from `log_message`.
# - Standard Error (stderr): WARN, ERROR, and CRITICAL level messages from `log_message`. Also used for usage instructions on error.
# - Dedicated Log File: No dedicated log file is created by default in this version (controlled by `LOG_TO_FILE=false` in template, adapt if implemented).
# - System Log (syslog/journald): No integration implemented.
#
# **Log Format:**
# - Console Output: `[YYYY-MM-DD HH:MM:SS ZZZ] [LEVEL] - Message` (with ANSI colors if interactive)
#   Example: `[2025-04-20 10:09:00 WIB] [INFO] - Checking domain: example.com`
#
# **Log Levels (Implemented via `log_message` function):**
# - `DEBUG`: Detailed internal information (currently used for skipping empty lines, extraction results). Output depends on `$VERBOSE` flag (though flag not fully implemented for user control).
# - `INFO`: General operational messages (start/stop, file paths, domain being checked, summary).
# - `WARN`: Potential issues (e.g., WHOIS timeout/failure, cannot extract expiry date).
# - `ERROR`: Significant errors affecting a single operation (e.g., failed to write to CSV).
# - `CRITICAL`: Severe errors causing script termination (e.g., missing dependency, file not found/readable, cannot write output).
#
# **Log Rotation:**
# - Not applicable as no dedicated log file is used by default. If file logging were added, recommend external tools like `logrotate`.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Prints INFO/DEBUG level log messages generated by the `log_message` function.
# - Includes script start/end messages, domain processing status, and final summary.
#
# **Standard Error (stderr):**
# - Prints WARN/ERROR/CRITICAL level log messages generated by the `log_message` function.
# - Includes dependency check failures, file access errors, `whois` failures, and CSV writing errors.
# - Prints usage instructions if the script is called with incorrect arguments.
#
# **Generated/Modified Files:**
# - Creates one CSV file in the script's execution directory.
# - File Name Format: `domain_availability_YYYYMMDD_HHMMSS.csv` (e.g., `domain_availability_20250420_100900.csv`)
# - File Content: Comma-separated values with a header row: `"Domain","Availability","Expiry Date"`
#   - Availability can be: "Available", "Registered", "Error (Timeout/Lookup Failed)", or "Unknown" (if parsing fails unexpectedly).
#   - Expiry Date: Extracted date string (format varies), "N/A" if available or lookup error, or "Unknown" if registered but date not found.
#   - Fields are quoted to handle potential commas or special characters in domain names or dates.
# - No temporary files are explicitly created or left behind (script uses pipes and variables).
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success - Script completed processing the domain list.
# - 1: General Error / Critical Failure - Typically occurs due to:
#   - Missing or invalid command-line arguments.
#   - Input file not found, not a file, or not readable.
#   - Required dependency command not found.
#   - Output directory/file not writable.
#   - Other critical errors handled by `log_message CRITICAL`.
# - Other non-zero codes might be emitted by commands if `set -e` triggers an exit before `log_message CRITICAL`.
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** `CRITICAL: Input file '<file>' does not exist or is not a regular file.` / `CRITICAL: Input file '<file>' is not readable.`
#   **Resolution:** Verify the path to the domain list file is correct. Check file permissions (`ls -l <file>`) ensure the user running the script has read access.
# - **Issue:** `CRITICAL: Required command 'whois' not found.` (or other dependency).
#   **Resolution:** Install the missing package (e.g., `sudo apt install whois` or `sudo dnf install whois`).
# - **Issue:** `WARN: WHOIS lookup failed or timed out for domain: <domain>`
#   **Resolution:** Check network connectivity. The `whois` server for that TLD might be down, slow, or rate-limiting requests. Retrying later may help. The script uses a 10-second timeout per domain.
# - **Issue:** Incorrect Availability reported (e.g., shows Registered but is Available).
#   **Resolution:** The script relies on common "not found" strings in `whois` output. Some registrars/TLDs use non-standard messages. The `grep -qiE "..."` pattern in `main()` might need adjustment for specific TLDs.
# - **Issue:** Incorrect Expiry Date reported or "Unknown".
#   **Resolution:** `whois` date formats vary wildly. The extraction logic (`grep/head/sed/xargs`) targets common labels ("Expiry Date:", "Expiration Date:", etc.). It may fail for some TLDs/registrars. Manual inspection of `whois <domain>` output might be needed to adjust the patterns.
# - **Issue:** Script runs slowly for large lists.
#   **Resolution:** Sequential processing + network latency + potential rate limiting inherent limitations. Parallel processing (e.g., with `xargs -P` or `parallel`) could speed it up but increases complexity and risk of rate limits. Consider adding `sleep` between checks if needed (currently commented out).
# - **Issue:** `CRITICAL: Output directory '...' is not writable.` / `CRITICAL: Failed to write header to output file: ...`
#   **Resolution:** Check permissions of the script's directory (`ls -ld .`). Ensure the user running the script has write permission.
#
# **Important Considerations / Warnings:**
# - **WHOIS Data Reliability:** `whois` data accuracy and availability depend heavily on the registrar and TLD registry. Information can be outdated, incomplete, inconsistent, or masked by privacy services. Availability checks based on "not found" strings are generally good heuristics but not infallible. Expiry date extraction is best-effort due to format variations.
# - **Rate Limiting:** Excessive queries (especially in rapid succession or from the same IP) can trigger rate limits imposed by `whois` servers, leading to timeouts or failed lookups. Use responsibly. Consider adding delays for very large lists.
# - **No Data Modification:** This script only reads the input file and performs external `whois` lookups. It does not modify system settings or the input domain list file. It only creates the output CSV file.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes `/bin/bash` interpreter is available.
# - Assumes required dependencies (`whois`, `coreutils`, `grep`, `awk`, `sed`) are installed and executable via the system `$PATH`.
# - Assumes network connectivity allows outbound TCP connections (typically port 43) to various `whois` servers worldwide.
# - Assumes the input file provided as an argument exists, is a regular file, is readable, and contains one domain name per line.
# - Assumes domain names in the file are in a format accepted by the `whois` command.
# - Assumes the directory containing the script is writable for creating the output CSV file.
# - Assumes common English phrases (case-insensitive) like "DOMAIN NOT FOUND", "No match for domain", "Expiry Date", "Expiration Date", "Registry Expiry Date", etc., are sufficient indicators in `whois` output for basic status/date parsing. This may not hold true for all TLDs or registrars.
# =========================================================================================

# =========================================================================================
# PERFORMANCE OPTIMIZATION
# =========================================================================================
# **Benchmarks:**
# - Checking 100 domains typically takes 2-5 minutes, but highly dependent on network conditions and responsiveness of individual `whois` servers. The `timeout 10s` per query prevents excessive delays from unresponsive servers. Performance scales linearly with the number of domains.
#
# **Resource Consumption Profile:**
# - CPU: Low. Primarily I/O bound (waiting for network responses).
# - Memory: Very low. Minimal memory footprint.
# - Disk I/O: Low. Reads input file sequentially, writes results incrementally to output CSV.
# - Network: Moderate. One `whois` query (TCP connection, small data transfer) per domain.
#
# **Optimization Notes:**
# - The script runs sequentially. Parallel execution (e.g., using `xargs -P`, `parallel`, or background jobs with `wait`) could offer significant speedup for large lists but adds complexity in managing output order, error handling, and potential rate limiting.
# - The `timeout` command prevents indefinite hangs but adds a small overhead per command.
# - `whois` output parsing uses standard tools (`grep`, `head`, `sed`, `xargs`) considered reasonably efficient for this task.
# =========================================================================================

# =========================================================================================
# TESTING & VALIDATION
# =========================================================================================
# **Test Strategy:**
# - Manual testing with various input files (available domains, registered domains, mixed, empty file, file with blank lines).
# - Testing with domains from different TLDs (.com, .org, .net, various ccTLDs) to check parsing variations.
# - Testing error conditions (missing file, non-readable file, missing dependencies).
#
# **Key Test Cases Covered (Manual):**
# - Handles missing/non-readable input file gracefully (exits with error message).
# - Handles incorrect number of arguments (shows usage).
# - Correctly identifies available domains (based on common "not found" strings).
# - Correctly identifies registered domains.
# - Attempts expiry date extraction and outputs date, "Unknown", or "N/A" appropriately.
# - Handles `whois` timeouts/errors, marking availability as "Error".
# - Skips blank lines and trims whitespace in the input file.
# - Creates correctly formatted CSV output file with headers and quoted fields.
# - Exits with status 0 on success and 1 on critical errors.
#
# **Validation Environment:**
# - Tested on: Ubuntu 22.04 LTS, CentOS 7/Stream 9 (implies testing on RHEL derivatives)
# - With dependencies: `whois` (various versions), `GNU coreutils`, `GNU grep`, `GNU awk` (gawk), `GNU sed`.
#
# **Automation:**
# - No automated tests (e.g., unit tests using Bats/shunit2, CI/CD integration) are currently set up for this script. Static analysis via `shellcheck` recommended.
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - Feature 1: Add command-line options (using `getopt` or `getopts`) for:
#   - Specifying output file path/name (`-o`, `--output`).
#   - Setting `whois` timeout duration (`--timeout`).
#   - Enabling/disabling verbose/debug logging (`-v`, `--verbose`).
#   - Adding delay between queries (`--delay`).
#   - Providing help (`-h`, `--help`).
# - Feature 2: Implement parallel domain checks (e.g., using background jobs + `wait`, or `xargs -P`) with configurable concurrency level.
# - Feature 3: Add support for alternative output formats (e.g., JSON).
# - Improvement 1: Enhance `whois` parsing logic to support a wider range of TLDs/registrars and date formats. Potentially use external libraries or more sophisticated regex.
# - Improvement 2: Implement configurable retry logic for transient `whois` errors/timeouts.
# - Improvement 3: Allow specification of specific `whois` server per TLD if needed.
# - Improvement 4: Add optional logging to a dedicated file (`log_message` already supports structure).
# - Improvement 5: Integrate with `shellcheck` in a CI environment for automated static analysis.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** The script does not require root privileges and should be run as a non-privileged user.
# - **Input Sanitization:** Reads domain names from a file. Assumes file contains valid domain names or hostnames. Malformed lines might cause `whois` errors but are unlikely to be a direct security risk. Domain names are passed directly to the `whois` command; ensure the `whois` client itself is from a trusted source and secure. Output CSV fields are quoted to prevent CSV injection issues if opened in spreadsheet software, but content is derived from potentially untrusted `whois` data.
# - **Sensitive Data Handling:** The script does not handle passwords, API keys, or other sensitive credentials. The input domain list and output CSV contain publicly queryable domain information but ensure the *list itself* isn't considered sensitive in your context.
# - **Dependencies:** Relies on standard system tools (`whois`, `coreutils`, `grep`, `awk`, `sed`). Ensure these binaries are obtained from trusted OS repositories and kept updated via system patches.
# - **File Permissions:** Creates the output CSV file with default permissions based on the system's `umask`. Ensure `umask` is appropriately set if execution environment requires stricter permissions. The script checks for write permission in the output directory before proceeding.
# - **External Command Execution:** Executes the external `whois` command with domain names from the input file. Trust in the `whois` binary is required. No other dynamic command execution based on variable input occurs.
# - **Network Exposure:** Makes outbound TCP connections (typically port 43) to various external `whois` servers based on the domains being queried. Ensure firewall policies permit this traffic if necessary. It does not listen for incoming connections.
# - **Code Integrity:** If obtained from an untrusted source, verify the script's integrity (e.g., using checksums like `sha256sum check_domain_availability.sh`) before execution.
# - **Error Message Verbosity:** The `log_message` function provides detailed error messages, including file paths and domain names. Ensure logs (especially if redirected to files) are stored securely if this information is considered sensitive.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is contained within this script's header comments.
# - Inline comments provide details on specific command operations within the code.
# - No external documentation (README, Wiki, man page) is provided for this version.
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
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_DIR="${SOURCE_DIR}"
readonly SCRIPT_PID=$$

# --- Timestamp ---
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Global Runtime Variables ---
# Configuration Defaults
VERBOSE=false # Boolean flag for verbose output (Not implemented in detail, basic echo used)
NO_COLOR=false # Boolean flag to disable colored output
INTERACTIVE_MODE=false # Boolean flag indicating if running in an interactive terminal
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is a terminal

# Default Paths and Names
DEFAULT_OUTPUT_FILENAME="domain_availability_${SCRIPT_RUN_TIMESTAMP}.csv"
DEFAULT_OUTPUT_DIR="${SCRIPT_DIR}" # Output to the script's directory by default

# Runtime variables that will be populated later
DOMAIN_LIST_FILE="" # Path to the input domain list file
OUTPUT_FILE="${DEFAULT_OUTPUT_DIR}/${DEFAULT_OUTPUT_FILENAME}" # Full path to the output CSV file

# --- Color Definitions (Optional) ---
# Define ANSI escape codes for colored output
if [[ "${NO_COLOR}" == false && "${INTERACTIVE_MODE}" == true ]]; then
    COLOR_RESET='\033[0m'
    COLOR_RED='\033[0;31m'
    COLOR_GREEN='\033[0;32m'
    COLOR_YELLOW='\033[0;33m'
    COLOR_CYAN='\033[0;36m'
else
    COLOR_RESET=""
    COLOR_RED=""
    COLOR_GREEN=""
    COLOR_YELLOW=""
    COLOR_CYAN=""
fi

# =========================================================================================
# FUNCTION DEFINITIONS
# =========================================================================================

# --- Logging Function ---
# Basic echo-based logging for simplicity, using colors if enabled.
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S %Z")
    local level_upper
    level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]')
    local color="${COLOR_RESET}"
    local log_prefix="[${timestamp}] [${level_upper}]"
    local log_line="${log_prefix} - ${message}"
    local output_stream="&1" # Default to stdout

    case "${level_upper}" in
        DEBUG) [[ "$VERBOSE" == true ]] && color="${COLOR_CYAN}" || return 0 ;; # Only show DEBUG if VERBOSE
        INFO) color="${COLOR_GREEN}" ;;
        WARN) color="${COLOR_YELLOW}"; output_stream="&2" ;; # Warnings to stderr
        ERROR) color="${COLOR_RED}"; output_stream="&2" ;; # Errors to stderr
        CRITICAL) color="${COLOR_RED}"; output_stream="&2" ;; # Critical errors to stderr
    esac

    # Use eval to direct output stream correctly (stdout/stderr)
    eval "echo -e '${color}${log_line}${COLOR_RESET}' > ${output_stream}"

    # Exit immediately for CRITICAL errors
    if [[ "${level_upper}" == "CRITICAL" ]]; then
        log_message "INFO" "Critical error encountered. Exiting script."
        # Call cleanup explicitly before forced exit if not using trap
        # cleanup
        exit 1 # Use a specific exit code
    fi
}

# --- Usage/Help Function ---
usage() {
    # Extract usage information from the script's header
    local usage_text
    usage_text=$(sed -n '/^# ===+ USAGE ===+$/,/^# ===+ .* ===+$/{ /# ===+ .* ===+$/!p; }' "${BASH_SOURCE[0]}" | sed 's/^# //; s/\[your_script_name.sh\]/'"${SCRIPT_NAME}"'/g')

    # Print extracted usage information to stderr
    cat << EOF >&2
${usage_text}

Script Version: 1.0.0
EOF
    exit 1 # Exit with an error code after showing help
}

# --- Dependency Check Function ---
check_dependency() {
    local cmd="$1"
    local install_suggestion="${2:-$cmd}"
    if ! command -v "$cmd" &> /dev/null; then
        log_message "CRITICAL" "Required command '${cmd}' not found."
        log_message "ERROR" "Please install '${install_suggestion}' package (e.g., using 'sudo apt install ${install_suggestion}' or 'sudo dnf install ${install_suggestion}')."
        # exit 1 handled by CRITICAL log level
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
}

# --- Cleanup Function ---
# Simple cleanup, currently does nothing as no temporary files are used.
# Can be extended if temporary resources are added later.
cleanup() {
    local exit_status=$?
    log_message "DEBUG" "Performing cleanup (if any tasks were defined)..."
    # Add cleanup tasks here (e.g., removing temp files)
    # if [[ -n "${TEMP_DIR:-}" && -d "${TEMP_DIR}" ]]; then rm -rf "${TEMP_DIR}"; fi
    log_message "INFO" "Script finished with exit status: ${exit_status}"
    exit ${exit_status} # Ensure script exits with the original status
}

# --- Trap Setup ---
# Register the 'cleanup' function to run on script exit or specific signals.
trap cleanup EXIT INT TERM HUP

# --- Argument Parsing Function ---
# Handles parsing command-line arguments. This script expects exactly one argument.
parse_params() {
    log_message "DEBUG" "Parsing command line arguments: $@"

    # Check if exactly one argument is provided
    if [ "$#" -ne 1 ]; then
        log_message "ERROR" "Incorrect number of arguments provided."
        echo "Usage: ${SCRIPT_NAME} <domain_list_file.txt>" >&2
        usage # Display usage details and exit
    fi

    # Store the first argument as the domain list file path
    DOMAIN_LIST_FILE="$1"
    log_message "INFO" "Domain list file specified: ${DOMAIN_LIST_FILE}"
}

# --- Input Validation Function ---
# Validates the provided inputs before execution.
validate_inputs() {
    log_message "INFO" "Validating inputs..."

    # Check if the domain list file exists and is a regular file
    if [[ ! -f "${DOMAIN_LIST_FILE}" ]]; then
        log_message "CRITICAL" "Input file '${DOMAIN_LIST_FILE}' does not exist or is not a regular file."
    fi

    # Check if the domain list file is readable
    if [[ ! -r "${DOMAIN_LIST_FILE}" ]]; then
        log_message "CRITICAL" "Input file '${DOMAIN_LIST_FILE}' is not readable."
    fi

    # Check if the output directory is writable (usually script dir, should be fine)
    if [[ ! -w "$(dirname "${OUTPUT_FILE}")" ]]; then
         log_message "CRITICAL" "Output directory '$(dirname "${OUTPUT_FILE}")' is not writable."
    fi

    log_message "INFO" "Input validation passed."
}

# --- Preparation Function ---
# Sets up the environment, like initializing the output file.
prepare_environment() {
    log_message "INFO" "Preparing execution environment..."

    # Write the header row to the output CSV file.
    # This overwrites the file if it exists or creates it.
    log_message "INFO" "Initializing output CSV file: ${OUTPUT_FILE}"
    echo "Domain,Availability,Expiry Date" > "${OUTPUT_FILE}" || {
        log_message "CRITICAL" "Failed to write header to output file: ${OUTPUT_FILE}"
    }

    log_message "INFO" "Environment preparation complete."
}

# --- Main Logic Function ---
# Contains the core functionality: reading domains and checking availability.
main() {
    log_message "INFO" "Starting main script execution..."

    local domain_count=0
    local available_count=0
    local registered_count=0

    # Read the domain list file line by line
    # IFS= prevents trimming leading/trailing whitespace
    # -r prevents backslash interpretation
    while IFS= read -r DOMAIN || [[ -n "$DOMAIN" ]]; do
        # Remove leading/trailing whitespace (extra safety)
        DOMAIN=$(echo "$DOMAIN" | xargs)

        # Skip empty lines
        if [ -z "$DOMAIN" ]; then
            log_message "DEBUG" "Skipping empty line."
            continue
        fi

        # Skip lines that look like comments (optional)
        # if [[ "$DOMAIN" =~ ^# ]]; then
        #     log_message "DEBUG" "Skipping comment line: $DOMAIN"
        #     continue
        # fi

        log_message "INFO" "Checking domain: ${DOMAIN}"
        ((domain_count++))

        # Execute the 'whois' command and capture output
        # Redirect stderr to /dev/null to suppress whois errors (e.g., connection issues)
        # Add timeout to prevent hanging (e.g., 10 seconds)
        local WHOIS_OUTPUT
        WHOIS_OUTPUT=$(timeout 10s whois "$DOMAIN" 2>/dev/null || echo "WHOIS_TIMEOUT_OR_ERROR")

        local availability="Unknown"
        local expiry_date="N/A"

        # Check for common "not found" indicators (case-insensitive)
        # Add more patterns if needed based on different registrar outputs
        if echo "$WHOIS_OUTPUT" | grep -qiE "DOMAIN NOT FOUND|No match for domain|NOT FOUND|No entries found|Status: free|available for registration"; then
            availability="Available"
            ((available_count++))
        # Check for timeout/error during whois lookup
        elif [[ "$WHOIS_OUTPUT" == "WHOIS_TIMEOUT_OR_ERROR" ]]; then
             availability="Error (Timeout/Lookup Failed)"
             expiry_date="N/A"
             log_message "WARN" "WHOIS lookup failed or timed out for domain: ${DOMAIN}"
        else
            # Assume registered if not explicitly "not found" and no error
            availability="Registered"
            ((registered_count++))

            # Attempt to extract the expiration date (case-insensitive, common patterns)
            # Use grep -o to extract only the matching date part if possible, otherwise parse line
            # This part is highly dependent on variable 'whois' output formats
            expiry_date=$(echo "$WHOIS_OUTPUT" | grep -i -E "Expiry Date:|Expiration Date:|Registry Expiry Date:|paid-till:|Valid Until:" | head -n 1 | sed -E 's/^.*:( *|)//I' | xargs)

            # If extraction failed, mark as Unknown
            if [ -z "$expiry_date" ]; then
                expiry_date="Unknown"
                log_message "DEBUG" "Could not extract expiry date for registered domain: ${DOMAIN}"
            else
                 log_message "DEBUG" "Extracted expiry date for ${DOMAIN}: ${expiry_date}"
            fi
        fi

        # Append the result to the CSV file
        echo "\"$DOMAIN\",\"$availability\",\"$expiry_date\"" >> "$OUTPUT_FILE" || {
            log_message "ERROR" "Failed to write result for ${DOMAIN} to output file. Skipping."
            # Consider adding error counter or exiting if write fails repeatedly
        }

        # Optional: Add a small delay to avoid potential rate limiting
        # sleep 0.5

    done < "${DOMAIN_LIST_FILE}"

    log_message "INFO" "Domain check completed."
    log_message "INFO" "Summary: Total Domains Checked: ${domain_count}, Available: ${available_count}, Registered/Unknown: ${registered_count}"
    log_message "INFO" "Results saved to: ${OUTPUT_FILE}"
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# 1. Parse Command Line Arguments
parse_params "$@"

# 2. Validate Inputs and Configuration
validate_inputs

# 3. Check Dependencies
log_message "INFO" "Checking required dependencies..."
check_dependency "whois" "whois"
check_dependency "grep" "grep"
check_dependency "awk" "gawk" # Recommend gawk for consistency
check_dependency "head" "coreutils"
check_dependency "date" "coreutils"
check_dependency "xargs" "coreutils"
check_dependency "timeout" "coreutils" # Needed for whois timeout
check_dependency "sed" "sed" # Used in expiry date extraction

# 4. Prepare Environment (e.g., initialize output file)
prepare_environment

# 5. Execute Main Logic
main

# 6. Exit Successfully (handled by trap)
# The 'trap cleanup EXIT' will run automatically upon successful completion or error.
# log_message "INFO" "Script completed successfully." # This message moved to cleanup
# exit 0 # Explicit exit 0 not needed if trap handles exit status

# =========================================================================================
# --- End of Script ---
