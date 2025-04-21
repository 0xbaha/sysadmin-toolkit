#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : obfuscate.sh
# PURPOSE       : Obfuscates bash scripts via base64, randomization, and noise.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2024-09-30
# LAST UPDATED  : 2024-09-30
# VERSION       : 1.0.0
# =========================================================================================

# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This script takes an input bash script and obfuscates it. The obfuscation process involves:
# 1. Reading the content of the input script.
# 2. Generating random names for internal functions and variables used by the obfuscated script.
# 3. Generating random noise data (a base64 string).
# 4. Base64 encoding the entire original script content into a single string.
# 5. Creating a new bash script (the loader) that includes:
#    - A decoy/noise function using the generated noise data.
#    - A main execution function with a randomized name.
#    - This main function stores the base64 encoded original script in a variable with a randomized name.
#    - The main function decodes the base64 string and pipes the result directly into 'bash' for execution.
# 6. Outputting two versions of the resulting obfuscated script:
#    - One includes comments explaining the loader's structure (_with_comments.sh).
#    - The other strips all comments and blank lines for maximum obfuscation (_without_comments.sh).
#
# The goal is to make the script's logic less obvious upon casual inspection, not to provide
# unbreakable security. It serves as a basic deterrent against simple analysis.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Obfuscation Layer**: Add a layer of indirection by encoding the original script and using randomized names.
# - **Functionality Preservation**: Ensure the obfuscated script behaves exactly like the original input script.
# - **Dependency Management**: Automatically check and attempt to install required tools (openssl, coreutils).
# - **User Clarity**: Provide clear usage instructions, output file descriptions, and error handling information.
# - **Dual Output**: Offer both a commented version (for understanding the technique) and a non-commented version (for deployment).
# - **Simplicity**: Keep the obfuscation technique straightforward (base64 encoding) for easy understanding and modification if needed.
# - **Robustness**: Includes error handling for missing arguments, files, and dependencies. Uses Bash strict mode (`set -euo pipefail`).
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - Developers needing a simple way to make shell scripts less immediately readable.
# - System Administrators distributing scripts who want to deter casual modification or analysis.
# - Security Enthusiasts exploring basic obfuscation techniques.
# - Students learning about shell scripting and basic security concepts.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x obfuscate.sh`
# - Elevated privileges: Requires `sudo` privileges ONLY if dependencies (`openssl`, `coreutils`) need to be installed automatically.
# - File system access: Requires write permissions in the current directory (or specified output directory) to create the output files. Read access to the input script file.
#
# **Basic Syntax:**
#   ./obfuscate.sh <input_script.sh> <output_base_name>
#
# **Arguments:**
#   <input_script.sh>  : The path to the bash script you want to obfuscate. This file must exist and be readable.
#   <output_base_name> : The base name for the generated output files (e.g., 'my_app'). Do not include extensions like '.sh'.
#
# **Options:**
#   This script does not currently accept command-line options (like -h, --verbose, etc.).
#
# **Common Examples:**
# 1. Basic execution:
#    `./obfuscate.sh my_original_script.sh my_obfuscated_app`
#    (Reads `my_original_script.sh`, outputs `my_obfuscated_app_with_comments.sh` and `my_obfuscated_app_without_comments.sh` in the current directory)
#
# **Advanced Execution (Automation):**
# - This script is primarily intended for manual execution during development or deployment preparation.
# - It's not typically run unattended via cron or systemd, but could be integrated into a build pipeline.
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - Place the `obfuscate.sh` script in a development toolkit directory or a directory included in your system's PATH (e.g., `/usr/local/bin/`, `~/bin/`) for easy access.
#
# **Manual Setup:**
# 1. Place the script in the chosen location.
# 2. Set executable permissions: `chmod +x obfuscate.sh`.
# 3. Ensure dependencies are installed (see DEPENDENCIES section - automatic check included).
#
# **Integration:**
# - This script is intended for manual execution when obfuscation is needed.
# - Ensure the output directory (current directory by default) is writable by the user running the script.
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: The Bourne-Again SHell interpreter (Version >= 4 recommended due to usage of `command -v`, associative arrays in logging template, etc.).
#
# **Required System Binaries/Tools:**
# - `openssl`: Used for generating random data (for randomized names and noise).
# - `base64`: Used for encoding the original script content (Usually part of `coreutils`).
# - `coreutils`: Provides `cat`, `echo`, `tr`, `chmod`, `basename`, `dirname`, `date`, `mkdir`, `rm`.
# - `grep`: For removing comments/blank lines in the non-commented output version.
# - `sed`: Used in logging function, usage extraction.
# - `command`: Bash built-in for checking command existence.
# - `sudo`: Required only if automatic dependency installation is needed.
#
# **Automatic Setup Instructions:**
# - The script includes a function (`install_requirements`) that checks for `openssl` and `base64`.
# - If missing, it attempts to install `openssl` and `coreutils` using `apt` (Debian/Ubuntu), `yum` (CentOS/RHEL <8), or `dnf` (Fedora/RHEL >=8).
# - This automatic installation requires `sudo` privileges.
#
# **Manual Setup (if automatic fails or sudo is not available/desired):**
#   - Debian/Ubuntu: `sudo apt update && sudo apt install -y openssl coreutils`
#   - CentOS/RHEL (<8): `sudo yum install -y openssl coreutils`
#   - Fedora/RHEL (>=8): `sudo dnf install -y openssl coreutils`
#   - Other OS: Install `openssl` and `coreutils` (or equivalent providing `base64`) using your package manager.
#
# **Operating System Compatibility:**
# - Designed primarily for Linux distributions using common package managers (apt, yum, dnf).
# - May work on macOS or other Unix-like systems if dependencies are installed manually, but package manager detection might fail.
#
# **Environment Variables Used:**
# - The script does not require any specific environment variables to be set for its own operation.
# - Standard `PATH` variable is used to locate commands.
# - Note: The *generated* obfuscated script will inherit and use the environment variables present when *it* is executed, just like the original script would.
#
# **System Resource Requirements:**
# - Minimal: Low CPU and memory usage. Requires enough disk space for the two output scripts (size depends on the original script size plus minor overhead).
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): Used for informational messages (`INFO`), success messages, and final output file names. Debug messages (`DEBUG`) if enabled (not currently via flag).
# - Standard Error (stderr): Used for warning (`WARN`) and error (`ERROR`, `CRITICAL`) messages. Also used for usage/help output.
# - Dedicated Log File: No dedicated log file is generated by default. Logging to file can be added by modifying the `log_message` function and related variables if desired.
#
# **Log Format:**
# - Uses a structured format: `[YYYY-MM-DD HH:MM:SS TZ] [LEVEL] - Message`
# - Example: `[2024-10-27 14:30:00 UTC] [INFO] - Starting obfuscation process...`
# - Colors are used for levels on interactive terminals (stdout/stderr).
#
# **Log Levels (Implemented):**
# - `DEBUG`: Detailed info (used internally, not currently user-controllable via flag).
# - `INFO`: General operational messages.
# - `WARN`: Potential issues or non-critical failures.
# - `ERROR`: Significant errors, causing script exit (via `log_message` function).
# - `CRITICAL`: Severe errors (typically reserved for future use, currently treated like ERROR).
# - Control: Log level filtering based on severity (currently hardcoded to show INFO and above, DEBUG if VERBOSE, but VERBOSE flag isn't implemented).
#
# **Log Rotation:**
# - Not applicable as no dedicated log file is generated by default. If file logging is added, rotation would need to be handled externally (e.g., `logrotate`).
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - Prints `INFO` level status messages during execution (dependency checks, steps).
# - Prints the final success message listing the names of the generated output files.
#
# **Standard Error (stderr):**
# - Prints `WARN` and `ERROR`/`CRITICAL` messages.
# - Prints usage instructions if arguments are incorrect (`usage` function).
#
# **Generated/Modified Files:**
# 1. `<output_base_name>_with_comments.sh`:
#    - An executable bash script (`chmod +x`) containing the obfuscated loader logic.
#    - Includes comments within the loader explaining its structure (how it decodes/executes the original script).
#    - Useful for understanding the obfuscation mechanism or for debugging the loader itself.
# 2. `<output_base_name>_without_comments.sh`:
#    - An executable bash script (`chmod +x`) containing the same obfuscated loader logic as the "with_comments" version.
#    - All comments and blank lines are removed from the loader script to make it more compact and slightly harder to read.
#    - This is the version typically intended for distribution if reduced readability is desired.
#
# **Example Output Files (from `./obfuscate.sh script.sh obfuscated_script`):**
# - `obfuscated_script_with_comments.sh` (executable)
# - `obfuscated_script_without_comments.sh` (executable)
# Both files are created in the current working directory.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Script execution completed successfully.
# - 1: General Error / Failure. Triggered by `ERROR` or `CRITICAL` log messages. Common causes include:
#   - Incorrect number of command-line arguments provided (via `usage`).
#   - Input script file specified does not exist or is not readable.
#   - Required dependencies (`openssl`, `base64`) are missing and could not be installed automatically (e.g., permission issues via `sudo`, unsupported package manager).
#   - Failure during core operations (reading input, encoding, writing output, openssl random generation).
#   - Failure within the generated script's execution logic (if the generated script returns non-zero).
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** "Usage Information:" displayed with argument errors.
#   **Resolution:** Provide exactly two arguments: the path to the script to obfuscate and a base name for the output files. Check the `Usage Information` section for syntax.
# - **Issue:** "ERROR - Input file '...' not found or not readable."
#   **Resolution:** Verify the path to the input script is correct and the file exists with read permissions for the user running `obfuscate.sh`.
# - **Issue:** "ERROR - No supported package manager (apt, yum, dnf) found." or "ERROR - Failed to install ..."
#   **Resolution:** The script couldn't detect a known package manager or failed during `sudo apt/yum/dnf install`. Install `openssl` and `coreutils` manually using your system's package manager. Check `sudo` permissions.
# - **Issue:** "ERROR - openssl command failed..." or "ERROR - Failed to encode script..."
#   **Resolution:** Ensure `openssl` and `base64` are correctly installed and functioning. Check for unusual characters or encoding issues in the input script (though base64 should handle most text).
# - **Issue:** Obfuscated script (`*.sh`) fails with errors originating from the *original* script's logic.
#   **Resolution:** The obfuscation process does not fix errors in the input script. Debug the original script (`<input_script.sh>`) first. The obfuscated script simply decodes and runs the original content.
#
# **Important Considerations / Warnings:**
# - **Obfuscation != Security:** This script provides only basic obfuscation (making code less immediately readable). It does NOT provide security or encryption. The original script can be easily recovered by decoding the base64 string inside the generated files.
# - **Trust:** Only obfuscate scripts whose content you trust. The obfuscated version executes the original code directly via `bash`. Do not run obfuscated scripts from untrusted sources without inspection.
# - **Performance:** The obfuscated script has a very minor performance overhead due to the initial base64 decoding step compared to running the original script directly. This is usually negligible.
# - **Debugging:** Debugging the *obfuscated* script's *loader* logic is complex. Debug the *original* script first. The `_with_comments.sh` version can help understand the loader's flow if needed.
# - **Idempotency:** Running `obfuscate.sh` multiple times with the same inputs will overwrite the output files. The generated filenames are deterministic. The *content* will differ due to randomized names/noise.
# - **Concurrency:** `obfuscate.sh` itself is not designed for concurrent execution if writing to the same output base name (race condition on file writes). It does not implement locking.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes a Bash (v4+) environment with access to standard core utilities available in the `PATH`.
# - Assumes required dependencies (`openssl`, `base64` from `coreutils`) are installed or can be installed via `apt`, `yum`, or `dnf` with `sudo` permissions if needed.
# - Assumes standard Unix tools (`grep`, `sed`, `tr`, `cat`, `echo`, `chmod`, `date`, `mkdir`, `rm`, `command`, `basename`, `dirname`) are available.
# - Assumes the user running the script has permission to write files in the current working directory.
# - Assumes the input file provided is a text-based script intended for execution with `bash`. Binary files or incorrectly encoded text files might lead to unpredictable behavior or errors during base64 encoding/decoding.
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - Add command-line options (e.g., `-o` for output directory, `-f` to force overwrite, `-q` for quiet mode, `--no-comments` to only generate the uncommented version).
# - Implement more sophisticated obfuscation layers (e.g., simple variable/function renaming *within* the encoded script, splitting the encoded string, using different encoding/compression, adding more complex decoding logic).
# - Include options to embed checksums for integrity verification of the obfuscated script.
# - Improve platform compatibility checks (e.g., for macOS differences in `base64` or other tools).
# - Add unit tests (e.g., using BATS).
# - Add ShellCheck integration to CI/development workflow.
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** This script (`obfuscate.sh`) only requires `sudo` if automatic dependency installation is triggered. Normal operation runs with user privileges. The *generated* obfuscated scripts run with the privileges of the user executing them.
# - **Input Sanitization:** The script reads the input file content directly. It does **not** sanitize the *content* of the script being obfuscated. Malicious code in the input script will still be present (though base64 encoded) in the output script and will be executed.
# - **Sensitive Data:** **DO NOT** use this script to "protect" sensitive information like passwords, API keys, or private keys embedded directly within the script text. Base64 is trivially reversible. Use proper secrets management techniques instead (environment variables, secure configuration files with strict permissions, vaults).
# - **Dynamic Command Execution:** The generated script uses `echo "..." | base64 --decode | bash`. This executes arbitrary code decoded from the embedded string. Ensure the original script content is trusted.
# - **Dependencies:** Relies on standard system tools (`openssl`, `coreutils`, etc.). Ensure these are obtained from trusted sources (e.g., official OS repositories) and kept updated.
# - **File Permissions:** Creates output files with execute permissions (`chmod +x`). Default permissions depend on the system's `umask`. Ensure output files are stored securely if they contain sensitive logic (even if obfuscated).
# - **Code Integrity:** Verify the integrity of `obfuscate.sh` itself if downloaded from an untrusted source (e.g., using `sha256sum`).
# - **Randomness:** Uses `openssl rand` for names/noise. While generally good, it's used here for obfuscation, not strong cryptography.
# - **Error Message Verbosity:** Current error messages do not intentionally leak sensitive data, but care should be taken if adding more detailed diagnostics.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is within this script's header comments.
# - Usage information can be obtained by running the script with incorrect arguments.
# - See the repository for potential README or further documentation: https://baha.my.id/github
# =========================================================================================

# =========================================================================================
# SUPPORT & CONTACT
# =========================================================================================
# - Author/Maintainer: Baha
# - Contact: contact [at] baha.my.id
# - Bug Reports/Issues: Please report issues or suggest improvements via the GitHub repository: https://baha.my.id/github
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
# Resolve the absolute path of the script's directory, handling symlinks.
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_DIR="${SOURCE_DIR}"
readonly SCRIPT_PID=$$

# --- Global Constants ---
readonly SUFFIX_WITH_COMMENTS="_with_comments.sh"
readonly SUFFIX_WITHOUT_COMMENTS="_without_comments.sh"

# --- Global Runtime Variables ---
INTERACTIVE_MODE=false
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is a terminal

# --- Color Definitions (Optional) ---
# Define ANSI escape codes for colored output, checking if interactive.
if [[ "${INTERACTIVE_MODE}" == true ]]; then
    readonly COLOR_RESET='\033[0m'
    readonly COLOR_RED='\033[0;31m'
    readonly COLOR_GREEN='\033[0;32m'
    readonly COLOR_YELLOW='\033[0;33m'
    readonly COLOR_BLUE='\033[0;34m'
    readonly COLOR_CYAN='\033[0;36m'
else
    readonly COLOR_RESET=""
    readonly COLOR_RED=""
    readonly COLOR_GREEN=""
    readonly COLOR_YELLOW=""
    readonly COLOR_BLUE=""
    readonly COLOR_CYAN=""
fi

# =========================================================================================
# FUNCTION DEFINITIONS
# =========================================================================================

# --- Logging Function ---
# Description: Handles formatted logging to stdout/stderr.
# Usage: log_message LEVEL "Message string"
# Levels: INFO, WARN, ERROR, DEBUG (DEBUG only shown if VERBOSE/DEBUG enabled - not implemented here)
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local level_upper
    level_upper=$(echo "$level" | tr '[:lower:]' '[:upper:]')
    local log_prefix="[${timestamp}] [${level_upper}]"
    local log_line="${log_prefix} - ${message}"
    local color=""

    case "${level_upper}" in
        INFO) color="${COLOR_GREEN}" ;;
        WARN) color="${COLOR_YELLOW}" ;;
        ERROR) color="${COLOR_RED}" ;;
        DEBUG) color="${COLOR_CYAN}" ;; # Example if debug needed later
        *) color="" ;;                   # Default no color
    esac

    # Output ERROR and WARN to stderr, INFO to stdout
    if [[ "${level_upper}" == "ERROR" || "${level_upper}" == "WARN" ]]; then
        echo -e "${color}${log_line}${COLOR_RESET}" >&2
    else
        echo -e "${color}${log_line}${COLOR_RESET}"
    fi

    # Exit immediately for ERROR level messages
    if [[ "${level_upper}" == "ERROR" ]]; then
        log_message "INFO" "Script exiting due to error."
        exit 1 # Use exit code 1 for general errors
    fi
}

# --- Usage/Help Function ---
# Description: Displays help information based on header comments and exits.
usage() {
    local usage_text
    # Extract Usage section dynamically (adjust markers if needed)
    usage_text=$(sed -n '/^# ===+ USAGE ===+$/,/^# ===+ .* ===+$/{ /# ===+ .* ===+$/!p; }' "${BASH_SOURCE[0]}" | sed 's/^# //; s/\[your_script_name.sh\]/'"${SCRIPT_NAME}"'/g')
    echo -e "${COLOR_BLUE}Usage Information:${COLOR_RESET}" >&2
    echo "${usage_text}" >&2
    exit 1 # Exit with error code 1 after showing help
}

# --- Dependency Check Function ---
# Description: Checks if a command-line utility is installed and executable.
# Arguments: $1: Command name (e.g., "openssl")
# Returns: 0 if found, 1 if not found. Does not exit.
check_dependency() {
    local cmd="$1"
    if command -v "$cmd" &>/dev/null; then
        log_message "INFO" "Dependency check passed for command: ${cmd}"
        return 0
    else
        log_message "WARN" "Required command '${cmd}' not found."
        return 1
    fi
}

# --- Dependency Installation Function ---
# Description: Checks for required dependencies (openssl, base64) and attempts installation if missing.
# Exits script if installation fails or dependencies are unavailable.
install_requirements() {
    log_message "INFO" "Checking required dependencies..."
    local openssl_found=false
    local base64_found=false
    local pkg_manager=""
    local install_cmd=""
    local openssl_pkg="openssl"
    local coreutils_pkg="coreutils" # Package usually providing 'base64'

    # Check for openssl
    if check_dependency "openssl"; then
        openssl_found=true
    fi

    # Check for base64
    if check_dependency "base64"; then
        base64_found=true
    fi

    # If both found, return
    if [[ "${openssl_found}" == true && "${base64_found}" == true ]]; then
        log_message "INFO" "All dependencies are satisfied."
        return 0
    fi

    # Determine package manager
    if command -v apt &>/dev/null; then
        pkg_manager="apt"
        install_cmd="sudo apt update && sudo apt install -y"
    elif command -v yum &>/dev/null; then
        pkg_manager="yum"
        install_cmd="sudo yum install -y"
    elif command -v dnf &>/dev/null; then
        pkg_manager="dnf"
        install_cmd="sudo dnf install -y"
    else
        log_message "ERROR" "No supported package manager (apt, yum, dnf) found."
        log_message "ERROR" "Please install required packages manually: ${openssl_pkg} ${coreutils_pkg}"
        # Exit code 1 handled by log_message ERROR
    fi

    log_message "INFO" "Detected package manager: ${pkg_manager}"

    # Attempt installation if needed
    if [[ "${openssl_found}" == false ]]; then
        log_message "INFO" "Attempting to install ${openssl_pkg} using ${pkg_manager}..."
        if ${install_cmd} ${openssl_pkg}; then
            log_message "INFO" "${openssl_pkg} installed successfully."
            openssl_found=true
        else
            log_message "ERROR" "Failed to install ${openssl_pkg}. Please install it manually."
        fi
        # Re-check after install attempt
        check_dependency "openssl" || log_message "ERROR" "${openssl_pkg} still not found after installation attempt."
    fi

    if [[ "${base64_found}" == false ]]; then
        log_message "INFO" "Attempting to install ${coreutils_pkg} (provides base64) using ${pkg_manager}..."
        if ${install_cmd} ${coreutils_pkg}; then
            log_message "INFO" "${coreutils_pkg} installed successfully."
            base64_found=true
        else
            log_message "ERROR" "Failed to install ${coreutils_pkg}. Please install it manually."
        fi
        # Re-check after install attempt
        check_dependency "base64" || log_message "ERROR" "base64 still not found after installation attempt."
    fi

    log_message "INFO" "Dependency check and installation process complete."
}


# --- Obfuscation Function ---
# Description: Contains the core logic for reading, obfuscating, and writing the scripts.
# Arguments: $1: Input script file path
#            $2: Output base name
generate_obfuscated_script() {
    local input_file="$1"
    local output_base="$2"
    local original_script rand_var1 rand_func1 rand_noise_func noise_value encoded_script
    local obfuscated_script_with_comments obfuscated_script_without_comments
    local output_with_comments output_without_comments

    log_message "INFO" "Starting obfuscation process for file: ${input_file}"

    # Check if input file exists and is readable
    if [[ ! -f "${input_file}" || ! -r "${input_file}" ]]; then
        log_message "ERROR" "Input file '${input_file}' not found or not readable."
        # Exit code 1 handled by log_message
    fi

    # Read the input script content
    log_message "INFO" "Reading input script..."
    original_script=$(cat "${input_file}") || {
        log_message "ERROR" "Failed to read input file: ${input_file}"
        exit 1 # Use specific exit code? e.g., 6 for File System Error
    }

    # Generate random names
    log_message "INFO" "Generating random names..."
    rand_var1="x$(openssl rand -hex 3)" || { log_message "ERROR" "openssl command failed during random name generation."; exit 1; }
    rand_func1="f$(openssl rand -hex 3)" || { log_message "ERROR" "openssl command failed during random name generation."; exit 1; }
    rand_noise_func="n$(openssl rand -hex 3)" || { log_message "ERROR" "openssl command failed during random name generation."; exit 1; }

    # Generate noise value
    log_message "INFO" "Generating noise value..."
    noise_value="$(openssl rand -base64 12)" || { log_message "ERROR" "openssl command failed during noise generation."; exit 1; }

    # Encode the original script
    log_message "INFO" "Encoding original script using base64..."
    encoded_script=$(echo "${original_script}" | base64 | tr -d '\n') || {
        log_message "ERROR" "Failed to encode script using base64 or tr."
        exit 1
    }

    # Construct the obfuscated script with comments (Here Document)
    log_message "INFO" "Constructing obfuscated script (with comments)..."
    # Note: Using \$ to escape variables intended for the *output* script.
    obfuscated_script_with_comments=$(cat << EOF
#!/bin/bash
# --- Obfuscated Script ---
# Generated by ${SCRIPT_NAME} on $(date)
# Original script: ${input_file}
# WARNING: Obfuscation is not security. This is easily reversible.

# Noise function (decoy)
${rand_noise_func}() {
    local noise="${noise_value}"
    echo "Noise function executed." > /dev/null
    return 0
}

# Main execution function
${rand_func1}() {
    # Call noise function
    ${rand_noise_func}

    # Encoded script data
    local ${rand_var1}="${encoded_script}"

    # Decode and execute
    # Using process substitution <(...) might be slightly more robust than pipe, but pipe is common.
    if ! echo "\$${rand_var1}" | base64 --decode | bash; then
        echo "ERROR: Failed to decode or execute the embedded script." >&2
        return 1 # Propagate failure
    fi
    return 0 # Success
}

# Entry point: Call the main execution function
if ${rand_func1}; then
    exit 0 # Exit with success if the function succeeded
else
    exit 1 # Exit with failure if the function failed
fi

# Fallback exit (should not be reached if function called)
exit 1
EOF
)

    # Construct the obfuscated script without comments
    log_message "INFO" "Constructing obfuscated script (without comments)..."
    obfuscated_script_without_comments=$(echo "$obfuscated_script_with_comments" | grep -v '^\s*#' | grep -v '^\s*$')

    # Define output filenames
    output_with_comments="${output_base}${SUFFIX_WITH_COMMENTS}"
    output_without_comments="${output_base}${SUFFIX_WITHOUT_COMMENTS}"

    # Write the output files
    log_message "INFO" "Writing output file: ${output_with_comments}"
    echo "$obfuscated_script_with_comments" > "$output_with_comments" || {
        log_message "ERROR" "Failed to write to file: ${output_with_comments}"
        exit 1 # File System Error
    }

    log_message "INFO" "Writing output file: ${output_without_comments}"
    echo "$obfuscated_script_without_comments" > "$output_without_comments" || {
        log_message "ERROR" "Failed to write to file: ${output_without_comments}"
        exit 1 # File System Error
    }

    # Set execute permissions
    log_message "INFO" "Setting execute permissions on output files..."
    chmod +x "$output_with_comments" || {
        log_message "WARN" "Failed to set execute permission on: ${output_with_comments}"
        # Don't necessarily exit for chmod failure, but warn
    }
    chmod +x "$output_without_comments" || {
        log_message "WARN" "Failed to set execute permission on: ${output_without_comments}"
    }

    log_message "INFO" "Obfuscation process completed successfully."
    echo -e "${COLOR_GREEN}Obfuscated scripts written to:${COLOR_RESET}"
    echo " - ${output_with_comments}"
    echo " - ${output_without_comments}"
}

# --- Main Logic Function ---
# Description: Orchestrates the script execution flow.
# Arguments: $@ - Command line arguments passed to the script
main() {
    # --- Argument Parsing ---
    if [[ "$#" -ne 2 ]]; then
        log_message "ERROR" "Invalid number of arguments. Expected 2, got $#."
        usage # Display usage and exit
    fi
    local input_script="$1"
    local output_base_name="$2"
    log_message "INFO" "Script started with PID: ${SCRIPT_PID}"
    log_message "INFO" "Input script: '${input_script}'"
    log_message "INFO" "Output base name: '${output_base_name}'"

    # --- Dependency Check & Installation ---
    install_requirements

    # --- Core Logic ---
    generate_obfuscated_script "${input_script}" "${output_base_name}"

    log_message "INFO" "Script completed successfully."
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# Call the main function, passing all command-line arguments
main "$@"

# Explicitly exit with success code 0 if main() completes without errors
# Note: 'set -e' would cause exit on error anyway, and log_message handles exits.
# This exit 0 is technically redundant if main finishes, but good practice.
exit 0

# =========================================================================================
# --- End of Script ---
