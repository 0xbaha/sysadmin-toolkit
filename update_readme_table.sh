#!/bin/bash
# SPDX-FileCopyrightText: © 2025 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : update_readme_table.sh
# PURPOSE       : Finds shell scripts and updates table in a specified README file.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2025-04-20
# LAST UPDATED  : 2025-04-20
# VERSION       : 1.0.0
# =========================================================================================

# =========================================================================================
# DESCRIPTION
# =========================================================================================
# Searches a specified directory (recursively) for shell scripts (*.sh). For each script
# found, it extracts the 'PURPOSE' metadata comment (line starting with '# PURPOSE :').
# It generates a Markdown table listing the script's folder, a relative link to the
# script, and its purpose. This generated table replaces the content between
# specified start and end marker lines within a target Markdown file (e.g., README.md).
# A fixed comment warning against manual edits ("<!-- This table is automatically ... -->")
# is always included between the markers, just above the generated table.
#
# Key Workflow:
# - Parses command-line arguments (README file, markers, search directory). Uses defaults if not provided.
# - Validates inputs (file existence, permissions, marker presence).
# - Checks for required command dependencies (find, grep, sed, awk, mktemp, etc.).
# - Creates a temporary file to build the Markdown table content.
# - Uses 'find' to locate eligible '.sh' files.
# - For each script, extracts PURPOSE metadata using 'grep' and 'sed'.
# - Formats a Markdown table row, escaping pipe characters ('|') in extracted metadata.
# - Adds the fixed comment "<!-- This table is automatically generated... -->".
# - Updates the target README file using 'awk', replacing content between markers atomically via a temp file.
# - Provides INFO/DEBUG/WARN/ERROR logging messages controlled by verbosity flag.
# - Cleans up temporary files using a 'trap' on exit or interrupt.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Read access to the search directory and all scripts within it.
# - Read and Write access to the target README file.
# - Execute permission for this script (`chmod +x update_readme_table.sh`).
#
# **Basic Syntax:**
# ./update_readme_table.sh [options]
#
# **Options:**
#  -s MARKER   The exact line marking the beginning of the table section.
#              (Default: "<!-- SCRIPT_TABLE_START -->")
#  -e MARKER   The exact line marking the end of the table section.
#              (Default: "<!-- SCRIPT_TABLE_END -->")
#  -f FILE     Path to the README file to update (Default: "./README.md").
#  -d DIR      Directory to search for scripts recursively (Default: ".").
#  -r          Include scripts found directly in the root of the search directory (DIR).
#              (Default: Ignore scripts in the root, only process subdirectories).
#  -v          Enable verbose (DEBUG level) output.
#  -h          Display this help message and exit.
#
# **Example (using all defaults on ./README.md):**
# ./update_readme_table.sh
#
# **Example (specifying non-default markers and search directory):**
# ./update_readme_table.sh -s '<!-- BEGIN SCRIPTS -->' -e '<!-- END SCRIPTS -->' -d ./lib/scripts -f ./docs/Reference.md
#
# **Automation (Example Git pre-commit hook):**
# # In .git/hooks/pre-commit (ensure executable: chmod +x .git/hooks/pre-commit)
# #!/bin/sh
# echo "Updating README script table..."
# # Ensure the script is run from the repository root or use full paths
# ./path/to/update_readme_table.sh -f README.md || exit 1 # Run script relative to repo root
# # Add the potentially modified README to the commit
# git add README.md
# exit 0
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Interpreter:**
# - /bin/bash (Uses Bash features like [[ ]], BASH_SOURCE[0], getopts, mktemp) 
#
# **Required Tools:**
# - Coreutils: basename, dirname, date, echo, mkdir, mv, rm, cat, tr
# - find: Locating script files (Uses -print0).
# - grep: Searching for metadata and markers (Uses -F, -m1, -q).
# - sed: Extracting metadata values, escaping pipes.
# - awk: Processing the README file and inserting the table.
# - mktemp: Creating secure temporary files.
#
# **Operating System Compatibility:**
# - Designed primarily for Linux/Unix-like systems.
# - Tested on Linux. Expected to work on macOS and WSL (Windows Subsystem for Linux).
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success
# - 1: General Error (e.g., argument parsing failure)
# - 2: Dependency Error (Required command missing)
# - 3: File/Directory Error (Not found, invalid markers in file)
# - 4: Permission Error (Cannot read/write required files/directories)
# - 5: Update Failure (awk command failed or generated empty temporary file)
#
# **Potential Issues:**
# - Target README file lacks the specified START_MARKER or END_MARKER comments exactly as provided (or defaulted).
# - Insufficient permissions to read script files or write to the target README file.
# - Shell scripts found might not contain the '# PURPOSE :' metadata line, resulting in them being skipped.
# - Pipe characters ('|') within extracted 'PURPOSE' metadata might interfere with Markdown table rendering if escaping fails (current script uses `sed 's/|/\\|/g'` to mitigate).
# - The `awk` logic assumes markers appear in the correct order (start before end) within the README.
#
# **Considerations:**
# - **In-Place Modification:** The script modifies the target README file directly. It is highly recommended to use version control (like Git) to track changes and revert if necessary.
# - **Atomicity:** The update process uses a temporary file (`mktemp`) and `mv` to make the replacement of the README content relatively atomic, reducing the risk of corruption if the script is interrupted during the `awk` processing phase.
# - **Temporary Files:** Secure temporary files are created via `mktemp` and automatically removed on script exit (success or failure) or interruption via a `trap` handler [3, 5].
# =========================================================================================

# =========================================================================================
# SCRIPT EXECUTION ENVIRONMENT & CONFIGURATION
# =========================================================================================

# --- Bash Strict Mode ---
set -euo pipefail

# --- Debug Mode ---
# Uncomment for debugging: set -x

# --- Script Information ---
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly SCRIPT_DIR="${SOURCE_DIR}"
readonly SCRIPT_PID=$$

# --- Timestamp ---
readonly SCRIPT_RUN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- Global Runtime Variables ---
VERBOSE=false
INTERACTIVE_MODE=false
[[ -t 1 ]] && INTERACTIVE_MODE=true # Check if stdout is a terminal
INCLUDE_ROOT_FILES=false # Whether to include files directly in SEARCH_DIR

# Configuration Defaults
readonly DEFAULT_README_FILE="./README.md"
readonly DEFAULT_SEARCH_DIR="."
readonly DEFAULT_START_MARKER="<!-- SCRIPT_TABLE_START -->" # Default start marker 
readonly DEFAULT_END_MARKER="<!-- SCRIPT_TABLE_END -->"   # Default end marker 

# Runtime variables populated by arguments/defaults
README_FILE="${DEFAULT_README_FILE}"
SEARCH_DIR="${DEFAULT_SEARCH_DIR}"
START_MARKER="${DEFAULT_START_MARKER}" # Initialize with default 
END_MARKER="${DEFAULT_END_MARKER}"   # Initialize with default 
TEMP_TABLE_FILE="" # Will be set by mktemp

# --- Color Definitions (Optional) ---
if [[ "${INTERACTIVE_MODE}" == true ]]; then
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
        DEBUG) [[ "${VERBOSE}" == false ]] && return; color="${COLOR_CYAN}" ;;
        INFO) color="${COLOR_GREEN}" ;;
        WARN) color="${COLOR_YELLOW}" ;;
        ERROR) color="${COLOR_RED}" ;;
        *) color="" ;;
    esac

    if [[ "${level_upper}" == "ERROR" || "${level_upper}" == "WARN" ]]; then
        echo -e "${color}${log_line}${COLOR_RESET}" >&2
    else
        echo -e "${color}${log_line}${COLOR_RESET}"
    fi
}

# --- Usage/Help Function ---
usage() {
    local usage_text
    # Extract Usage section (adjust line matching if needed)
    usage_text=$(sed -n '/^# ===+ USAGE ===+$/,/^# ===+ .* ===+$/{ /# ===+ .* ===+$/!p; }' "${BASH_SOURCE[0]}" | sed 's/^# //; s/\[your_script_name.sh\]/'"${SCRIPT_NAME}"'/g')
    cat << EOF >&2
${usage_text}

Defaults:
  README File:      ${DEFAULT_README_FILE}
  Search Directory: ${DEFAULT_SEARCH_DIR}
  Start Marker:     ${DEFAULT_START_MARKER}
  End Marker:       ${DEFAULT_END_MARKER}
  Include Root:     ${INCLUDE_ROOT_FILES} # Show the default state
EOF
    exit 1
}

# --- Dependency Check Function ---
check_dependency() {
    local cmd="$1"
    if ! command -v "$cmd" &> /dev/null; then
        log_message "ERROR" "Required command '${cmd}' not found. Please install it."
        exit 2
    fi
    log_message "DEBUG" "Dependency check passed for command: ${cmd}"
}

# --- Cleanup Function ---
cleanup() {
    local exit_status=$?
    log_message "DEBUG" "Performing cleanup..."
    if [[ -n "${TEMP_TABLE_FILE:-}" && -f "${TEMP_TABLE_FILE}" ]]; then
        log_message "DEBUG" "Removing temporary table file: ${TEMP_TABLE_FILE}"
        rm -f "${TEMP_TABLE_FILE}"
    fi
    log_message "INFO" "Script finished with exit status: ${exit_status}"
    exit "${exit_status}"
}

# --- Trap Setup ---
trap cleanup EXIT INT TERM HUP

# --- Argument Parsing Function ---
parse_params() {
    # Add 'r' to the getopts string (no colon as it's a boolean flag)
    while getopts ":s:e:f:d:vrh" opt; do # Added 'r' here
        case $opt in
            s) START_MARKER="$OPTARG" ;;
            e) END_MARKER="$OPTARG" ;;
            f) README_FILE="$OPTARG" ;;
            d) SEARCH_DIR="$OPTARG" ;;
            v) VERBOSE=true ;;
            r) INCLUDE_ROOT_FILES=true ;; # Set the flag to true if -r is present
            h) usage ;;
            \?) log_message "ERROR" "Invalid option: -${OPTARG}"; usage ;;
            :) log_message "ERROR" "Option -${OPTARG} requires an argument."; usage ;;
        esac
    done
    shift $((OPTIND-1))

    # REMOVED mandatory argument checks for -s and -e

    # Check for unexpected positional arguments
    if [[ $# -gt 0 ]]; then
        log_message "ERROR" "Unexpected argument(s): $*"
        usage
    fi
    log_message "DEBUG" "Arguments parsed. README: '${README_FILE}', Search Dir: '${SEARCH_DIR}', Start Marker: '${START_MARKER}', End Marker: '${END_MARKER}', Verbose: ${VERBOSE}, Include Root: ${INCLUDE_ROOT_FILES}"
}

# --- Input Validation Function ---
validate_inputs() {
    log_message "INFO" "Validating inputs..."
    if [[ ! -f "${README_FILE}" ]]; then
        log_message "ERROR" "README file not found: ${README_FILE}"
        exit 3
    fi
     if [[ ! -r "${README_FILE}" || ! -w "${README_FILE}" ]]; then
         log_message "ERROR" "Insufficient permissions (read/write) for README file: ${README_FILE}"
         exit 4
    fi
    # Use grep -F for fixed string matching, which is safer and faster for markers
    if ! grep -qF "${START_MARKER}" "${README_FILE}"; then
        log_message "ERROR" "Start marker not found in ${README_FILE}: '${START_MARKER}'"
        exit 3
    fi
    if ! grep -qF "${END_MARKER}" "${README_FILE}"; then
        log_message "ERROR" "End marker not found in ${README_FILE}: '${END_MARKER}'"
        exit 3
    fi
    if [[ ! -d "${SEARCH_DIR}" ]]; then
        log_message "ERROR" "Search directory not found: ${SEARCH_DIR}"
        exit 3
    fi
     if [[ ! -r "${SEARCH_DIR}" ]]; then
        log_message "ERROR" "Cannot read search directory: ${SEARCH_DIR}"
        exit 4
    fi
    log_message "INFO" "Input validation passed."
}

# --- Generate Table Content Function ---
generate_table_content() {
    log_message "INFO" "Generating table content..."

    # Create temp files securely
    TEMP_TABLE_FILE=$(mktemp) # Final table output
    local TEMP_SORT_INPUT_FILE # Intermediate data for sorting
    TEMP_SORT_INPUT_FILE=$(mktemp)
    local TEMP_SORTED_FILE # Sorted intermediate data
    TEMP_SORTED_FILE=$(mktemp)

    log_message "DEBUG" "Created temporary table file: ${TEMP_TABLE_FILE}"
    log_message "DEBUG" "Created temporary sort input file: ${TEMP_SORT_INPUT_FILE}"
    log_message "DEBUG" "Created temporary sorted data file: ${TEMP_SORTED_FILE}"

    # Write Markdown table header to the final output file
    printf "| %s | %s | %s |\n" "Folder" "Script Name" "Purpose" > "${TEMP_TABLE_FILE}"
    printf "|%s|%s|%s|\n" ":--" ":--" ":--" >> "${TEMP_TABLE_FILE}" # Alignment

    local found_scripts=0
    local script_path purpose folder_path slash_count

    # --- Step 1 & 2: Find scripts, extract data, and write to sort input file ---
    log_message "INFO" "Finding scripts and extracting metadata..."

    # --- Define find command arguments based on INCLUDE_ROOT_FILES flag ---
    # Start with the search path
    local find_args=("${SEARCH_DIR}")

    # Add global options *next*
    if [[ "${INCLUDE_ROOT_FILES}" == true ]]; then
        log_message "INFO" "Including files from root directory (${SEARCH_DIR})."
        find_args+=("-mindepth" "1") # Global option placed early 
    else
        log_message "INFO" "Ignoring files from root directory (${SEARCH_DIR}). Use -r to include them."
        find_args+=("-mindepth" "2") # Global option placed early 
    fi

    # Add tests and actions *after* global options
    find_args+=(-type f -name "*.sh" -print0) # Tests and primary action

    # --- End of find argument definition ---

    # Execute find with the constructed arguments
    while IFS= read -r -d $'\0' script_path; do
        log_message "DEBUG" "Processing script for sorting: ${script_path}"

        # Extract PURPOSE (first occurrence)
        purpose=$(grep -m1 "^# PURPOSE[[:space:]]*:" "$script_path" | sed 's/^# PURPOSE[[:space:]]*:[[:space:]]*//')

        if [[ -n "$purpose" ]]; then
            folder_path=$(dirname "$script_path")
            # Calculate depth (number of slashes) as primary sort key
            local normalized_path="${script_path#./}"
            slash_count=$(echo "$normalized_path" | tr -cd '/' | wc -c)

            # Write data to intermediate file: slash_count<TAB>script_path<TAB>folder_path<TAB>purpose
            printf "%s\t%s\t%s\t%s\n" "$slash_count" "$script_path" "$folder_path" "$purpose" >> "${TEMP_SORT_INPUT_FILE}"
            found_scripts=$((found_scripts + 1))
        else
            log_message "DEBUG" "Skipping script (no PURPOSE found): ${script_path}"
        fi
    done < <(find "${find_args[@]}") # Use the argument array here

    # Handle case where no eligible scripts were found
    if [[ $found_scripts -eq 0 ]]; then
        log_message "WARN" "No scripts with '# PURPOSE:' metadata found in ${SEARCH_DIR}."
        # Add placeholder row directly to the final table file
        printf "| %s | %s | %s |\n" "-" "*(No scripts found)*" "-" >> "${TEMP_TABLE_FILE}"
        # Clean up intermediate files as they are not needed
        rm -f "${TEMP_SORT_INPUT_FILE}" "${TEMP_SORTED_FILE}"
        return 0 # Exit the function successfully
    fi

    log_message "INFO" "Found ${found_scripts} script(s) with metadata."

    # --- Step 3: Sort the intermediate data ---
    log_message "INFO" "Sorting script data..."
    # Sort numerically by slash_count (field 1), then alphabetically by script_path (field 2) [4, 6]
    sort -t$'\t' -n -k1,1 -k2,2 "${TEMP_SORT_INPUT_FILE}" > "${TEMP_SORTED_FILE}"
    if [[ $? -ne 0 ]]; then
         log_message "ERROR" "Failed to sort script data."
         # Cleanup is handled by trap, but explicit removal here is okay too
         rm -f "${TEMP_SORT_INPUT_FILE}" "${TEMP_SORTED_FILE}"
         # Let the main script exit via the trap
         exit 1 # Or return 1 if you want main to handle differently
    fi
    log_message "DEBUG" "Sorting complete. Sorted data in ${TEMP_SORTED_FILE}"


    # --- Step 4: Generate Markdown table from sorted data ---
    log_message "INFO" "Generating final Markdown table..."
    local script_filename script_name_meta link_text script_link folder_path_md purpose_md link_target

    # Read the sorted file line by line
    # IFS=$'\t' ensures fields separated by tabs are read correctly
    while IFS=$'\t' read -r _ script_path folder_path purpose; do
        log_message "DEBUG" "Generating table row for: ${script_path}"

        # Recalculate filename, link etc. based on the sorted path
        script_filename=$(basename "$script_path")
        # Extract SCRIPT NAME metadata as fallback/alternative link text (optional)
        script_name_meta=$(grep -m1 "^# SCRIPT NAME[[:space:]]*:" "$script_path" | sed 's/^# SCRIPT NAME[[:space:]]*:[[:space:]]*//')
        link_text=${script_filename:-$script_name_meta} # Prefer filename for link text

        # Ensure link path is relative and clean (remove leading './')
        link_target="${script_path#./}"
        script_link="[${link_text}](${link_target})"

        # Escape pipe characters '|' for Markdown table cells
        folder_path_md=$(echo "$folder_path" | sed 's/|/\\|/g')
        purpose_md=$(echo "$purpose" | sed 's/|/\\|/g')

        # Append the formatted Markdown row to the final table file
        printf "| %s | %s | %s |\n" "$folder_path_md" "$script_link" "$purpose_md" >> "${TEMP_TABLE_FILE}"

    done < "${TEMP_SORTED_FILE}"

    # Clean up intermediate sorting files now that the final table file is built
    rm -f "${TEMP_SORT_INPUT_FILE}" "${TEMP_SORTED_FILE}"
    log_message "DEBUG" "Removed intermediate sort files."

    log_message "INFO" "Finished generating table content."
    return 0 # Indicate success
}

# --- Cleanup Function ---
cleanup() {
    local exit_status=$?
    log_message "DEBUG" "Performing cleanup..."
    # Remove the final table file if it still exists (it shouldn't if awk succeeded)
    if [[ -n "${TEMP_TABLE_FILE:-}" && -f "${TEMP_TABLE_FILE}" ]]; then
        log_message "DEBUG" "Removing temporary table file: ${TEMP_TABLE_FILE}"
        rm -f "${TEMP_TABLE_FILE}"
    fi
    # Add cleanup for the sort intermediate files in case of errors before they are removed
    # Use find with the base names to be safe if variables aren't set
    find /tmp -maxdepth 1 -type f -name "$(basename "${TEMP_SORT_INPUT_FILE:-temp_sort_input_dummy}")" -delete 2>/dev/null
    find /tmp -maxdepth 1 -type f -name "$(basename "${TEMP_SORTED_FILE:-temp_sorted_dummy}")" -delete 2>/dev/null

    log_message "INFO" "Script finished with exit status: ${exit_status}"
    exit "${exit_status}"
}

# --- Update README Function ---
update_readme() {
    log_message "INFO" "Updating ${README_FILE}..."
    local temp_readme
    temp_readme=$(mktemp)
    log_message "DEBUG" "Created temporary README output file: ${temp_readme}"

    # Define the fixed comment line
    local fixed_comment="<!-- This table is automatically generated. Do not edit manually. -->"

    # Use awk to replace content between markers, inserting the fixed comment
    # Pass the fixed comment as a variable using -v for safety and clarity
    awk -v start="${START_MARKER}" \
        -v end="${END_MARKER}" \
        -v tablefile="${TEMP_TABLE_FILE}" \
        -v comment="${fixed_comment}" ' # Pass the comment here
        BEGIN { printing = 1; found_start = 0; processed = 0 }
        $0 == start {
            print start             # Print the start marker
            print ""                # Add a blank line after start marker
            print comment           # <<< INSERT THE FIXED COMMENT HERE
            print ""                # Add a blank line after the fixed comment (optional, for spacing)
            # Read and print the content from the table file
            while ( (getline line < tablefile) > 0 ) {
                print line
            }
            close(tablefile)        # Close the file explicitly
            print ""                # Add a blank line before end marker
            print end               # Print the end marker
            printing = 0            # Stop printing original lines until end marker is found
            found_start = 1
            processed = 1           # Mark that we processed the section
            next                    # Skip the start marker line itself from original file
        }
        $0 == end {
            if (!found_start) {
                # End marker found before start marker - issue warning
                 print "[AWK WARN] End marker found before Start marker." > "/dev/stderr";
            }
            printing = 1            # Start printing original lines again
            next                    # Skip the end marker line itself from original file
        }
        printing { print }          # Print lines outside the markers or before start/after end
        END {
             if (!processed) {
                 # Markers were not found correctly during processing
                 print "[AWK ERROR] Start/End markers not processed correctly in file." > "/dev/stderr"
                 exit 1              # Signal error from awk
             }
        }
        ' "${README_FILE}" > "${temp_readme}" # Process the README file 

    # Check awk exit status and if the temp file was created and is non-empty
    if [[ $? -eq 0 && -s "${temp_readme}" ]]; then
        # Replace original file
        mv "${temp_readme}" "${README_FILE}"
        log_message "INFO" "Successfully updated table in ${README_FILE}."
    else
        log_message "ERROR" "Failed to update ${README_FILE}. awk command failed or temporary file '${temp_readme}' is empty/missing."
        # Clean up failed temp file if it exists
        [[ -f "${temp_readme}" ]] && rm -f "${temp_readme}"
        exit 5 # Specific exit code for update failure
    fi
     # temp_readme is moved on success, no need to remove in cleanup
}

# --- Main Logic Function ---
main() {
    log_message "INFO" "Starting script execution: ${SCRIPT_NAME}"
    validate_inputs
    generate_table_content
    update_readme
    log_message "INFO" "Script execution completed successfully."
}

# =========================================================================================
# SCRIPT EXECUTION FLOW
# =========================================================================================

# 1. Parse Command Line Arguments
parse_params "$@"

# 2. Check Dependencies
log_message "INFO" "Checking dependencies..."
check_dependency "find"
check_dependency "grep"
check_dependency "sed"
check_dependency "awk"
check_dependency "mktemp"
check_dependency "dirname"
check_dependency "basename"
log_message "INFO" "Dependencies check passed."

# 3. Execute Main Logic
main

# 4. Exit Successfully (implicit via trap)
# =========================================================================================
# --- End of Script ---
