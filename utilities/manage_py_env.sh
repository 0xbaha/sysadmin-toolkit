#!/bin/bash

# --- Configuration ---
PROJECT_DIR="."
REQUIREMENTS_FILE="requirements.txt"
PYTHON_EXECUTABLE="python3"
VENV_DIR=".venv"

# --- Helper Functions ---
log_info() { echo "[INFO] $1"; }
log_warn() { echo "[WARN] $1"; }
log_error() { echo "[ERROR] $1" >&2; }

# --- Function to attempt pip install via system package manager (Advisory Only) ---
attempt_system_pip_install_advice() {
    log_error "Attempting system-wide pip installation is discouraged when using virtual environments."
    log_error "'ensurepip' failed even within the venv: ${VIRTUAL_ENV}"
    log_error "This might indicate a problem with the Python installation used to create the venv, or the venv itself."
    log_error "Consider recreating the virtual environment (delete '${VENV_DIR}' and run '${PYTHON_EXECUTABLE} -m venv ${VENV_DIR}' again)."
    log_error "If issues persist, check your base Python installation's integrity."
    return 1 # Indicate failure/discouragement
}

# --- Function to Check/Install pipreqs ---
# Installs pipreqs into the venv if needed and confirmed by user.
# Returns 0 if pipreqs command is available after execution, 1 otherwise.
check_and_install_pipreqs() {
    local python_exe_path="$1" # Pass the venv python path
    log_info "Checking for 'pipreqs' command..."
    if command -v pipreqs &> /dev/null; then
        local pipreqs_path=$(command -v pipreqs)
        if [[ "$pipreqs_path" == "${VIRTUAL_ENV}"* ]]; then
            log_info "'pipreqs' command found in venv: ${pipreqs_path}"
            return 0 # Available in venv
        else
            log_warn "'pipreqs' command found, but seems to be outside the current venv (${pipreqs_path})."
            read -p "Install 'pipreqs' into the current venv '${VIRTUAL_ENV}' for consistency? (y/N): " confirm_reinstall
            if [[ "$(echo "$confirm_reinstall" | tr '[:upper:]' '[:lower:]')" == "y" || "$(echo "$confirm_reinstall" | tr '[:upper:]' '[:lower:]')" == "yes" ]]; then
                 # Fall through to installation logic below
                 : # No operation needed here, will proceed to install prompt
            else
                log_info "Using external 'pipreqs'. Note this may have unexpected behavior."
                return 0 # User opted to use external one
            fi
        fi
    fi

    # If not found in venv or user wants to reinstall into venv
    log_warn "'pipreqs' not found in venv or reinstall requested."
    read -p "Attempt to install 'pipreqs' into the active venv using pip? (y/N): " confirm_install
    if [[ "$(echo "$confirm_install" | tr '[:upper:]' '[:lower:]')" == "y" || "$(echo "$confirm_install" | tr '[:upper:]' '[:lower:]')" == "yes" ]]; then
        log_info "Attempting to install pipreqs into the venv..."
        if "${python_exe_path}" -m pip install pipreqs; then
            log_info "'pipreqs' installed successfully into the venv." [1]
            if [[ "$(command -v pipreqs)" == "${VIRTUAL_ENV}"* ]]; then
                log_info "'pipreqs' command is now available in venv."
                return 0 # Success
            else
                log_error "'pipreqs' installed, but command not found in venv PATH. Check venv."
                return 1 # Failure post-install
            fi
        else
            log_error "Failed to install 'pipreqs' using pip into the venv."
            return 1 # Failure during install
        fi
    else
        log_info "Skipping 'pipreqs' installation."
        return 1 # Not available and install skipped
    fi
}

# --- Function to Generate requirements.txt using pipreqs ---
# Requires pipreqs to be available. Returns 0 on success, 1 on failure.
generate_requirements_file() {
    local req_path="$1"
    local proj_dir="$2"
    log_info "Attempting to generate '${req_path}' using pipreqs..."
     if [[ ! -d "${proj_dir}" ]]; then log_error "Project directory '${proj_dir}' not found for generation."; return 1; fi

     if pipreqs "${proj_dir}" --encoding=utf-8 --ignore "${VENV_DIR}" --savepath "${req_path}"; then
         log_info "Successfully generated '${req_path}' using pipreqs."
         # Check if it was actually created
         if [[ ! -f "${req_path}" ]]; then
              log_warn "pipreqs reported success, but '${req_path}' was not created. It might be empty if no requirements were found."
              # Create an empty file in this case, as pipreqs should have
              touch "${req_path}"
              log_info "Created empty '${req_path}'."
         fi
         return 0 # Success (or empty success)
     else
         log_error "'pipreqs' failed during file generation. Check output."
         return 1 # Failure
     fi
}

# --- Main Script ---

# 1. VIRTUAL ENVIRONMENT CHECK
# First, check if we are already inside an active virtual environment.
if [[ -z "${VIRTUAL_ENV}" ]]; then
    # --- Not inside an active venv ---
    log_error "------------------------------------------------------------------"
    log_error " SCRIPT ABORTED: Python virtual environment not active."
    log_error "------------------------------------------------------------------"

    # Determine the path to the script itself to use in instructions
    script_path="${BASH_SOURCE[0]}"
    # Prepare the expected path for the venv directory (relative to CWD usually)
    venv_path_relative="${VENV_DIR}" # Usually "./.venv" or ".venv"

    # Check if the virtual environment directory exists
    if [[ ! -d "${venv_path_relative}" ]]; then
        # --- Venv directory DOES NOT exist ---
        log_error "Virtual environment directory ('${venv_path_relative}') not found."
        log_error "" # Blank line for readability
        log_error "You need to create the virtual environment first."
        log_error "Please run the following command in your terminal:"
        log_error "" # Blank line for readability

        # Provide command to create the venv using configured Python executable
        echo "    ${PYTHON_EXECUTABLE} -m venv ${venv_path_relative}"

        log_error "" # Blank line for readability
        log_error "After creating the environment, activate it and re-run this script using:"
        log_error "" # Blank line for readability

        # Provide command to activate and then run the script (pass original args)
        # Assumes standard venv structure (bin/activate)
        echo "    source \"${venv_path_relative}/bin/activate\" && \"${script_path}\" \"$@\""

        log_error "" # Blank line for readability
    else
        # --- Venv directory EXISTS, but is not active ---
        log_error "The virtual environment directory ('${venv_path_relative}') exists, but it's not active."
        log_error "" # Blank line for readability
        log_error "This script needs an active virtual environment to manage dependencies correctly."
        log_error "To fix this, activate the environment first, then re-run the script."
        log_error "Please run the following command in your terminal:"
        log_error "" # Blank line for readability

        # Provide command to activate the existing venv and then run the script
        # Assumes standard venv structure (bin/activate)
        echo "    source \"${venv_path_relative}/bin/activate\" && \"${script_path}\" \"$@\""

        log_error "" # Blank line for readability
    fi

    exit 1 # Exit the script with a failure code as environment setup is needed

fi

# --- Venv is active, proceed ---
log_info "Active virtual environment detected: ${VIRTUAL_ENV}"

# 2. PREREQUISITE CHECKS (Python & Pip in Venv)
log_info "Performing prerequisite checks within the virtual environment..."
PYTHON_VENV_PATH=$(command -v "${PYTHON_EXECUTABLE}")
if [[ -z "$PYTHON_VENV_PATH" || ! "$PYTHON_VENV_PATH" == "${VIRTUAL_ENV}"* ]]; then
   log_error "Could not find '${PYTHON_EXECUTABLE}' within the active virtual environment (${VIRTUAL_ENV}). Check venv activation."; exit 1
fi
log_info "Using Python from venv: ${PYTHON_VENV_PATH} ($(${PYTHON_VENV_PATH} --version))"

log_info "Checking for pip module associated with '${PYTHON_VENV_PATH}'..."
if ! "${PYTHON_VENV_PATH}" -m pip --version &> /dev/null; then
    log_warn "'pip' module not found for the venv's Python."
    log_info "Attempting to install/bootstrap pip within the venv using 'ensurepip'..."
    if "${PYTHON_VENV_PATH}" -m ensurepip --upgrade; then
        log_info "Successfully installed/upgraded pip using ensurepip within the venv."
        if ! "${PYTHON_VENV_PATH}" -m pip --version &> /dev/null; then log_error "Pip install seemed ok, but still not found."; exit 1; fi
         log_info "Pip is now available in venv: $(${PYTHON_VENV_PATH} -m pip --version | head -n 1)"
    else
        log_error "Attempt using 'ensurepip' failed even within the venv."
        attempt_system_pip_install_advice # Provides error messages and advice
        exit 1
    fi
else
    log_info "Found pip in venv: $(${PYTHON_VENV_PATH} -m pip --version | head -n 1)"
fi

# 3. FIND OR GENERATE requirements.txt
REQUIREMENTS_PATH="${PROJECT_DIR}/${REQUIREMENTS_FILE}"
log_info "Checking for requirements file: ${REQUIREMENTS_PATH}"
if [[ ! -f "${REQUIREMENTS_PATH}" ]]; then
    log_warn "Requirements file '${REQUIREMENTS_PATH}' not found."
    log_info "Attempting to generate it using 'pipreqs'."

    # Check/Install pipreqs BEFORE attempting generation
    if ! check_and_install_pipreqs "${PYTHON_VENV_PATH}"; then
         log_error "Cannot generate requirements file because 'pipreqs' is not available and could not be installed."
         log_error "Please create '${REQUIREMENTS_PATH}' manually or fix the pipreqs installation."
         exit 1
    fi

    # Attempt generation
    if ! generate_requirements_file "${REQUIREMENTS_PATH}" "${PROJECT_DIR}"; then
        log_error "Failed to generate '${REQUIREMENTS_PATH}'. Cannot proceed."
        exit 1
    fi
    # Generation succeeded, REQUIREMENTS_PATH now points to the new file
else
    log_info "Found existing requirements file: ${REQUIREMENTS_PATH}"
fi

# 4. INSTALL REQUIREMENTS FROM FILE
log_info "Checking requirements listed in '${REQUIREMENTS_PATH}'..."
# Check if the file is empty or contains only whitespace/comments
if ! grep -qE '^[^#[:space:]]' "${REQUIREMENTS_PATH}"; then
    log_info "'${REQUIREMENTS_PATH}' is empty or contains no active requirements. Skipping installation."
else
    log_info "Requirements found in '${REQUIREMENTS_PATH}'."
    # Display potential changes/missing packages (Optional, but informative)
    log_info "Comparing listed requirements with installed packages (use 'pip list --outdated' or 'pip freeze' for details)..."
    # Consider adding a `pip list --outdated` check or similar if desired

    # Ask user confirmation to install
    read -p "Do you want to install/update packages from '${REQUIREMENTS_PATH}' into the venv? (y/N): " confirm_install
    confirm_install_lower=$(echo "$confirm_install" | tr '[:upper:]' '[:lower:]')

    if [[ "$confirm_install_lower" == "y" || "$confirm_install_lower" == "yes" ]]; then
        log_info "Attempting to install packages from ${REQUIREMENTS_PATH} into the venv..."
        if "${PYTHON_VENV_PATH}" -m pip install -r "${REQUIREMENTS_PATH}"; then
            log_info "Successfully installed/updated packages from '${REQUIREMENTS_PATH}' into the venv."
        else
            log_error "Failed to install packages using pip from '${REQUIREMENTS_PATH}'. Check output."
            exit 1 # Stop if installation fails
        fi
    else
        log_info "Installation from '${REQUIREMENTS_PATH}' skipped by user."
    fi
fi

# 5. UPDATE requirements.txt (Optional)
log_info "------------------------------------------------------------------"
log_info "Environment setup based on '${REQUIREMENTS_PATH}' is complete (or skipped)."
read -p "Do you want to run 'pipreqs' now to update '${REQUIREMENTS_PATH}' based on current code? (y/N): " confirm_update
confirm_update_lower=$(echo "$confirm_update" | tr '[:upper:]' '[:lower:]')

if [[ "$confirm_update_lower" == "y" || "$confirm_update_lower" == "yes" ]]; then
    log_info "Checking 'pipreqs' availability again before update..."
     # Check/Install pipreqs again, in case it wasn't installed earlier
    if ! check_and_install_pipreqs "${PYTHON_VENV_PATH}"; then
         log_error "Cannot update requirements file because 'pipreqs' is not available and could not be installed."
         log_warn "Skipping update step."
    else
        log_info "Running 'pipreqs --force' to update '${REQUIREMENTS_PATH}'..."
         if pipreqs "${PROJECT_DIR}" --force --encoding=utf-8 --ignore "${VENV_DIR}" --savepath "${REQUIREMENTS_PATH}"; then
            log_info "Successfully updated '${REQUIREMENTS_PATH}' based on current project code."
             # Display content if not empty
             if [[ -s "${REQUIREMENTS_PATH}" ]]; then
                 log_info "--- New Content of ${REQUIREMENTS_FILE} ---"
                 cat "${REQUIREMENTS_PATH}"
                 log_info "---------------------------------"
             else
                  log_info "'${REQUIREMENTS_PATH}' is now empty after update."
             fi
         else
            log_error "'pipreqs --force' failed during update. Check output. The file might be in an inconsistent state."
         fi
    fi
else
    log_info "Skipping update of '${REQUIREMENTS_PATH}'."
fi

log_info "Script finished."
exit 0
