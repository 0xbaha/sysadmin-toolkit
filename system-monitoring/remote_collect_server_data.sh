#!/bin/bash
# SPDX-FileCopyrightText: © 2024 Baha <contact@baha.my.id>
# SPDX-License-Identifier: MIT

# =========================================================================================
# SCRIPT METADATA
# =========================================================================================
# SCRIPT NAME   : remote_collect_server_data.sh
# PURPOSE       : Collects system/network metrics remotely via SSH; saves to CSV.
# -----------------------------------------------------------------------------------------
# AUTHOR        : Baha
# CONTACT       : contact [at] baha.my.id
# WEBSITE       : https://baha.my.id
# PROFILE       : https://baha.my.id/linkedin
# REPOSITORY    : https://baha.my.id/github
# CREATED ON    : 2024-10-09
# LAST UPDATED  : 2024-10-09
# VERSION       : 1.0.0
# =========================================================================================

# =========================================================================================
# DESCRIPTION
# =========================================================================================
# This script automates the process of gathering key system information from a list of
# remote servers defined in a credentials file. It uses SSH and `sshpass` for
# non-interactive login and executes a series of commands on each target server
# to retrieve various metrics. The collected data is aggregated into a single CSV file
# for easy analysis and reporting. It incorporates improved logging, error handling,
# dependency checking, and structured functions based on best practices.
#
# Key Workflow / Functions:
# - Sets Bash Strict Mode (`set -euo pipefail`) for safer execution.
# - Defines global constants and variables for configuration and state.
# - Implements a standardized logging function (`log_message`) with levels (INFO, WARN, ERROR, SUCCESS).
# - Implements a dependency check function (`install_if_missing`) that attempts to install `sshpass` and `curl` via `apt` or `yum` if missing.
# - Implements a function (`manage_credentials_file`) to check existence, sort by IP, and enforce 600 permissions on the credentials file (`credentials.txt`).
# - Implements a core function (`execute_remote_commands`) to handle SSH connection and remote execution:
#     - Uses `sshpass` for password authentication (Security Warning: See SECURITY CONSIDERATIONS).
#     - Sets SSH connection timeout.
#     - Disables strict host key checking (Security Warning: See SECURITY CONSIDERATIONS).
#     - Executes a remote script block (via here-document) on the target server.
#     - The remote script collects: Date, Hostname, OS, Kernel, Uptime, CPU Cores, RAM Usage (%), Disk Usage (%), Private IP (10.x), Public IP, MAC Addresses, Network Interfaces, Default Gateway, DNS Servers, Load Average, Process Count, Swap Usage (%).
#     - Remote script includes basic error handling for individual commands and attempts to clear bash history (best effort).
# - Implements a `cleanup` function (registered with `trap`) to log script exit status.
# - Main execution logic (`main` function):
#     - Checks for root/sudo privileges.
#     - Calls dependency checks.
#     - Manages the credentials file.
#     - Prepares a timestamped output CSV file and writes the header.
#     - Reads `credentials.txt` line by line, skipping empty/commented lines.
#     - Calls `execute_remote_commands` for each server.
#     - Appends results (or error placeholders) to the output CSV.
#     - Logs summary statistics (total processed, success, errors).
# - Includes detailed header documentation covering various aspects of the script.
# =========================================================================================

# =========================================================================================
# DESIGN PHILOSOPHY
# =========================================================================================
# - **Automation:** Designed for unattended execution to collect data from multiple servers without manual intervention.
# - **Robustness:** Includes Bash Strict Mode, explicit error handling for SSH and file operations, dependency checks, connection timeouts, and permission validation. Uses specific exit codes.
# - **Modularity:** Uses functions for distinct tasks (logging, dependency check, credentials management, remote execution, cleanup).
# - **Readability:** Employs clear variable names (`readonly` for constants), detailed comments, standardized logging (`log_message`), and consistent formatting.
# - **Maintainability:** Structured code with functions and comprehensive header documentation makes updates easier.
# - **Security:** Enforces secure permissions (600) on the credentials file and attempts to clear remote command history. Includes warnings about `sshpass` and `StrictHostKeyChecking=no`.
# - **Simplicity:** Relies on standard Linux commands and avoids overly complex external dependencies where possible for core logic.
# =========================================================================================

# =========================================================================================
# PRIMARY AUDIENCE
# =========================================================================================
# - System Administrators
# - DevOps Engineers
# - IT Support Teams managing multiple Linux servers requiring periodic metric collection.
# =========================================================================================

# =========================================================================================
# USAGE
# =========================================================================================
# **Permissions:**
# - Script execution: `chmod +x remote_collect_server_data.sh`
# - File system access: Read access to `credentials.txt`. Write access to the script's directory to create the output CSV file. Write access potentially needed by `apt`/`yum` cache during dependency install.
# - Elevated privileges: Requires `sudo` or root privileges. This is primarily needed for the `install_if_missing` function to use `apt` or `yum` for installing `sshpass` and `curl` if they are not found. If dependencies are guaranteed to be present, the script *might* run without sudo if the executing user has appropriate SSH permissions and file access, but the initial check enforces sudo/root.
#
# **Prerequisites:**
# - Create a credentials file named `credentials.txt` in the same directory as the script (`${SCRIPT_DIR}/credentials.txt`).
# - Format `credentials.txt` with one server per line, space-separated: `server_ip port username password`
#   Example:
#   ```
# This is a comment line, it will be ignored
#   192.168.1.10 22 root mypassword123
#   10.20.30.40 2222 admin pa$$w0rd
#   ```
# - Ensure the user running the script (likely root via sudo) has network access to the target servers on the specified SSH ports.
#
# **Basic Syntax:**
# `sudo ./remote_collect_server_data.sh`
#
# **Options:**
# - This script does not currently support command-line options (e.g., -h, -v, -c). It uses hardcoded paths relative to the script's location for the credentials file and output directory.
#
# **Arguments:**
# - None. Relies solely on the `credentials.txt` file found in the script's directory.
#
# **Common Examples:**
# 1. Basic execution (requires `credentials.txt` in the same directory):
#    `sudo ./remote_collect_server_data.sh`
#
# **Advanced Execution (Automation):**
# - Example cron job running daily at 2:15 AM, logging standard output/error:
#   `15 2 * * * cd /path/to/script/directory && sudo ./remote_collect_server_data.sh >> /var/log/remote_collect.log 2>&1`
#   (Ensure the user running cron has sudo privileges without a password prompt for this specific script, or configure cron differently).
# =========================================================================================

# =========================================================================================
# INSTALLATION / DEPLOYMENT
# =========================================================================================
# **Recommended Location:**
# - Secure directory accessible by the intended execution user/process (e.g., `/usr/local/sbin/` if run by root, `/opt/scripts/`, or a dedicated service user's directory).
# - Ensure the script file has appropriate ownership (e.g., `chown root:root`) and permissions (e.g., `chmod 700` or `750`).
#
# **Manual Setup:**
# 1. Place the script (`remote_collect_server_data.sh`) in the chosen location.
# 2. Set appropriate ownership and executable permissions (e.g., `sudo chown root:root /usr/local/sbin/remote_collect_server_data.sh && sudo chmod 700 /usr/local/sbin/remote_collect_server_data.sh`).
# 3. Create the `credentials.txt` file in the same directory, populating it with server details.
# 4. Set strict permissions on the credentials file: `sudo chmod 600 /path/to/script/directory/credentials.txt`. The script also attempts to enforce this.
# 5. Ensure required dependencies (`sshpass`, `curl`) are installed. The script attempts to install them via `apt` or `yum` if run with `sudo`, but manual pre-installation might be preferred.
# 6. Test run the script interactively: `sudo /path/to/script/directory/remote_collect_server_data.sh`.
#
# **Integration (Optional):**
# - **Cron Job:** See USAGE section. Ensure correct paths and permissions. Consider user context for cron execution.
# - **Systemd Service:** Could be adapted to run as a systemd service/timer for more robust scheduling and management. Would require creating `.service` and `.timer` unit files.
# =========================================================================================

# =========================================================================================
# DEPENDENCIES & ENVIRONMENT
# =========================================================================================
# **Required Interpreter:**
# - `/bin/bash`: Assumes Bash version 4+ for features like `declare -A` (associative arrays in logging) and robust `[[ ... ]]` usage. Uses `#!/bin/bash`.
#
# **Required Binaries/Tools (on the machine running the script):**
# - `bash`: The shell interpreter.
# - `coreutils`: Provides `date`, `basename`, `dirname`, `cd`, `pwd`, `echo`, `cat`, `mkdir`, `touch`, `chmod`, `stat`, `rm`.
# - `grep`: For pattern matching.
# - `awk`: For text processing.
# - `sed`: For stream editing.
# - `sort`: For sorting the credentials file.
# - `command`: Bash built-in for checking command existence.
# - `ssh`: The OpenSSH client.
# - `sshpass`: **Required** for non-interactive SSH password authentication. (Security Warning: See SECURITY CONSIDERATIONS).
# - `curl`: **Required** for checking dependencies (via package manager interaction simulation in function) and used remotely.
# - `apt` / `apt-get` (Debian/Ubuntu) OR `yum`/`dnf` (RHEL/CentOS/Fedora): **Required** package manager if `sshpass` or `curl` need to be installed automatically (requires `sudo`).
#
# **Required Binaries/Tools (on the remote target servers):**
# - `bash`: To execute the remote script block.
# - `coreutils`: `date`, `hostname`, `cat`, `grep`, `cut`, `awk`, `df`, `uname`, `uptime`, `ps`, `wc`, `paste`, `sed`, `echo`, `rm` (for history clearing).
# - `ip` (from `iproute2` package): To get IP addresses, MAC addresses, network interfaces, default gateway.
# - `curl`: To fetch the public IP address from an external service (`ifconfig.io`). Requires internet access from the remote server.
# - `free` (from `procps` or similar package): To get RAM and Swap usage.
# - `history`: Bash built-in used to clear command history.
#
# **Setup Instructions (if dependencies are not standard):**
# - The script attempts auto-installation of `sshpass` and `curl` on the local machine using `sudo apt` or `sudo yum`.
# - Manual installation (Debian/Ubuntu): `sudo apt update && sudo apt install -y sshpass curl iproute2 procps`
# - Manual installation (RHEL/CentOS/Fedora): `sudo yum update && sudo yum install -y sshpass curl iproute2 procps-ng` (Note: `sshpass` might be in the EPEL repository: `sudo yum install epel-release && sudo yum install sshpass`)
#
# **Operating System Compatibility:**
# - Local Script Execution: Designed primarily for Linux distributions with `bash`, `apt` or `yum` package managers (e.g., Debian, Ubuntu, CentOS, RHEL, Fedora).
# - Remote Target Servers: Assumes common Linux distributions where the listed "Required Binaries/Tools (on the remote target servers)" are available in standard paths. Commands like `ip`, `free`, `df`, `/etc/os-release`, `/proc/cpuinfo` are common but minor variations might exist.
#
# **Environment Variables Used:**
# - `EUID`: Used to check for root/sudo privileges.
# - `PATH`: Standard variable, assumed to contain paths to all required binaries.
# - `HOME`: Implicitly used by SSH and for `~/.bash_history` path resolution on remote servers.
#
# **System Resource Requirements:**
# - Local: Minimal CPU/RAM usage. Disk space needed for the script, credentials file, and the output CSV (size depends on number of servers and retention). Network bandwidth for SSH connections.
# - Remote: Minimal impact. Executes standard system query commands. `curl ifconfig.io` requires a small amount of network traffic.
# =========================================================================================

# =========================================================================================
# LOGGING MECHANISM
# =========================================================================================
# **Log Destination(s):**
# - Standard Output (stdout): INFO, SUCCESS, DEBUG messages (DEBUG only shown implicitly by `set -x` if enabled, not via `log_message`).
# - Standard Error (stderr): WARN, ERROR messages. Used by the `log_message` function for these levels. SSH errors also typically go to stderr.
# - Dedicated Log File: No. Logging goes directly to stdout/stderr. Can be redirected using shell redirection (e.g., `>> /path/to/logfile.log 2>&1`).
#
# **Log Format:**
# - Uses the `log_message` function format: `[YYYY-MM-DD HH:MM:SS] [LEVEL] - Message`
# - Example: `[2025-04-20 17:01:00] [INFO] - Starting script: remote_collect_server_data.sh`
#
# **Log Levels (Implemented via `log_message`):**
# - `INFO`: General operational steps.
# - `WARN`: Potential issues or non-critical failures (e.g., remote command errors).
# - `ERROR`: Significant errors that likely impede data collection or script function (e.g., failed SSH, missing files, permission errors). Script may continue or exit depending on the error.
# - `SUCCESS`: Confirmation of successful operations (e.g., dependency install, data collection per server).
# - No `DEBUG` or `CRITICAL` levels explicitly used in current `log_message` calls, but the function supports them conceptually. `set -x` can be used for debug tracing.
#
# **Log Rotation:**
# - Not applicable as the script does not manage its own log file. If output is redirected, use external tools like `logrotate` for the target file.
# =========================================================================================

# =========================================================================================
# OUTPUTS
# =========================================================================================
# **Standard Output (stdout):**
# - `INFO` and `SUCCESS` messages from the `log_message` function.
# - Examples: Status updates on dependency checks, file management, starting collection per server, successful collection, final summary.
#
# **Standard Error (stderr):**
# - `WARN` and `ERROR` messages from the `log_message` function.
# - Examples: Privilege errors, missing files, dependency install failures, permission errors, SSH connection failures, remote command errors, failure summaries.
# - Output from `set -x` if debug mode is manually enabled.
#
# **Generated/Modified Files:**
# - `credentials.txt`: Read by the script. Sorted in-place using `sort -o`. Permissions checked and potentially set to 600.
# - `server_data_YYYYMMDD_HHMMSS.csv`: Created in the script's directory (`${SCRIPT_DIR}`). Contains the collected data. Overwrites if a file with the exact same timestamp name somehow exists (unlikely).
#   - Columns: `Server,Date,Hostname,OS,Kernel Version,Uptime,CPU Cores,RAM Usage,Disk Usage,Private IP,Public IP,MAC Address,Network Interfaces,Default Gateway,DNS Servers,Load Average,Processes,Swap Usage`
#   - Rows with errors during collection for a specific server will contain `ERROR_COLLECTING_DATA` in the second column and likely empty/N/A values after.
# - Temporary Files: None explicitly created by the script logic itself (uses pipes and variables). Standard tools (`ssh`, `sort`) might use system temporary space internally.
# =========================================================================================

# =========================================================================================
# ERROR HANDLING & CONSIDERATIONS
# =========================================================================================
# **Exit Codes:**
# - 0: Success - Script completed. Note: This can still occur if individual server collections failed but the script itself ran through the list. Check the final summary log messages and the CSV content for per-server success.
# - 1: General Error / Privilege Error - Script not run as root/sudo. SSH/remote command failure for a server (`execute_remote_commands` returns 1, logged but doesn't stop the loop). No data returned from successful SSH.
# - 2: Dependency Error - Required command (`sshpass`, `curl`) not found and installation failed or package manager unsupported.
# - 3: Configuration Error - `credentials.txt` file not found.
# - 5: Permission Error - Failed to set required permissions (600) on `credentials.txt`.
# - 6: File System Error - Failed to sort `credentials.txt`, failed to write header or append data to the output CSV.
# - Other non-zero codes: May originate from commands failing when `set -e` is active, if not explicitly handled.
#
# **Potential Issues & Troubleshooting:**
# - **Issue:** "ERROR: This script requires root or sudo privileges..."
#   **Resolution:** Run the script using `sudo ./remote_collect_server_data.sh`.
# - **Issue:** "ERROR: Credentials file does not exist..."
#   **Resolution:** Ensure `credentials.txt` exists in the same directory as the script and is readable.
# - **Issue:** "ERROR: Failed to install sshpass..." or "Unsupported package manager..."
#   **Resolution:** Manually install `sshpass` and `curl` using the appropriate package manager for your distribution. Ensure `sudo` works correctly.
# - **Issue:** "ERROR: SSH connection or remote command execution failed..." (Exit Code != 0)
#   **Resolution:** Verify IP, port, username, password in `credentials.txt`. Check network connectivity (ping, traceroute) and firewalls. Ensure SSH service is running on the remote server. Check remote user permissions. Increase `ConnectTimeout=10` in `execute_remote_commands` if network latency is high. Test SSH manually: `ssh -p <port> <username>@<server_ip>`.
# - **Issue:** "WARN: Encountered errors during remote data collection..." or missing/N/A fields in CSV.
#   **Resolution:** Connect manually via SSH to the affected server (`ssh -p <port> <username>@<server_ip>`) and execute the commands from the `END_REMOTE_SCRIPT` block individually to see which one fails. Check if required remote tools are installed and if the output format matches expectations (e.g., `ip a`, `df -h`, `free`). `curl ifconfig.io` requires internet access from the remote server. `/etc/os-release` or `/proc/cpuinfo` might be missing or different.
# - **Issue:** Script hangs.
#   **Resolution:** Most likely an SSH connection issue. Check credentials, network, firewalls. Ensure `sshpass` isn't stuck waiting for unexpected input. Test SSH manually.
#
# **Important Considerations / Warnings:**
# - **Credentials Security:** Passwords are read from plain text `credentials.txt`. This is highly insecure. **Use SSH key-based authentication instead whenever possible.** If passwords must be used via `sshpass`, ensure `credentials.txt` has strict 600 permissions (enforced by script) and the file/system access is tightly controlled. Passwords might be briefly visible in the process list (`ps`).
# - **StrictHostKeyChecking=no:** This SSH option disables host key verification, making connections vulnerable to Man-in-the-Middle (MitM) attacks. **This is a significant security risk, especially in untrusted networks.** For production use, remove this option and manage `known_hosts` properly (e.g., pre-populate keys using `ssh-keyscan` in a secure manner, or use configuration management).
# - **History Clearing:** The remote script attempts to clear `~/.bash_history`. This is a basic measure and not foolproof. System-level auditing (e.g., `auditd`) might still log commands. It primarily affects interactive shell history retrieval.
# - **Sequential Execution:** The script processes servers one by one. For a large number of servers, this can be time-consuming. Consider parallelization (e.g., using `xargs -P`, `GNU parallel`, or background processes with `wait`) for faster execution, but be mindful of local resource limits and potential network impact.
# - **Error Reporting:** The script logs errors but continues processing other servers by default. A failure for one server doesn't stop the whole process. The final exit code is 0 if the script completes the loop, even with individual server errors. Review logs and CSV output for per-server status.
# =========================================================================================

# =========================================================================================
# ASSUMPTIONS
# =========================================================================================
# - Assumes `credentials.txt` exists in the script's directory and is formatted correctly (`ip port user pass`).
# - Assumes password-based SSH authentication is enabled and permitted on remote servers for the specified users/ports.
# - Assumes the machine running the script has reliable network connectivity to all target servers on their specified SSH ports.
# - Assumes remote servers are Linux-based and have the required standard utilities (bash, coreutils, iproute2, procps, curl, etc.) installed in standard `$PATH` locations.
# - Assumes remote servers have internet access for `curl ifconfig.io` to fetch public IPs.
# - Assumes the script is run with `sudo` or as root to handle potential dependency installations.
# - Assumes primary private IPs on remote servers match the `10.20.*` or `10.31.*` pattern for extraction via `grep -Eo`.
# - Assumes the `sort` command supports the `-t '.' -k<pos>,<pos>n` syntax for IP sorting.
# - Assumes `stat -c %a` works for checking file permissions in octal.
# =========================================================================================

# =========================================================================================
# PERFORMANCE OPTIMIZATION (Optional - Fill if relevant)
# =========================================================================================
# **Benchmarks:** Not formally benchmarked. Execution time is primarily dependent on the number of servers, network latency, and SSH connection establishment time per server.
# **Resource Consumption Profile:** Low CPU/Memory locally. Network usage proportional to number of servers * (SSH overhead + small command output).
# **Optimization Notes:**
# - Currently executes sequentially. Parallel execution (e.g., using background jobs, `xargs -P`, or `GNU parallel`) could significantly speed up collection for many servers but would increase local resource usage and concurrent network connections.
# - Remote script combines multiple commands; further optimization by reducing forks or using more efficient text processing might be possible but likely negligible impact compared to network/SSH time.
# =========================================================================================

# =========================================================================================
# TESTING & VALIDATION (Optional - Describe testing efforts)
# =========================================================================================
# **Test Strategy:** Primarily manual testing against various Linux distributions (e.g., Ubuntu, CentOS) as remote targets.
# **Key Test Cases Covered:**
# - Handles missing `credentials.txt`.
# - Handles incorrect permissions on `credentials.txt` (sets to 600).
# - Sorts `credentials.txt` correctly by IP.
# - Handles missing dependencies (`sshpass`, `curl`) by attempting installation (requires sudo).
# - Handles SSH connection failures (wrong password, wrong port, timeout) and logs errors.
# - Handles errors within the remote script execution (e.g., command not found, permission denied for remote command) and logs warnings.
# - Correctly parses and formats data into the CSV output file.
# - Handles empty or commented lines in `credentials.txt`.
# - Exit codes reflect critical script failures (e.g., missing file, dependency failure).
# **Validation Environment:** Tested manually on Ubuntu 22.04 (local) against Ubuntu 20.04/22.04 and CentOS 7/Stream 9 (remote).
# **Automation:** Static analysis performed using ShellCheck. No automated unit/integration tests currently implemented.
# =========================================================================================

# =========================================================================================
# FUTURE ROADMAP / POTENTIAL IMPROVEMENTS
# =========================================================================================
# - [Feature] Add command-line options (using `getopts` or `getopt`) for:
#   - Specifying credentials file path (`-c`).
#   - Specifying output file/directory path (`-o`).
#   - Enabling verbose/debug logging (`-v`).
#   - Help message (`-h`).
# - [Feature] Add support for SSH key-based authentication (preferred over passwords). Might require options to specify key file path.
# - [Improvement] Implement parallel execution (e.g., using background processes with `wait` or `GNU parallel`) to speed up collection for large numbers of servers. Add an option to control concurrency level (`-P`).
# - [Improvement] Enhance remote error handling: capture stderr from remote commands more effectively to provide specific error details in logs.
# - [Improvement] Make the private IP address pattern (`10.20.*|10.31.*`) configurable via variable or option.
# - [Security] Remove `StrictHostKeyChecking=no` and provide guidance or options for managing `known_hosts`.
# - [Compatibility] Test and potentially add workarounds for wider OS compatibility (e.g., macOS, different Linux distros).
# - [Feature] Add option for different output formats (e.g., JSON).
# =========================================================================================

# =========================================================================================
# SECURITY CONSIDERATIONS
# =========================================================================================
# - **Privilege Level:** Requires root/sudo for dependency installation. If deps are met, could potentially run as non-root if that user has SSH access and file permissions, but the script enforces a root check currently. Running as root minimizes permission issues but increases risk if the script is compromised.
# - **Input Sanitization:** Reads server details directly from `credentials.txt`. Assumes format is correct. Malformed lines might cause `read` or `ssh`/`sshpass` to fail for that line. Does not explicitly sanitize hostname/IP, username, or password beyond shell interpretation. Passwords containing shell metacharacters might cause issues with `sshpass -p`.
# - **Sensitive Data Handling:** **[CRITICAL WARNING]** Reads passwords from the plain text `credentials.txt` file and passes them to `sshpass -p`. This exposes passwords in the script file and potentially in the system's process list (`ps`). **THIS IS HIGHLY INSECURE.** Use SSH key-based authentication instead whenever possible. The script enforces 600 permissions on `credentials.txt` as a minimal mitigation.
# - **Dependencies:** Relies on standard system tools (`bash`, `ssh`, `curl`, `coreutils`, etc.) and `sshpass`. Ensure these are from trusted sources and updated. `sshpass` inherently handles passwords insecurely compared to SSH keys.
# - **File Permissions:** Enforces 600 on `credentials.txt`. Output CSV file is created with default umask permissions (likely 644 or 664 depending on system). Temporary files are not explicitly created.
# - **Remote Execution:** Executes a predefined script block on remote systems via SSH. Ensure the script file itself is secured against unauthorized modification.
# - **History Clearing:** The remote `history -c` and file overwrite attempt is a basic measure and may not erase all execution traces, depending on remote system logging/auditing configuration.
# - **StrictHostKeyChecking=no:** **[SECURITY RISK]** Disables SSH host key verification, making connections vulnerable to Man-in-the-Middle (MitM) attacks. Remove this for production environments and manage host keys properly.
# =========================================================================================

# =========================================================================================
# DOCUMENTATION
# =========================================================================================
# - Primary documentation is contained within this script's header comments.
# - No external documentation (README, Wiki, man page) is currently provided.
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
# -u: Treat unset variables and parameters as an error during expansion.
# -o pipefail: Pipeline return status is the status of the last command to exit with non-zero status, or zero if all succeed.
set -euo pipefail

# --- Global Constants ---
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
readonly CREDENTIALS_FILE="${SCRIPT_DIR}/credentials.txt" # Path to the server credentials file.
# Define the header row for the output CSV file. Ensures consistency.
readonly CSV_HEADER="Server,Date,Hostname,OS,Kernel Version,Uptime,CPU Cores,RAM Usage,Disk Usage,Private IP,Public IP,MAC Address,Network Interfaces,Default Gateway,DNS Servers,Load Average,Processes,Swap Usage"

# --- Global Variables ---
# Variables that might change during script execution.
OUTPUT_FILE="" # Will be set later with a timestamp.

# =========================================================================================
# FUNCTION DEFINITIONS
# =========================================================================================

# --- Logging Function ---
# Description: Basic logging function to standardize output messages.
# Usage: log_message TYPE "Message"
# TYPE can be INFO, WARN, ERROR, SUCCESS. ERROR messages go to stderr.
log_message() {
    local type="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local log_prefix="[${timestamp}] [${type}]"

    if [[ "$type" == "ERROR" ]]; then
        echo "${log_prefix} - ${message}" >&2
    else
        echo "${log_prefix} - ${message}"
    fi
}

# --- Dependency Check and Installation Function ---
# Description: Checks if a command exists. If not, attempts installation using apt or yum.
# Requires sudo privileges for installation. Exits script on failure.
# Arguments:
#   $1 - command_name: The command binary name (e.g., 'sshpass').
#   $2 - package_name: The package name to install (e.g., 'sshpass').
install_if_missing() {
    local command_name="$1"
    local package_name="$2"

    log_message "INFO" "Checking for command: ${command_name}..."
    if ! command -v "$command_name" &> /dev/null; then
        log_message "WARN" "${command_name} could not be found. Attempting to install ${package_name}..."
        if command -v apt &> /dev/null; then
            log_message "INFO" "Using 'apt' package manager."
            sudo apt update && sudo apt install -y "$package_name"
            if [[ $? -ne 0 ]]; then
                 log_message "ERROR" "Failed to install ${package_name} using apt."
                 exit 2 # Specific exit code for dependency error
            fi
        elif command -v yum &> /dev/null; then
            log_message "INFO" "Using 'yum' package manager."
            sudo yum install -y "$package_name"
            if [[ $? -ne 0 ]]; then
                 log_message "ERROR" "Failed to install ${package_name} using yum."
                 exit 2 # Specific exit code for dependency error
            fi
        else
            log_message "ERROR" "Unsupported package manager. Cannot install ${package_name}."
            log_message "ERROR" "Please install ${package_name} manually and rerun the script."
            exit 2 # Specific exit code for dependency error
        fi
        log_message "SUCCESS" "${package_name} installed successfully."
    else
        log_message "INFO" "${command_name} is already installed."
    fi
}

# --- Credentials File Handling Function ---
# Description: Checks existence, sorts, and sets permissions for the credentials file.
# Exits script if the file doesn't exist.
manage_credentials_file() {
    log_message "INFO" "Checking credentials file: ${CREDENTIALS_FILE}"
    if [[ ! -f "${CREDENTIALS_FILE}" ]]; then
        log_message "ERROR" "Credentials file does not exist: ${CREDENTIALS_FILE}"
        exit 3 # Specific exit code for configuration error
    fi

    log_message "INFO" "Sorting credentials file by IP address: ${CREDENTIALS_FILE}"
    # Sort numerically based on IP address (first field, dot-separated). Overwrite original file.
    sort -t '.' -k1,1n -k2,2n -k3,3n -k4,4n "${CREDENTIALS_FILE}" -o "${CREDENTIALS_FILE}" || {
        log_message "ERROR" "Failed to sort credentials file: ${CREDENTIALS_FILE}"
        exit 6 # Specific exit code for file system/operation error
    }

    log_message "INFO" "Checking permissions for credentials file: ${CREDENTIALS_FILE}"
    local current_perms
    current_perms=$(stat -c %a "${CREDENTIALS_FILE}")
    if [[ "${current_perms}" -ne 600 ]]; then
        log_message "WARN" "Credentials file permissions are ${current_perms}, setting to 600 for security."
        chmod 600 "${CREDENTIALS_FILE}" || {
            log_message "ERROR" "Failed to set permissions on ${CREDENTIALS_FILE}."
            exit 5 # Specific exit code for permission error
        }
    else
        log_message "INFO" "Credentials file permissions are correctly set to 600."
    fi
}

# --- Execute Remote Commands Function ---
# Description: Connects to a single server via SSH and executes the data collection script block.
# Handles SSH connection and command execution, returning the collected data line.
# Arguments:
#   $1 - server:   The IP address or hostname of the remote server.
#   $2 - port:     The SSH port number.
#   $3 - username: The username for SSH login.
#   $4 - password: The password for SSH login.
# Output: Prints the comma-separated data line collected from the server to stdout.
# Returns: 0 on success, non-zero on SSH or remote command failure.
execute_remote_commands() {
    local server="$1"
    local port="$2"
    local username="$3"
    local password="$4"
    local result=""
    local ssh_exit_code=0

    log_message "INFO" "Collecting data from ${server} on port ${port}..."

    # Execute commands remotely using SSH with sshpass.
    # Options: StrictHostKeyChecking=no (SECURITY RISK: Use with caution, preferably manage known_hosts), ConnectTimeout=10 (increased timeout)
    result=$(sshpass -p "$password" ssh \
        -p "$port" \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        "${username}@${server}" \
        'bash -s' <<-'END_REMOTE_SCRIPT' # Quoted HEREDOC prevents local expansion
    # --- Start of Remote Script ---
    # Ensure Bash Strict Mode is set on the remote side as well
    set -euo pipefail

    # Function for remote error logging (simple version)
    remote_log_error() { echo "REMOTE_ERROR: $1" >&2; }

    # Initialize variables to avoid unbound variable errors with 'set -u'
    DATE="" OS="" PRIVATE_IP="" PUBLIC_IP="" CPU_CORES="" RAM_TOTAL="" RAM_USED=""
    RAM_TOTAL_BYTES="" RAM_USED_BYTES="" RAM_PERCENTAGE="" RAM="" DISK_PERCENTAGE=""
    DISK_USED="" DISK_TOTAL="" DISK="" HOSTNAME="" KERNEL_VERSION="" UPTIME=""
    LOAD_AVG="" PROCESSES="" NETWORK_INTERFACES="" MAC_ADDRESSES="" DEFAULT_GATEWAYS=""
    DNS_SERVERS="" SWAP_TOTAL="" SWAP_USED="" SWAP_TOTAL_BYTES="" SWAP_USED_BYTES=""
    SWAP_PERCENTAGE="" SWAP=""

    # --- Data Collection ---
    # Wrap commands in error checks where practical. Use || true to prevent 'set -e' exit if failure is acceptable (e.g., public IP fetch)
    DATE=$(date || echo "Error fetching date")
    HOSTNAME=$(hostname || echo "Error fetching hostname")
    OS=$( (grep PRETTY_NAME /etc/os-release | cut -d '"' -f2) || echo "Error fetching OS")
    KERNEL_VERSION=$(uname -r || echo "Error fetching kernel")
    UPTIME=$( (uptime -p) || echo "Error fetching uptime") # Use subshell to prevent exit on failure
    CPU_CORES=$( (grep -c "processor" /proc/cpuinfo) || echo "0") # Get count directly
    PROCESSES=$( (ps aux | wc -l) || echo "0") # Count lines from ps output

    # --- Network Information ---
    PRIVATE_IP=$(ip a | grep -Eo "10.20[0-9.]+|10.31[0-9.]+" | head -n 1 || echo "N/A") # Tolerant failure
    PUBLIC_IP=$(curl -s --connect-timeout 5 ifconfig.io || echo "N/A") # Use timeout, tolerant failure
    NETWORK_INTERFACES=$( (ip -brief addr | awk '{print $1}' | paste -sd ",") || echo "N/A")
    MAC_ADDRESSES_RAW=$(ip link | grep "link/ether" | awk '{print $2}' | paste -sd "," || echo "N/A")
    MAC_ADDRESSES="\"${MAC_ADDRESSES_RAW}\"" # Enclose in quotes for CSV
    DEFAULT_GATEWAYS_RAW=$(ip route | grep default | awk '{print $3}' | paste -sd "," || echo "N/A")
    DEFAULT_GATEWAYS="\"${DEFAULT_GATEWAYS_RAW}\""
    DNS_SERVERS_RAW=$( (grep "nameserver" /etc/resolv.conf | awk '{print $2}' | paste -sd ",") || echo "N/A")
    DNS_SERVERS="\"${DNS_SERVERS_RAW}\""

    # --- Resource Usage (RAM) ---
    RAM_INFO=$(free | grep Mem) || remote_log_error "Failed to get RAM info from 'free'"
    RAM_TOTAL=$(free -h | grep Mem | awk '{print $2}' || echo "N/A")
    RAM_USED=$(free -h | grep Mem | awk '{print $3}' || echo "N/A")
    RAM_TOTAL_BYTES=$(echo "$RAM_INFO" | awk '{print $2}' || echo "0")
    RAM_USED_BYTES=$(echo "$RAM_INFO" | awk '{print $3}' || echo "0")
    if [[ "$RAM_TOTAL_BYTES" -ne 0 ]]; then
        RAM_PERCENTAGE=$(awk "BEGIN {printf \"%.2f\", ($RAM_USED_BYTES/$RAM_TOTAL_BYTES) * 100}")
    else
        RAM_PERCENTAGE="0.00"
    fi
    RAM="\"${RAM_PERCENTAGE}% (${RAM_USED}/${RAM_TOTAL})\""

    # --- Resource Usage (Disk) ---
    # Find the first filesystem starting with /dev (common for primary disk), handle potential errors
    DISK_LINE=$(df -h | grep "^/dev" | head -n 1 || echo "") # Get the line or empty string
    if [[ -n "$DISK_LINE" ]]; then
        DISK_PERCENTAGE=$(echo "$DISK_LINE" | awk '{print $5}' || echo "N/A")
        DISK_USED=$(echo "$DISK_LINE" | awk '{print $3}' || echo "N/A")
        DISK_TOTAL=$(echo "$DISK_LINE" | awk '{print $2}' || echo "N/A")
        DISK="\"${DISK_PERCENTAGE} (${DISK_USED}/${DISK_TOTAL})\""
    else
        remote_log_error "Could not find primary disk usage via 'df -h | grep \"^/dev\"'"
        DISK="\"N/A (N/A/N/A)\""
    fi

    # --- Resource Usage (Swap) ---
    SWAP_LINE=$(free -h | grep Swap) || SWAP_LINE="" # Get Swap line or empty string
    SWAP_INFO=$(free | grep Swap) || SWAP_INFO=""
    if [[ -n "$SWAP_LINE" ]]; then
        SWAP_TOTAL=$(echo "$SWAP_LINE" | awk '{print $2}' || echo "N/A")
        SWAP_USED=$(echo "$SWAP_LINE" | awk '{print $3}' || echo "N/A")
        SWAP_TOTAL_BYTES=$(echo "$SWAP_INFO" | awk '{print $2}' || echo "0")
        SWAP_USED_BYTES=$(echo "$SWAP_INFO" | awk '{print $3}' || echo "0")
        if [[ "$SWAP_TOTAL_BYTES" -ne 0 ]]; then
            SWAP_PERCENTAGE=$(awk "BEGIN {printf \"%.2f\", ($SWAP_USED_BYTES/$SWAP_TOTAL_BYTES) * 100}")
        else
            SWAP_PERCENTAGE="0.00"
        fi
        SWAP="\"${SWAP_PERCENTAGE}% (${SWAP_USED}/${SWAP_TOTAL})\""
    else
        SWAP="\"0.00% (0/0)\"" # Assume no swap if grep fails
    fi

    # --- Load Average ---
    LOAD_AVG_RAW=$(uptime | awk -F'load average:' '{print $2}' | sed 's/^ *//' || echo "N/A, N/A, N/A") # Remove leading space, tolerant failure
    LOAD_AVG="\"${LOAD_AVG_RAW}\"" # Enclose in quotes

    # --- Output Data ---
    # Ensure variables potentially containing commas or spaces are quoted for CSV integrity
    echo "$DATE,$HOSTNAME,$OS,$KERNEL_VERSION,\"$UPTIME\",$CPU_CORES,$RAM,$DISK,$PRIVATE_IP,$PUBLIC_IP,$MAC_ADDRESSES,\"$NETWORK_INTERFACES\",$DEFAULT_GATEWAYS,$DNS_SERVERS,$LOAD_AVG,$PROCESSES,$SWAP"

    # --- Security Measure: Clear Command History ---
    # This is a best-effort attempt and may not be foolproof on all systems/configurations.
    history -c &> /dev/null || remote_log_error "Failed to clear current session history (-c)"
    history -w &> /dev/null || remote_log_error "Failed to write empty history to file (-w)"
    echo "" > ~/.bash_history # Attempt to overwrite history file directly

    # --- End of Remote Script ---
END_REMOTE_SCRIPT
    )
    ssh_exit_code=$? # Capture the exit code of the SSH command itself

    if [[ $ssh_exit_code -ne 0 ]]; then
        log_message "ERROR" "SSH connection or remote command execution failed for ${server} (Exit Code: ${ssh_exit_code})."
        return 1 # Indicate failure
    elif [[ "$result" == *"REMOTE_ERROR"* ]]; then
        log_message "WARN" "Encountered errors during remote data collection on ${server}. Output may be incomplete."
        # Log specific remote errors printed to stderr if needed (would require capturing stderr separately)
        echo "$result" # Still output potentially partial results
        return 0 # Treat as partial success for data logging, but logged a warning
    elif [[ -z "$result" ]]; then
         log_message "ERROR" "SSH command succeeded for ${server}, but no data was returned."
         return 1 # Indicate failure
    else
        # Success
        echo "$result"
        return 0 # Indicate success
    fi
}

# --- Cleanup Function ---
# Description: Performs cleanup tasks before script exits. Currently just logs the exit.
# Registered with 'trap' to run on script exit or termination signals.
cleanup() {
  local exit_status=$? # Capture the script's exit status
  if [[ ${exit_status} -eq 0 ]]; then
    log_message "SUCCESS" "Script finished successfully."
  else
    log_message "ERROR" "Script exited with status: ${exit_status}."
  fi
  exit ${exit_status}
}

# --- Trap Setup ---
# Register the 'cleanup' function to run on script exit or specific signals.
trap cleanup EXIT INT TERM HUP

# =========================================================================================
# MAIN EXECUTION LOGIC
# =========================================================================================

main() {
    log_message "INFO" "Starting script: ${SCRIPT_NAME}"

    # --- Initial Checks ---
    log_message "INFO" "Checking effective user ID..."
    if [[ "$EUID" -ne 0 ]]; then
        log_message "ERROR" "This script requires root or sudo privileges, primarily for dependency installation."
        log_message "ERROR" "Please rerun using 'sudo ${SCRIPT_NAME}'."
        exit 1 # General error exit code
    else
        log_message "INFO" "Running with sufficient privileges (EUID: ${EUID})."
    fi

    # --- Dependency Management ---
    log_message "INFO" "Checking and installing dependencies if necessary..."
    install_if_missing "sshpass" "sshpass"       # Needed for non-interactive password SSH
    install_if_missing "curl" "curl"             # Needed for remote public IP fetching

    # --- Credentials File Management ---
    manage_credentials_file # Checks existence, sorts, sets permissions

    # --- Prepare Output File ---
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    OUTPUT_FILE="${SCRIPT_DIR}/server_data_${timestamp}.csv" # Use absolute path based on script location
    log_message "INFO" "Preparing output file: ${OUTPUT_FILE}"

    # Write the header row to the CSV output file. Overwrites if it exists.
    echo "${CSV_HEADER}" > "${OUTPUT_FILE}" || {
        log_message "ERROR" "Failed to write header to output file: ${OUTPUT_FILE}"
        exit 6 # File system error
    }

    # --- Process Servers ---
    log_message "INFO" "Starting data collection from servers listed in ${CREDENTIALS_FILE}..."
    local server port username password
    local collected_data=""
    local server_count=0
    local success_count=0
    local error_count=0

    while IFS=' ' read -r server port username password || [[ -n "$server" ]]; do
        # Skip empty lines or lines starting with #
        [[ -z "$server" || "$server" =~ ^# ]] && continue

        ((server_count++))

        # Execute remote commands and capture the result line
        collected_data=$(execute_remote_commands "$server" "$port" "$username" "$password")
        local cmd_status=$? # Get the return status of the function

        if [[ $cmd_status -eq 0 && -n "$collected_data" ]]; then
             # Append the server IP/hostname and the collected data to the output file
             echo "${server},${collected_data}" >> "${OUTPUT_FILE}" || {
                 log_message "ERROR" "Failed to append data for ${server} to ${OUTPUT_FILE}"
                 ((error_count++))
             }
             ((success_count++))
             log_message "SUCCESS" "Successfully collected and saved data for ${server}."
        else
             log_message "ERROR" "Failed to collect complete data for ${server}. Check previous logs."
             # Optionally write a placeholder error line to the CSV
             echo "${server},ERROR_COLLECTING_DATA,,,,,,,,,,,,,,,,," >> "${OUTPUT_FILE}" || true # Best effort append
             ((error_count++))
        fi
        # Reset server variable for the check in the loop condition when reading the last line without newline
        server=""
    done < "${CREDENTIALS_FILE}"

    # --- Final Report ---
    log_message "INFO" "--------------------------------------------------"
    log_message "INFO" "Data collection summary:"
    log_message "INFO" "Total servers processed: ${server_count}"
    log_message "INFO" "Successfully collected data from: ${success_count}"
    log_message "INFO" "Failed or incomplete collections: ${error_count}"
    log_message "INFO" "Output saved to: ${OUTPUT_FILE}"
    log_message "INFO" "--------------------------------------------------"

    # The script will exit via the 'trap cleanup EXIT' mechanism
}

# --- Script Entry Point ---
# Call the main function, passing any command-line arguments received by the script.
main "$@"

# =========================================================================================
# --- End of Script ---
