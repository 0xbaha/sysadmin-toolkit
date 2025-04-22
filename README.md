# sysadmin-toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-brightgreen.svg?style=flat)](./CONTRIBUTING.md)

A practical sysadmin-toolkit: A collection of versatile shell scripts designed to automate routine tasks, simplify system management, and enhance operational efficiency for Linux/Unix administrators comfortable with reading and executing shell scripts.

## Overview

Welcome to the sysadmin-toolkit repository! This project gathers a curated set of practical shell scripts aimed at automating and streamlining common tasks encountered daily by system administrators, DevOps engineers, and IT operations professionals. The toolkit addresses various domains including operating system management, networking configuration and diagnostics, storage operations, system monitoring, virtualization management (with a focus on Proxmox), security auditing, and user administration.

The core philosophy is to provide modular, functional scripts organized logically by category. Each script focuses on solving specific, real-world administrative challenges, aiming to reduce manual effort and improve consistency across managed systems.

## Table of Contents

- [sysadmin-toolkit](#sysadmin-toolkit)
  - [Overview](#overview)
  - [Table of Contents](#table-of-contents)
  - [Target Audience \& Skill Level](#target-audience--skill-level)
  - [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
  - [Usage](#usage)
    - [Important Safety Note](#important-safety-note)
    - [Execution Steps](#execution-steps)
    - [Example](#example)
  - [Repository Structure](#repository-structure)
  - [Script Categories](#script-categories)
  - [Script Inventory](#script-inventory)
  - [Contributing](#contributing)
  - [Versioning](#versioning)
  - [License](#license)
  - [Disclaimer](#disclaimer)

## Target Audience & Skill Level

This toolkit is primarily intended for:

*   System Administrators (Linux/Unix)
*   DevOps Engineers
*   IT Operations Staff
*   Power Users managing Linux/Unix systems

Users should be comfortable navigating the command line, understanding shell scripting basics (`bash`), and capable of reviewing script code to understand its function and potential impact before execution.

## Getting Started

Follow these steps to get a local copy of the toolkit and begin using the scripts.

### Prerequisites

*   **Shell:** Most scripts are written for `bash`. While some might be POSIX-compliant, assume `bash` is required unless otherwise noted in the script comments. Compatibility with other shells (like `zsh`, `sh`) is not guaranteed.
*   **Core Utilities:** Standard Linux/Unix utilities (`coreutils`, `grep`, `awk`, `sed`, etc.) are generally expected.
*   **Git:** Required for cloning the repository (`git clone`).
*   **Common Dependencies:** Certain scripts rely on external tools. Frequently used dependencies across the toolkit include:
    *   `nmap` (for network scanning)
    *   `rsync` (for file synchronization)
    *   `jq` (for JSON processing, especially in virtualization scripts)
    *   `curl` or `wget` (for network requests)
    *   `fping` (optional alternative for `check_ip.sh`)
*   **Script-Specific Dependencies:** **Crucially, always check the comments at the beginning of each script file** or any `README.md` within its category folder for specific prerequisites or required tools before running it.

### Installation

1.  Clone the repository to your desired location on your local machine:
    ```
    git clone https://github.com/0xbaha/sysadmin-toolkit.git
    ```
2.  Navigate into the cloned directory:
    ```
    cd sysadmin-toolkit
    ```

## Usage

### Important Safety Note

**CRITICAL: Always review the source code of any script *before* executing it, especially if running with elevated privileges (sudo) or if the script performs modifications (e.g., file changes, service restarts, configuration updates, data deletion). Understand the script's actions fully to prevent unintended side effects or data loss. Use in a test environment first whenever possible.**

### Execution Steps

1.  **Navigate:** Change into the specific category directory containing the script you wish to use (e.g., `cd networking/`).
2.  **Permissions:** Ensure the script has execute permissions set: `chmod +x script_name.sh`.
3.  **Review Code:** Open the script in a text editor and carefully read through it (see Safety Note above).
4.  **Check Usage/Configuration:** Look for comments within the script or a category `README.md` detailing:
    *   Required arguments or command-line options.
    *   Environment variables or configuration settings within the script that might need customization.
5.  **Execute:** Run the script, typically prepended with `./` to execute from the current directory: `./script_name.sh [arguments...]`.

### Example

Checking the availability of IPs within a subnet using the `check_ip.sh` script:

```
# Navigate to the networking tools directory
cd networking/

# Make the script executable
chmod +x check_ip.sh

# Review the script's code (e.g., using 'less' or 'cat')
less check_ip.sh

# Execute the script
./check_ip.sh
```


## Repository Structure

The toolkit employs a category-based folder structure directly under the root directory for organization:

```
sysadmin-toolkit/
├── .git/
├── .gitignore
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── application-management/
├── automation-scheduling/
├── backup-recovery/
├── ... (other categories) ...
└── virtualization/
```

*Note: Category folders *may* contain their own `README.md` file providing more detailed information, usage instructions, or dependency lists specific to the scripts within that category. Contributors are encouraged to add or update these files, especially for categories with complex or numerous scripts.*

## Script Categories

Scripts are grouped into functional categories. The table below outlines the intended scope of each category.

| Category Name                | Description                                                                                                          |
| :--------------------------- | :------------------------------------------------------------------------------------------------------------------- |
| **Application Management**   | Deploying, configuring, managing specific applications (e.g., web servers, databases, monitoring agents).              |
| **Automation & Scheduling**  | Automating complex workflows, task scheduling (cron helpers), orchestration primitives.                              |
| **Backup & Recovery**        | Automating backups (files, databases, configs), potentially assisting recovery processes.                             |
| **Cloud Management**         | Interacting with cloud provider APIs (AWS, Azure, GCP) for basic resource tasks or information gathering.            |
| **Configuration Management** | Automating system configuration, applying settings consistently, managing configuration files templates.                 |
| **Database Management**      | Database backup automation, user management helpers, simple query execution, maintenance tasks.                     |
| **Hardware & Inventory**     | Gathering hardware information (CPU, RAM, disks, peripherals), managing hardware settings where scriptable.           |
| **Logging & Reporting**      | Managing log files (rotation, archiving), parsing logs for specific events, generating system reports.                |
| **Networking**               | Managing network interfaces, firewall rules (iptables/firewalld helpers), connectivity testing, DNS/DHCP tasks.         |
| **OS Management**            | OS-level tasks: updates/patching automation, service management (start/stop/status), system reboots, package management. |
| **Permissions & Access**     | Managing file/directory permissions/ownership (potentially advanced like ACLs), sudo configuration helpers.           |
| **Performance & Testing**    | Stress testing components (CPU, memory, disk I/O), basic performance benchmarking.                                   |
| **Security & Auditing**      | Security checks (open ports, listening services), basic vulnerability scanning helpers, system hardening scripts.      |
| **Storage & File Systems**   | Managing disk space, partitions, file systems (creation, checks), data synchronization (rsync wrappers), LVM tasks.    |
| **System Monitoring**        | Checking system resources (CPU, RAM, disk), application/service status checks, collecting performance metrics.          |
| **Text Processing**          | Utilities for complex text file manipulation, data parsing/extraction, formatting output (using `awk`, `sed`, `grep`).    |
| **User & Group Management**  | Creating/deleting/modifying users/groups, password management helpers, checking account status.                       |
| **Utilities / Misc**         | General-purpose helper scripts, environment setup tools, tasks not fitting neatly elsewhere.                           |
| **Virtualization**           | Managing VMs/containers (Proxmox, KVM, Docker); includes creation, deletion, status checks, resource reporting.        |

## Script Inventory

<!-- SCRIPT_TABLE_START -->

<!-- This table is automatically generated. Do not edit manually. -->

| Folder | Script Name | Purpose |
|:--|:--|:--|
| ./application-management | [update_chrome.sh](application-management/update_chrome.sh) | Checks/installs updates for a specific APT package if available. |
| ./configuration-management | [auto_set_wallpaper.sh](configuration-management/auto_set_wallpaper.sh) | Standardizes backgrounds & displays hostname on Cinnamon desktops. |
| ./networking | [add_google_ip_to_fortigate.sh](networking/add_google_ip_to_fortigate.sh) | Automates Google IP import to FortiGate via CLI scripts/threat feeds. |
| ./networking | [check_domain_availability.sh](networking/check_domain_availability.sh) | Checks domain availability and expiry from an input file. |
| ./networking | [check_ip.sh](networking/check_ip.sh) | Scans specified CIDR IPs for availability using ping/fping. |
| ./networking | [check_port_nc.sh](networking/check_port_nc.sh) | Checks server IPs for open ports using netcat; generates reports. |
| ./networking | [check_port_nmap.sh](networking/check_port_nmap.sh) | Uses nmap TCP scan to check server ports; generates CSV reports. |
| ./os-management | [auto_reboot_pc.sh](os-management/auto_reboot_pc.sh) | Monitors user logins; reboots system if idle for defined period. |
| ./os-management | [buster_apt_setup_imagemagick.sh](os-management/buster_apt_setup_imagemagick.sh) | Standardizes Debian 10 APT repos, cleans sources, installs pkg. |
| ./performance-testing | [stress_test_dns_server.sh](performance-testing/stress_test_dns_server.sh) | Automates continuous background DNS stress testing with logging. |
| ./performance-testing | [stress_test_local_resources.sh](performance-testing/stress_test_local_resources.sh) | Applies configurable CPU/memory/disk stress load on Linux systems. |
| ./permissions-access | [parallel_chown.sh](permissions-access/parallel_chown.sh) | Changes file ownership in parallel with logging/dry-run options. |
| ./security-auditing | [obfuscate.sh](security-auditing/obfuscate.sh) | Obfuscates bash scripts via base64, randomization, and noise. |
| ./storage-file-systems | [check_storage_speed.sh](storage-file-systems/check_storage_speed.sh) | Checks drive type, measures R/W speed, generates CSV report. |
| ./storage-file-systems | [remote_check_df_lsblk.sh](storage-file-systems/remote_check_df_lsblk.sh) | Remotely collects disk usage (df/lsblk) info from servers. |
| ./storage-file-systems | [remote_check_du.sh](storage-file-systems/remote_check_du.sh) | Collects top 'du' entries remotely via SSH; outputs CSV/logs. |
| ./storage-file-systems | [rsync_mirror.sh](storage-file-systems/rsync_mirror.sh) | Automated rsync mirrors source to remote with robust features. |
| ./system-monitoring | [remote_collect_server_data.sh](system-monitoring/remote_collect_server_data.sh) | Collects system/network metrics remotely via SSH; saves to CSV. |
| ./user-group-management | [reset_homes.sh](user-group-management/reset_homes.sh) | Automates resetting user home directories in /home for consistency. |
| ./utilities | [check_usernames_github.sh](utilities/check_usernames_github.sh) | Checks availability of usernames on GitHub via HTTP status codes. |
| ./utilities | [dos2unix_git_repo.sh](utilities/dos2unix_git_repo.sh) | Convert line endings of all Git-tracked files to Unix (LF) format. |
| ./utilities | [generate_test_files.sh](utilities/generate_test_files.sh) | Generates configurable random files for testing via CLI options. |
| ./utilities | [manage_py_env.sh](utilities/manage_py_env.sh) | Manages Python virtual environment setup within a project. |
| ./utilities | [python_web_env_setup.sh](utilities/python_web_env_setup.sh) | Automates Python web env setup with tools on Debian/Ubuntu via PPA. |
| ./utilities | [update_readme_table.sh](utilities/update_readme_table.sh) | Finds shell scripts and updates table in a specified README file. |
| ./virtualization | [collect_proxmox_vm.sh](virtualization/collect_proxmox_vm.sh) | Collects VM, storage, network, host info on a Proxmox node. |
| ./virtualization | [proxmox_check_storage_data2.sh](virtualization/proxmox_check_storage_data2.sh) | Collects Proxmox 'data2' pool free space for PRTG via JSON. |
| ./virtualization | [proxmox_check_storage_local.sh](virtualization/proxmox_check_storage_local.sh) | Collects Proxmox 'local' pool free space for PRTG via JSON. |
| ./virtualization | [proxmox_check_storage_local_lvm.sh](virtualization/proxmox_check_storage_local_lvm.sh) | Collects Proxmox 'local-lvm' usage/free % for PRTG via JSON. |
| ./virtualization | [proxmox_check_vm_offline.sh](virtualization/proxmox_check_vm_offline.sh) | Counts offline Proxmox VMs and outputs count for PRTG via JSON. |
| ./virtualization | [proxmox_check_vm_online.sh](virtualization/proxmox_check_vm_online.sh) | Counts online Proxmox VMs and outputs count for PRTG via JSON. |

<!-- SCRIPT_TABLE_END -->

## Contributing

Contributions are highly welcomed and appreciated! If you have ideas for improvements, new scripts (especially for currently empty or sparse categories!), bug fixes, or documentation enhancements, please follow these steps:

1.  **Open an Issue:** Discuss the proposed change or report a bug first by opening an issue on the GitHub repository. This allows for discussion before work begins.
2.  **Fork the Repository:** Create your personal fork of the project.
3.  **Create a Feature Branch:** Make your changes in a descriptively named branch (e.g., `git checkout -b feature/add-log-rotation-script`).
4.  **Develop and Test:** Write your script or make your changes. Ensure scripts are well-commented, explaining purpose, usage, and dependencies. Test thoroughly.
5.  **Documentation:** If adding a new script, place it in the most relevant category folder. Consider adding or updating the category's `README.md` with specific details. Contributions to documentation (including this main README) are also valuable.
6.  **Commit Changes:** Commit your work with clear, concise commit messages (`git commit -m 'feat: Add script for basic log rotation'`).
7.  **Push to Your Fork:** Push your feature branch to your fork (`git push origin feature/add-log-rotation-script`).
8.  **Open a Pull Request (PR):** Submit a PR from your feature branch to the main branch of the original `sysadmin-toolkit` repository. Reference the issue number in your PR description.

## Versioning

This project currently follows a continuous development model where the `main` branch reflects the latest state. Significant changes or stable releases *may* be marked using Git tags (e.g., `v1.0`, `v1.1`) in the future. Check the repository's tags or releases section on GitHub for any specific version information.

## License

This project is distributed under the MIT License. See the `LICENSE` file in the repository for the full license text.

## Disclaimer

**Use at Your Own Risk.** The scripts provided in this repository are offered "as is" without any warranty, express or implied. **You assume full responsibility and liability for any consequences, damages, or data loss resulting from their use or misuse.**

**Always test scripts thoroughly in a non-production, isolated environment before deploying them on critical systems.** Carefully review the code of each script to understand its functionality and potential impact prior to execution, especially scripts requiring elevated privileges (root/sudo) or performing modifications to system configuration, files, or network settings. The authors and contributors are not liable for any issues arising from the use of this toolkit.
