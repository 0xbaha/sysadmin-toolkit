# sysadmin-toolkit

A practical sysadmin-toolkit: A collection of versatile shell scripts to automate routine tasks, simplify system management, and enhance operational efficiency for Linux/Unix administrators.

## Overview

Welcome to the sysadmin-toolkit! This repository gathers a range of shell scripts aimed at simplifying and automating common tasks faced by system administrators and operations engineers. The toolkit covers areas like OS management, networking, storage, monitoring, virtualization, security, user management, and more.

The scripts are organized into logical directories based on their function. Each script aims to be practical and solve specific, real-world problems encountered in system management.

## Table of Contents

*   [Getting Started](#getting-started)
    *   [Prerequisites](#prerequisites)
    *   [Installation](#installation)
*   [Usage](#usage)
*   [Repository Structure](#repository-structure)
*   [Script Categories](#script-categories)
    *   [OS Management (`os-management/`)](#os-management)
    *   [Configuration Management (`configuration-management/`)](#configuration-management)
    *   [Networking (`networking/`)](#networking)
    *   [Storage & File Systems (`storage-file-systems/`)](#storage--file-systems)
    *   [User & Group Management (`user-group-management/`)](#user--group-management)
    *   [Permissions & Access (`permissions-access/`)](#permissions--access)
    *   [Security & Auditing (`security-auditing/`)](#security--auditing)
    *   [System Monitoring (`system-monitoring/`)](#system-monitoring)
    *   [Logging & Reporting (`logging-reporting/`)](#logging--reporting)
    *   [Backup & Recovery (`backup-recovery/`)](#backup--recovery)
    *   [Virtualization (`virtualization/`)](#virtualization)
    *   [Cloud Management (`cloud-management/`)](#cloud-management)
    *   [Database Management (`database-management/`)](#database-management)
    *   [Application Management (`application-management/`)](#application-management)
    *   [Hardware & Inventory (`hardware-inventory/`)](#hardware--inventory)
    *   [Automation & Scheduling (`automation-scheduling/`)](#automation--scheduling)
    *   [Text Processing (`text-processing/`)](#text-processing)
    *   [Performance & Testing (`performance-testing/`)](#performance--testing)
    *   [Utilities (`utilities/`)](#utilities)
*   [Contributing](#contributing)
*   [License](#license)
*   [Disclaimer](#disclaimer)

## Getting Started

Follow these steps to get a local copy of the toolkit and start using the scripts.

### Prerequisites

Most scripts are written for `bash` and standard Linux/Unix environments. Specific scripts may have additional dependencies (e.g., `rsync`, `nmap`, `nc`, `curl`, specific command-line tools). Check the comments within each script or any `README.md` file inside the specific category folder for detailed requirements.

*   **Common Tools:** `git` (for cloning), `bash`, `coreutils` (ls, chmod, chown, etc.).
*   **Script-Specific Tools:** Refer to individual script comments or category READMEs.

### Installation

Clone the repository to your local machine:

```
git clone https://github.com/0xbaha/sysadmin-toolkit.git
cd sysadmin-toolkit
```

## Usage

1.  **Navigate:** Change into the directory containing the script you want to use (e.g., `cd networking/`).
2.  **Permissions:** Ensure the script has execute permissions: `chmod +x script_name.sh`.
3.  **Review:** **Always review the script's code before executing it**, especially if it performs modifications (e.g., file changes, permission changes, network configuration) or runs as root. Understand what it does to avoid unintended consequences.
4.  **Execute:** Run the script, typically using `./script_name.sh`.
5.  **Arguments/Options:** Some scripts may accept arguments or have configurable options. Check the comments within the script file or the category `README.md` for usage instructions.

## Repository Structure

The repository is organized using a comprehensive set of functional categories directly under the root directory. Empty categories serve as placeholders for future additions.

```
sysadmin-toolkit/
├── .git/
├── .gitignore
├── LICENSE
├── README.md
│
├── application-management/
│ └── .sh # Scripts like update_chrome.sh
├── automation-scheduling/ # (No scripts yet)
├── backup-recovery/ # (No scripts yet)
├── cloud-management/ # (No scripts yet)
├── configuration-management/ # (No scripts yet)
├── database-management/ # (No scripts yet)
├── hardware-inventory/ # (No scripts yet)
├── logging-reporting/ # (No scripts yet)
├── networking/
│ └── .sh # Scripts like add_google_ranges, check_domain, check_port*
├── os-management/
│ └── *.sh # Scripts like clean_up_repo.sh
├── performance-testing/
│ └── .sh # Scripts like stress_test_, check_storage_speed.sh
├── permissions-access/
│ └── *.sh # Scripts like parallel_chown.sh
├── security-auditing/ # (No scripts yet)
├── storage-file-systems/
│ └── .sh # Scripts like rsync_mirror.sh, generate_test_files.sh
├── system-monitoring/
│ └── .sh # Scripts like remote_check, remote_collect_server_data.sh
├── text-processing/ # (No scripts yet)
├── user-group-management/
│ └── .sh # Scripts like check_usernames, reset_homes.sh
├── utilities/
│ └── *.sh # Scripts like obfuscate.sh, auto_set_wallpaper.sh
└── virtualization/
└── .sh # All proxmox_ scripts, collect_proxmox_vm.sh
```

*Note: Each category folder may optionally contain its own `README.md` for specific details.*

## Script Categories

Scripts are organized into the following potential categories. Existing scripts have been placed in the most relevant category.

### OS Management (`os-management/`)
Scripts for managing the operating system, including installation, updates, patching, reboots, and service management.
*   `clean_up_repo.sh`: Cleans up system package repositories (e.g., apt cache).

### Configuration Management (`configuration-management/`)
Scripts to automate system configuration, apply settings consistently, or manage configuration files.
*(No scripts in this category yet)*

### Networking (`networking/`)
Managing network interfaces, firewall rules, connectivity testing, DNS/DHCP tasks, network monitoring.
*   `add_google_ranges_to_fortigate.sh`: Adds Google IP ranges to a FortiGate firewall.
*   `check_domain_availability.sh`: Checks if a domain name is available.
*   `check_ip.sh`: Validates and analyzes IP addresses.
*   `check_port_nc.sh`: Checks if a specific port is open using Netcat (`nc`).
*   `check_port_nmap.sh`: Scans and checks for open ports using `nmap`.

### Storage & File Systems (`storage-file-systems/`)
Managing disk space, partitions, file systems, backups, file operations, and data synchronization.
*   `rsync_mirror.sh`: Synchronizes files and directories using rsync.
*   `generate_test_files_100.sh`: Generates 100 small test files.
*   `generate_test_files_100k.sh`: Generates 100,000 test files for large-scale testing.

### User & Group Management (`user-group-management/`)
Creating, deleting, modifying users/groups, managing passwords, checking account status.
*   `check_usernames_github_twitter.sh`: Checks for the availability of specified usernames on GitHub and Twitter.
*   `reset_homes.sh`: Resets home directories for specified non-system users. **Use with extreme caution.**

### Permissions & Access (`permissions-access/`)
Managing file/directory permissions, ownership, access control lists (ACLs), sudo configurations.
*   `parallel_chown.sh`: Modifies file/directory ownership in parallel for potentially faster processing on large numbers of files.

### Security & Auditing (`security-auditing/`)
Scripts for security checks, vulnerability scanning, hardening systems, managing certificates, security log analysis.
*(No scripts in this category yet)*

### System Monitoring (`system-monitoring/`)
Checking system resources (CPU, RAM, Disk I/O), application status, service health, performance metrics.
*   `remote_check_df_lsblk.sh`: Gathers disk usage (`df`) and block device (`lsblk`) information from remote servers.
*   `remote_check_du.sh`: Checks disk usage (`du`) on remote servers.
*   `remote_collect_server_data.sh`: Collects and aggregates various system data points from remote servers.

### Logging & Reporting (`logging-reporting/`)
Managing log files (rotation, archiving), parsing logs, generating reports from system data or logs.
*(No scripts in this category yet)*

### Backup & Recovery (`backup-recovery/`)
Scripts for automating backups of files, databases, or system configurations, and potentially assisting with recovery processes.
*(No scripts in this category yet)*

### Virtualization (`virtualization/`)
Managing virtual machines and containers (e.g., Proxmox, KVM, Docker, VMware). Includes creation, deletion, status checks, resource allocation.
*   `prtg-sensor-for-proxmox.sh`: Custom sensor script for integrating Proxmox monitoring with PRTG.
*   `proxmox_check_data2_storage.sh`: Checks storage usage on a Proxmox storage named 'data2'.
*   `proxmox_check_local_lvm_storage.sh`: Monitors 'local-lvm' storage usage on Proxmox.
*   `proxmox_check_local_storage.sh`: Monitors 'local' storage usage on Proxmox.
*   `proxmox_check_offline_vm.sh`: Lists all VMs currently in an offline state on Proxmox.
*   `proxmox_check_online_vm.sh`: Lists all VMs currently in an online state on Proxmox.
*   `collect_proxmox_vm.sh`: Collects detailed information about Proxmox VMs.

### Cloud Management (`cloud-management/`)
Interacting with cloud provider APIs (AWS, Azure, GCP) for resource management, deployment, or monitoring.
*(No scripts in this category yet)*

### Database Management (`database-management/`)
Scripts for database backup, user management, simple queries, or maintenance tasks (if applicable).
*(No scripts in this category yet)*

### Application Management (`application-management/`)
Scripts for deploying, configuring, or managing specific applications (e.g., web servers, mail servers).
*   `update_chrome.sh`: Script to update Google Chrome browser.

### Hardware & Inventory (`hardware-inventory/`)
Scripts to gather hardware information, list devices, or manage hardware-related settings.
*(No scripts in this category yet)*

### Automation & Scheduling (`automation-scheduling/`)
Scripts focused on automating complex workflows, scheduling tasks via cron or other schedulers.
*(No scripts in this category yet)*

### Text Processing (`text-processing/`)
Utilities for manipulating text files, parsing data, formatting output (using tools like `awk`, `sed`, `grep`).
*(No scripts in this category yet)*

### Performance & Testing (`performance-testing/`)
Scripts designed to stress test systems or components, measure performance benchmarks.
*   `stress_test_dns_server.sh`: Performs a stress test on a DNS server.
*   `stress_test_local_resources.sh`: Tests local server CPU/memory/IO resources under load.
*   `check_storage_speed.sh`: Measures storage read/write speed, potentially across multiple servers.

### Utilities (`utilities/`)
General-purpose helper scripts, environment setup, miscellaneous tasks that don't fit neatly elsewhere.
*   `obfuscate.sh`: Provides simple obfuscation for shell scripts.
*   `auto_set_wallpaper.sh`: Automatically sets the desktop wallpaper (environment-dependent).

## Contributing

Contributions are welcome! If you have ideas for improvements, new scripts (especially for the empty categories!), or find bugs, please feel free to:

1.  **Open an Issue:** Discuss the change you wish to make or report a bug.
2.  **Fork the Repository:** Create your own copy of the project.
3.  **Create a Branch:** Make your changes in a dedicated branch (`git checkout -b feature/AmazingFeature`).
4.  **Commit Your Changes:** (`git commit -m 'Add some AmazingFeature'`)
5.  **Push to the Branch:** (`git push origin feature/AmazingFeature`)
6.  **Open a Pull Request:** Submit your changes for review.

Please ensure any submitted scripts are well-commented, explaining their purpose, usage, and any dependencies. Place the script in the most relevant category folder and consider adding or updating the category `README.md` if necessary.

## License

Distributed under the MIT License. See `LICENSE` file for more information.

## Disclaimer

The scripts in this repository are provided "as is" without warranty of any kind. **You assume full responsibility for any consequences resulting from their use.** Always test scripts in a non-production environment first and review the code carefully before execution, especially those involving system modifications, permissions changes, or stress testing. The authors are not liable for any damage or data loss caused by these scripts.
