# Contributing to sysadmin-toolkit

First off, thank you for considering contributing to the `sysadmin-toolkit`! We welcome contributions from the community to make this collection of scripts even more useful for system administrators and operations engineers. Whether you're fixing a bug, proposing a new script, improving documentation, or suggesting enhancements, your input is valuable.

This document provides guidelines for contributing to the project to ensure a smooth and effective collaboration process.

## Table of Contents

- [Contributing to sysadmin-toolkit](#contributing-to-sysadmin-toolkit)
  - [Table of Contents](#table-of-contents)
  - [Code of Conduct](#code-of-conduct)
  - [How Can I Contribute?](#how-can-i-contribute)
    - [Reporting Bugs](#reporting-bugs)
    - [Suggesting Enhancements or New Scripts](#suggesting-enhancements-or-new-scripts)
    - [Submitting Code Changes (Pull Requests)](#submitting-code-changes-pull-requests)
  - [Getting Started](#getting-started)
  - [Your First Code Contribution](#your-first-code-contribution)
  - [Pull Request Process](#pull-request-process)
  - [Scripting Guidelines \& Best Practices](#scripting-guidelines--best-practices)
    - [Shell \& Compatibility](#shell--compatibility)
    - [File Structure \& Naming](#file-structure--naming)
    - [Commenting \& Documentation](#commenting--documentation)
    - [Dependencies](#dependencies)
    - [Error Handling \& Robustness](#error-handling--robustness)
    - [Testing](#testing)
    - [Style \& Readability](#style--readability)
  - [Category READMEs](#category-readmes)
  - [Issue and PR Labels (Optional)](#issue-and-pr-labels-optional)
  - [Questions?](#questions)

## Code of Conduct

This project and everyone participating in it is governed by a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers. We strive to maintain a welcoming and respectful environment for everyone.

## How Can I Contribute?

There are several ways you can contribute to the `sysadmin-toolkit`:

### Reporting Bugs

If you encounter a bug or unexpected behavior in one of the scripts:

1.  **Search Existing Issues:** Check the [GitHub Issues](https://github.com/0xbaha/sysadmin-toolkit/issues) first to see if the bug has already been reported.
2.  **Open a New Issue:** If not, please open a new issue. Provide as much detail as possible:
    *   A clear and descriptive title.
    *   The name of the script and its category folder.
    *   The version of the OS and relevant tools (e.g., `bash` version, `nmap` version if applicable).
    *   Detailed steps to reproduce the bug.
    *   What you expected to happen.
    *   What actually happened (include relevant error messages or output).
    *   Any relevant configuration details.

### Suggesting Enhancements or New Scripts

Have an idea for improving an existing script or a proposal for a new script that fits the toolkit's purpose?

1.  **Search Existing Issues:** Check the [GitHub Issues](https://github.com/0xbaha/sysadmin-toolkit/issues) to see if a similar enhancement or script idea has already been suggested.
2.  **Open a New Issue:** If not, open a new issue describing your suggestion:
    *   Use a clear and descriptive title (e.g., "Enhancement: Add timeout option to check_port.sh" or "New Script Idea: Automated log rotation").
    *   Provide a detailed description of the enhancement or the purpose and functionality of the proposed new script.
    *   Explain the use case and why it would be beneficial to sysadmins.
    *   (Optional) Suggest a possible implementation approach.

### Submitting Code Changes (Pull Requests)

Improvements to existing scripts, new scripts, documentation updates, and bug fixes are primarily handled through GitHub Pull Requests (PRs). Please follow the process outlined below.

## Getting Started

Before you start coding:

1.  **Ensure Prerequisites:** Make sure you have `git` and `bash` installed. Review the general prerequisites in the main [README.md](README.md#prerequisites).
2.  **Fork & Clone:** Fork the repository to your own GitHub account and then clone your fork locally:
    ```
    git clone https://github.com/YOUR_USERNAME/sysadmin-toolkit.git
    cd sysadmin-toolkit
    ```
3.  **Set Upstream Remote:** Configure the original repository as the `upstream` remote:
    ```
    git remote add upstream https://github.com/0xbaha/sysadmin-toolkit.git
    ```

## Your First Code Contribution

Unsure where to begin?

*   Look for issues tagged `good first issue` or `help wanted`.
*   Start with something small, like fixing a typo in comments, improving documentation, or addressing a simple bug.
*   Feel free to ask questions on an issue if you need clarification before starting work.

## Pull Request Process

1.  **Sync Your Fork:** Keep your local `main` branch synchronized with the `upstream` repository:
    ```
    git checkout main
    git pull upstream main
    ```
2.  **Create a Branch:** Create a new branch for your changes, named descriptively (e.g., `fix/check-ip-timeout`, `feat/add-log-rotation-script`):
    ```
    git checkout -b your-branch-name
    ```
3.  **Make Your Changes:** Write your code, following the [Scripting Guidelines](#scripting-guidelines--best-practices). Add or modify scripts as needed.
4.  **Test:** Thoroughly test your changes locally to ensure they work as expected and don't introduce regressions.
5.  **Commit:** Commit your changes with clear, concise, and informative commit messages. Reference the relevant issue number if applicable (e.g., `git commit -m 'feat: Add timeout option to check_ip.sh (fixes #123)'`).
6.  **Push:** Push your branch to your fork on GitHub:
    ```
    git push origin your-branch-name
    ```
7.  **Open a Pull Request:** Navigate to the original `sysadmin-toolkit` repository on GitHub and open a Pull Request from your branch to the `main` branch.
    *   Provide a clear title and description for your PR.
    *   Explain the purpose of your changes and *why* they are needed.
    *   Link to any relevant issues (e.g., "Closes #123").
    *   Outline the testing you have performed.
8.  **Review & Discussion:** Project maintainers will review your PR. Be prepared to discuss your changes and make adjustments based on feedback. The maintainers aim to review PRs in a timely manner, but response times may vary.

## Scripting Guidelines & Best Practices

To maintain consistency and quality across the toolkit, please adhere to the following guidelines when contributing scripts:

### Shell & Compatibility

*   **Target Shell:** Write scripts primarily for `bash`. Use the shebang `#!/bin/bash`.
*   **Portability:** While `bash` is the target, avoid overly obscure `bash`-specific features (bashisms) if standard POSIX features suffice, unless the feature significantly improves the script. Assume a reasonably modern `bash` version (e.g., 4.x+).

### File Structure & Naming

*   **Placement:** Place new scripts in the most relevant category folder as defined in the main [README.md](README.md#script-categories). If unsure, suggest a category in your PR or issue.
*   **Naming:** Use descriptive, lowercase filenames with underscores separating words (e.g., `check_disk_usage.sh`, `backup_database.sh`). Use the `.sh` extension.

### Commenting & Documentation

*   **Header Comments:** Include comments at the top of each script explaining:
    *   Its purpose and functionality.
    *   Basic usage instructions (arguments, options).
    *   Any required dependencies (non-standard tools).
    *   (Optional) Author/Contributor and date.
*   **Inline Comments:** Use comments to explain complex logic, algorithms, or non-obvious steps (explain the *why*, not just the *what*).

### Dependencies

*   **Minimize:** Use standard Linux/Unix utilities whenever possible.
*   **Document:** Clearly list any non-standard dependencies (e.g., `nmap`, `jq`, `rsync`, specific packages) in the header comments.
*   **Check Existence (Optional but Recommended):** Consider adding checks within the script to verify if required commands exist (`command -v tool_name &> /dev/null`) and provide a helpful error message if they don't.

### Error Handling & Robustness

*   **Check Exit Codes:** Check the exit status (`$?`) of critical commands and handle potential failures gracefully.
*   **Use `set` Options (Recommended):** Consider using `set -eo pipefail` at the beginning of scripts to exit on errors (`-e`), treat unset variables as errors (`-u`, use with caution), and handle errors in pipelines (`-o pipefail`). Understand the implications before using them.
*   **Provide Useful Output:** Print informative status messages and clear error messages to standard error (`>&2`).

### Testing

*   **Manual Testing:** Thoroughly test your script in various scenarios (different inputs, edge cases, failure conditions) on a standard Linux environment before submitting.
*   **Idempotency (Where Applicable):** If a script makes configuration changes, strive to make it idempotent (running it multiple times produces the same result).

### Style & Readability

*   **Consistency:** Try to follow the general style of existing scripts.
*   **Indentation:** Use consistent indentation (e.g., 2 or 4 spaces).
*   **Variable Names:** Use descriptive variable names (e.g., `target_directory` instead of `td`). Prefer `${variable_name}` syntax for clarity.
*   **Tools:** Consider using tools like `shellcheck` to identify potential issues and improve script quality.

## Category READMEs

If you are adding a script to a category that involves complex setup, multiple related scripts, or specific configurations, please consider adding or updating a `README.md` file within that category folder. This helps users understand the scripts in that specific context.

## Issue and PR Labels (Optional)

Maintainers may use labels (e.g., `bug`, `enhancement`, `documentation`, `good first issue`) on issues and PRs to help organize work. Feel free to suggest appropriate labels when opening issues or PRs.

## Questions?

If you have questions about contributing, the project's direction, or how to approach a specific change, feel free to open an issue on GitHub and ask!

Thank you for contributing to the `sysadmin-toolkit`!
