#!/bin/bash

# NAME: dos2unix_git_repo.sh
# PURPOSE: Runs dos2unix recursively on all files currently tracked by Git
#          in the repository, ensuring consistent LF line endings.
# WARNING: Modifies files in place. Ensure you have committed or backed up
#          any important changes before running.

set -euo pipefail # Exit on error, unset variable, or pipe failure

# --- Configuration ---
# Number of parallel processes to use (uses 'nproc' if available)
PROCESSORS=1
if command -v nproc &> /dev/null; then
  PROCESSORS=$(nproc)
  echo "INFO: Using $PROCESSORS processor(s) for conversion."
else
  echo "WARN: 'nproc' command not found. Running dos2unix sequentially." >&2
fi

# Batch size for xargs (process files in chunks)
BATCH_SIZE=50

# --- Dependency Checks ---
if ! command -v dos2unix &> /dev/null; then
  echo "ERROR: 'dos2unix' command not found. Please install it." >&2
  echo " (e.g., 'sudo apt install dos2unix' or 'sudo yum install dos2unix')" >&2
  exit 1
fi

if ! command -v git &> /dev/null; then
  echo "ERROR: 'git' command not found. Please install it." >&2
  exit 1
fi

# --- Safety Check ---
if ! git rev-parse --is-inside-work-tree &> /dev/null; then
  echo "ERROR: This script must be run from within a Git repository." >&2
  exit 1
fi

echo "INFO: Starting dos2unix conversion for files tracked by Git..."
echo "INFO: Processing files in batches of ${BATCH_SIZE} using ${PROCESSORS} parallel process(es)."

# --- Execution ---
# 1. git ls-files -z: Lists all files tracked by Git, null-terminated (-z).
#    This handles filenames with spaces or special characters correctly
#    and inherently excludes the .git directory and respects .gitignore [5].
# 2. xargs -0: Reads null-terminated input.
# 3. xargs -r: Ensures dos2unix isn't run if no files are found.
# 4. xargs -n ${BATCH_SIZE}: Passes files in batches to dos2unix.
# 5. xargs -P ${PROCESSORS}: Runs multiple dos2unix commands in parallel [3, 6].
# 6. dos2unix: Converts the files passed by xargs.
if git ls-files -z | xargs -0 -r -n "${BATCH_SIZE}" -P "${PROCESSORS}" dos2unix; then
  echo "SUCCESS: dos2unix conversion completed successfully for Git-tracked files."
else
  # xargs returns non-zero if any invocation of the command fails
  echo "ERROR: One or more files failed conversion during the dos2unix process." >&2
  exit 1
fi

exit 0
