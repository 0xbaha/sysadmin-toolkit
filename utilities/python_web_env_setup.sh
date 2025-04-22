#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

# === Configuration ===
# Base system packages - Python packages will be added dynamically
BASE_SYSTEM_PACKAGES=(
    build-essential # Basic C/C++ build tools (gcc, make, etc.) 
    git             # Version control system 
    nginx           # Web server / Reverse proxy 
    postgresql      # PostgreSQL database server 
    libpq-dev       # Development headers for PostgreSQL (needed by psycopg2) 
    curl            # Utility for transferring data with URLs 
    wget            # Utility for non-interactive network downloads 
    libssl-dev      # Development libraries for Secure Sockets Layer 
    libffi-dev      # Development libraries for Foreign Function Interface 
    supervisor      # Process control system (for running apps) 
    software-properties-common # Needed for add-apt-repository 
    pipx            # Install Python CLI tools in isolated environments
    # Removed python3-gunicorn to avoid default python dependency, recommend pipx install gunicorn
)

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# === Script Logic ===

echo -e "${YELLOW}Starting Python Development & Deployment Environment Setup...${NC}"

# 1. Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run with root privileges (use sudo).${NC}"
   exit 1
fi
echo -e "${GREEN}Sudo privileges check passed.${NC}"

# 2. Detect OS (Basic Check for Debian/Ubuntu)
if ! command -v apt > /dev/null; then
    echo -e "${RED}Error: 'apt' command not found. This script is designed for Debian/Ubuntu-based systems.${NC}"
    exit 1
fi
echo -e "${GREEN}Detected apt package manager.${NC}"

# 3. Update package lists
echo -e "\n${YELLOW}Updating package lists...${NC}"
if sudo apt update; then
    echo -e "${GREEN}Package lists updated successfully.${NC}"
else
    echo -e "${RED}Failed to update package lists. Please check your network connection and repository configuration.${NC}"
    exit 1
fi

# 4. Install software-properties-common (needed for PPA)
echo -e "\n${YELLOW}Ensuring 'software-properties-common' is installed...${NC}"
if sudo apt install -y software-properties-common; then
    echo -e "${GREEN}'software-properties-common' is installed.${NC}"
else
    echo -e "${RED}Failed to install 'software-properties-common'. Cannot add PPA.${NC}"
    exit 1
fi

# 5. Add Deadsnakes PPA for Python versions
echo -e "\n${YELLOW}Adding deadsnakes PPA for Python versions...${NC}"
if sudo add-apt-repository -y ppa:deadsnakes/ppa; then
    echo -e "${GREEN}Deadsnakes PPA added successfully.${NC}"
    echo -e "${YELLOW}Updating package lists again after adding PPA...${NC}"
    if ! sudo apt update; then
        echo -e "${RED}Failed to update package lists after adding PPA.${NC}"
        exit 1
    fi
    echo -e "${GREEN}Package lists updated successfully.${NC}"
else
    echo -e "${RED}Failed to add deadsnakes PPA.${NC}"
    exit 1
fi

# 6. Prompt user for Python version
PYTHON_VERSION=""
while [[ -z "$PYTHON_VERSION" ]]; do
    # Prompt the user for input [2][3]
    read -p "Enter the Python 3 version to install (e.g., 3.10, 3.11, 3.12): " PYTHON_VERSION
    # Basic validation (starts with 3. and has digits after)
    if ! [[ "$PYTHON_VERSION" =~ ^3\.[0-9]+$ ]]; then
        echo -e "${RED}Invalid format. Please enter version like '3.10', '3.11', etc.${NC}"
        PYTHON_VERSION="" # Clear variable to loop again
    fi
done
echo -e "${GREEN}Will attempt to install Python version: ${PYTHON_VERSION}${NC}"

# 7. Construct Python package names
PYTHON_PKG="python${PYTHON_VERSION}"
PYTHON_DEV_PKG="python${PYTHON_VERSION}-dev"
PYTHON_VENV_PKG="python${PYTHON_VERSION}-venv"

# Combine base packages and specific Python packages
# Now includes python3-pip along with the chosen python version
SYSTEM_PACKAGES=("${BASE_SYSTEM_PACKAGES[@]}" "${PYTHON_PKG}" "${PYTHON_DEV_PKG}" "${PYTHON_VENV_PKG}")

# 8. Install System Packages (including the chosen Python version and python3-pip)
echo -e "\n${YELLOW}Installing essential system packages including ${PYTHON_PKG} and python3-pip...${NC}"
packages_to_install=$(IFS=" "; echo "${SYSTEM_PACKAGES[*]}")
echo "Attempting to install: ${packages_to_install}"

if sudo apt install -y ${packages_to_install}; then
    echo -e "${GREEN}System packages installed successfully.${NC}"
else
    echo -e "${RED}Failed to install one or more system packages.${NC}"
    echo -e "${RED}Please check if Python version '${PYTHON_VERSION}' is available in the PPA and apt output above.${NC}"
    exit 1
fi

# 9. REMOVED: The section attempting to run ensurepip is removed entirely.
#    The pythonX.Y-venv package enables 'pythonX.Y -m venv ...'
#    The python3-pip package provides the system 'pip3' command.

# 10. Ensure pipx paths are usable (optional, good practice)
echo -e "\n${YELLOW}Ensuring pipx paths are configured (run 'pipx ensurepath' manually in your user shell if needed)...${NC}"
# Note: `pipx ensurepath` typically needs to be run by the user themselves,
# as it modifies user-specific shell configuration files (like .bashrc).
# Running it with sudo here might configure it for the root user, not the regular user.
# We'll just print a reminder.

# 11. Final Information (UPDATED Instructions)
echo -e "\n${GREEN}=====================================================================${NC}"
echo -e "${GREEN} System Preparation Script Completed! ${NC}"
echo -e "${GREEN}=====================================================================${NC}"
echo -e "\nYour system should now have the basic tools:"
echo -e "  - Python ${PYTHON_VERSION} (including -dev and -venv packages)"
echo -e "  - Standard Pip package manager ('pip3' command via python3-pip)"
echo -e "  - Build tools, git, nginx, postgresql-dev, supervisor, pipx, etc."
echo -e "\n${RED}VERY IMPORTANT - Using Pip with Python ${PYTHON_VERSION}:${NC}"
echo -e "  - The system 'pip3' command likely manages packages for the *default* system Python."
echo -e "  - To install packages specifically for Python ${PYTHON_VERSION}, you ${YELLOW}MUST${NC} use a virtual environment:"
echo -e "\n${YELLOW}Next Steps for Your Project:${NC}"
echo -e "      1. Create environment:  ${YELLOW}${PYTHON_PKG} -m venv path/to/your/venv${NC}" # Added -e
echo -e "      2. Activate environment: ${YELLOW}source path/to/your/venv/bin/activate${NC}" # Added -e
echo -e "      3. Install packages:    ${YELLOW}pip install <package_name>   # <-- This pip uses Python ${PYTHON_VERSION}${NC}" # Added -e
echo -e "      4. Deactivate when done: ${YELLOW}deactivate${NC}" # Added -e
echo -e "\n${YELLOW}Note:${NC} Database users/databases and Nginx/Supervisor configurations are NOT set up by this script and need manual configuration per project."
echo -e "${YELLOW}Note:${NC} If pipx commands don't work, you might need to run 'pipx ensurepath' and restart your shell."
echo -e "\n${YELLOW}Other Next Steps:${NC}"
echo "  - Install global tools cleanly (like Gunicorn): pipx install gunicorn"
echo "  - Configure Nginx, Supervisor, PostgreSQL, etc. per project."
echo -e "\n${YELLOW}Note:${NC} If pipx commands don't work, you might need to run 'pipx ensurepath' and restart your shell."

exit 0