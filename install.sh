#!/bin/bash
# FortiCore Safe Installation Script
# Maintains system stability while adding new components

# Configuration - Adjust these based on your needs
FORTICORE_DIR="/opt/forticore"
VENV_PATH="$FORTICORE_DIR/venv"
BIN_LINK="/usr/local/bin/ftcore"
TOOL_INSTALL_DIR="$FORTICORE_DIR/tools"

# Exit on error and prevent partial installations
set -euo pipefail

# Check root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo -e "\033[1;31m[!] Please run as root\033[0m" >&2
    exit 1
fi

# Cleanup function for failed installations
cleanup() {
    echo -e "\n\033[1;33m[!] Installation failed. Performing cleanup...\033[0m"
    rm -rf "$FORTICORE_DIR" || true
    exit 1
}
trap cleanup ERR INT TERM

# Check existing installations
check_existing() {
    echo -e "\033[1;34m[i] Checking system compatibility...\033[0m"
    
    # Check conflicting files
    local conflict_files=(
        "$BIN_LINK"
        "/usr/local/bin/xsstrike"
        "/usr/local/bin/nuclei"
    )
    
    for file in "${conflict_files[@]}"; do
        if [ -f "$file" ]; then
            echo -e "\033[1;31m[!] Conflict found: $file exists!\033[0m" >&2
            echo -e "\033[1;33m[?] Choose: (1) Backup and replace, (2) Skip installation, (3) Abort\033[0m"
            read -r choice
            case $choice in
                1) mv "$file" "${file}.bak-$(date +%s)" ;;
                2) echo -e "\033[1;33m[i] Skipping $file installation...\033[0m"; return 1 ;;
                3) exit 1 ;;
                *) echo -e "\033[1;31m[!] Invalid choice. Aborting.\033[0m"; exit 1 ;;
            esac
        fi
    done
}

# Install system dependencies safely
install_dependencies() {
    echo -e "\033[1;34m[i] Installing system dependencies...\033[0m"
    
    # Essential packages
    apt-get update && apt-get install -y \
        python3 \
        python3-venv \
        python3-dev \
        git \
        libssl-dev \
        libffi-dev \
        nmap \
        sqlmap
    
    # Optional tools (install only if missing)
    command -v go >/dev/null || apt-get install -y golang
    command -v gem >/dev/null || apt-get install -y ruby-full
}

# Install FortiCore components
install_forticore() {
    echo -e "\033[1;34m[i] Setting up FortiCore environment...\033[0m"
    
    # Create directory structure
    mkdir -p "$FORTICORE_DIR" "$TOOL_INSTALL_DIR"
    chmod 755 "$FORTICORE_DIR"
    
    # Python virtual environment
    python3 -m venv "$VENV_PATH"
    source "$VENV_PATH/bin/activate"
    
    # Install Python requirements
    pip install --upgrade pip wheel setuptools
    pip install -r requirements.txt
    
    # Install tools in isolated directory
    install_security_tools
    
    # Create launcher script
    echo -e "\033[1;34m[i] Creating FortiCore launcher...\033[0m"
    cat > "$BIN_LINK" << EOF
#!/bin/bash
source "$VENV_PATH/bin/activate"
python -m forticore "$@"
EOF
    chmod 755 "$BIN_LINK"
    chmod +x "$BIN_LINK"
}

# Security tools installation with version control
install_security_tools() {
    echo -e "\033[1;34m[i] Installing security tools...\033[0m"
    
    # XSStrike
    if ! command -v xsstrike >/dev/null; then
        echo -e "\033[1;32m[+] Installing XSStrike...\033[0m"
        git clone https://github.com/s0md3v/XSStrike "$TOOL_INSTALL_DIR/XSStrike"
        pip install -r "$TOOL_INSTALL_DIR/XSStrike/requirements.txt"
        
        # Create proper wrapper script
        cat > /usr/local/bin/xsstrike << 'EOF'
#!/usr/bin/env python3
import sys
from XSStrike.core import main

if __name__ == "__main__":
    sys.argv[0] = 'xsstrike'
    main()
EOF
        chmod +x /usr/local/bin/xsstrike
    fi
    
    # Nuclei (user-space installation)
    if ! command -v nuclei >/dev/null; then
        echo -e "\033[1;32m[+] Installing Nuclei...\033[0m"
        go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
        ln -sf ~/go/bin/nuclei /usr/local/bin/nuclei
    fi
    
    # Subfinder (user-space installation)
    if ! command -v subfinder >/dev/null; then
        echo -e "\033[1;32m[+] Installing Subfinder...\033[0m"
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        ln -sf ~/go/bin/subfinder /usr/local/bin/subfinder
    fi
}

# Post-installation checks
verify_installation() {
    echo -e "\n\033[1;34m[i] Verifying installation...\033[0m"
    
    local success=0
    declare -A tools=(
        ["ftcore"]="FortiCore main script"
        ["xsstrike"]="XSStrike vulnerability scanner"
        ["nuclei"]="Nuclei template scanner"
        ["subfinder"]="Subdomain discovery tool"
    )
    
    for tool in "${!tools[@]}"; do
        if command -v "$tool" >/dev/null; then
            echo -e "\033[1;32m[✓] ${tools[$tool]} installed\033[0m"
            ((success++))
        else
            echo -e "\033[1;31m[✗] ${tools[$tool]} missing\033[0m" >&2
        fi
    done
    
    if [ $success -ne ${#tools[@]} ]; then
        echo -e "\n\033[1;31m[!] Some components failed to install!\033[0m" >&2
        echo -e "\033[1;33m[i] Try manual installation for missing components\033[0m"
        exit 1
    fi
}

# Main installation flow
main() {
    check_existing
    install_dependencies
    install_forticore
    verify_installation
    
    echo -e "\n\033[1;32m[✓] FortiCore installed successfully!\033[0m"
    echo -e "\033[1;33m[i] Usage: ftcore -u <target-domain>\033[0m"
}

# Execute main function
main