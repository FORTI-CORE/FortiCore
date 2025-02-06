#!/bin/bash
# FortiCore Complete Installation Script
# Version 2.0 - System-wide Installation

# Configuration
INSTALL_DIR="/opt/forticore"
VENV_DIR="$INSTALL_DIR/venv"
BIN_LINK="/usr/local/bin/ftcore"
TOOLS_DIR="$INSTALL_DIR/tools"
REQUIREMENTS="requirements.txt"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Error handling
set -euo pipefail
trap 'echo -e "${RED}[!] Installation failed. Cleaning up...${NC}"; rm -rf "$INSTALL_DIR"; exit 1' ERR

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] Please run as root${NC}" >&2
    exit 1
fi

# Clean previous installation
cleanup() {
    echo -e "${YELLOW}[!] Removing previous installation...${NC}"
    rm -rf "$INSTALL_DIR"
    rm -f "$BIN_LINK"
}

# Verify Python version
verify_python() {
    echo -e "${GREEN}[+] Verifying Python installation...${NC}"
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}[!] Python 3 not found!${NC}"
        exit 1
    fi
    python3 -m venv --help >/dev/null 2>&1 || {
        echo -e "${RED}[!] python3-venv package required${NC}"
        exit 1
    }
}

# Install system dependencies
install_dependencies() {
    echo -e "${GREEN}[+] Installing system dependencies...${NC}"
    apt-get update && apt-get install -y \
        python3 \
        python3-venv \
        python3-dev \
        python3-pip \
        git \
        nmap \
        sqlmap \
        golang \
        ruby \
        gem \
        build-essential \
        libssl-dev \
        libffi-dev \
        libxml2-dev \
        libxslt-dev
}

# Setup virtual environment
setup_venv() {
    echo -e "${GREEN}[+] Setting up Python virtual environment...${NC}"
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip wheel setuptools
}

# Install Python requirements
install_requirements() {
    echo -e "${GREEN}[+] Installing Python requirements...${NC}"
    if [ -f "$REQUIREMENTS" ]; then
        pip install -r "$REQUIREMENTS"
    else
        pip install \
            colorama \
            python-nmap \
            requests \
            questionary \
            httpx \
            jinja2 \
            pyyaml \
            aiohttp \
            dnspython
    fi
}

# Install security tools
install_tools() {
    echo -e "${GREEN}[+] Installing security tools...${NC}"
    mkdir -p "$TOOLS_DIR"
    
    # XSStrike
    echo -e "${YELLOW}[*] Installing XSStrike...${NC}"
    if [ -d "$TOOLS_DIR/XSStrike" ]; then
        git -C "$TOOLS_DIR/XSStrike" pull
    else
        git clone https://github.com/s0md3v/XSStrike "$TOOLS_DIR/XSStrike"
    fi
    pip install -r "$TOOLS_DIR/XSStrike/requirements.txt"
    ln -sf "$TOOLS_DIR/XSStrike/xsstrike.py" /usr/local/bin/xsstrike
    
    # Nuclei
    echo -e "${YELLOW}[*] Installing Nuclei...${NC}"
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    ln -sf ~/go/bin/nuclei /usr/local/bin/nuclei
    
    # Subfinder
    echo -e "${YELLOW}[*] Installing Subfinder...${NC}"
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    ln -sf ~/go/bin/subfinder /usr/local/bin/subfinder
}

# Install FortiCore package
install_forticore() {
    echo -e "${GREEN}[+] Installing FortiCore...${NC}"
    if [ -f "setup.py" ]; then
        pip install -e .
    else
        echo -e "${YELLOW}[!] setup.py not found, installing as module${NC}"
        mkdir -p "$INSTALL_DIR/src"
        cp -r . "$INSTALL_DIR/src/"
        pip install "$INSTALL_DIR/src"
    fi
}

# Create launcher
create_launcher() {
    echo -e "${GREEN}[+] Creating system launcher...${NC}"
    cat > "$BIN_LINK" << EOF
#!/bin/bash
source "$VENV_DIR/bin/activate"
python -m forticore "\$@"
EOF
    chmod +x "$BIN_LINK"
}

# Verify installation
verify_installation() {
    echo -e "${GREEN}[+] Verifying installation...${NC}"
    if command -v ftcore >/dev/null 2>&1; then
        echo -e "${GREEN}[✓] Installation successful!${NC}"
        echo -e "Run with: ftcore -u example.com"
    else
        echo -e "${RED}[!] Installation verification failed!${NC}"
        exit 1
    fi
}

# Main installation flow
main() {
    cleanup
    verify_python
    install_dependencies
    setup_venv
    install_requirements
    install_tools
    install_forticore
    create_launcher
    verify_installation
}

# Execute
main