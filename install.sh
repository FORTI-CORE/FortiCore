#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Update package lists
apt update

# Install system dependencies
apt install -y python3 python3-pip python3-venv golang-go figlet

# Install required pentesting tools
apt install -y nmap dirb nikto dnsmap hashcat hydra john medusa ncrack netcat sqlmap subfinder amass

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python packages in virtual environment
pip3 install -r requirements.txt

# Install Go-based tools
echo "Installing Go-based security tools..."
GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
GO111MODULE=on go install -v github.com/tomnomnom/assetfinder@latest
GO111MODULE=on go install -v github.com/ffuf/ffuf@latest
GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Add Go binaries to PATH
echo 'export PATH=$PATH:/root/go/bin' >> ~/.bashrc

# Create wrapper script for ftcore
cat > /usr/local/bin/ftcore << 'EOF'
#!/bin/bash
VENV_PATH="$(dirname $(dirname $(readlink -f $0)))/venv"
source "$VENV_PATH/bin/activate"
python3 -m forticore "$@"
EOF

# Make wrapper script executable
chmod +x /usr/local/bin/ftcore

# Install the package in development mode
pip3 install -e .

echo "FortiCore has been installed successfully!"
echo "You can now run it by typing 'ftcore' in your terminal."

# Deactivate virtual environment
deactivate 