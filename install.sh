#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Update package lists
apt update

# Install basic requirements
apt install -y python3 python3-pip golang-go figlet

# Install required pentesting tools
apt install -y nmap dirb nikto dnsmap hashcat hydra john medusa ncrack netcat sqlmap

# Install Go-based tools
echo "Installing Go-based security tools..."
GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
GO111MODULE=on go install -v github.com/tomnomnom/assetfinder@latest
GO111MODULE=on go install -v github.com/ffuf/ffuf@latest
GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install additional tools
apt install -y subfinder amass

# Install the Python package
pip3 install -e .

# Install Python-based tools
pip3 install xsstrike
pip3 install wafw00f
pip3 install whatweb
pip3 install -r requirements.txt

# Add Go binaries to PATH
echo 'export PATH=$PATH:/root/go/bin' >> ~/.bashrc
source ~/.bashrc

# Make script executable
chmod +x install.sh

echo "FortiCore has been installed successfully!"
echo "You can now run it by typing 'ftcore' in your terminal." 