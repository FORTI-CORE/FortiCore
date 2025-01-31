#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Update package list
apt update

# Install required system dependencies
apt install -y python3 python3-pip figlet

# Install required pentesting tools
apt install -y nmap dirb nikto dnsmap hashcat hydra john medusa ncrack netcat sqlmap

# Install additional tools
apt install -y subfinder amass

# Install the Python package
pip3 install -e .

# Make the command available system-wide
chmod +x forticore/__main__.py

echo "FortiCore has been installed successfully!"
echo "You can now run it by typing 'ftcore' in your terminal." 