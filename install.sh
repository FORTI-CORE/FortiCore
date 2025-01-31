#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

9e@kgbk4@X5JJG6

# Update package list
apt update 

# Install required system dependencies
apt install -y python3 python3-pip python3-venv figlet

# Install required pentesting tools
apt install -y nmap dirb nikto dnsmap hashcat hydra john medusa ncrack netcat sqlmap

# Install additional tools
apt install -y subfinder amass

# Create virtual environment
python3 -m venv /opt/forticore
source /opt/forticore/bin/activate

# Install the Python package
cd "$(dirname "$0")"
/opt/forticore/bin/pip install -e .

# Create wrapper script
cat > /usr/local/bin/ftcore << 'EOF'
#!/bin/bash
source /opt/forticore/bin/activate
python -m forticore "$@"
EOF

# Make the wrapper executable
chmod +x /usr/local/bin/ftcore

echo "FortiCore has been installed successfully!"
echo "You can now run it by typing 'ftcore' in your terminal."
