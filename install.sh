#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Function to check and kill existing apt processes
check_apt_locks() {
    echo "Checking for existing apt processes..."
    if ps aux | grep -i apt | grep -v grep > /dev/null; then
        echo "Killing existing apt processes..."
        killall apt apt-get
        rm -f /var/lib/apt/lists/lock
        rm -f /var/cache/apt/archives/lock
        rm -f /var/lib/dpkg/lock*
        dpkg --configure -a
    fi
}

# Main installation process
echo "Starting FortiCore installation..."

# Check and remove apt locks
check_apt_locks

# Update package list
echo "Updating package list..."
apt update

# Install required system dependencies
echo "Installing system dependencies..."
DEBIAN_FRONTEND=noninteractive apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    figlet \
    nmap \
    dirb \
    nikto \
    dnsmap \
    hashcat \
    hydra \
    john \
    medusa \
    ncrack \
    netcat \
    sqlmap \
    subfinder \
    amass

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv /opt/forticore
source /opt/forticore/bin/activate

# Install Python dependencies
echo "Installing Python dependencies..."
/opt/forticore/bin/pip install --upgrade pip
/opt/forticore/bin/pip install colorama python-nmap concurrent-futures

# Install the package
echo "Installing FortiCore..."
cd "$(dirname "$0")"
/opt/forticore/bin/pip install -e .

# Create wrapper script
echo "Creating wrapper script..."
cat > /usr/local/bin/ftcore << 'EOF'
#!/bin/bash
source /opt/forticore/bin/activate
python -m forticore "$@"
EOF

chmod +x /usr/local/bin/ftcore

echo "FortiCore has been installed successfully!"
echo "You can now run it by typing 'ftcore' in your terminal."
