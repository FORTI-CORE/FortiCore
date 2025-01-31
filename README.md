# FortiCore

A comprehensive penetration testing framework that combines multiple tools to streamline the pentesting process.

## Installation

### Quick Install (Kali Linux)

```bash
git clone https://github.com/yourusername/forticore.git
cd forticore
sudo ./install.sh
```


### Manual Installation


Clone the repository

```bash
git clone https://github.com/yourusername/forticore.git
cd forticore
```


Install dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-pip figlet nmap dirb nikto
```

Install Python package
```bash
pip3 install -e .
```


## Usage

After installation, you can run FortiCore using:

bash
ftcore

This will launch the FortiCore terminal interface, where you can access various modules and tools.


Basic commands:
- Website scanning: `ftcore -u example.com`
- Server scanning: `ftcore -s example.com`
- Database scanning: `ftcore -d example.com`
- Help: `ftcore -h`

## Report Formats

FortiCore supports multiple report formats:
- HTML (default)
- JSON
- CSV
- YAML

To specify a report format:

```bash
ftcore -u example.com -format json
```

