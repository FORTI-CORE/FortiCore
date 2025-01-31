from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent.parent.parent

# Output directory
SCAN_DIR = BASE_DIR / "scans"

# Tool configurations
TOOLS = {
    "required": [
        "nmap",
        "subfinder",
        "amass",
        "dirb",
        "nikto",
        "dnsmap",
        "hashcat",
        "hydra",
        "john",
        "medusa",
        "ncrack",
        "netcat",
        "sqlmap",
        "zenmap"
    ],
    "optional": [
        "nuclei",
        "httpx",
        "massdns",
        "gowitness"
    ]
}

# Scanning configurations
SCAN_TIMEOUT = 5  # seconds
THREADS = 10
USER_AGENT = "FortiCore Scanner v1.0"

# API Keys (move to environment variables in production)
API_KEYS = {
    "securitytrails": "",
    "censys": "",
    "shodan": ""
}
