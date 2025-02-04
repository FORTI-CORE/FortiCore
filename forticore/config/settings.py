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
        "zenmap",
        "sublist3r",
        "assetfinder",
        "httpx",
        "httprobe",
        "whatweb",
        "nuclei",
        "xsstrike",
        "wafw00f",
        "jinja2"
    ],
    "optional": [
        "massdns",
        "gowitness",
        "wappalyzer-cli"
    ]
}

# Scanning configurations
SCAN_TIMEOUT = 300  # increased timeout for comprehensive scans
MAX_THREADS = 20    # increased thread count
RETRY_COUNT = 3     # number of retries for failed tools
USER_AGENT = "FortiCore Scanner v1.0"

# API Keys (move to environment variables in production)
API_KEYS = {
    "securitytrails": "",
    "censys": "",
    "shodan": ""
}
