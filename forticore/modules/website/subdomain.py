from ...core.scanner import BaseScanner
import subprocess
import requests
from typing import Set, Dict, Any
from pathlib import Path

class SubdomainScanner(BaseScanner):
    def __init__(self, target: str, report_format: str = "html"):
        super().__init__(target, f"scans/{target}", report_format)
        self.subdomains: Set[str] = set()
        self.alive_domains: list = []
        self.vulnerabilities: Dict[str, list] = {}

    def run_subfinder(self) -> Set[str]:
        try:
            result = subprocess.run(
                ["subfinder", "-d", self.target],
                capture_output=True,
                text=True
            )
            return set(result.stdout.splitlines())
        except Exception as e:
            self.logger.error(f"Subfinder failed: {e}")
            return set()

    def run_amass(self) -> Set[str]:
        try:
            result = subprocess.run(
                ["amass", "enum", "-passive", "-d", self.target],
                capture_output=True,
                text=True
            )
            return set(result.stdout.splitlines())
        except Exception as e:
            self.logger.error(f"Amass failed: {e}")
            return set()

    def check_alive_domains(self):
        for subdomain in self.subdomains:
            try:
                response = requests.head(f"http://{subdomain}", timeout=5)
                if response.status_code == 200:
                    self.alive_domains.append(subdomain)
                    self.logger.info(f"Found alive domain: {subdomain}")
            except:
                continue

    def run(self) -> Set[str]:
        self.logger.info(f"Starting subdomain enumeration for {self.target}")
        self.setup()
        
        # Collect subdomains
        self.subdomains.update(self.run_subfinder())
        self.subdomains.update(self.run_amass())

        # Save raw results
        output_file = self.output_dir / "subdomains.txt"
        output_file.write_text("\n".join(sorted(self.subdomains)))

        # Check alive domains
        self.check_alive_domains()

        # Prepare scan results
        self.scan_results = {
            "target": self.target,
            "summary": {
                "total_subdomains": len(self.subdomains),
                "alive_domains": len(self.alive_domains)
            },
            "details": {
                "all_subdomains": list(sorted(self.subdomains)),
                "alive_domains": sorted(self.alive_domains)
            }
        }

        # Generate report
        report_path = self.generate_report(
            self.scan_results,
            f"{self.target}_subdomain_scan"
        )
        
        if report_path:
            self.logger.info(f"Scan report available at: {report_path}")
        
        return self.subdomains
