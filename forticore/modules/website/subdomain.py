from ...core.scanner import BaseScanner
import subprocess
import requests
import concurrent.futures
from typing import Set, Dict, Any
from pathlib import Path
from colorama import Fore, Style, init
import nmap
import urllib3
from ...utils.report_generator import ReportGenerator
from .vulnscan import VulnerabilityScanner
import asyncio
import re

# Initialize colorama
init()

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SubdomainScanner(BaseScanner):
    def __init__(self, target: str, report_format: str = "html"):
        """
        Initialize the subdomain scanner
        Args:
            target: Target domain to scan
            report_format: Format for the report (html, json, or yaml)
        """
        output_dir = f"scans/{target}"
        super().__init__(target, output_dir)
        self.subdomains: Set[str] = set()
        self.alive_domains: list = []
        self.vulnerabilities: Dict[str, Dict] = {}
        self.ports: Dict[str, list] = {}
        self.technologies: Dict[str, list] = {}
        self.report_format = report_format
        self.report_generator = ReportGenerator(output_dir)
        self.vuln_scanner = VulnerabilityScanner(target)

    def print_status(self, message: str, status: str = "INFO"):
        colors = {
            "INFO": Fore.BLUE,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED
        }
        color = colors.get(status, Fore.WHITE)
        print(f"{color}[{status}]{Style.RESET_ALL} {message}")

    def show_banner(self):
        """Display FortiCore banner"""
        banner = """
███████╗ ██████╗ ██████╗ ████████╗██╗ ██████╗ ██████╗ ██████╗ ███████╗
██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██║██╔════╝██╔═══██╗██╔══██╗██╔════╝
█████╗  ██║   ██║██████╔╝   ██║   ██║██║     ██║   ██║██████╔╝█████╗  
██╔══╝  ██║   ██║██╔══██╗   ██║   ██║██║     ██║   ██║██╔══██╗██╔══╝  
██║     ╚██████╔╝██║  ██║   ██║   ██║╚██████╗╚██████╔╝██║  ██║███████╗
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
        """
        print(f"{Fore.RED}{banner}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] A Comprehensive Penetration Testing Framework{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[*] Version: 1.0.0{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Target: {self.target}{Style.RESET_ALL}\n")

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
        self.print_status("Checking for alive domains...", "INFO")
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for subdomain in self.subdomains:
                futures.append(executor.submit(self._check_single_domain, subdomain))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.print_status(f"Found alive domain: {result}", "SUCCESS")
                except Exception as e:
                    self.logger.error(f"Error checking domain: {e}")

    def _check_single_domain(self, subdomain: str) -> str:
        try:
            for protocol in ['https://', 'http://']:
                try:
                    response = requests.head(f"{protocol}{subdomain}", 
                                          timeout=5, 
                                          verify=False)
                    if response.status_code == 200:
                        self.alive_domains.append(subdomain)
                        return subdomain
                except:
                    continue
        except:
            pass
        return ""

    def scan_ports(self, domain: str):
        self.print_status(f"Scanning ports for {domain}...", "INFO")
        nm = nmap.PortScanner()
        try:
            nm.scan(domain, arguments='-sS -sV -F --version-intensity 5')
            self.ports[domain] = []
            self.technologies[domain] = []
            
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]
                        if service['state'] == 'open':
                            self.ports[domain].append({
                                'port': port,
                                'service': service['name'],
                                'version': service.get('version', 'unknown')
                            })
                            if service.get('product'):
                                self.technologies[domain].append({
                                    'name': service['product'],
                                    'version': service.get('version', 'unknown')
                                })
        except Exception as e:
            self.print_status(f"Error scanning ports: {e}", "ERROR")

    async def scan_vulnerabilities(self, domain: str):
        """Perform comprehensive vulnerability scanning using VulnerabilityScanner"""
        self.print_status(f"Scanning vulnerabilities for {domain}...", "INFO")
        
        try:
            scan_results = await self.vuln_scanner.scan_target(domain)
            if scan_results:
                self.vulnerabilities[domain] = scan_results
                
                # Log critical and high vulnerabilities
                for vuln in scan_results.get('vulnerabilities', []):
                    if vuln.get('severity', '').lower() in ['critical', 'high']:
                        self.print_status(
                            f"Found {vuln['severity']} vulnerability in {domain}: {vuln.get('name', 'Unknown')}",
                            "WARNING"
                        )
                        
        except Exception as e:
            self.logger.error(f"Error scanning vulnerabilities for {domain}: {e}")

    async def scan_all_domains(self):
        """Scan all alive domains for vulnerabilities"""
        tasks = []
        for domain in self.alive_domains:
            tasks.append(self.scan_vulnerabilities(domain))
        
        await asyncio.gather(*tasks)

    def run(self):
        """Main execution flow"""
        self.show_banner()
        
        # Enumerate subdomains
        self.print_status("Starting subdomain enumeration...", "INFO")
        self.subdomains.update(self.run_subfinder())
        self.subdomains.update(self.run_amass())
        
        if not self.subdomains:
            self.print_status("No subdomains found!", "WARNING")
            return set()

        self.print_status(f"Found {len(self.subdomains)} subdomains", "SUCCESS")
        
        # Check alive domains
        self.print_status("Phase 2: Identifying alive domains...")
        self.check_alive_domains()
        
        # Scan ports for alive domains
        for domain in self.alive_domains:
            self.scan_ports(domain)
        
        # Run vulnerability scans asynchronously
        asyncio.run(self.scan_all_domains())
        
        # Generate report
        self.generate_final_report()
        
        return self.subdomains

    def generate_final_report(self):
        """Generate final report"""
        try:
            scan_results = self._prepare_scan_results()
            report_path = self.report_generator.generate_report(
                scan_results, 
                f"{self.target}_scan_report",
                format=self.report_format
            )
            self.print_status(f"Report generated: {report_path}", "SUCCESS")
        except Exception as e:
            self.print_status(f"Error generating report: {e}", "ERROR")

    def _prepare_scan_results(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "summary": {
                "total_subdomains": len(self.subdomains),
                "alive_domains": len(self.alive_domains),
                "total_open_ports": sum(len(ports) for ports in self.ports.values()),
                "total_vulnerabilities": sum(len(vulns['cves']) + len(vulns['findings']) 
                                          for vulns in self.vulnerabilities.values())
            },
            "details": {
                "all_subdomains": list(sorted(self.subdomains)),
                "alive_domains": sorted(self.alive_domains),
                "ports": self.ports,
                "technologies": self.technologies,
                "vulnerabilities": self.vulnerabilities
            }
        }
