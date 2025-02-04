from typing import Dict, Any, Callable
from ..modules.website.subdomain import SubdomainScanner
from ..modules.website.vulnscan import VulnerabilityScanner
from colorama import Fore, Style
import questionary
from pathlib import Path

class CommandHandler:
    def __init__(self):
        self.commands: Dict[str, Dict[str, Any]] = {
            "-h": {
                "func": self.show_help,
                "help": "Show this help message"
            },
            "--help": {
                "func": self.show_help,
                "help": "Show this help message"
            },
            "-u": {
                "func": self.website_info,
                "help": "Scan a website (e.g., -u example.com)"
            },
            "--url": {
                "func": self.website_info,
                "help": "Scan a website (e.g., --url example.com)"
            },
            "-v": {
                "func": self.show_version,
                "help": "Show version information"
            },
            "--version": {
                "func": self.show_version,
                "help": "Show version information"
            },
            "--format": {
                "func": self.set_report_format,
                "help": "Set report format (html, json, yaml, csv)"
            }
        }
        self.report_format = "html"

    def handle_command(self, command: str, *args) -> None:
        """Handle the given command with its arguments"""
        if command in self.commands:
            self.commands[command]["func"](*args)
        else:
            print(f"{Fore.RED}Error: Unknown command '{command}'{Style.RESET_ALL}")
            self.show_help()

    def show_help(self, *args) -> None:
        """Display help information"""
        print(f"\n{Fore.BLUE}FortiCore - Penetration Testing Framework{Style.RESET_ALL}")
        print("\nUsage:")
        print("  ftcore [command] [arguments]\n")
        print("Commands:")
        for cmd, info in self.commands.items():
            if cmd.startswith("--"):  # Skip short versions of commands
                print(f"  {cmd:<12} {info['help']}")
        print()

    def website_info(self, domain: str = None, *args) -> None:
        """Handle website scanning with enhanced functionality"""
        if not domain:
            print(f"{Fore.RED}Error: Please provide a domain (e.g., -u example.com){Style.RESET_ALL}")
            return

        try:
            print(f"\n{Fore.BLUE}[*] Starting scan for {domain}{Style.RESET_ALL}\n")
            
            # Initialize scanners
            subdomain_scanner = SubdomainScanner(domain)
            vuln_scanner = VulnerabilityScanner(domain)
            
            # Run subdomain enumeration
            subdomains = subdomain_scanner.run()
            
            if not subdomains:
                print(f"\n{Fore.YELLOW}[!] No subdomains found for {domain}{Style.RESET_ALL}")
                return
            
            # Ask user if they want to proceed with vulnerability scanning
            should_scan_vulns = questionary.confirm(
                "Would you like to scan for vulnerabilities?",
                default=True
            ).ask()
            
            if should_scan_vulns:
                for subdomain in subdomains:
                    scan_results = vuln_scanner.scan_target(subdomain)
                    if scan_results.get('vulnerabilities'):
                        print(f"\n{Fore.RED}[!] Vulnerabilities found in {subdomain}{Style.RESET_ALL}")
                        for vuln in scan_results['vulnerabilities']:
                            print(f"  - {vuln['type']}: {vuln['description']}")
                
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error during scan: {e}{Style.RESET_ALL}")

    def show_version(self, *args) -> None:
        """Display version information"""
        print(f"\n{Fore.BLUE}FortiCore v1.0.0{Style.RESET_ALL}")
        print("A comprehensive penetration testing framework")
        print()

    def set_report_format(self, format_type: str = "html", *args) -> None:
        """Set the report format"""
        valid_formats = ["html", "json", "yaml", "csv"]
        if format_type.lower() in valid_formats:
            self.report_format = format_type.lower()
            print(f"{Fore.GREEN}Report format set to: {format_type}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Invalid format. Please use one of: {', '.join(valid_formats)}{Style.RESET_ALL}")