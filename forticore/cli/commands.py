from typing import Dict, Any, Callable
from ..modules.website.subdomain import SubdomainScanner
from colorama import Fore, Style
from ..modules.database import DatabaseScanner

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
            "--d":{
                "func":self.database_info,
                "help":"Scan a parametrized website (e.g., -d example.com?id=1"
            },
            "-v": {
                "func": self.show_version,
                "help": "Show version information"
            },
            "--version": {
                "func": self.show_version,
                "help": "Show version information"
            }
        }

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
        """Handle website scanning"""
        if not domain:
            print(f"{Fore.RED}Error: Please provide a domain (e.g., -u example.com){Style.RESET_ALL}")
            return

        try:
            print(f"\n{Fore.BLUE}[*] Starting scan for {domain}{Style.RESET_ALL}\n")
            scanner = SubdomainScanner(domain)
            subdomains = scanner.run()
            
            
            if not subdomains:
                print(f"\n{Fore.YELLOW}[!] No results found for {domain}{Style.RESET_ALL}")
                return
                
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error during scan: {e}{Style.RESET_ALL}")
    def database_info(self, website:str=None, *args) -> None:
        """Handle database scanning"""
        if not website:
            print(f"{Fore.RED}Error: Please provide a parametrized website (e.g., -d example.com?id=1){Style.RESET_ALL}")
            return
        try:
            print(f"\n{Fore.BLUE}[*] Start scan for {website}{Style.RESET_ALL}\n")
            database = DatabaseScanner(website)
            databases=database.run_sqlmap()
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error during scan: {e}{Style.RESET_ALL}")
          
    def show_version(self, *args) -> None:
        """Display version information"""
        print(f"\n{Fore.BLUE}FortiCore v1.0.0{Style.RESET_ALL}")
        print("A comprehensive penetration testing framework")
        print()
