import subprocess
import random
from ..utils.logger import Logger
from ..utils.tools import check_and_install_tools, update_tools
from ..utils.network import get_ip_address, is_private_ip
from ..config.settings import TOOLS
from ..modules.website.subdomain import SubdomainScanner

BLUE = "\033[34m"
RESET = "\033[0m"

class FortiCoreTerminal:
    def __init__(self):
        self.logger = Logger.get_logger(__name__)
        self.commands = {
            "-h": (self.display_help, 0),
            "--help": (self.display_help, 0),
            "-u": (self.website_info, 1),
            "--info": (self.website_info, 1),
            "-s": (self.server_info, 1),
            "--server": (self.server_info, 1),
            "-i": (self.find_ip_address, 1),
            "--ip-address": (self.find_ip_address, 1),
            "-d": (self.database_info, 1),
            "--database": (self.database_info, 1),
        }

    def initialize(self):
        """Initial setup and checks"""
        self._print_banner()
        self._check_environment()
        self._print_welcome()

    def _print_banner(self):
        fonts = ["slant", "banner", "block", "big", "shadow", "smscript", "lean", "standard"]
        font = random.choice(fonts)
        figlet_output = subprocess.run(["figlet", "-f", font, "FORTI CORE"], 
                                     capture_output=True, text=True)
        colored_output = f"{BLUE}{figlet_output.stdout}{RESET}"
        print(colored_output)

    def _check_environment(self):
        """Check tools and network security"""
        name = subprocess.run(["whoami"], capture_output=True, text=True)
        print(f"{name.stdout.strip().upper()} Welcome to FORTI CORE")
        
        print("Checking for the availability of required tools ...")
        check_and_install_tools(TOOLS["required"])
        print("All required tools installed")
        
        print("Updating tools ... Amount of time taken depends on your internet connection")
        update_tools()
        
        print("Checking the security of your network...")
        ip = get_ip_address()
        if not ip:
            print("Unable to determine the IP address.")
            return
            
        if is_private_ip(ip):
            print("Your network is private, make sure to keep in a safe internal organization.\n\n")
        else:
            print("Alert!! your network is public - This is risky hence connect to a private network ")
            print("Program exiting ...")
            exit()

    def _print_welcome(self):
        print("Welcome to FortiCore terminal!")
        print(f"Type {BLUE}-h {RESET}or {BLUE}--help {RESET}for a list of commands.")
        print(f"Type {BLUE}exit{RESET} or {BLUE}quit {RESET}to leave.\n")

    def display_help(self):
        help_text = """
        -h, --help            Show this help message  
        -u, --info            Gathers all information for a given website link
        -s, --server          Gathers all information about a server
        -i, --ip-address      Finds the IP address of a given website link
        -d, --database        Gathers all information about a database
        Type 'exit' or 'quit' to leave.
        """
        print(help_text)

    def website_info(self, domain: str, report_format: str = "html"):
        """
        Gather information about a website
        Args:
            domain: Target domain
            report_format: Report format (html, json, csv, or yaml)
        """
        print(f"\n{BLUE}[*] Starting scan for {domain}{RESET}\n")
        
        try:
            scanner = SubdomainScanner(domain, report_format=report_format)
            subdomains = scanner.run()
            
            if not subdomains:
                print(f"\n{BLUE}[!] No results found for {domain}{RESET}")
                return
            
        except Exception as e:
            print(f"\n{BLUE}[!] Error during scan: {e}{RESET}")

    def server_info(self, server_name: str):
        print(f"Gathering information for the server: {server_name}")

    def find_ip_address(self, website: str):
        print(f"Resolving IP address for: {website}")

    def database_info(self, db_name: str):
        print(f"Gathering information for the database: {db_name}")

    def execute_command(self, flag: str, *args):
        command = self.commands.get(flag)
        if command:
            func, expected_args = command
            if len(args) < expected_args:
                print(f"Error: Missing arguments for {flag}.")
            else:
                func(*args)
        else:
            print(f"Unknown command: {flag}. Use -h or --help for a list of commands.")

    def run(self):
        """Main terminal loop"""
        self.initialize()
        
        while True:
            user_input = input("ftcore> ").strip()

            if user_input.lower() in ["exit", "quit"]:
                print("Exiting FortiCore terminal. Goodbye!")
                break

            args = user_input.split()
            if args:
                flag = args[0]
                self.execute_command(flag, *args[1:])

def main():
    terminal = FortiCoreTerminal()
    terminal.run()

if __name__ == "__main__":
    main()
