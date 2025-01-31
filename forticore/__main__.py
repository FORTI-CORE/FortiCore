#!/usr/bin/env python3
import sys
import subprocess
from colorama import init, Fore, Style
from forticore.cli.terminal import FortiCoreTerminal

def show_banner():
    try:
        print(f"{Fore.RED}")
        subprocess.run(['figlet', '-f', 'slant', 'FortiCore'])
        print(f"{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] A Comprehensive Penetration Testing Framework{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[*] Version: 1.0.0{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Author: Your Name{Style.RESET_ALL}\n")
    except:
        print("\nFortiCore - Penetration Testing Framework\n")

def main():
    init()  # Initialize colorama
    show_banner()
    terminal = FortiCoreTerminal()
    terminal.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Exiting...{Style.RESET_ALL}")
        sys.exit(0)