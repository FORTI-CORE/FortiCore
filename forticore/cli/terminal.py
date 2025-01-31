import sys
from typing import List
from colorama import init, Fore, Style
from .commands import CommandHandler

class FortiCoreTerminal:
    def __init__(self):
        init()  # Initialize colorama
        self.command_handler = CommandHandler()
        self.prompt = f"{Fore.GREEN}ftcore>{Style.RESET_ALL} "

    def run(self):
        """Run the terminal interface"""
        if len(sys.argv) > 1:
            # Handle command-line arguments
            self._handle_args(sys.argv[1:])
        else:
            # Interactive mode
            self._interactive_mode()

    def _handle_args(self, args: List[str]):
        """Handle command-line arguments"""
        if args:
            self.command_handler.handle_command(args[0], *args[1:])
        else:
            self.command_handler.show_help()

    def _interactive_mode(self):
        """Run in interactive mode"""
        while True:
            try:
                command = input(self.prompt).strip()
                if not command:
                    continue
                    
                if command.lower() in ['exit', 'quit', 'q']:
                    break

                args = command.split()
                self.command_handler.handle_command(args[0], *args[1:])
                
            except KeyboardInterrupt:
                print("\nUse 'exit' or 'quit' to close FortiCore")
            except Exception as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
