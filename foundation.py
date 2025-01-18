import subprocess
import random
import socket
import ipaddress


BLUE = "\033[34m"
RESET = "\033[0m"
def check_and_install_tools(tools):

    for tool in tools:
        try:
            tool_availability = subprocess.run(["which", tool], capture_output=True, text=True)
            if not tool_availability.stdout.strip():
                print(f"Installing {tool} ...")
                try:
                    installation = subprocess.run(["sudo", "apt", "install", tool, "-y"], check=True)
                    print(f"{tool} successfully installed")
                except subprocess.CalledProcessError:
                    print(f"Failed to install {tool}")
                    print(f"Visit https://forticore/troubleshoot/tools/{tool} to get details on how to install {tool}")
                    exit()
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

def update_tools():
    try:
        subprocess.run(["sudo", "apt", "upgrade", "-y"])
        print("All tools updated")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        exit()


def get_ip_address():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        print(f"Error fetching IP address: {e}")
        return None


def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError as e:
        print(f"Invalid IP address: {e}")
        return False
def display_help():
    help_text = """
      -h, --help            Show this help message  
      -u, --info            Gathers all information for a given website link
      -s, --server          Gathers all information about a server
      -i, --ip-address      Finds the IP address of a given website link
      -d, --database        Gathers all information about a database
    Type 'exit' or 'quit' to leave.
    """
    print(help_text)


def website_info(link):
    print(f"Gathering information for the website: {link}")


def server_info(server_name):
    print(f"Gathering information for the server: {server_name}")


def find_ip_address(website):
    print(f"Resolving IP address for: {website}")


def database_info(db_name):
    print(f"Gathering information for the database: {db_name}")

COMMANDS = {
    "-h": (display_help, 0),
    "--help": (display_help, 0),
    "-u": (website_info, 1),
    "--info": (website_info, 1),
    "-s": (server_info, 1),
    "--server": (server_info, 1),
    "-i": (find_ip_address, 1),
    "--ip-address": (find_ip_address, 1),
    "-d": (database_info, 1),
    "--database": (database_info, 1),
}


def execute_command(flag, *args):
    command = COMMANDS.get(flag)
    if command:
        func, expected_args = command
        if len(args) < expected_args:
            print(f"Error: Missing arguments for {flag}.")
        else:
            func(*args)
    else:
        print(f"Unknown command: {flag}. Use -h or --help for a list of commands.")


def custom_terminal():
    while True:
        user_input = input("ftcore> ").strip()

        if user_input.lower() in ["exit", "quit"]:
            print("Exiting FortiCore terminal. Goodbye!")
            break

         
        args = user_input.split()
        if args:
            flag = args[0]
            execute_command(flag, *args[1:])



def main():
    fonts = ["slant", "banner", "block", "big", "shadow", "smscript", "lean", "standard"]
    font = random.choice(fonts)
    figlet_output = subprocess.run(["figlet", "-f", font, "FORTI CORE"], capture_output=True, text=True)
    colored_output = f"{BLUE}{figlet_output.stdout}{RESET}"
    print(colored_output)
    name = subprocess.run(["whoami"], capture_output=True, text=True)
    print(name.stdout.strip().upper(), "Welcome to FORTI CORE")
    print("Checking for the availability of required tools ...")
    tools = ["nmap", "dirb", "nikto", "dnsmap", "hashcat", "hydra", "john", "medusa", "ncrack", "netcat", "sqlmap", "zenmap"]
    check_and_install_tools(tools)
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
    print("Welcome to FortiCore terminal!")
    print("Type "+f"{BLUE}-h {RESET}" +" or "+f"{BLUE}--help {RESET}"+"for a list of commands.")
    print("Type "+f"{BLUE}exit{RESET}"+" or "+f"{BLUE}quit {RESET}"+"to leave.\n")
    custom_terminal()

    
    

if __name__ == "__main__":
    main()
