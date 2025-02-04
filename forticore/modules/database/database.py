import subprocess
import re
import argparse
from urllib.parse import urlparse, parse_qs
import sys
from ...utils.report_generator import ReportGenerator;

class DatabaseScanner():
   def has_query_parameters(url):
    """
    Check if the URL contains query parameters.
    """
    parsed_url = urlparse(url)
    return bool(parse_qs(parsed_url.query))

def __init__(self,target:str,report_format:str="html"):
    output_dir=f"scans/{target}"
    super().__init__(target,output_dir)
    self.databases:Set[str]=set()
    self.report_format=report_format
    self.report_generator = ReportGenerator(output_dir)


def run_sqlmap(target_url, additional_flags=None):
    try:
        # Base SQLMap command
        command = ["sqlmap", "-u", target_url, "--batch", "--dbs"]

        # If the URL has no query parameters, add flags to test other parts of the request
        if not has_query_parameters(target_url):
            command.extend(["--forms", "--crawl=1"])  # Crawl the site and test forms
            command.extend(["--level=3", "--risk=3"])  # Increase level and risk for thorough testing

        # Add custom flags if provided
        if additional_flags:
            command.extend(additional_flags.split())

        # Run SQLMap
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Capture the output
        output = result.stdout
        if result.returncode != 0:
            print(f"[!] Error running sqlmap: {result.stderr}")
            return None

        # Save raw output to a file for reference
        return output

    except FileNotFoundError:
        print("[!] SQLMap is not installed or not in the PATH.")
        return None
    except Exception as e:
        print(f"[!] An error occurred: {e}")
        return None

def extract_findings(output):
    """
    Extract relevant findings such as DBMS type and databases from SQLMap output.
    """
    if not output:
        return None, []

    # Extract DBMS type
    dbms_match = re.search(r"the back-end DBMS is (\w+)", output)
    dbms_type = dbms_match.group(1) if dbms_match else "Unknown"

    # Extract unique database names, ignoring irrelevant entries
    databases = set(re.findall(r"\[\*\] ([\w_]+)", output))
    databases.discard("starting")
    databases.discard("ending")

    return dbms_type, list(databases)

def common_vulnerability_tests(target_url):
    """
    Perform common database vulnerability tests using SQLMap and display findings for each technique.
    """
    vulnerability_tests = {
        "Error-Based SQL Injection": "--technique=E",
        "Boolean-Based Blind SQL Injection": "--technique=B",
        "Time-Based Blind SQL Injection": "--technique=T",
        "Union-Based SQL Injection": "--technique=U",
        "Stacked Queries SQL Injection": "--technique=S",
        "Out-of-Band SQL Injection": "--technique=O",
    }

    all_databases = set()
    detected_dbms = None

    for vuln_type, flags in vulnerability_tests.items():
        print(f"\n[+] Testing for {vuln_type}...")
        output = run_sqlmap(target_url, additional_flags=flags)

        # Extract findings for this technique
        dbms_type, databases = extract_findings(output)

        # Display intermediate results
        if dbms_type and dbms_type != "Unknown":
            print(f"[+] Detected DBMS Type: {dbms_type}")
            detected_dbms = dbms_type  # Save DBMS type if detected

        if databases:
            print("[+] Databases found:")
            for db in sorted(databases):
                print(f"    - {db}")
            all_databases.update(databases)
        else:
            print("[!] No databases found with this technique.")

    # Display consolidated results
    print("\n[+] Final Scan Results")
    if detected_dbms:
        print(f"[+] Detected DBMS Type: {detected_dbms}")
    else:
        print("[!] No DBMS detected.")

    if all_databases:
        print("[+] Databases found:")
        for db in sorted(all_databases):
            print(f"    - {db}")
    else:
        print("[!] No databases found.")

def _prepare_scan_results(self)->Dict[str,Any]:
    return{
        "target_url": self.target_url,
        "report_format": self.report_format,
        "dbms_type": self.detected_dbms,
        "databases": sorted(list(self.all_databases)),
        "raw_output": self.raw_output,
        "report_path": self.report_generator.generate_report() if self.report_format == "html" else None,
        "report_data": self._generate_report_data() if self.report_format == "json" else None,
    }

if __name__ == "__main__":
    # Check if a target URL is provided
    if len(sys.argv) != 2:
        print("[!] Usage: python sqlmap6.py <target_url>")
        sys.exit(1)

    # Get the target URL from the command line
    target_url = sys.argv[1]

    # Run all common vulnerability tests
    common_vulnerability_tests(target_url)
