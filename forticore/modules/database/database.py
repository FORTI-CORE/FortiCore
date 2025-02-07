import subprocess
import re
from colorama import Fore, Style
import time
from urllib.parse import urlparse, parse_qs
from typing import Set, Dict, Any
from ...utils.report_generator import ReportGenerator

class DatabaseScanner:
    def __init__(self, target: str, report_format: str = "html"):
        self.target = target
        self.output_dir = f"scans/{target}"
        self.report_format = report_format
        self.report_generator = ReportGenerator(self.output_dir)
        self.detected_dbms = None
        self.all_databases = set()
        self.raw_output = ""
        
    def print_status(self, message: str, status: str = "INFO"):
        colors = {
            "INFO": Fore.BLUE,
            "SUCCESS": Fore.GREEN,
            "ERROR": Fore.RED
        }
        color = colors.get(status, Fore.WHITE)
        print(f"{color}[{status}]{Style.RESET_ALL} {message}")

    def has_query_parameters(self, url):
        """Check if the URL contains query parameters."""
        parsed_url = urlparse(url)
        return bool(parse_qs(parsed_url.query))

    def run_sqlmap(self, additional_flags=None):
        self.print_status("Checking for database..","INFO")
        try:
            # Base SQLMap command
            command = ["sqlmap", "-u", self.target, "--batch", "--dbs", "--level=1", "--risk=1"]

            # If the URL has no query parameters, add extra scan options
            if not self.has_query_parameters(self.target):
                command.extend(["--forms", "--crawl=1"])

            # Add custom flags if provided
            if additional_flags:
                command.extend(additional_flags.split())

            # Run SQLMap and capture the output incrementally
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = []
            for line in process.stdout:
                output.append(line)
                print(line, end="")  # Print output in real-time
            process.wait()

            if process.returncode != 0:
                print(f"[!] Error running sqlmap: {process.stderr.read()}")
                return None
            
            """Generate the report after the scan is complete."""
            scan_results = self._prepare_scan_results()
            report_path = self.report_generator.generate_report(scan_results, f"{self.target}_scan_report", format=self.report_format)
            self.print_status(f"Report generated: {report_path}")
            
        except Exception as e:
            self.print_status(f"Error generating report: {e}","ERROR")

            self.raw_output = "".join(output)
            return self.raw_output

        except FileNotFoundError:
            print("[!] SQLMap is not installed or not in the PATH.")
            return None
        except Exception as e:
            print(f"[!] An error occurred: {e}")
            return None

    def extract_findings(self, output):
        """Extract relevant findings such as DBMS type and databases from SQLMap output."""
        if not output:
            return None, []

        # Extract DBMS type
        dbms_match = re.search(r"the back-end DBMS is (\w+)", output)
        dbms_type = dbms_match.group(1) if dbms_match else "Unknown"

        # Extract database names, filtering irrelevant entries
        databases = set(re.findall(r"\[\*\] ([\w_]+)", output))
        irrelevant_entries = {"starting", "ending", "payload"}
        databases -= irrelevant_entries  # Remove irrelevant entries

        return dbms_type, list(databases)

    def common_vulnerability_tests(self):
        """Perform common database vulnerability tests using SQLMap."""
        vulnerability_tests = {
            "Error-Based SQL Injection": "--technique=E",
            "Boolean-Based Blind SQL Injection": "--technique=B",
            "Union-Based SQL Injection": "--technique=U",
        }

        for vuln_type, flags in vulnerability_tests.items():
            print(f"\n[+] Testing for {vuln_type}...")
            start_time = time.time()
            output = self.run_sqlmap(additional_flags=flags)
            print(f"Time taken: {time.time() - start_time} seconds")

            # Extract findings
            dbms_type, databases = self.extract_findings(output)

            if dbms_type and dbms_type != "Unknown":
                self.detected_dbms = dbms_type

            self.all_databases.update(databases)

        # Final results
        print("\n[+] Final Scan Results")
        print(f"[+] Detected DBMS Type: {self.detected_dbms if self.detected_dbms else 'Unknown'}")
        print(f"[+] Databases found: {', '.join(self.all_databases) if self.all_databases else 'None found'}")

    # def generate_report(self):
    #     try:
    #         """Generate the report after the scan is complete."""
    #         scan_results = self._prepare_scan_results()
    #         report_path = self.report_generator.generate_report(scan_results, f"{self.target}_scan_report", format=self.report_format)
    #         self.print_status(f"Report generated: {report_path}")
    #     except Exception as e:
    #         self.print_status(f"Error generating report: {e}","ERROR")

    def _prepare_scan_results(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "database": {
                "dbms_type": self.detected_dbms if self.detected_dbms else "Unknown",
                "databases": sorted(list(self.all_databases)),
                "vulnerabilities": [
                    {
                        "type": "SQL Injection",
                        "details": "Found SQLi vulnerability in 'db1'",
                        "severity": "High"
                    },
                    {
                        "type": "Misconfiguration",
                        "details": "Default credentials found in 'db2'",
                        "severity": "Medium"
                    }
                ]
            }
        }
