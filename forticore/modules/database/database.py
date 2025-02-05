import subprocess
import re
import argparse
import sys
from urllib.parse import urlparse, parse_qs
from typing import Set, Dict, Any
from ...utils.report_generator import ReportGenerator


class DatabaseScanner:
    def __init__(self, target: str, report_format: str = "html"):
        output_dir = f"scans/{target}"
        super().__init__()
        self.target = target
        self.output_dir = output_dir
        self.databases: Set[str] = set()
        self.report_format = report_format
        self.report_generator = ReportGenerator(output_dir)
        self.detected_dbms = None
        self.all_databases = set()
        self.raw_output = ""

    def has_query_parameters(self, url):
        """
        Check if the URL contains query parameters.
        """
        parsed_url = urlparse(url)
        return bool(parse_qs(parsed_url.query))

    def run_sqlmap(self, additional_flags=None):
        try:
            # Generate detailed report
            scan_results = self._prepare_scan_results()
            report_path = self.report_generator.generate_report(scan_results, f"{self.target}_scan_report", format=self.report_format)
            print(f"Report generated: {report_path}")

            # Base SQLMap command
            command = ["sqlmap", "-u", self.target, "--batch", "--dbs"]

            # If the URL has no query parameters, add extra scan options
            if not self.has_query_parameters(self.target):
                command.extend(["--forms", "--crawl=1", "--level=3", "--risk=3"])

            # Add custom flags if provided
            if additional_flags:
                command.extend(additional_flags.split())

            # Run SQLMap
            #result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            subprocess.run(["sqlmap", "-u", self.target, "--batch", "--dbs"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


            # Capture output
            output = result.stdout
            if result.returncode != 0:
                print(f"[!] Error running sqlmap: {result.stderr}")
                return None

            self.raw_output = output  # Store raw output
            return output

        except FileNotFoundError:
            print("[!] SQLMap is not installed or not in the PATH.")
            return None
        except Exception as e:
            print(f"[!] An error occurred: {e}")
            return None

    def extract_findings(self, output):
        """
        Extract relevant findings such as DBMS type and databases from SQLMap output.
        """
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
        """
        Perform common database vulnerability tests using SQLMap.
        """
        vulnerability_tests = {
            "Error-Based SQL Injection": "--technique=E",
            "Boolean-Based Blind SQL Injection": "--technique=B",
            "Time-Based Blind SQL Injection": "--technique=T",
            "Union-Based SQL Injection": "--technique=U",
            "Stacked Queries SQL Injection": "--technique=S",
            "Out-of-Band SQL Injection": "--technique=O",
        }

        for vuln_type, flags in vulnerability_tests.items():
            print(f"\n[+] Testing for {vuln_type}...")
            output = self.run_sqlmap(additional_flags=flags)

            # Extract findings
            dbms_type, databases = self.extract_findings(output)

            if dbms_type and dbms_type != "Unknown":
                self.detected_dbms = dbms_type

            self.all_databases.update(databases)

        # Final results
        print("\n[+] Final Scan Results")
        print(f"[+] Detected DBMS Type: {self.detected_dbms if self.detected_dbms else 'Unknown'}")
        print(f"[+] Databases found: {', '.join(self.all_databases) if self.all_databases else 'None found'}")

    def _prepare_scan_results(self) -> Dict[str, Any]:
      return {
         "target_url": self.target,
         "report_format": self.report_format,
         "dbms_type": self.detected_dbms if self.detected_dbms else "Unknown",
         "databases": sorted(list(self.all_databases)),
         "raw_output": self.raw_output,
         "details": "Scan completed successfully"  # Ensure 'details' is present
    }




if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Database vulnerability scanner using SQLMap")
    parser.add_argument("target_url", help="Target URL to scan")
    parser.add_argument("--format", default="html", choices=["html", "json"], help="Report format (html/json)")
    args = parser.parse_args()

    scanner = DatabaseScanner(args.target_url, report_format=args.format)
    scanner.run_sqlmap()
    scanner.common_vulnerability_tests()
