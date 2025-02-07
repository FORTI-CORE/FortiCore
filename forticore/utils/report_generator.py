import json
import yaml
import os
from datetime import datetime
from typing import Dict, Any
from pathlib import Path
from colorama import Fore, Style

class ReportGenerator:
    def __init__(self, output_dir: str):
        """
        Initialize the ReportGenerator.
        :param output_dir: Directory where reports will be saved. Default is "scans".
        """
        self.output_dir = Path(output_dir)
        # Create the output directory if it doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def _create_html_report(self, data: Dict[str, Any], filename: str) -> str:
        """Generate an HTML report with improved styling"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FortiCore Scan Report - {target}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .summary {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }}
        .domain-list {{
            list-style: none;
            padding: 0;
        }}
        .domain-item {{
            padding: 10px;
            border-bottom: 1px solid #eee;
        }}
        .port-info {{
            margin-left: 20px;
            color: #666;
        }}
        .tech-info {{
            margin-left: 20px;
            color: #2980b9;
        }}
        .timestamp {{
            color: #666;
            font-size: 0.9em;
            margin-top: 20px;
        }}
        .alert {{
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
        }}
        .alert-success {{
            background-color: #d4edda;
            color: #155724;
        }}
        .alert-warning {{
            background-color: #fff3cd;
            color: #856404;
        }}
        .vulnerability-list {{
            margin-top: 20px;
        }}
        .vuln-item {{
            background-color: #fff3cd;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 4px;
        }}
        .vuln-cves {{
            color: #721c24;
            background-color: #f8d7da;
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
        }}
        .vuln-findings {{
            color: #856404;
            background-color: #fff3cd;
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
        }}
        .database-info {{
            margin-top: 20px;
        }}
        .database-vulns {{
            margin-left: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>FortiCore Scan Report</h1>
        <div class="timestamp">Generated on: {timestamp}</div>
        
        <h2>Target Information</h2>
        <div class="summary">
            <p><strong>Target Domain:</strong> {target}</p>
            <p><strong>Total Subdomains:</strong> {total_subdomains}</p>
            <p><strong>Alive Domains:</strong> {alive_domains}</p>
            <p><strong>Total Open Ports:</strong> {total_open_ports}</p>
            <p><strong>Databases Found:</strong> {databases_found}</p>
        </div>

        <h2>Alive Domains and Services</h2>
        <div class="domain-list">
            {domain_details}
        </div>

        <h2>All Discovered Subdomains</h2>
        <div class="domain-list">
            {all_subdomains}
        </div>

        <h2>Database Information</h2>
        <div class="database-info">
            <p><strong>DBMS Type:</strong> {dbms_type}</p>
            <p><strong>Databases Found:</strong> {databases_list}</p>
            <h3>Database Vulnerabilities</h3>
            <div class="database-vulns">
                {database_vulns}
            </div>
        </div>

        <h2>Vulnerabilities</h2>
        <div class="vulnerability-list">
            {vuln_details}
        </div>
    </div>
</body>
</html>
"""

        domain_details_template = """
            <div class="domain-item">
                <h3>{domain}</h3>
                {ports}
                {technologies}
            </div>
        """

        vuln_item_template = """
            <div class="vuln-item">
                <strong>{domain}</strong><br>
                {cves}
                {findings}
            </div>
        """

        # Format domain details
        domain_details = []
        for domain in data['details']['alive_domains']:
            ports_html = ""
            if domain in data['details']['ports']:
                ports_html = "<div class='port-info'><strong>Open Ports:</strong><ul>"
                for port in data['details']['ports'][domain]:
                    ports_html += f"<li>Port {port['port']}: {port['service']} ({port['version']})</li>"
                ports_html += "</ul></div>"

            tech_html = ""
            if domain in data['details']['technologies']:
                tech_html = "<div class='tech-info'><strong>Technologies:</strong><ul>"
                for tech in data['details']['technologies'][domain]:
                    tech_html += f"<li>{tech['name']} {tech['version']} (Port {tech['port']})</li>"
                tech_html += "</ul></div>"

            domain_details.append(domain_details_template.format(
                domain=domain,
                ports=ports_html,
                technologies=tech_html
            ))

        # Format all subdomains
        all_subdomains_html = "<ul>"
        for subdomain in data['details']['all_subdomains']:
            all_subdomains_html += f"<li>{subdomain}</li>"
        all_subdomains_html += "</ul>"

        # Format database information
        dbms_type = data.get("database", {}).get("dbms_type", "Unknown")
        databases = data.get("database", {}).get("databases", [])
        databases_list = "<ul>" + "".join(f"<li>{db}</li>" for db in databases) + "</ul>"

        # Format database vulnerabilities
        database_vulns = []
        for vuln in data.get("database", {}).get("vulnerabilities", []):
            database_vulns.append(f"""
                <div class="vuln-item">
                    <strong>{vuln['type']}</strong> ({vuln['severity']})<br>
                    Details: {vuln['details']}
                </div>
            """)
        database_vulns = "".join(database_vulns)

        # Format vulnerability details
        vuln_details = []
        for domain, vulns in data['details'].get('vulnerabilities', {}).items():
            cves_html = ""
            if vulns.get('cves'):
                cves_html = "<div class='vuln-cves'><strong>CVEs:</strong><ul>"
                for cve in vulns['cves']:
                    cves_html += f"""
                    <li>
                        <strong>{cve['id']}</strong><br>
                        Source: {cve['source']}<br>
                        Details: {cve['details']}
                    </li>
                    """
                cves_html += "</ul></div>"

            findings_html = ""
            if vulns.get('findings'):
                findings_html = "<div class='vuln-findings'><strong>Other Findings:</strong><ul>"
                for finding in vulns['findings']:
                    findings_html += f"""
                    <li>
                        <strong>{finding['type']}</strong><br>
                        Details: {finding['details']}
                    </li>
                    """
                findings_html += "</ul></div>"

            vuln_details.append(vuln_item_template.format(
                domain=domain,
                cves=cves_html,
                findings=findings_html
            ))

        # Add all sections to the report
        html_content = html_template.format(
            target=data['target'],
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_subdomains=data['summary']['total_subdomains'],
            alive_domains=data['summary']['alive_domains'],
            total_open_ports=data['summary']['total_open_ports'],
            databases_found=len(databases),
            domain_details="\n".join(domain_details),
            all_subdomains=all_subdomains_html,
            dbms_type=dbms_type,
            databases_list=databases_list,
            database_vulns=database_vulns,
            vuln_details="\n".join(vuln_details)
        )

        # Write HTML file
        output_path = self.output_dir / f"{filename}.html"
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return str(output_path)

    def _create_json_report(self, data: Dict[str, Any], filename: str) -> str:
        """Generate a JSON report"""
        output_path = self.output_dir / f"{filename}.json"
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        return str(output_path)

    def _create_yaml_report(self, data: Dict[str, Any], filename: str) -> str:
        """Generate a YAML report"""
        output_path = self.output_dir / f"{filename}.yaml"
        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False)
        return str(output_path)

    def generate_report(self, data: Dict[str, Any], filename: str, format: str = "html") -> str:
        """Generate a report in the specified format"""
        try:
            if format.lower() == "html":
                return self._create_html_report(data, filename)
            elif format.lower() == "json":
                return self._create_json_report(data, filename)
            elif format.lower() == "yaml":
                return self._create_yaml_report(data, filename)
            else:
                print(f"{Fore.YELLOW}Warning: Unsupported format '{format}'. Falling back to JSON.{Style.RESET_ALL}")
                return self._create_json_report(data, f"{filename}_fallback")
        except Exception as e:
            print(f"{Fore.RED}Failed to generate {format} report. Falling back to JSON. Error: {e}{Style.RESET_ALL}")
            return self._create_json_report(data, f"{filename}_fallback")