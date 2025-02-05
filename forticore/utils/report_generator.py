import json
import yaml
import os
from datetime import datetime
from typing import Dict, Any
from pathlib import Path
from colorama import Fore, Style
from jinja2 import Template
import logging

class ReportGenerator:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.template_dir = Path(__file__).parent / 'templates'
        self.logger = logging.getLogger(__name__)
        
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
        </div>

        <h2>Alive Domains and Services</h2>
        <div class="domain-list">
            {domain_details}
        </div>

        <h2>All Discovered Subdomains</h2>
        <div class="domain-list">
            {all_subdomains}
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

        # Add vulnerability section to the report
        html_content = html_template.format(
            target=data['target'],
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_subdomains=data['summary']['total_subdomains'],
            alive_domains=data['summary']['alive_domains'],
            total_open_ports=data['summary']['total_open_ports'],
            domain_details="\n".join(domain_details),
            all_subdomains=all_subdomains_html,
            vuln_details="\n".join(vuln_details)
        )

        # Add vulnerability-specific styling
        html_content = html_content.replace("</style>", """
            .vulnerability-list {
                margin-top: 20px;
            }
            .vuln-item {
                background-color: #fff3cd;
                padding: 15px;
                margin-bottom: 15px;
                border-radius: 4px;
            }
            .vuln-cves {
                color: #721c24;
                background-color: #f8d7da;
                padding: 10px;
                margin: 10px 0;
                border-radius: 4px;
            }
            .vuln-findings {
                color: #856404;
                background-color: #fff3cd;
                padding: 10px;
                margin: 10px 0;
                border-radius: 4px;
            }
        </style>
        """)

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

    async def generate_html(self, data: Dict[str, Any]) -> str:
        """Generate HTML report with vulnerability details"""
        try:
            template = self._load_template('vulnerability_report.html')
            
            # Ensure all required keys exist
            data.setdefault('target', 'Unknown')
            data.setdefault('scan_time', datetime.now().isoformat())
            data.setdefault('summary', {'critical': 0, 'high': 0, 'medium': 0, 'low': 0})
            data.setdefault('vulnerabilities', [])
            data.setdefault('tools_used', [])
            data.setdefault('cves', [])
            data.setdefault('services', {})
            data.setdefault('technologies', {})
            
            # Generate final HTML
            html_content = template.render(
                target=data['target'],
                scan_time=data['scan_time'],
                summary=data['summary'],
                vulnerabilities=data['vulnerabilities'],
                tools_used=data['tools_used'],
                cves=data['cves'],
                services=data['services'],
                technologies=data['technologies']
            )
            
            # Save report
            output_file = self.output_dir / f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            output_file.write_text(html_content)
            return str(output_file)
            
        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {e}")
            return await self.generate_json(data)  # Fallback to JSON

    async def generate_json(self, data: Dict[str, Any]) -> str:
        """Generate JSON report"""
        try:
            output_file = self.output_dir / f"{data['target']}_scan_report_fallback.json"
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            return str(output_file)
        except Exception as e:
            self.logger.error(f"Failed to generate JSON report: {e}")
            return ""

    def _load_template(self, template_name: str) -> Template:
        """Load a template file"""
        try:
            template_path = self.template_dir / template_name
            if not template_path.exists():
                raise FileNotFoundError(f"Template file not found: {template_name}")
            return Template(template_path.read_text())
        except Exception as e:
            self.logger.error(f"Failed to load template {template_name}: {e}")
            # Return a basic template as fallback
            return Template("""
                <html>
                <body>
                <h1>Scan Report for {{ target }}</h1>
                <p>Scan Time: {{ scan_time }}</p>
                <pre>{{ vulnerabilities | tojson(indent=2) }}</pre>
                </body>
                </html>
            """)

    def _format_vuln_entry(self, vuln: Dict[str, Any]) -> str:
        """Format a single vulnerability entry"""
        return f"""
            <li class='vuln-item severity-{vuln.get("severity", "low")}'>
                <h4>{vuln.get('name', 'Unknown Vulnerability')}</h4>
                <p><strong>Type:</strong> {vuln.get('type', 'Unknown')}</p>
                <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
                {self._format_vuln_details(vuln)}
            </li>
        """
        
    def _format_vuln_details(self, vuln: Dict[str, Any]) -> str:
        """Format additional vulnerability details"""
        details = []
        
        if vuln.get('cve'):
            details.append(f"<p><strong>CVE:</strong> {vuln['cve']}</p>")
        if vuln.get('cvss_score'):
            details.append(f"<p><strong>CVSS Score:</strong> {vuln['cvss_score']}</p>")
        if vuln.get('proof'):
            details.append(f"<p><strong>Proof of Concept:</strong> {vuln['proof']}</p>")
        
        return "\n".join(details)
