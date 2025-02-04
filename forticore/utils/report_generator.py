from typing import Dict, Any, List
from datetime import datetime
import json
import yaml
from pathlib import Path
from jinja2 import Template
import cvss
from colorama import Fore, Style

class ReportGenerator:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.vuln_templates = self._load_vulnerability_templates()

    def _load_vulnerability_templates(self) -> Dict[str, str]:
        """Load vulnerability description templates"""
        return {
            'sql_injection': 'SQL Injection vulnerability allowing unauthorized database access',
            'xss': 'Cross-Site Scripting vulnerability enabling client-side attacks',
            'ssl_vuln': 'SSL/TLS vulnerability affecting secure communications',
            'cms_vuln': 'Content Management System vulnerability',
            'default': 'Security vulnerability detected'
        }

    def _validate_scan_data(self, data: Dict[str, Any]) -> bool:
        """Validate scan data structure"""
        required_fields = {
            'target': str,
            'summary': dict,
            'details': dict
        }
        
        try:
            for field, field_type in required_fields.items():
                if field not in data:
                    self.logger.error(f"Missing required field: {field}")
                    return False
                if not isinstance(data[field], field_type):
                    self.logger.error(f"Invalid type for {field}")
                    return False
            return True
        except Exception as e:
            self.logger.error(f"Error validating scan data: {e}")
            return False

    def generate_report(self, data: Dict[str, Any], filename: str, format: str = "html") -> str:
        """Generate scan report with validation"""
        if not self._validate_scan_data(data):
            raise ValueError("Invalid scan data structure")
        
        try:
            if format == "html":
                return self._create_html_report(data, filename)
            elif format == "json":
                return self._create_json_report(data, filename)
            elif format == "yaml":
                return self._create_yaml_report(data, filename)
            else:
                raise ValueError(f"Unsupported format: {format}")
        except Exception as e:
            self.logger.error(f"Error generating report: {e}")
            raise

    def _calculate_risk_score(self, vulnerability: Dict[str, Any]) -> float:
        """Calculate CVSS-based risk score"""
        try:
            if 'cvss_vector' in vulnerability:
                c = cvss.CVSS3(vulnerability['cvss_vector'])
                return c.base_score
            # Default scoring based on severity
            severity_scores = {
                'critical': 9.0,
                'high': 7.0,
                'medium': 5.0,
                'low': 3.0,
                'info': 1.0
            }
            return severity_scores.get(vulnerability.get('severity', 'info'), 1.0)
        except:
            return 1.0

    def _format_vulnerability_details(self, vulns: List[Dict[str, Any]]) -> str:
        """Format vulnerability details with severity indicators"""
        details = []
        for vuln in sorted(vulns, key=lambda x: self._calculate_risk_score(x), reverse=True):
            severity = vuln.get('severity', 'info').upper()
            details.append(f"""
                <div class="vuln-item severity-{severity.lower()}">
                    <h4>{vuln.get('type', 'Unknown Vulnerability')}</h4>
                    <p><strong>Severity:</strong> {severity}</p>
                    <p><strong>Description:</strong> {vuln.get('description', self.vuln_templates['default'])}</p>
                    {'<p><strong>CVE:</strong> ' + vuln['cve'] + '</p>' if 'cve' in vuln else ''}
                    {'<p><strong>CVSS Score:</strong> ' + str(self._calculate_risk_score(vuln)) + '</p>' if 'cvss_vector' in vuln else ''}
                    <div class="vuln-details">{vuln.get('details', '')}</div>
                </div>
            """)
        return "\n".join(details)

    def _create_html_report(self, data: Dict[str, Any], filename: str) -> str:
        """Reference existing HTML template and update"""
        startLine: 14
        endLine: 225

        # Add vulnerability section template
        vuln_item_template = """
        <div class="domain-section">
            <h3>{domain}</h3>
            <div class="vulnerability-container">
                {cves}
                {findings}
            </div>
        </div>
        """

        # Add enhanced styling for vulnerabilities
        additional_styles = """
            .severity-critical { background-color: #ff5252; color: white; }
            .severity-high { background-color: #ff7f50; color: white; }
            .severity-medium { background-color: #ffd700; }
            .severity-low { background-color: #90ee90; }
            .severity-info { background-color: #87ceeb; }
            .vuln-item { margin: 10px 0; padding: 15px; border-radius: 5px; }
            .vuln-details { margin-top: 10px; font-family: monospace; }
            .stats-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
            .stat-box { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        """

        return self._write_report(filename, "html", html_content)

    def _create_json_report(self, data: Dict[str, Any], filename: str) -> str:
        """Generate JSON report"""
        report_path = self.output_dir / f"{filename}.json"
        with open(report_path, 'w') as f:
            json.dump(data, f, indent=2)
        return str(report_path)

    def _create_yaml_report(self, data: Dict[str, Any], filename: str) -> str:
        """Generate YAML report"""
        report_path = self.output_dir / f"{filename}.yaml"
        with open(report_path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False)
        return str(report_path)

    def _write_report(self, filename: str, extension: str, content: str) -> str:
        """Write report to file"""
        report_path = self.output_dir / f"{filename}.{extension}"
        with open(report_path, 'w') as f:
            f.write(content)
        return str(report_path)

...

...
