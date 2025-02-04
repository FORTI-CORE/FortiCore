from typing import Dict, List, Any, Optional
import asyncio
import subprocess
import json
from pathlib import Path
from ...core.scanner import BaseScanner
from ...utils.report_generator import ReportGenerator
import httpx
import re
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
import questionary
from .csrf_ssrf_scanner import CSRFSSRFScanner
from datetime import datetime

class VulnerabilityScanner(BaseScanner):
    def __init__(self, target: str, scan_profile: str = "normal"):
        super().__init__(target, f"scans/{target}/vulnerabilities")
        self.scan_profile = scan_profile
        self.findings = {}
        self.scan_config = self._get_scan_config()
        self.report_generator = ReportGenerator(self.output_dir)
        
    def _get_scan_config(self) -> Dict[str, bool]:
        """Interactive configuration for vulnerability scanning"""
        print(f"\n{Fore.CYAN}[*] Configuring Vulnerability Scan{Style.RESET_ALL}")
        
        config = {}
        questions = [
            {
                "type": "confirm",
                "name": "web_vulns",
                "message": "Scan for web vulnerabilities (SQLi, XSS, etc.)?",
                "default": True
            },
            {
                "type": "confirm",
                "name": "cms_vulns",
                "message": "Scan for CMS vulnerabilities?",
                "default": True
            },
            {
                "type": "confirm",
                "name": "ssl_vulns",
                "message": "Check for SSL/TLS vulnerabilities?",
                "default": True
            },
            {
                "type": "confirm",
                "name": "aggressive_scan",
                "message": "Enable aggressive scanning (longer but more thorough)?",
                "default": False
            }
        ]
        
        answers = questionary.prompt(questions)
        return answers if answers else {q["name"]: q["default"] for q in questions}

    async def scan_target(self, target: str, interactive: bool = True) -> Dict[str, Any]:
        """Enhanced vulnerability scanning with multiple tools"""
        start_time = datetime.now()
        
        scan_results = {
            'target': target,
            'scan_time': start_time.isoformat(),
            'vulnerabilities': [],
            'summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        # Run parallel vulnerability scans
        async with asyncio.TaskGroup() as tg:
            if self.scan_config['web_vulns']:
                tg.create_task(self._run_web_scans(target, scan_results))
            if self.scan_config['cms_vulns']:
                tg.create_task(self._run_cms_scans(target, scan_results))
            if self.scan_config['ssl_vulns']:
                tg.create_task(self._run_ssl_scans(target, scan_results))
        
        # Update summary counts
        for vuln in scan_results['vulnerabilities']:
            severity = vuln.get('severity', 'low').lower()
            scan_results['summary'][severity] = scan_results['summary'].get(severity, 0) + 1
        
        # Generate report
        await self._generate_reports(scan_results)
        
        return scan_results

    async def _run_web_scans(self, target: str, results: Dict[str, Any]):
        """Enhanced web vulnerability scanning"""
        csrf_ssrf_scanner = CSRFSSRFScanner(target)
        
        tasks = [
            self.run_nuclei_scan(target),
            self._run_sqlmap_scan(target),
            self.run_xsstrike(target),
            csrf_ssrf_scanner.scan_csrf(f"https://{target}"),
            csrf_ssrf_scanner.scan_ssrf(f"https://{target}")
        ]
        
        scan_results = await asyncio.gather(*tasks)
        for result in scan_results:
            if result:
                results['vulnerabilities'].extend(result)

    async def _run_cms_scans(self, target: str, results: Dict[str, Any]):
        """Run CMS-specific scans"""
        # Reference WordPress scanning implementation from subdomain.py
        startLine: 397
        endLine: 414

    async def _run_ssl_scans(self, target: str, results: Dict[str, Any]):
        """Run SSL/TLS vulnerability scans"""
        try:
            scripts = [
                "ssl-heartbleed",
                "ssl-poodle",
                "ssl-ccs-injection",
                "ssl-dh-params",
                "ssl-enum-ciphers"
            ]
            
            cmd = [
                "nmap", "-p443",
                "--script", ",".join(scripts),
                "-Pn", target
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await process.communicate()
            if stdout:
                results['vulnerabilities'].append({
                    'type': 'ssl_scan',
                    'details': stdout.decode()
                })
        except Exception as e:
            self.logger.error(f"SSL scan failed: {e}")

    def show_progress(self, current: int, total: int, scan_type: str):
        """Show scan progress"""
        percentage = (current / total) * 100
        bar_length = 50
        filled_length = int(bar_length * current // total)
        bar = '=' * filled_length + '-' * (bar_length - filled_length)
        print(f'\r{Fore.CYAN}[{bar}] {percentage:.1f}% - {scan_type}{Style.RESET_ALL}', end='')

    async def run_nuclei_scan(self, domain: str) -> List[Dict[str, Any]]:
        try:
            cmd = [
                "nuclei",
                "-u", domain,
                "-severity", "critical,high,medium",
                "-json",
                "-timeout", "5"
            ]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            return [json.loads(line) for line in stdout.decode().splitlines() if line]
        except Exception as e:
            self.logger.error(f"Nuclei scan failed: {e}")
            return []

    async def run_xsstrike(self, url: str) -> List[Dict[str, Any]]:
        try:
            cmd = ["xsstrike", "--url", url, "--json"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            return json.loads(stdout.decode())
        except Exception as e:
            self.logger.error(f"XSStrike failed: {e}")
            return []

    def run_sqlmap(self, url: str) -> List[Dict[str, Any]]:
        try:
            output_file = self.output_dir / f"{self.target}_sqlmap.json"
            cmd = [
                "sqlmap",
                "-u", url,
                "--batch",
                "--random-agent",
                "--level", "2",
                "--risk", "2",
                "--threads", "4",
                "--output-dir", str(self.output_dir),
                "--json-output", str(output_file)
            ]
            subprocess.run(cmd, capture_output=True)
            
            if output_file.exists():
                with open(output_file) as f:
                    return json.load(f)
            return []
        except Exception as e:
            self.logger.error(f"SQLMap failed: {e}")
            return []

    async def scan_domain(self, domain: str):
        tasks = [
            self.run_nuclei_scan(domain),
            self.run_xsstrike(f"https://{domain}"),
        ]
        
        # Run async tasks
        nuclei_results, xss_results = await asyncio.gather(*tasks)
        
        # Run SQLMap in a thread pool
        with ThreadPoolExecutor() as executor:
            sqlmap_future = executor.submit(self.run_sqlmap, f"https://{domain}")
            sqlmap_results = sqlmap_future.result()
        
        self.findings[domain] = {
            'nuclei': nuclei_results,
            'xss': xss_results,
            'sqlmap': sqlmap_results
        }

    async def scan_multiple_domains(self, domains: List[str]):
        tasks = [self.scan_domain(domain) for domain in domains]
        await asyncio.gather(*tasks)

    def _map_severity(self, finding: Dict[str, Any]) -> str:
        """Map tool-specific severity ratings to standard levels"""
        severity_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'info',
            # Nuclei-specific mappings
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low',
            'INFO': 'info'
        }
        
        if 'severity' in finding:
            return severity_map.get(finding['severity'].lower(), 'info')
        elif 'risk' in finding:
            return severity_map.get(finding['risk'].lower(), 'info')
        return 'info'

    async def _process_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process and standardize vulnerability findings"""
        processed = []
        for finding in findings:
            processed.append({
                'type': finding.get('type', 'unknown'),
                'severity': self._map_severity(finding),
                'description': finding.get('description', ''),
                'details': finding.get('details', ''),
                'cvss_vector': finding.get('cvss_vector', ''),
                'cve': finding.get('cve', ''),
                'references': finding.get('references', [])
            })
        return processed

    async def _generate_reports(self, scan_results: Dict[str, Any]):
        """Generate reports in multiple formats"""
        report_data = {
            'target': scan_results['target'],
            'scan_time': scan_results['scan_time'],
            'summary': scan_results['summary'],
            'details': {
                'vulnerabilities': self._format_vulnerabilities(scan_results['vulnerabilities']),
                'technologies': self.findings.get('technologies', {}),
                'services': self.findings.get('services', {})
            }
        }
        
        # Generate HTML report
        html_report = await self.report_generator.generate_html(report_data)
        
        # Generate JSON report
        json_report = await self.report_generator.generate_json(report_data)
        
        print(f"\n{Fore.GREEN}[+] Reports generated:{Style.RESET_ALL}")
        print(f"    HTML: {html_report}")
        print(f"    JSON: {json_report}")
        
    def _format_vulnerabilities(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Format vulnerabilities for reporting"""
        formatted = {
            'by_severity': {
                'critical': [],
                'high': [],
                'medium': [],
                'low': []
            },
            'by_type': {},
            'total_count': len(vulns)
        }
        
        for vuln in vulns:
            severity = vuln.get('severity', 'low').lower()
            vuln_type = vuln.get('type', 'unknown')
            
            # Add to severity-based classification
            formatted['by_severity'][severity].append(vuln)
            
            # Add to type-based classification
            if vuln_type not in formatted['by_type']:
                formatted['by_type'][vuln_type] = []
            formatted['by_type'][vuln_type].append(vuln)
            
        return formatted
