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
import shutil

class VulnerabilityScanner(BaseScanner):
    def __init__(self, target: str, scan_profile: str = "normal"):
        super().__init__(target, f"scans/{target}/vulnerabilities")
        self.scan_profile = scan_profile
        self.findings = {}
        self.scan_config = self._get_scan_config()
        self.report_generator = ReportGenerator(self.output_dir)
        self.available_tools = self._check_available_tools()
        
    def _check_available_tools(self) -> Dict[str, bool]:
        """Check which security tools are available"""
        tools = {
            'nuclei': False,
            'sqlmap': False,
            'xsstrike': False,
            'nmap': False
        }
        
        for tool in tools.keys():
            if shutil.which(tool):
                tools[tool] = True
            else:
                self.logger.warning(f"{tool} not found in PATH. Related scans will be skipped.")
        
        return tools

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
        print(f"\n{Fore.GREEN}[+] Starting vulnerability scan for {target}{Style.RESET_ALL}")
        
        try:
            if self.scan_config['web_vulns']:
                await self._run_web_scans(target, self.findings)
            if self.scan_config['cms_vulns']:
                await self._run_cms_scans(target, self.findings)
            if self.scan_config['ssl_vulns']:
                await self._run_ssl_scans(target, self.findings)

            # Update summary counts
            self._update_summary_counts()

            # Prepare final report data
            report_data = {
                'target': target,
                'scan_time': start_time.isoformat(),
                'summary': self.findings['summary'],
                'vulnerabilities': self.findings['vulnerabilities'],
                'technologies': self.findings.get('technologies', {}),
                'services': self.findings.get('services', {}),
                'tools_used': [tool for tool, available in self.available_tools.items() if available],
                'scan_config': self.scan_config
            }

            # Generate report
            try:
                report_path = await self.report_generator.generate_html(report_data)
                print(f"\n{Fore.GREEN}[+] Report generated: {report_path}{Style.RESET_ALL}")
            except Exception as e:
                self.logger.error(f"Error generating report: {e}")
                # Fallback to JSON report
                report_path = await self.report_generator.generate_json(report_data)
                print(f"\n{Fore.YELLOW}[!] Fallback JSON report generated: {report_path}{Style.RESET_ALL}")

            return report_data
            
        except Exception as e:
            self.logger.error(f"Error during vulnerability scan: {e}")
            return {
                'target': target,
                'scan_time': start_time.isoformat(),
                'error': str(e),
                'summary': self.findings.get('summary', {}),
                'vulnerabilities': self.findings.get('vulnerabilities', [])
            }

    async def _run_web_scans(self, target: str, results: Dict[str, Any]):
        """Enhanced web vulnerability scanning"""
        tasks = []
        
        if self.available_tools['nuclei']:
            tasks.append(self.run_nuclei_scan(target))
        if self.available_tools['sqlmap']:
            tasks.append(self._run_sqlmap_scan(target))
        if self.available_tools['xsstrike']:
            tasks.append(self.run_xsstrike(target))
            
        if not tasks:
            self.logger.warning("No vulnerability scanning tools available. Please install nuclei, sqlmap, or xsstrike.")
            return
            
        try:
            scan_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in scan_results:
                if result and not isinstance(result, Exception):
                    if isinstance(result, list):
                        results['vulnerabilities'].extend(result)
                    else:
                        results['vulnerabilities'].append(result)
                elif isinstance(result, Exception):
                    self.logger.error(f"Scan error: {str(result)}")
                    
        except Exception as e:
            self.logger.error(f"Error in web scans: {e}")

    async def _run_sqlmap_scan(self, target: str) -> List[Dict[str, Any]]:
        """Run SQLMap scan with proper async handling"""
        try:
            output_file = self.output_dir / f"{target}_sqlmap.json"
            cmd = [
                "sqlmap",
                "-u", f"https://{target}",
                "--batch",
                "--random-agent",
                "--level", "2",
                "--risk", "2",
                "--threads", "4",
                "--output-dir", str(self.output_dir),
                "--json-output", str(output_file)
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await process.communicate()
            
            if output_file.exists():
                with open(output_file) as f:
                    data = json.load(f)
                    return self._format_sqlmap_results(data)
            return []
            
        except Exception as e:
            self.logger.error(f"SQLMap scan failed: {e}")
            return []

    async def run_nuclei_scan(self, target: str) -> List[Dict[str, Any]]:
        """Run Nuclei scan with proper error handling"""
        if not self.available_tools['nuclei']:
            return []
            
        try:
            cmd = [
                "nuclei",
                "-u", f"https://{target}",
                "-severity", "critical,high",
                "-json",
                "-silent"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if stdout:
                findings = []
                for line in stdout.decode().splitlines():
                    try:
                        if line.strip():
                            finding = json.loads(line)
                            findings.append(finding)
                    except json.JSONDecodeError:
                        continue
                return self._format_nuclei_results(findings)
            return []
            
        except Exception as e:
            self.logger.error(f"Nuclei scan failed: {e}")
            return []

    def _format_sqlmap_results(self, data: Dict) -> List[Dict[str, Any]]:
        """Format SQLMap results"""
        formatted = []
        if data.get('vulnerabilities'):
            for vuln in data['vulnerabilities']:
                formatted.append({
                    'type': 'sql_injection',
                    'severity': 'high',
                    'name': vuln.get('name', 'SQL Injection'),
                    'description': vuln.get('details', ''),
                    'proof': vuln.get('payload', '')
                })
        return formatted

    def _format_nuclei_results(self, findings: List[Dict]) -> List[Dict[str, Any]]:
        """Format Nuclei results"""
        formatted = []
        for finding in findings:
            formatted.append({
                'type': finding.get('template-id', 'unknown'),
                'severity': finding.get('severity', 'low'),
                'name': finding.get('info', {}).get('name', 'Unknown'),
                'description': finding.get('info', {}).get('description', ''),
                'proof': finding.get('matched-at', '')
            })
        return formatted

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

    async def run_xsstrike(self, target: str) -> List[Dict[str, Any]]:
        """Run XSStrike with proper error handling"""
        if not self.available_tools['xsstrike']:
            return []
            
        try:
            cmd = [
                "xsstrike",
                "--url", f"https://{target}",
                "--json"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if stdout:
                try:
                    findings = json.loads(stdout)
                    return self._format_xsstrike_results(findings)
                except json.JSONDecodeError:
                    self.logger.error("Failed to parse XSStrike output")
            return []
            
        except Exception as e:
            self.logger.error(f"XSStrike failed: {e}")
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
