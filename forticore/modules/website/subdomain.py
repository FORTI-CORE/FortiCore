from ...core.scanner import BaseScanner
import subprocess
import requests
import concurrent.futures
from typing import Set, Dict, Any
from pathlib import Path
from colorama import Fore, Style, init
import nmap
import urllib3
from ...utils.report_generator import ReportGenerator
import figlet
import re

# Initialize colorama
init()

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SubdomainScanner(BaseScanner):
    def __init__(self, target: str, report_format: str = "html"):
        """
        Initialize the subdomain scanner
        Args:
            target: Target domain to scan
            report_format: Format for the report (html, json, or yaml)
        """
        output_dir = f"scans/{target}"
        super().__init__(target, output_dir)
        self.subdomains: Set[str] = set()
        self.alive_domains: list = []
        self.vulnerabilities: Dict[str, Dict] = {}
        self.ports: Dict[str, list] = {}
        self.technologies: Dict[str, list] = {}
        self.report_format = report_format
        self.report_generator = ReportGenerator(output_dir)

    def print_status(self, message: str, status: str = "INFO"):
        colors = {
            "INFO": Fore.BLUE,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED
        }
        color = colors.get(status, Fore.WHITE)
        print(f"{color}[{status}]{Style.RESET_ALL} {message}")

    def show_banner(self):
        try:
            subprocess.run(['figlet', '-f', 'slant', 'FortiCore'])
            print(f"{Fore.BLUE}A Comprehensive Penetration Testing Framework{Style.RESET_ALL}\n")
            print(f"{Fore.GREEN}Version: 1.0.0{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Target: {self.target}{Style.RESET_ALL}\n")
        except:
            print("\nFortiCore - Penetration Testing Framework\n")

    def run_subfinder(self) -> Set[str]:
        try:
            result = subprocess.run(
                ["subfinder", "-d", self.target],
                capture_output=True,
                text=True
            )
            return set(result.stdout.splitlines())
        except Exception as e:
            self.logger.error(f"Subfinder failed: {e}")
            return set()

    def run_amass(self) -> Set[str]:
        try:
            result = subprocess.run(
                ["amass", "enum", "-passive", "-d", self.target],
                capture_output=True,
                text=True
            )
            return set(result.stdout.splitlines())
        except Exception as e:
            self.logger.error(f"Amass failed: {e}")
            return set()

    def check_alive_domains(self):
        self.print_status("Checking for alive domains...", "INFO")
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for subdomain in self.subdomains:
                futures.append(executor.submit(self._check_single_domain, subdomain))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.print_status(f"Found alive domain: {result}", "SUCCESS")
                except Exception as e:
                    self.logger.error(f"Error checking domain: {e}")

    def _check_single_domain(self, subdomain: str) -> str:
        try:
            for protocol in ['https://', 'http://']:
                try:
                    response = requests.head(f"{protocol}{subdomain}", 
                                          timeout=5, 
                                          verify=False)
                    if response.status_code == 200:
                        self.alive_domains.append(subdomain)
                        return subdomain
                except:
                    continue
        except:
            pass
        return ""

    def scan_ports(self, domain: str):
        self.print_status(f"Scanning ports for {domain}...", "INFO")
        nm = nmap.PortScanner()
        try:
            nm.scan(domain, arguments='-sS -sV -F --version-intensity 5')
            self.ports[domain] = []
            self.technologies[domain] = []
            
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]
                        if service['state'] == 'open':
                            self.ports[domain].append({
                                'port': port,
                                'service': service['name'],
                                'version': service.get('version', 'unknown')
                            })
                            if service.get('product'):
                                self.technologies[domain].append({
                                    'name': service['product'],
                                    'version': service.get('version', 'unknown')
                                })
        except Exception as e:
            self.print_status(f"Error scanning ports: {e}", "ERROR")

    def scan_vulnerabilities(self, domain: str):
        """Perform comprehensive vulnerability scanning"""
        self.print_status(f"Scanning vulnerabilities for {domain}...", "INFO")
        
        nm = nmap.PortScanner()
        try:
            # Common web vulnerabilities
            scripts = [
                "http-sql-injection",
                "http-csrf",
                "http-dombased-xss",
                "http-stored-xss",
                "http-phpself-xss",
                "http-wordpress-users",
                "http-methods",
                "http-enum",
                "http-headers",
                "http-git",
                "http-shellshock",
                "ssl-heartbleed",
                "ssl-poodle",
                "ssl-ccs-injection",
                "vuln"
            ]
            
            script_args = " ".join(scripts)
            scan_args = f"-sV -sC --script={script_args} -T4 --version-intensity 5"
            
            nm.scan(domain, arguments=scan_args)
            
            self.vulnerabilities[domain] = {
                'cves': [],
                'findings': [],
                'ssl_issues': [],
                'misconfigurations': []
            }
            
            for host in nm.all_hosts():
                # Extract vulnerabilities from scan results
                if 'script' in nm[host]:
                    for script_name, result in nm[host]['script'].items():
                        # Extract CVEs
                        cves = re.findall(r'CVE-\d{4}-\d+', result)
                        if cves:
                            for cve in cves:
                                self.vulnerabilities[domain]['cves'].append({
                                    'id': cve,
                                    'source': script_name,
                                    'details': result
                                })
                                self.print_status(f"Found {cve} in {domain}", "WARNING")

                        # Check for specific vulnerabilities
                        if 'VULNERABLE' in result:
                            self.vulnerabilities[domain]['findings'].append({
                                'type': script_name,
                                'details': result
                            })
                            self.print_status(f"Found {script_name} vulnerability in {domain}", "WARNING")

            # Additional targeted scanning based on detected services
            if domain in self.ports:
                for port_info in self.ports[domain]:
                    if port_info['service'] == 'http' or port_info['service'] == 'https':
                        # Web application scanning
                        self._scan_web_vulnerabilities(domain, port_info['port'])
                    elif port_info['service'] == 'ssh':
                        # SSH vulnerability scanning
                        self._scan_ssh_vulnerabilities(domain, port_info['port'])
                    elif port_info['service'] == 'ftp':
                        # FTP vulnerability scanning
                        self._scan_ftp_vulnerabilities(domain, port_info['port'])

        except Exception as e:
            self.print_status(f"Error during vulnerability scan: {e}", "ERROR")

    def _scan_ssh_vulnerabilities(self, domain: str, port: int):
        """Perform SSH vulnerability scanning"""
        self.print_status(f"Scanning SSH vulnerabilities on {domain}:{port}")
        
        try:
            nm = nmap.PortScanner()
            scripts = [
                "ssh2-enum-algos",
                "ssh-auth-methods",
                "ssh-hostkey",
                "ssh-publickey-acceptance",
                "sshv1",
                "vulners"
            ]
            
            scan_args = f"-p{port} -sV --script={','.join(scripts)}"
            nm.scan(domain, arguments=scan_args)
            
            for host in nm.all_hosts():
                if 'script' in nm[host]:
                    for script_name, result in nm[host]['script'].items():
                        if result and 'VULNERABLE' in result:
                            self.vulnerabilities[domain]['findings'].append({
                                'type': f'ssh_{script_name}',
                                'port': port,
                                'details': result
                            })
                            self.print_status(f"Found SSH vulnerability: {script_name}", "WARNING")
        
        except Exception as e:
            self.print_status(f"Error during SSH scan: {e}", "ERROR")

    def _scan_ftp_vulnerabilities(self, domain: str, port: int):
        """Perform FTP vulnerability scanning"""
        self.print_status(f"Scanning FTP vulnerabilities on {domain}:{port}")
        
        try:
            nm = nmap.PortScanner()
            scripts = [
                "ftp-anon",
                "ftp-bounce",
                "ftp-libopie",
                "ftp-proftpd-backdoor",
                "ftp-vsftpd-backdoor",
                "ftp-vuln-cve2010-4221",
                "vulners"
            ]
            
            scan_args = f"-p{port} -sV --script={','.join(scripts)}"
            nm.scan(domain, arguments=scan_args)
            
            for host in nm.all_hosts():
                if 'script' in nm[host]:
                    for script_name, result in nm[host]['script'].items():
                        if result and ('VULNERABLE' in result or 'Anonymous FTP login allowed' in result):
                            self.vulnerabilities[domain]['findings'].append({
                                'type': f'ftp_{script_name}',
                                'port': port,
                                'details': result
                            })
                            self.print_status(f"Found FTP vulnerability: {script_name}", "WARNING")

            # Try anonymous login
            self._try_anonymous_ftp(domain, port)
        
        except Exception as e:
            self.print_status(f"Error during FTP scan: {e}", "ERROR")

    def _try_anonymous_ftp(self, domain: str, port: int):
        """Attempt anonymous FTP login"""
        try:
            from ftplib import FTP
            ftp = FTP()
            ftp.connect(domain, port, timeout=10)
            ftp.login()  # Try anonymous login
            self.vulnerabilities[domain]['findings'].append({
                'type': 'ftp_anonymous_access',
                'port': port,
                'details': 'Anonymous FTP login successful'
            })
            ftp.quit()
        except:
            pass

    def _scan_web_vulnerabilities(self, domain: str, port: int):
        """Perform detailed web application vulnerability scanning"""
        self.print_status(f"Scanning web vulnerabilities on {domain}:{port}")
        
        try:
            # Determine protocol
            protocol = "https" if port == 443 else "http"
            base_url = f"{protocol}://{domain}:{port}"
            
            # Basic directory enumeration
            dirb_cmd = ["dirb", base_url, "/usr/share/dirb/wordlists/common.txt", "-S", "-r"]
            result = subprocess.run(dirb_cmd, capture_output=True, text=True, timeout=300)
            if "DIRECTORY" in result.stdout:
                self.vulnerabilities[domain]['findings'].append({
                    'type': 'directory_exposure',
                    'port': port,
                    'details': result.stdout
                })
                self.print_status("Found exposed directories", "WARNING")

            # Nikto scan
            nikto_cmd = ["nikto", "-h", f"{domain}:{port}", "-Format", "txt", "-Tuning", "x 6"]
            result = subprocess.run(nikto_cmd, capture_output=True, text=True, timeout=300)
            if result.stdout:
                findings = self._parse_nikto_output(result.stdout)
                if findings:
                    self.vulnerabilities[domain]['findings'].extend(findings)
                    self.print_status(f"Found {len(findings)} vulnerabilities via Nikto", "WARNING")

            # SQLMap check on common parameters
            self._run_sqlmap_check(base_url)
            
            # Check for common CMS
            self._detect_cms(base_url)
            
        except subprocess.TimeoutExpired:
            self.print_status(f"Scan timeout for {domain}:{port}", "WARNING")
        except Exception as e:
            self.print_status(f"Error during web vulnerability scan: {e}", "ERROR")

    def _parse_nikto_output(self, output: str) -> list:
        """Parse Nikto output for vulnerabilities"""
        findings = []
        for line in output.split('\n'):
            if '+ ' in line:  # Nikto uses '+ ' to indicate findings
                findings.append({
                    'type': 'nikto_finding',
                    'details': line.strip()
                })
        return findings

    def _run_sqlmap_check(self, url: str):
        """Basic SQLMap check"""
        try:
            sqlmap_cmd = [
                "sqlmap", 
                "-u", f"{url}/?id=1", 
                "--batch", 
                "--random-agent",
                "--level", "1",
                "--risk", "1",
                "--threads", "4",
                "--smart"
            ]
            result = subprocess.run(sqlmap_cmd, capture_output=True, text=True, timeout=300)
            if "sqlmap identified" in result.stdout:
                self.vulnerabilities[self.target]['findings'].append({
                    'type': 'sql_injection',
                    'details': 'Potential SQL injection found'
                })
                self.print_status("Found potential SQL injection", "WARNING")
        except:
            pass

    def _detect_cms(self, url: str):
        """Detect and scan common CMS platforms"""
        try:
            # Check for WordPress
            wp_login = requests.get(f"{url}/wp-login.php", verify=False, timeout=10)
            if wp_login.status_code == 200:
                self._scan_wordpress(url)
            
            # Check for Joomla
            joomla_admin = requests.get(f"{url}/administrator", verify=False, timeout=10)
            if joomla_admin.status_code == 200:
                self._scan_joomla(url)
                
        except:
            pass

    def _scan_wordpress(self, url: str):
        """Scan WordPress installation"""
        try:
            wpscan_cmd = [
                "wpscan",
                "--url", url,
                "--random-user-agent",
                "--enumerate", "vp,vt,tt,cb,dbe,u,m",
                "--format", "json"
            ]
            result = subprocess.run(wpscan_cmd, capture_output=True, text=True, timeout=300)
            if result.stdout:
                self.vulnerabilities[self.target]['findings'].append({
                    'type': 'wordpress_scan',
                    'details': result.stdout
                })
        except:
            pass

    def run(self) -> Set[str]:
        self.show_banner()
        self.print_status(f"Starting comprehensive scan for {self.target}")
        self.setup()
        
        # Original subdomain enumeration code
        self.print_status("Phase 1: Enumerating subdomains...")
        self.subdomains.update(self.run_subfinder())
        self.subdomains.update(self.run_amass())
        
        if not self.subdomains:
            self.print_status("No subdomains found!", "WARNING")
            return set()

        self.print_status(f"Found {len(self.subdomains)} subdomains", "SUCCESS")
        
        # Check alive domains
        self.print_status("Phase 2: Identifying alive domains...")
        self.check_alive_domains()
        
        # Enhanced scanning for each alive domain
        self.print_status("Phase 3: Performing comprehensive vulnerability scanning...")
        for domain in self.alive_domains:
            self.scan_ports(domain)
            self.scan_vulnerabilities(domain)

        # Generate detailed report
        try:
            scan_results = self._prepare_scan_results()
            report_path = self.report_generator.generate_report(
                scan_results, 
                f"{self.target}_scan_report",
                format=self.report_format
            )
            self.print_status(f"Report generated: {report_path}", "SUCCESS")
        except Exception as e:
            self.print_status(f"Error generating report: {e}", "ERROR")
        
        return self.subdomains

    def _prepare_scan_results(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "summary": {
                "total_subdomains": len(self.subdomains),
                "alive_domains": len(self.alive_domains),
                "total_open_ports": sum(len(ports) for ports in self.ports.values()),
                "total_vulnerabilities": sum(len(vulns['cves']) + len(vulns['findings']) 
                                          for vulns in self.vulnerabilities.values())
            },
            "details": {
                "all_subdomains": list(sorted(self.subdomains)),
                "alive_domains": sorted(self.alive_domains),
                "ports": self.ports,
                "technologies": self.technologies,
                "vulnerabilities": self.vulnerabilities
            }
        }
