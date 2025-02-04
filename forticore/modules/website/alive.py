import asyncio
import aiohttp
import dns.resolver
from typing import Set, Dict, List
from ...core.scanner import BaseScanner
from colorama import Fore, Style
import socket
from concurrent.futures import ThreadPoolExecutor
import subprocess

class AliveHostScanner(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        self.timeout = 10
        self.ports = [80, 443, 21, 22, 8080, 8443]
        
    async def verify_hosts(self, domains: Set[str]) -> Dict[str, Dict]:
        """Enhanced live host verification"""
        results = {}
        
        print(f"\n{Fore.CYAN}[*] Verifying live hosts with multiple methods...{Style.RESET_ALL}")
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for domain in domains:
                task = asyncio.create_task(self._check_domain(session, domain))
                tasks.append(task)
            
            domain_results = await asyncio.gather(*tasks)
            
            for result in domain_results:
                if result:  # Only include live domains
                    results.update(result)
        
        return results

    async def _check_domain(self, session: aiohttp.ClientSession, domain: str) -> Dict:
        """Comprehensive domain checking"""
        result = {
            domain: {
                'http_status': None,
                'https_status': None,
                'ports': [],
                'dns_records': [],
                'services': {}
            }
        }
        
        # Check HTTP/HTTPS
        for protocol in ['http', 'https']:
            try:
                async with session.head(
                    f"{protocol}://{domain}", 
                    timeout=self.timeout,
                    allow_redirects=True
                ) as response:
                    result[domain][f'{protocol}_status'] = response.status
            except:
                continue

        # DNS resolution
        try:
            dns_results = await self._resolve_dns(domain)
            result[domain]['dns_records'] = dns_results
        except Exception as e:
            self.logger.debug(f"DNS resolution failed for {domain}: {e}")

        # Port scanning
        open_ports = await self._scan_ports(domain)
        result[domain]['ports'] = open_ports

        # Service detection for open ports
        if open_ports:
            services = await self._detect_services(domain, open_ports)
            result[domain]['services'] = services

        # Return result only if domain is alive
        if (result[domain]['http_status'] or 
            result[domain]['https_status'] or 
            result[domain]['ports']):
            return result
        return None

    async def _resolve_dns(self, domain: str) -> List[Dict]:
        """Resolve DNS records"""
        records = []
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for answer in answers:
                    records.append({
                        'type': record_type,
                        'value': str(answer)
                    })
            except:
                continue
                
        return records

    async def _scan_ports(self, domain: str) -> List[int]:
        """Fast port scanning"""
        open_ports = []
        
        try:
            # Use faster nmap scan for initial port discovery
            result = subprocess.run(
                ['nmap', '-p-', '-T4', '--min-rate=1000', '-n', domain],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # Parse nmap output for open ports
            for line in result.stdout.splitlines():
                if 'open' in line and 'tcp' in line:
                    port = int(line.split('/')[0])
                    open_ports.append(port)
                    
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Port scan timed out for {domain}")
        except Exception as e:
            self.logger.error(f"Port scan failed for {domain}: {e}")
            
        return open_ports

    async def _detect_services(self, domain: str, ports: List[int]) -> Dict:
        """Detect services on open ports"""
        services = {}
        
        try:
            # Use nmap for service detection
            port_list = ','.join(map(str, ports))
            result = subprocess.run(
                ['nmap', '-sV', '-p', port_list, domain],
                capture_output=True,
                text=True
            )
            
            # Parse service information
            for line in result.stdout.splitlines():
                if 'open' in line and 'tcp' in line:
                    parts = line.split()
                    port = int(parts[0].split('/')[0])
                    service = ' '.join(parts[2:])
                    services[port] = service
                    
        except Exception as e:
            self.logger.error(f"Service detection failed for {domain}: {e}")
            
        return services

    def is_domain_alive(self, results: Dict) -> bool:
        """Check if domain is considered alive based on results"""
        for domain_data in results.values():
            if (domain_data['http_status'] in [200, 301, 302, 403] or
                domain_data['https_status'] in [200, 301, 302, 403] or
                domain_data['ports']):
                return True
        return False
