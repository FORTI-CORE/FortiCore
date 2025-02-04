import asyncio
import httpx
from typing import List, Dict, Any
from ...core.scanner import BaseScanner

class CSRFSSRFScanner(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target, f"scans/{target}/csrf_ssrf")
        self.collaborator_url = "http://collaborator.example.com"  # Replace with actual collaborator
        
    async def scan_csrf(self, url: str) -> List[Dict[str, Any]]:
        """Scan for CSRF vulnerabilities"""
        findings = []
        timeout = httpx.Timeout(30.0)
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            try:
                # Get the form
                response = await client.get(url)
                forms = self._extract_forms(response.text)
                
                for form in forms:
                    if not self._has_csrf_token(form):
                        findings.append({
                            'type': 'csrf',
                            'severity': 'medium',
                            'url': url,
                            'details': 'Form found without CSRF token',
                            'form': form
                        })
            except Exception as e:
                self.logger.error(f"CSRF scan error: {e}")
        
        return findings

    async def scan_ssrf(self, url: str) -> List[Dict[str, Any]]:
        """Scan for SSRF vulnerabilities"""
        findings = []
        payloads = [
            self.collaborator_url,
            f"http://{self.collaborator_url}",
            f"https://{self.collaborator_url}"
        ]
        
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            for payload in payloads:
                try:
                    params = {'url': payload, 'path': payload}
                    response = await client.get(url, params=params)
                    
                    # Check for successful SSRF
                    if self._check_collaborator_interaction(payload):
                        findings.append({
                            'type': 'ssrf',
                            'severity': 'high',
                            'url': url,
                            'payload': payload,
                            'details': 'Potential SSRF vulnerability detected'
                        })
                except Exception as e:
                    self.logger.error(f"SSRF scan error: {e}")
        
        return findings 