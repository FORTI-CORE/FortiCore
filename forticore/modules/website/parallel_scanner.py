import asyncio
import concurrent.futures
from typing import Set, Dict, Any
import subprocess
from ...core.scanner import BaseScanner
import httpx
import json
import threading
from queue import Queue
from .alive import AliveHostScanner
import os

class ParallelScanner(BaseScanner):
    def __init__(self, target: str, scan_profile: str = "normal"):
        super().__init__(target)
        self.scan_profile = scan_profile
        self.results_queue = Queue()
        self.scan_status = {"running": True}
        self.timeout = 300  # 5 minutes timeout
        
    async def run_tool_async(self, tool: str, args: list) -> Set[str]:
        """Run a tool with fallback and retry logic"""
        retries = 3
        for attempt in range(retries):
            try:
                process = await asyncio.create_subprocess_exec(
                    tool, *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                if process.returncode == 0:
                    return set(stdout.decode().splitlines())
                else:
                    self.logger.warning(f"{tool} failed (attempt {attempt + 1}/{retries}): {stderr.decode()}")
            except Exception as e:
                self.logger.error(f"Error running {tool} (attempt {attempt + 1}/{retries}): {e}")
                await asyncio.sleep(1)  # Wait before retry
        return set()  # Return empty set if all attempts fail

    async def enumerate_subdomains(self) -> Set[str]:
        """Enhanced subdomain enumeration using multiple tools in parallel"""
        tasks = [
            self.run_tool_async("subfinder", ["-d", self.target]),
            self.run_tool_async("amass", ["enum", "-passive", "-d", self.target]),
            self.run_tool_async("assetfinder", [self.target]),
            self.run_tool_async("sublist3r", ["-d", self.target, "-o", "temp_sublist3r.txt"])
        ]
        
        try:
            results = await asyncio.gather(*tasks)
            all_subdomains = set().union(*results)
            return all_subdomains
        except Exception as e:
            self.logger.error(f"Error during subdomain enumeration: {e}")
            return set()

    async def verify_live_hosts(self, subdomains: Set[str]) -> Set[str]:
        """Enhanced live host verification using multiple tools"""
        alive_scanner = AliveHostScanner(self.target)
        results = await alive_scanner.verify_hosts(subdomains)
        
        # Filter for alive domains
        alive_domains = {
            domain for domain, data in results.items() 
            if alive_scanner.is_domain_alive({domain: data})
        }
        
        # Store detailed results
        self.host_details = results
        return alive_domains

    async def detect_technologies(self, domain: str) -> Dict[str, Any]:
        """Detect technologies used by the target"""
        results = {}
        
        # Run whatweb scan
        try:
            whatweb_cmd = [
                "whatweb",
                "--color=never",
                "--log-json=-",
                domain
            ]
            process = await asyncio.create_subprocess_exec(
                *whatweb_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            if stdout:
                results['whatweb'] = json.loads(stdout)
        except Exception as e:
            self.logger.error(f"WhatWeb scan failed: {e}")

        # Run wafw00f for WAF detection
        try:
            wafw00f_cmd = ["wafw00f", "-a", domain]
            process = await asyncio.create_subprocess_exec(
                *wafw00f_cmd,
                stdout=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            if stdout:
                results['waf'] = stdout.decode()
        except Exception as e:
            self.logger.error(f"WAF detection failed: {e}")

        return results

    def scan_vulnerabilities_parallel(self, domain: str):
        threads = []
        
        # SQL Injection scanning
        sql_thread = threading.Thread(
            target=self._run_sqlmap_scan,
            args=(domain,)
        )
        threads.append(sql_thread)
        
        # XSS scanning
        xss_thread = threading.Thread(
            target=self._run_xsstrike_scan,
            args=(domain,)
        )
        threads.append(xss_thread)
        
        # Nuclei scanning
        nuclei_thread = threading.Thread(
            target=self._run_nuclei_scan,
            args=(domain,)
        )
        threads.append(nuclei_thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
            
        # Wait for completion
        for thread in threads:
            thread.join()

    def _run_nuclei_scan(self, domain: str):
        try:
            cmd = [
                "nuclei",
                "-u", domain,
                "-severity", "critical,high",
                "-json"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.stdout:
                findings = json.loads(result.stdout)
                self.results_queue.put(("nuclei", domain, findings))
        except Exception as e:
            self.logger.error(f"Nuclei scan failed: {e}") 

    async def cleanup(self):
        """Cleanup resources after scanning"""
        try:
            if hasattr(self, 'temp_files'):
                for temp_file in self.temp_files:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}") 