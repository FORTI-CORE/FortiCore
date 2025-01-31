import os
import subprocess
from typing import Set
from pathlib import Path
from ..utils.report_generator import ReportGenerator
import logging

class BaseScanner:
    def __init__(self, target: str, output_dir: str):
        """
        Initialize the base scanner
        Args:
            target: Target to scan
            output_dir: Directory to store scan results
        """
        self.target = target
        self.output_dir = Path(output_dir)
        self.logger = logging.getLogger(__name__)
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def setup(self):
        """Setup required for scanning"""
        pass

    def run_subfinder(self) -> Set[str]:
        """Run subfinder for subdomain enumeration"""
        try:
            result = subprocess.run(
                ['subfinder', '-d', self.target, '-silent'],
                capture_output=True,
                text=True
            )
            return set(result.stdout.strip().split('\n')) if result.stdout else set()
        except Exception as e:
            self.logger.error(f"Error running subfinder: {e}")
            return set()

    def run_amass(self) -> Set[str]:
        """Run amass for subdomain enumeration"""
        try:
            result = subprocess.run(
                ['amass', 'enum', '-passive', '-d', self.target],
                capture_output=True,
                text=True
            )
            return set(result.stdout.strip().split('\n')) if result.stdout else set()
        except Exception as e:
            self.logger.error(f"Error running amass: {e}")
            return set()

    def run(self) -> None:
        """Run the scanner"""
        raise NotImplementedError("Subclasses must implement run()")
