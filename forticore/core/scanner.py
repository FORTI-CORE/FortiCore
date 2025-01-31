from abc import ABC, abstractmethod
from pathlib import Path
from ..utils.logger import Logger
from ..utils.report_generator import ReportGenerator
from typing import Dict, Any

class BaseScanner(ABC):
    def __init__(self, target: str, output_dir: str, report_format: str = "html"):
        self.target = target
        self.output_dir = Path(output_dir)
        self.logger = Logger.get_logger(__name__)
        self.report_generator = ReportGenerator(self.output_dir, format=report_format)
        self.scan_results: Dict[str, Any] = {}
        
    def setup(self):
        """Prepare scanning environment"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    @abstractmethod
    def run(self):
        """Main scanning method to be implemented by subclasses"""
        pass
        
    def cleanup(self):
        """Cleanup after scanning"""
        pass

    def generate_report(self, data: Dict[str, Any], report_name: str = "report") -> Path:
        """Generate a report from the provided data"""
        try:
            report_path = self.report_generator.generate(data, report_name)
            self.logger.info(f"Report generated at: {report_path}")
            return report_path
        except Exception as e:
            self.logger.error(f"Failed to generate report: {e}")
            return None
