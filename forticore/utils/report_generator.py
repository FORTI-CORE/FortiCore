import json
from pathlib import Path
from datetime import datetime
import threading
from typing import Dict, Any
import csv
import yaml

class ReportGenerator:
    def __init__(self, output_dir, format="html"):
        self.output_dir = Path(output_dir)
        self.format = format.lower()
        self.supported_formats = {
            "html": self._generate_html,
            "json": self._generate_json,
            "csv": self._generate_csv,
            "yaml": self._generate_yaml
        }
        self._lock = threading.Lock()  # Thread safety for concurrent report generation

    def generate(self, data: Dict[str, Any], report_name: str = "report") -> Path:
        """
        Generate a report in the specified format.
        Thread-safe method that can be called from multiple scanners simultaneously.
        """
        if self.format not in self.supported_formats:
            raise ValueError(f"Unsupported format: {self.format}")

        # Add metadata to the report
        enriched_data = self._enrich_data(data)

        with self._lock:
            try:
                return self.supported_formats[self.format](enriched_data, report_name)
            except Exception as e:
                # Fallback to JSON if the chosen format fails
                print(f"Failed to generate {self.format} report. Falling back to JSON. Error: {e}")
                return self._generate_json(enriched_data, f"{report_name}_fallback")

    def _enrich_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add metadata to the report data"""
        return {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "report_format": self.format,
                "tool_version": "1.0.0"  # You can make this dynamic
            },
            "scan_results": data
        }

    def _generate_html(self, data: Dict[str, Any], report_name: str) -> Path:
        """Generate an HTML report with improved styling and structure"""
        report_path = self.output_dir / f"{report_name}.html"
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>FortiCore Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .container { max-width: 1200px; margin: 0 auto; }
                .metadata { background: #f5f5f5; padding: 10px; border-radius: 5px; }
                .results { margin-top: 20px; }
                .section { margin-bottom: 20px; }
                .vulnerability { color: #d63031; }
                table { width: 100%; border-collapse: collapse; }
                th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
                th { background-color: #f5f5f5; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>FortiCore Scan Report</h1>
                <div class="metadata">
                    <h2>Metadata</h2>
                    <table>
                        <tr><th>Timestamp</th><td>{timestamp}</td></tr>
                        <tr><th>Format</th><td>{format}</td></tr>
                        <tr><th>Version</th><td>{version}</td></tr>
                    </table>
                </div>
                <div class="results">
                    <h2>Scan Results</h2>
                    {results}
                </div>
            </div>
        </body>
        </html>
        """

        def dict_to_html(d, level=0):
            if isinstance(d, dict):
                result = "<table>"
                for k, v in d.items():
                    result += f"<tr><th>{k}</th><td>{dict_to_html(v, level+1)}</td></tr>"
                result += "</table>"
                return result
            elif isinstance(d, (list, set)):
                return "<ul>" + "".join(f"<li>{dict_to_html(i, level+1)}</li>" for i in d) + "</ul>"
            else:
                return str(d)

        with open(report_path, "w") as f:
            metadata = data["metadata"]
            results_html = dict_to_html(data["scan_results"])
            
            f.write(html_template.format(
                timestamp=metadata["timestamp"],
                format=metadata["report_format"],
                version=metadata["tool_version"],
                results=results_html
            ))

        return report_path

    def _generate_json(self, data: Dict[str, Any], report_name: str) -> Path:
        """Generate a JSON report with proper formatting"""
        report_path = self.output_dir / f"{report_name}.json"
        with open(report_path, "w") as f:
            json.dump(data, f, indent=4, sort_keys=True)
        return report_path

    def _generate_csv(self, data: Dict[str, Any], report_name: str) -> Path:
        """Generate a CSV report (flattened structure)"""
        report_path = self.output_dir / f"{report_name}.csv"
        
        def flatten_dict(d, parent_key='', sep='_'):
            items = []
            for k, v in d.items():
                new_key = f"{parent_key}{sep}{k}" if parent_key else k
                if isinstance(v, dict):
                    items.extend(flatten_dict(v, new_key, sep=sep).items())
                else:
                    items.append((new_key, v))
            return dict(items)

        flattened_data = flatten_dict(data)
        
        with open(report_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(flattened_data.keys())
            writer.writerow(flattened_data.values())
            
        return report_path

    def _generate_yaml(self, data: Dict[str, Any], report_name: str) -> Path:
        """Generate a YAML report"""
        report_path = self.output_dir / f"{report_name}.yaml"
        with open(report_path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        return report_path
