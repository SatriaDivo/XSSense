import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from lib.helper.Log import Log
from lib.scanner.contracts import ScanResult


class Reporter:
    def __init__(self, output_path="xss.txt"):
        self.output_path = output_path
        self.results = []

    def write_finding(self, target_url):
        with open(self.output_path, "a", encoding="utf-8") as file:
            file.write(str(target_url) + "\n\n")

    def report(self, result: ScanResult):
        self.results.append(asdict(result))

        if result.error:
            Log.info("Internal error: " + result.error)
            return

        if result.detected:
            Log.high(f"Detected XSS ({result.method}) at " + result.target_url)
            self.write_finding(result.target_url)
            if result.request_data is not None:
                Log.high(f"{result.method} data: " + str(result.request_data))
        else:
            Log.info(f"Parameter page using ({result.method}) payloads but not 100% yet...")

    def export_json(self, output_json_path):
        payload = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_checks": len(self.results),
            "total_findings": len([item for item in self.results if item.get("detected")]),
            "findings": [item for item in self.results if item.get("detected")],
            "results": self.results,
        }

        out_file = Path(output_json_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        Log.info("JSON report saved: " + str(output_json_path))
