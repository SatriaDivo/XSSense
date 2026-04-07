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
            confidence_text = ""
            if result.confidence_level is not None or result.confidence_score is not None:
                confidence_text = f" [{result.confidence_level or 'unknown'}:{result.confidence_score or 0}]"
            Log.high(f"Detected XSS ({result.method}) at " + result.target_url + confidence_text)
            self.write_finding(result.target_url)
            if result.request_data is not None:
                Log.high(f"{result.method} data: " + str(result.request_data))
            if result.evidence:
                Log.info("Evidence: " + result.evidence[:160])
        else:
            Log.info(f"Parameter page using ({result.method}) payloads but not 100% yet...")

    def export_json(self, output_json_path):
        confidence_summary = {
            "high": len([item for item in self.results if item.get("confidence_level") == "high"]),
            "medium": len([item for item in self.results if item.get("confidence_level") == "medium"]),
            "low": len([item for item in self.results if item.get("confidence_level") == "low"]),
        }

        payload = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_checks": len(self.results),
            "total_findings": len([item for item in self.results if item.get("detected")]),
            "confidence_summary": confidence_summary,
            "findings": [item for item in self.results if item.get("detected")],
            "results": self.results,
        }

        out_file = Path(output_json_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        Log.info("JSON report saved: " + str(output_json_path))
