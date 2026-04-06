from lib.helper.Log import Log
from lib.scanner.contracts import ScanResult


class Reporter:
    def __init__(self, output_path="xss.txt"):
        self.output_path = output_path

    def write_finding(self, target_url):
        with open(self.output_path, "a", encoding="utf-8") as file:
            file.write(str(target_url) + "\n\n")

    def report(self, result: ScanResult):
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
