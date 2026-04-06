from urllib.parse import parse_qs, urljoin, urlparse
from typing import List

from bs4 import BeautifulSoup

from lib.helper.Log import Log
from lib.helper.helper import C, G, N
from lib.scanner.contracts import ScanResult


class Injector:
    def __init__(self, session, base_url, html_body, payload, detector, reporter):
        self.session = session
        self.base_url = base_url
        self.html_body = html_body
        self.payload = payload
        self.detector = detector
        self.reporter = reporter

    def _collect_form_keys(self, form):
        keys = {}
        for item in form.find_all(["input", "textarea"]):
            name = item.get("name")
            if not name:
                continue

            value = name if item.get("type") == "submit" else self.payload
            Log.info("Form key name: " + G + name + N + " value: " + G + value)
            keys[name] = value
        return keys

    def scan_post_forms(self) -> List[ScanResult]:
        results: List[ScanResult] = []
        bs_obj = BeautifulSoup(self.html_body, "html.parser")
        forms = bs_obj.find_all("form", method=True)

        for form in forms:
            action = form.get("action", self.base_url)
            if form.get("method", "").lower().strip() != "post":
                continue

            form_url = urljoin(self.base_url, action)
            Log.warning("Target have form with POST method: " + C + form_url)
            Log.info("Collecting form input key.....")

            keys = self._collect_form_keys(form)
            if not keys:
                continue

            Log.info("Sending payload (POST) method...")
            try:
                response = self.session.post(form_url, data=keys, verify=False)
            except Exception as e:
                results.append(
                    ScanResult(
                        method="POST",
                        target_url=form_url,
                        payload=self.payload,
                        detected=False,
                        request_data=keys,
                        error=str(e),
                    )
                )
                continue

            results.append(
                ScanResult(
                    method="POST",
                    target_url=response.url,
                    payload=self.payload,
                    detected=self.detector.is_reflected(self.payload, response.text),
                    request_data=keys,
                )
            )
        return results

    def scan_get_forms(self) -> List[ScanResult]:
        results: List[ScanResult] = []
        bs_obj = BeautifulSoup(self.html_body, "html.parser")
        forms = bs_obj.find_all("form", method=True)

        for form in forms:
            action = form.get("action", self.base_url)
            if form.get("method", "").lower().strip() != "get":
                continue

            form_url = urljoin(self.base_url, action)
            Log.warning("Target have form with GET method: " + C + form_url)
            Log.info("Collecting form input key.....")

            keys = self._collect_form_keys(form)
            if not keys:
                continue

            Log.info("Sending payload (GET) method...")
            try:
                response = self.session.get(form_url, params=keys, verify=False)
            except Exception as e:
                results.append(
                    ScanResult(
                        method="GET",
                        target_url=form_url,
                        payload=self.payload,
                        detected=False,
                        request_data=keys,
                        error=str(e),
                    )
                )
                continue

            results.append(
                ScanResult(
                    method="GET",
                    target_url=response.url,
                    payload=self.payload,
                    detected=self.detector.is_reflected(self.payload, response.text),
                    request_data=keys,
                )
            )
        return results

    def scan_get_links(self) -> List[ScanResult]:
        results: List[ScanResult] = []
        bs_obj = BeautifulSoup(self.html_body, "html.parser")
        links = bs_obj.find_all("a", href=True)

        for anchor in links:
            raw_url = anchor["href"].strip()
            if raw_url.startswith(("mailto:", "tel:", "javascript:", "#")):
                Log.info("URL is not an HTTP url, ignoring")
                continue

            base = urljoin(self.base_url, raw_url)
            parsed = urlparse(base)
            if parsed.scheme not in ("http", "https") or not parsed.query:
                continue

            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue

            Log.warning("Found link with query: " + G + parsed.query + N + " Maybe a vuln XSS point")
            test_params = {key: self.payload for key in params}
            target_url = parsed._replace(query="").geturl()
            Log.info("Query (GET) : " + target_url + " -> " + str(test_params))

            try:
                response = self.session.get(target_url, params=test_params, verify=False)
            except Exception as e:
                results.append(
                    ScanResult(
                        method="GET",
                        target_url=target_url,
                        payload=self.payload,
                        detected=False,
                        request_data=test_params,
                        error=str(e),
                    )
                )
                continue

            results.append(
                ScanResult(
                    method="GET",
                    target_url=response.url,
                    payload=self.payload,
                    detected=self.detector.is_reflected(self.payload, response.text),
                    request_data=test_params,
                )
            )
        return results
