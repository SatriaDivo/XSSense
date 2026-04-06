from urllib.parse import parse_qs, urljoin, urlparse
from typing import List
import time

from bs4 import BeautifulSoup

from lib.helper.Log import Log
from lib.helper.helper import C, G, N
from lib.scanner.contracts import ScanResult


class Injector:
    def __init__(
        self,
        session,
        base_url,
        html_body,
        payload,
        detector,
        reporter,
        timeout=15,
        retries=1,
    ):
        self.session = session
        self.base_url = base_url
        self.html_body = html_body
        self.payload = payload
        self.detector = detector
        self.reporter = reporter
        self.timeout = timeout
        self.retries = retries

    def _send_request(self, method, url, **kwargs):
        last_error = None
        for _ in range(self.retries + 1):
            start = time.perf_counter()
            try:
                response = self.session.request(
                    method,
                    url,
                    verify=False,
                    timeout=self.timeout,
                    **kwargs,
                )
                elapsed_ms = int((time.perf_counter() - start) * 1000)
                return response, None, elapsed_ms, response.status_code
            except Exception as e:
                last_error = str(e)
        return None, last_error, None, None

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
            response, error, elapsed_ms, status_code = self._send_request("POST", form_url, data=keys)
            if response is None:
                results.append(
                    ScanResult(
                        method="POST",
                        source="post_form",
                        target_url=form_url,
                        parameter_name=",".join(keys.keys()),
                        payload=self.payload,
                        detected=False,
                        status_code=status_code,
                        response_time_ms=elapsed_ms,
                        request_data=keys,
                        error=error,
                    )
                )
                continue

            results.append(
                ScanResult(
                    method="POST",
                    source="post_form",
                    target_url=response.url,
                    parameter_name=",".join(keys.keys()),
                    payload=self.payload,
                    detected=self.detector.is_reflected(self.payload, response.text),
                    status_code=status_code,
                    response_time_ms=elapsed_ms,
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
            response, error, elapsed_ms, status_code = self._send_request("GET", form_url, params=keys)
            if response is None:
                results.append(
                    ScanResult(
                        method="GET",
                        source="get_form",
                        target_url=form_url,
                        parameter_name=",".join(keys.keys()),
                        payload=self.payload,
                        detected=False,
                        status_code=status_code,
                        response_time_ms=elapsed_ms,
                        request_data=keys,
                        error=error,
                    )
                )
                continue

            results.append(
                ScanResult(
                    method="GET",
                    source="get_form",
                    target_url=response.url,
                    parameter_name=",".join(keys.keys()),
                    payload=self.payload,
                    detected=self.detector.is_reflected(self.payload, response.text),
                    status_code=status_code,
                    response_time_ms=elapsed_ms,
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

            response, error, elapsed_ms, status_code = self._send_request("GET", target_url, params=test_params)
            if response is None:
                results.append(
                    ScanResult(
                        method="GET",
                        source="get_link",
                        target_url=target_url,
                        parameter_name=",".join(test_params.keys()),
                        payload=self.payload,
                        detected=False,
                        status_code=status_code,
                        response_time_ms=elapsed_ms,
                        request_data=test_params,
                        error=error,
                    )
                )
                continue

            results.append(
                ScanResult(
                    method="GET",
                    source="get_link",
                    target_url=response.url,
                    parameter_name=",".join(test_params.keys()),
                    payload=self.payload,
                    detected=self.detector.is_reflected(self.payload, response.text),
                    status_code=status_code,
                    response_time_ms=elapsed_ms,
                    request_data=test_params,
                )
            )
        return results
