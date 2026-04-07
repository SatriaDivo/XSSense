from urllib.parse import parse_qs, urlencode, urljoin, urlparse
from typing import List
import time

from bs4 import BeautifulSoup

from lib.helper.Log import Log
from lib.helper.helper import C, G, N
from lib.scanner.contracts import ScanResult

def _resolve_rust_engine():
    try:
        import xssense_engine as rust_engine
    except Exception:
        return None

    if hasattr(rust_engine, "scan_batch"):
        return rust_engine

    nested = getattr(rust_engine, "xssense_engine", None)
    if nested is not None and hasattr(nested, "scan_batch"):
        return nested

    return None


RUST_ENGINE = _resolve_rust_engine()


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

    def _analyze(self, response_text):
        return self.detector.analyze_reflection(self.payload, response_text)

    def _collect_get_link_candidates(self):
        candidates = []
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
            target_url = parsed._replace(query="", fragment="").geturl()
            injected_url = parsed._replace(query=urlencode(test_params), fragment="").geturl()
            Log.info("Query (GET) : " + target_url + " -> " + str(test_params))
            candidates.append(
                {
                    "target_url": target_url,
                    "injected_url": injected_url,
                    "parameter_name": ",".join(test_params.keys()),
                    "request_data": test_params,
                }
            )

        return candidates

    def _scan_get_links_with_rust_batch(self, candidates):
        if RUST_ENGINE is None:
            return None

        urls = [item["injected_url"] for item in candidates]
        payloads = [self.payload for _ in candidates]
        if not urls:
            return []

        if hasattr(RUST_ENGINE, "scan_batch_detailed"):
            try:
                detailed_results = RUST_ENGINE.scan_batch_detailed(urls, payloads)
            except Exception as e:
                Log.warning("Rust scan_batch_detailed failed, fallback to Python: " + str(e))
                return None

            if len(detailed_results) != len(candidates):
                Log.warning("Rust scan_batch_detailed result length mismatch, fallback to Python")
                return None

            Log.info("Rust scan_batch_detailed enabled for GET link checks: " + str(len(urls)) + " requests")
            results = []
            for item, entry in zip(candidates, detailed_results):
                target_url, response_body, status_code, response_time_ms, error = entry
                analysis = self._analyze(response_body)
                results.append(
                    ScanResult(
                        method="GET",
                        source="get_link_rust_batch",
                        target_url=target_url,
                        parameter_name=item["parameter_name"],
                        payload=self.payload,
                        detected=analysis["detected"],
                        status_code=status_code,
                        response_time_ms=response_time_ms,
                        request_data=item["request_data"],
                        error=error,
                        detection_mode=analysis["detection_mode"],
                        confidence_score=analysis["confidence_score"],
                        confidence_level=analysis["confidence_level"],
                        detection_reasons=analysis["detection_reasons"],
                        evidence=analysis["evidence"],
                    )
                )
            return results

        try:
            vulnerable_urls = set(RUST_ENGINE.scan_batch(urls, payloads))
        except Exception as e:
            Log.warning("Rust scan_batch failed, fallback to Python: " + str(e))
            return None

        Log.info("Rust scan_batch enabled for GET link checks: " + str(len(urls)) + " requests")
        results = []
        for item in candidates:
            detected = item["injected_url"] in vulnerable_urls
            confidence_score = 70 if detected else None
            results.append(
                ScanResult(
                    method="GET",
                    source="get_link_rust_batch",
                    target_url=item["injected_url"],
                    parameter_name=item["parameter_name"],
                    payload=self.payload,
                    detected=detected,
                    status_code=None,
                    response_time_ms=None,
                    request_data=item["request_data"],
                    detection_mode=getattr(self.detector, "mode", "strict"),
                    confidence_score=confidence_score,
                    confidence_level="medium" if detected else None,
                    detection_reasons=["rust_contains_payload"] if detected else None,
                )
            )
        return results

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
                        detection_mode=getattr(self.detector, "mode", "strict"),
                    )
                )
                continue

            analysis = self._analyze(response.text)
            results.append(
                ScanResult(
                    method="POST",
                    source="post_form",
                    target_url=response.url,
                    parameter_name=",".join(keys.keys()),
                    payload=self.payload,
                    detected=analysis["detected"],
                    status_code=status_code,
                    response_time_ms=elapsed_ms,
                    request_data=keys,
                    detection_mode=analysis["detection_mode"],
                    confidence_score=analysis["confidence_score"],
                    confidence_level=analysis["confidence_level"],
                    detection_reasons=analysis["detection_reasons"],
                    evidence=analysis["evidence"],
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
                        detection_mode=getattr(self.detector, "mode", "strict"),
                    )
                )
                continue

            analysis = self._analyze(response.text)
            results.append(
                ScanResult(
                    method="GET",
                    source="get_form",
                    target_url=response.url,
                    parameter_name=",".join(keys.keys()),
                    payload=self.payload,
                    detected=analysis["detected"],
                    status_code=status_code,
                    response_time_ms=elapsed_ms,
                    request_data=keys,
                    detection_mode=analysis["detection_mode"],
                    confidence_score=analysis["confidence_score"],
                    confidence_level=analysis["confidence_level"],
                    detection_reasons=analysis["detection_reasons"],
                    evidence=analysis["evidence"],
                )
            )
        return results

    def scan_get_links(self) -> List[ScanResult]:
        results: List[ScanResult] = []
        candidates = self._collect_get_link_candidates()

        rust_results = self._scan_get_links_with_rust_batch(candidates)
        if rust_results is not None:
            return rust_results

        for item in candidates:
            response, error, elapsed_ms, status_code = self._send_request(
                "GET",
                item["target_url"],
                params=item["request_data"],
            )
            if response is None:
                results.append(
                    ScanResult(
                        method="GET",
                        source="get_link",
                        target_url=item["target_url"],
                        parameter_name=item["parameter_name"],
                        payload=self.payload,
                        detected=False,
                        status_code=status_code,
                        response_time_ms=elapsed_ms,
                        request_data=item["request_data"],
                        error=error,
                        detection_mode=getattr(self.detector, "mode", "strict"),
                    )
                )
                continue

            analysis = self._analyze(response.text)
            results.append(
                ScanResult(
                    method="GET",
                    source="get_link",
                    target_url=response.url,
                    parameter_name=item["parameter_name"],
                    payload=self.payload,
                    detected=analysis["detected"],
                    status_code=status_code,
                    response_time_ms=elapsed_ms,
                    request_data=item["request_data"],
                    detection_mode=analysis["detection_mode"],
                    confidence_score=analysis["confidence_score"],
                    confidence_level=analysis["confidence_level"],
                    detection_reasons=analysis["detection_reasons"],
                    evidence=analysis["evidence"],
                )
            )
        return results
