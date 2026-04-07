import html
import re
from urllib.parse import unquote

from bs4 import BeautifulSoup


class Detector:
    DANGEROUS_ATTRS = {"href", "src", "action", "formaction", "xlink:href", "srcdoc", "data"}
    VALID_MODES = {"strict", "loose"}

    def __init__(self, mode="strict"):
        mode = (mode or "strict").lower().strip()
        self.mode = mode if mode in self.VALID_MODES else "strict"

    @staticmethod
    def _candidate_bodies(response_text):
        if response_text is None:
            return []

        candidates = [response_text]
        unescaped = html.unescape(response_text)
        if unescaped != response_text:
            candidates.append(unescaped)

        url_decoded = unquote(response_text)
        if url_decoded not in candidates:
            candidates.append(url_decoded)

        return candidates

    @staticmethod
    def _is_only_in_comments(payload, response_text):
        if payload not in response_text:
            return False
        without_comments = re.sub(r"<!--.*?-->", "", response_text, flags=re.DOTALL)
        return payload not in without_comments

    @staticmethod
    def _payload_in_script(payload, soup):
        for script in soup.find_all("script"):
            text = script.string if script.string is not None else script.get_text()
            if text and payload in text:
                return True
        return False

    @staticmethod
    def _payload_in_dangerous_attribute(payload, soup):
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                values = value if isinstance(value, list) else [value]
                for item in values:
                    if not isinstance(item, str) or payload not in item:
                        continue

                    attr_name = str(attr).lower()
                    item_lower = item.lower()
                    if attr_name.startswith("on"):
                        return True
                    if attr_name in Detector.DANGEROUS_ATTRS:
                        if attr_name == "srcdoc":
                            return True
                        if "javascript:" in item_lower or "data:text/html" in item_lower:
                            return True
                        if payload.startswith("<") or payload.startswith(("'", '"', "</")):
                            return True
        return False

    @staticmethod
    def _looks_like_tag_payload(payload):
        return "<" in payload and ">" in payload

    @staticmethod
    def _extract_evidence(payload, body, window=90):
        if payload not in body:
            return None
        idx = body.find(payload)
        start = max(0, idx - window)
        end = min(len(body), idx + len(payload) + window)
        snippet = body[start:end].replace("\n", " ").replace("\r", " ")
        return snippet.strip()

    def _score_body(self, payload, body):
        if payload not in body:
            return 0, [], None
        if Detector._is_only_in_comments(payload, body):
            if self.mode == "loose":
                return 20, ["reflected_in_html_comment"], Detector._extract_evidence(payload, body)
            return 0, [], None

        soup = BeautifulSoup(body, "html.parser")
        reasons = []
        score = 0

        if Detector._payload_in_script(payload, soup):
            reasons.append("payload_in_script_tag")
            score = max(score, 95)
        if Detector._payload_in_dangerous_attribute(payload, soup):
            reasons.append("payload_in_dangerous_attribute")
            score = max(score, 90)
        if Detector._looks_like_tag_payload(payload):
            reasons.append("tag_like_payload_reflected")
            score = max(score, 80)

        if self.mode == "loose" and score == 0:
            reasons.append("raw_payload_reflection")
            score = 45

        evidence = Detector._extract_evidence(payload, body)
        return score, reasons, evidence

    @staticmethod
    def _confidence_level(score):
        if score >= 85:
            return "high"
        if score >= 65:
            return "medium"
        if score > 0:
            return "low"
        return None

    def analyze_reflection(self, payload, response_text):
        best_score = 0
        best_reasons = []
        best_evidence = None

        for body in Detector._candidate_bodies(response_text):
            score, reasons, evidence = self._score_body(payload, body)
            if score > best_score:
                best_score = score
                best_reasons = reasons
                best_evidence = evidence

        threshold = 70 if self.mode == "strict" else 35
        detected = best_score >= threshold
        return {
            "detected": detected,
            "confidence_score": best_score if best_score > 0 else None,
            "confidence_level": Detector._confidence_level(best_score) if best_score > 0 else None,
            "detection_reasons": best_reasons if best_reasons else None,
            "evidence": best_evidence if detected else None,
            "detection_mode": self.mode,
        }

    def is_reflected(self, payload, response_text):
        return self.analyze_reflection(payload, response_text)["detected"]
