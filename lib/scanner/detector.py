import html
import re
from urllib.parse import unquote

from bs4 import BeautifulSoup


class Detector:
    DANGEROUS_ATTRS = {"href", "src", "action", "formaction", "xlink:href", "srcdoc", "data"}

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
    def _contextual_reflection(payload, body):
        if payload not in body:
            return False
        if Detector._is_only_in_comments(payload, body):
            return False

        soup = BeautifulSoup(body, "html.parser")
        if Detector._payload_in_script(payload, soup):
            return True
        if Detector._payload_in_dangerous_attribute(payload, soup):
            return True
        if Detector._looks_like_tag_payload(payload):
            # Unescaped tag-shaped payload reflected in non-comment HTML is high-signal.
            return True

        return False

    @staticmethod
    def is_reflected(payload, response_text):
        for body in Detector._candidate_bodies(response_text):
            if Detector._contextual_reflection(payload, body):
                return True
        return False
