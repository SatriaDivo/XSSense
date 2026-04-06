from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class ScanResult:
    method: str
    target_url: str
    payload: str
    detected: bool
    request_data: Optional[Dict[str, str]] = None
    error: Optional[str] = None
