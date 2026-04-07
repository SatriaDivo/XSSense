from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class ScanResult:
    method: str
    source: str
    target_url: str
    parameter_name: Optional[str]
    payload: str
    detected: bool
    status_code: Optional[int] = None
    response_time_ms: Optional[int] = None
    request_data: Optional[Dict[str, str]] = None
    error: Optional[str] = None
    detection_mode: Optional[str] = None
    confidence_score: Optional[int] = None
    confidence_level: Optional[str] = None
    detection_reasons: Optional[List[str]] = None
    evidence: Optional[str] = None
