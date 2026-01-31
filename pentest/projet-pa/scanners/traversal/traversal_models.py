from dataclasses import dataclass
from enum import Enum


class TraversalType(Enum):
    """Types de payloads de directory traversal"""
    BASIC = "basic"
    ENCODED = "encoded"
    DOUBLE_ENCODED = "double_encoded"
    UNICODE = "unicode"
    WINDOWS = "windows"
    LINUX = "linux"


@dataclass
class TraversalFinding:
    """Représente une vulnérabilité de directory traversal détectée"""
    url: str
    parameter: str
    payload: str
    issue: str
    severity: str
    evidence: str
    traversal_type: str
    method: str = "GET"  # GET ou POST
    
    def to_dict(self):
        return {
            "category": "Directory Traversal",
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "issue": self.issue,
            "severity": self.severity,
            "evidence": self.evidence,
            "traversal_type": self.traversal_type,
            "method": self.method
        }
