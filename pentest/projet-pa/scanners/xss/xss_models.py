# scanners/xss/xss_models.py

from dataclasses import dataclass


@dataclass
class XSSFinding:
    url: str
    parameter: str
    payload: str
    issue: str
    severity: str
    evidence: str
    method: str = "GET"
    vuln_type: str = "Reflected XSS"

    def to_dict(self):
        return {
            "category": "Cross-Site Scripting (XSS)",
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "issue": self.issue,
            "severity": self.severity,
            "evidence": self.evidence,
            "method": self.method,
            "type": self.vuln_type
        }