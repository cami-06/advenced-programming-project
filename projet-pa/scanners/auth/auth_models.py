from dataclasses import dataclass
from typing import Dict


# ================================
# SCANNER-INTERNAL MODEL
# ================================
@dataclass
class LoginForm:
    """
    Represents a detected authentication form.
    Used internally by AuthScanner.
    """
    action: str
    method: str
    inputs: Dict[str, str]
    has_csrf: bool


# ================================
# SCANNER → REPORTER MODEL
# ================================
@dataclass
class AuthFinding:
    """
    Represents an authentication-related vulnerability finding.
    Passed from scanner to reporter.
    """
    url: str
    issue: str
    severity: str
    evidence: str

    def to_dict(self):
        """
        Convert finding into a serializable dictionary
        understood by the reporting engine.
        """
        return {
            "category": "Authentication",
            "url": self.url,
            "issue": self.issue,
            "severity": self.severity,
            "evidence": self.evidence
        }
