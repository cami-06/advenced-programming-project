from dataclasses import dataclass


@dataclass
class SQLFinding:
    url:str
    parameter:str
    payload:str
    issue:str
    severity:str
    evidence:str

    def to_dict(self):
        return {
            "category":"SQL Injection",
            "url":self.url,
            "parameter":self.parameter,
            "payload":self.payload,
            "issue":self.issue,
            "severity":self.severity,
            "evidence":self.evidence
        }
