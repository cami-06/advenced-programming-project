from datetime import datetime
from reporter.export.export_html import HTMLExporter
from reporter.export.export_json import JSONExporter


class Reporter:
    """
    Central reporting engine.
    Collects findings from scanners and exports them in various formats.
    """

    def __init__(self, target=None):
        self.target = target
        self.start_time = datetime.now()
        self.findings = []

    # =============================
    # FINDING COLLECTION
    # =============================
    def add_finding(self, finding):
        """
        Add a vulnerability finding produced by a scanner.
        """
        self.findings.append(finding)

    # =============================
    # DATA AGGREGATION
    # =============================
    def get_summary(self):
        """
        Generate a high-level summary of findings.
        """
        summary = {
            "total": len(self.findings),
            "by_severity": {}
        }

        for finding in self.findings:
            severity = getattr(finding, "severity", "INFO")
            summary["by_severity"].setdefault(severity, 0)
            summary["by_severity"][severity] += 1

        return summary

    def serialize_findings(self):
        """
        Convert findings into serializable dictionaries.
        """
        return [finding.to_dict() for finding in self.findings]

    # =============================
    # REPORT GENERATION
    # =============================
    def generate(self, formats=("html", "json")):
        """
        Generate reports in selected formats.
        """
        context = {
            "target": self.target,
            "scan_date": self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": self.get_summary(),
            "findings": self.serialize_findings()
        }

        if "html" in formats:
            HTMLExporter().export(context)

        if "json" in formats:
            JSONExporter().export(context)
