# scanners/web/auth_scanner.py

from scanners.base_scanner import BaseScanner
from scanners.auth.auth_detector import AuthDetector
from scanners.auth.auth_tester import AuthTester
from scanners.auth.auth_models import AuthFinding

class AuthScanner(BaseScanner):

    def __init__(self, crawler, http_client, reporter):
        self.crawler = crawler
        self.http = http_client
        self.detector = AuthDetector()
        self.tester = AuthTester()
        self.reporter = reporter

    def scan(self):
        findings = []

        for url in self.crawler.get_urls():
            response = self.http.get(url)

            # Detect protected resources
            if self.detector.is_protected_response(response):
                bypassed, evidence = self.tester.test_unauthenticated_access(self.http, url)

                if bypassed:
                    findings.append(AuthFinding(
                        url=url,
                        issue="Authentication Bypass",
                        severity="HIGH",
                        evidence=evidence
                    ))

            # Detect login forms
            forms = self.detector.detect_login_forms(response.text)
            for form in forms:
                if not form["has_csrf"]:
                    findings.append(AuthFinding(
                        url=url,
                        issue="Login form without CSRF protection",
                        severity="MEDIUM",
                        evidence="No CSRF token detected"
                    ))

        for f in findings:
            self.reporter.add_finding(f)

        return findings
