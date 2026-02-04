# scanners/sql/sql_scanner.py

from scanners.base_scanner import BaseScanner
from scanners.sql.sql_detector import SQLDetector
from scanners.sql.sql_tester import SQLTester
from scanners.sql.sql_models import SQLFinding

class SQLScanner(BaseScanner):

    def __init__(self, crawler,http_client,reporter):
        self.crawler=crawler
        self.http=http_client
        self.detector=SQLDetector()
        self.tester=SQLTester()
        self.reporter=reporter

    def scan(self):
        findings=[]

        for url in self.crawler.get_urls():
            for param in self.detector.extract_parameters(url):
                for test in (
                    self.tester.test_error_based,
                    self.tester.test_boolean_based,
                    self.tester.test_time_based
                ):
                    vulnerable, payload, evidence = test(self.http,url,param)

                    if vulnerable:
                        finding=SQLFinding(
                            url=url,
                            parameter=param,
                            payload=payload,
                            issue="SQL Injection",
                            severity="CRITICAL",
                            evidence=evidence
                        )
                        self.reporter.add_finding(finding)
                        findings.append(finding)
                        break  # stop testing this parameter

        return findings
