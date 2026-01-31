# scanners/xss/xss_scanner.py

from scanners.base_scanner import BaseScanner
from scanners.xss.xss_detector import XSSDetector
from scanners.xss.test import XSSTester
from scanners.xss.xss_models import XSSFinding


class XSSScanner(BaseScanner):
    """
    Scanner pour détecter les vulnérabilités Cross-Site Scripting (XSS).
    
    Teste :
    - Les paramètres URL (Reflected XSS)
    - Les formulaires GET et POST (Reflected XSS)
    """

    def __init__(self, crawler, http_client, reporter):
        super().__init__(crawler, http_client, reporter)
        self.detector = XSSDetector()
        self.tester = XSSTester()

    # =============================
    # OVERRIDE : Désactiver les logs
    # =============================
    def pre_scan(self):
        """Override pour désactiver les logs de début de scan"""
        pass

    def post_scan(self):
        """Override pour désactiver les logs de fin de scan"""
        pass

    # =============================
    # SCAN PRINCIPAL
    # =============================
    def scan(self):
        """
        Point d'entrée principal du scanner XSS.
        """
        findings = []

        for url in self.crawler.get_urls():
            # Test 1 : Paramètres URL
            findings.extend(self._scan_url_parameters(url))
            
            # Test 2 : Formulaires
            findings.extend(self._scan_forms(url))
        
        return findings

    # =============================
    # SCAN URL PARAMETERS
    # =============================
    def _scan_url_parameters(self, url):
        """
        Teste les paramètres URL pour XSS.
        """
        findings = []
        params = self.detector.extract_url_parameters(url)
        
        if not params:
            return findings
        
        for param in params:
            vulnerable, payload, evidence = self.tester.test_url_parameter(
                self.http, url, param
            )
            
            if vulnerable:
                finding = XSSFinding(
                    url=url,
                    parameter=param,
                    payload=payload,
                    issue="Reflected XSS via URL parameter",
                    severity="HIGH",
                    evidence=evidence,
                    method="GET",
                    vuln_type="Reflected XSS (URL)"
                )
                
                self.reporter.add_finding(finding)
                findings.append(finding)
                
                # Stop testing this parameter after first vulnerability
                break
        
        return findings

    # =============================
    # SCAN FORMS
    # =============================
    def _scan_forms(self, url):
        """
        Teste les formulaires pour XSS.
        """
        findings = []
        
        # Récupérer le contenu de la page
        response = self.http.get(url)
        
        if not response:
            return findings
        
        # Détecter les formulaires
        forms = self.detector.extract_forms(response.text, url)
        
        if not forms:
            return findings
        
        for i, form_details in enumerate(forms):
            vulnerable, payload, evidence, param = self.tester.test_form(
                self.http, url, form_details
            )
            
            if vulnerable:
                finding = XSSFinding(
                    url=url,
                    parameter=param,
                    payload=payload,
                    issue="Reflected XSS via form input",
                    severity="HIGH",
                    evidence=evidence,
                    method=form_details["method"].upper(),
                    vuln_type="Reflected XSS (Form)"
                )
                
                self.reporter.add_finding(finding)
                findings.append(finding)
        
        return findings