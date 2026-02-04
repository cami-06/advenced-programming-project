# scanners/traversal/traversal_tester.py

from scanners.traversal.traversal_payloads import TRAVERSAL_PAYLOADS
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re


class TraversalTester:
    
    LINUX_SIGNATURES = [
        r"root:.*:0:0:",
        r"daemon:.*:/usr/sbin",
        r"root:x:0:0:",
        r"bin:.*:/bin",
        r"nobody:.*:",
    ]
    
    WINDOWS_SIGNATURES = [
        r"\[extensions\]",
        r"\[fonts\]",
        r"\[boot loader\]",
        r"default=",
        r"timeout=",
    ]
    
    SYSTEM_SIGNATURES = [
        r"localhost",
        r"127\.0\.0\.1",
    ]
    
    def __init__(self):
        pass
    
    def _inject(self, url: str, param: str, payload: str) -> str:
        """Injecte le payload dans le paramètre de l'URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
    
    def test_basic(self, http, url: str, param: str):
        """
        Teste avec des payloads basiques (seulement les plus courants).
        
        Returns:
            tuple: (vulnerable, payload, evidence)
        """
    
        payloads = TRAVERSAL_PAYLOADS["basic"][:5]  # Seulement 5 payloads
        
        for payload in payloads:
            try:
                injected_url = self._inject(url, param, payload)
                response = http.get(injected_url)
                
                if not response or response.status_code != 200:
                    continue
                
                response_text = response.text
                
                # Vérifier signatures Linux
                for pattern in self.LINUX_SIGNATURES:
                    match = re.search(pattern, response_text)
                    if match:
                        evidence = f"Linux file signature found: {match.group(0)[:50]}"
                        return True, payload, evidence
                
                # Vérifier signatures Windows
                for pattern in self.WINDOWS_SIGNATURES:
                    match = re.search(pattern, response_text, re.IGNORECASE)
                    if match:
                        evidence = f"Windows file signature found: {match.group(0)[:50]}"
                        return True, payload, evidence
                
                # Vérifier signatures système
                for pattern in self.SYSTEM_SIGNATURES:
                    match = re.search(pattern, response_text)
                    if match:
                        evidence = f"System file signature found: {match.group(0)[:50]}"
                        return True, payload, evidence
                        
            except Exception as e:
                continue
        
        return False, None, None
    
    def test_encoded(self, http, url: str, param: str):
        """Teste avec des payloads encodés (désactivé pour performance)"""
        return False, None, None
    
    def test_double_encoded(self, http, url: str, param: str):
        """Teste avec des payloads double-encodés (désactivé pour performance)"""
        return False, None, None
    
    def test_windows_specific(self, http, url: str, param: str):
        """Teste spécifiquement Windows (désactivé pour performance)"""
        return False, None, None
    
    def test_linux_specific(self, http, url: str, param: str):
        """Teste spécifiquement Linux (désactivé pour performance)"""
        return False, None, None
    
    def _calculate_severity(self, evidence: str) -> str:
        """Calcule la sévérité basée sur l'évidence"""
        evidence_lower = evidence.lower()
        
        if "shadow" in evidence_lower:
            return "CRITICAL"
        elif "passwd" in evidence_lower:
            return "HIGH"
        elif "win.ini" in evidence_lower or "boot.ini" in evidence_lower:
            return "HIGH"
        elif "hosts" in evidence_lower:
            return "MEDIUM"
        else:
            return "MEDIUM"