# scanners/traversal/traversal_scanner.py

from scanners.base_scanner import BaseScanner
from scanners.traversal.traversal_detector import TraversalDetector 
from scanners.traversal.traversal_tester import TraversalTester
from scanners.traversal.traversal_models import TraversalFinding


class TraversalScanner(BaseScanner):
    """
    Scanner pour détecter les vulnérabilités de Directory Traversal.
    Version optimisée et silencieuse.
    """
    
    def __init__(self, crawler, http_client, reporter):
        super().__init__(crawler, http_client, reporter)
        self.detector = TraversalDetector()
        self.tester = TraversalTester()
   
    def pre_scan(self):
        """Override pour désactiver les logs de début de scan"""
        pass

    def post_scan(self):
        """Override pour désactiver les logs de fin de scan"""
        pass
    
  
    def scan(self):
        """
        Scan rapide - teste seulement les paramètres suspects.
        """
        findings = []
        urls = self.crawler.get_urls()
        
        for url in urls:
            try:
                # Extraire les paramètres de l'URL
                params = self.detector.extract_parameters(url)
                if not params:
                    continue
                
                # Prioriser les paramètres suspects
                prioritized_params = self.detector.prioritize_parameters(params)
                
                # Tester chaque paramètre (seulement les suspects)
                for param in prioritized_params:
                    if not self.detector.is_suspicious_parameter(param):
                        continue  # Skip les paramètres non suspects
                    
                    try:
                        vulnerable, payload, evidence = self.tester.test_basic(
                            self.http, url, param
                        )
                        
                        if vulnerable:
                            severity = self.tester._calculate_severity(evidence)
                            
                            finding = TraversalFinding(
                                url=url,
                                parameter=param,
                                payload=payload,
                                issue="Directory Traversal - Unauthorized file access",
                                severity=severity,
                                evidence=evidence,
                                traversal_type="basic",
                                method="GET"
                            )
                            
                            self.reporter.add_finding(finding)
                            findings.append(finding)
                            
                            # Arrêter après la première vulnérabilité trouvée pour ce paramètre
                            break
                            
                    except Exception as e:
                        continue
                        
            except Exception as e:
                continue
        
        return findings
    
    def _determine_traversal_type(self, test_name: str) -> str:
        """Détermine le type de traversal basé sur le nom du test"""
        return "basic"
    
    def scan_with_forms(self):
        """Scan avec formulaires (actuellement identique au scan normal)"""
        return self.scan()
