# scanners/xss/xss_tester.py

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from scanners.xss.xss_payloads import XSS_PAYLOADS


class XSSTester:
    """
    Teste les vulnérabilités XSS sur les paramètres URL et les formulaires.
    """

    def __init__(self):
        # Combiner tous les payloads
        self.payloads = []
        for category in XSS_PAYLOADS.values():
            self.payloads.extend(category)

    # =============================
    # TEST XSS IN URL PARAMETERS
    # =============================
    def test_url_parameter(self, http, url, param):
        """
        Teste un paramètre URL pour les vulnérabilités XSS.
        
        Args:
            http: Instance de HttpClient
            url: URL à tester
            param: Nom du paramètre à tester
            
        Returns:
            tuple: (vulnerable, payload, evidence)
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for payload in self.payloads:
            # Injecter le payload dans le paramètre
            test_params = params.copy()
            test_params[param] = [payload]
            
            # Reconstruire l'URL
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))
            
            # Envoyer la requête
            response = http.get(test_url)
            
            if not response:
                continue
            
            # Vérifier si le payload est reflété dans la réponse
            if payload in response.text:
                evidence = f"Payload reflected in response for parameter '{param}'"
                return True, payload, evidence
        
        return False, None, None

    # =============================
    # TEST XSS IN FORMS
    # =============================
    def test_form(self, http, url, form_details):
        """
        Teste un formulaire pour les vulnérabilités XSS.
        
        Args:
            http: Instance de HttpClient
            url: URL de base
            form_details: Détails du formulaire (dict)
            
        Returns:
            tuple: (vulnerable, payload, evidence, param_name)
        """
        if not form_details["inputs"]:
            return False, None, None, None
        
        # Tester chaque payload
        for payload in self.payloads:
            # Tester chaque champ du formulaire
            for input_field in form_details["inputs"]:
                # Préparer les données du formulaire
                data = self._prepare_form_data(form_details, input_field, payload)
                
                if not data:
                    continue
                
                # Construire l'URL cible
                target_url = urljoin(url, form_details["action"]) if form_details["action"] else url
                
                # Envoyer la requête selon la méthode
                if form_details["method"] == "post":
                    response = http.post(target_url, data=data)
                else:
                    response = http.get(target_url, params=data)
                
                if not response:
                    continue
                
                # Vérifier si le payload est reflété
                if payload in response.text:
                    evidence = f"Payload reflected in form field '{input_field['name']}'"
                    return True, payload, evidence, input_field["name"]
        
        return False, None, None, None

    # =============================
    # HELPER METHODS
    # =============================
    def _prepare_form_data(self, form_details, target_input, payload):
        """
        Prépare les données du formulaire en injectant le payload.
        
        Args:
            form_details: Détails du formulaire
            target_input: Champ cible pour l'injection
            payload: Payload XSS à injecter
            
        Returns:
            dict: Données du formulaire
        """
        data = {}
        
        for input_field in form_details["inputs"]:
            # Injecter le payload dans le champ cible
            if input_field["name"] == target_input["name"]:
                if input_field["type"] in ["text", "search", "email", "textarea", "url"]:
                    data[input_field["name"]] = payload
                else:
                    data[input_field["name"]] = input_field["value"]
            else:
                # Utiliser la valeur par défaut pour les autres champs
                data[input_field["name"]] = input_field.get("value", "test")
        
        return data