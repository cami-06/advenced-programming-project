# scanners/xss/xss_detector.py

from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup


class XSSDetector:
    """
    Détecte les points d'injection potentiels pour XSS :
    - Paramètres URL (GET)
    - Formulaires (GET et POST)
    """

    def extract_url_parameters(self, url):
        """
        Extrait les paramètres d'une URL.
        
        Returns:
            list: Liste des noms de paramètres
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())

    def extract_forms(self, html_content, base_url):
        """
        Extrait tous les formulaires d'une page HTML.
        
        Args:
            html_content: Contenu HTML de la page
            base_url: URL de base pour résoudre les actions relatives
            
        Returns:
            list: Liste de dictionnaires contenant les détails des formulaires
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = soup.find_all('form')
        
        form_details = []
        for form in forms:
            details = self._get_form_details(form)
            form_details.append(details)
        
        return form_details

    def _get_form_details(self, form):
        """
        Extrait les détails d'un formulaire.
        
        Returns:
            dict: Détails du formulaire (action, method, inputs)
        """
        details = {
            "action": form.attrs.get("action", ""),
            "method": form.attrs.get("method", "get").lower(),
            "inputs": []
        }
        
        # Récupérer les inputs
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            if input_name:
                details["inputs"].append({
                    "type": input_type,
                    "name": input_name,
                    "value": input_tag.attrs.get("value", "")
                })
        
        # Récupérer les textareas
        for textarea in form.find_all("textarea"):
            textarea_name = textarea.attrs.get("name")
            if textarea_name:
                details["inputs"].append({
                    "type": "textarea",
                    "name": textarea_name,
                    "value": textarea.get_text()
                })
        
        # Récupérer les selects
        for select in form.find_all("select"):
            select_name = select.attrs.get("name")
            if select_name:
                details["inputs"].append({
                    "type": "select",
                    "name": select_name,
                    "value": ""
                })
        
        return details