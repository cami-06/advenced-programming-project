from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from typing import List, Dict, Tuple


class TraversalDetector:
    
    def __init__(self):
        # Patterns de paramètres susceptibles d'être vulnérables
        self.suspicious_param_names = [
            'file', 'path', 'dir', 'folder', 'document', 'doc',
            'pg', 'page', 'name', 'filename', 'filepath', 'template',
            'include', 'load', 'read', 'download', 'src', 'source',
            'view', 'show', 'display', 'img', 'image', 'pdf'
        ]
    
    def extract_parameters(self, url: str) -> List[str]:
      
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        injectable_params = []
        for param in params.keys():
            # Ajouter tous les paramètres, mais prioriser les suspects
            injectable_params.append(param)
        
        return injectable_params
    
    def extract_form_parameters(self, html_content: str, form_action: str = None) -> List[Dict]:
       
        soup = BeautifulSoup(html_content, 'html.parser')
        form_params = []
        
        for form in soup.find_all('form'):
            action = form.get('action', form_action or '')
            method = form.get('method', 'GET').upper()
            
            params = {}
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                if name:
                    value = input_tag.get('value', '')
                    params[name] = value
            
            if params:
                form_params.append({
                    'action': action,
                    'method': method,
                    'parameters': params
                })
        
        return form_params
    
    def is_suspicious_parameter(self, param_name: str) -> bool:
      
        param_lower = param_name.lower()
        
        # Vérifier si le nom contient des mots-clés suspects
        for suspicious in self.suspicious_param_names:
            if suspicious in param_lower:
                return True
        
        return False
    
    def prioritize_parameters(self, params: List[str]) -> List[str]:
     
        suspicious = []
        normal = []
        
        for param in params:
            if self.is_suspicious_parameter(param):
                suspicious.append(param)
            else:
                normal.append(param)
        
        # Retourner suspects en premier
        return suspicious + normal