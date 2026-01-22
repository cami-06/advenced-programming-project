from urllib.parse import urlparse, parse_qs

class SQLDetector:
    """
    Detects parameters that may be vulnerable to SQL Injection.
    """

    def extract_parameters(self,url: str):
        parsed=urlparse(url)
        params=parse_qs(parsed.query)

        injectable_params=[]
        for param in params.keys():
            injectable_params.append(param)

        return injectable_params
