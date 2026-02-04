# scanners/web/auth_detector.py

from bs4 import BeautifulSoup

class AuthDetector:

    LOGIN_KEYWORDS = ["login", "signin", "auth", "password"]

    def detect_login_forms(self, html: str):
        soup = BeautifulSoup(html, "html.parser")
        forms = []

        for form in soup.find_all("form"):
            inputs = {}
            has_password = False
            has_csrf = False

            for inp in form.find_all("input"):
                name = inp.get("name", "")
                itype = inp.get("type", "text")

                inputs[name] = itype

                if itype == "password":
                    has_password = True
                if "csrf" in name.lower() or "token" in name.lower():
                    has_csrf = True

            if has_password:
                forms.append({
                    "action": form.get("action", ""),
                    "method": form.get("method", "get").lower(),
                    "inputs": inputs,
                    "has_csrf": has_csrf
                })

        return forms

    def is_protected_response(self, response):
        indicators = ["login", "signin", "unauthorized", "forbidden"]

        if response.status_code in [401, 403]:
            return True

        content = response.text.lower()
        return any(word in content for word in indicators)
