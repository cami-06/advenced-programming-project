# scanners/auth/auth_tester.py

class AuthTester:
    """
    Tests whether protected resources can be accessed
    without authentication.
    """

    def test_unauthenticated_access(self, http_client, url):
        try:
            response = http_client.get(url)

            # If access is granted without redirect or auth challenge
            if response.status_code == 200:
                text = response.text.lower()

                # Very simple heuristic to detect login pages
                login_indicators = [
                    "login",
                    "connexion",
                    "sign in",
                    "password",
                    "username"
                ]

                if not any(keyword in text for keyword in login_indicators):
                    return True, (
                        f"Unauthenticated access allowed (HTTP 200) for {url}"
                    )

            return False, "Access properly restricted"

        except Exception as e:
            return False, f"Request failed: {e}"
