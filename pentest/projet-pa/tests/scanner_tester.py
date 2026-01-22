# scanners/web/auth_tester.py

class AuthTester:

    def test_unauthenticated_access(self, http_client, url):
        response = http_client.get(url)

        if response.status_code == 200:
            return True, "Page accessible without authentication"

        return False, None

    def test_method_override(self, http_client, url):
        get_resp = http_client.get(url)
        post_resp = http_client.post(url, data={})

        if post_resp.status_code == 200 and get_resp.status_code != 200:
            return True, "POST access allowed without session"

        return False, None

    def test_missing_session(self, http_client, url):
        http_client.clear_cookies()
        response = http_client.get(url)

        if response.status_code == 200:
            return True, "No session validation detected"

        return False, None
