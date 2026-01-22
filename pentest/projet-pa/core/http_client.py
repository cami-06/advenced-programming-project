import requests
from requests.exceptions import RequestException
from core.logger import logger


class HttpClient:
    """
    Centralized HTTP client abstraction.

    Responsibilities:
    - Send HTTP requests (GET / POST)
    - Maintain session state (cookies, headers)
    - Provide a single interface for all scanners
    """

    def __init__(self, timeout=10, verify_ssl=True):
        self.session = requests.Session()
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        # Default headers (browser-like)
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5"
        })

    # =============================
    # HTTP METHODS
    # =============================

    def get(self, url, params=None, headers=None):
        """
        Send a GET request.
        """
        try:
            response = self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            return response

        except RequestException as e:
            logger.error(f"GET request failed for {url}: {e}")
            return None

    def post(self, url, data=None, json=None, headers=None):
        """
        Send a POST request.
        """
        try:
            response = self.session.post(
                url,
                data=data,
                json=json,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            return response

        except RequestException as e:
            logger.error(f"POST request failed for {url}: {e}")
            return None

    # =============================
    # SESSION UTILITIES
    # =============================

    def set_header(self, key, value):
        """
        Set a persistent header for the session.
        """
        self.session.headers[key] = value

    def get_cookies(self):
        """
        Return current session cookies.
        """
        return self.session.cookies.get_dict()

    def clear_cookies(self):
        """
        Clear session cookies (useful for auth tests).
        """
        self.session.cookies.clear()
