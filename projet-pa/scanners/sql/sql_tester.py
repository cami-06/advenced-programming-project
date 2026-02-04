from scanners.sql.sql_payloads import SQL_PAYLOADS
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time


class SQLTester:

    ERROR_PATTERNS=[
        "sql syntax", "mysql", "sqlite",
        "postgresql", "oracle", "odbc"
    ]

    def _inject(self,url,param,payload):
        parsed=urlparse(url)
        params=parse_qs(parsed.query)

        # inject payload
        params[param]=[payload]

        return urlunparse(
            parsed._replace(query=urlencode(params, doseq=True))
        )

    def test_error_based(self, http, url, param):
        for payload in SQL_PAYLOADS["error"]:
            response=http.get(self._inject(url,param,payload))

            if not response:
                continue

            body=response.text.lower()
            for err in self.ERROR_PATTERNS:
                if err in body:
                    return True, payload, f"SQL error detected: {err}"

        return False, None, None

    def test_boolean_based(self,http,url,param):
        true_payload, false_payload = SQL_PAYLOADS["boolean"]

        r1=http.get(self._inject(url,param,true_payload))
        r2=http.get(self._inject(url,param,false_payload))

        if r1 and r2 and len(r1.text) != len(r2.text):
            return True, true_payload, "Boolean-based SQL Injection detected"

        return False, None, None

    def test_time_based(self,http,url,param):
        for payload in SQL_PAYLOADS["time"]:
            start=time.time()
            http.get(self._inject(url, param, payload))
            delay=time.time() - start

            if delay >= 3:
                return True, payload, f"Time-based SQL Injection ({delay:.2f}s)"

        return False, None, None
