import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


class Crawler:
    def __init__(self,start_url,limit=30):
        self.start_url=start_url
        self.limit=limit
        self.visited = set()
        self.to_visit=[start_url]
        self.domain=urlparse(start_url).netloc
        self.urls =[]  # utilisé par les scanners

    def run(self):
        while self.to_visit and len(self.visited) < self.limit:
            current = self.to_visit.pop(0)

            if current in self.visited:
                continue

            print(f"→ Visite de : {current}")
            self.visited.add(current)
            self.urls.append(current)

            try:
                response = requests.get(current,timeout=6)
                soup = BeautifulSoup(response.text, "html.parser")

                # =========================
                # 1️⃣ Crawl des liens <a>
                # =========================
                for a in soup.find_all("a", href=True):
                    new_url = urljoin(current, a["href"])
                    domain = urlparse(new_url).netloc

                    if (
                        domain == self.domain
                        and new_url not in self.visited
                        and new_url not in self.to_visit
                    ):
                        self.to_visit.append(new_url)

                # =====================================
                #  Détection des formulaires GET
                # =====================================
                for form in soup.find_all("form"):
                    if form.get("method", "get").lower() == "get":
                        action = form.get("action") or current
                        action_url = urljoin(current, action)

                        params=[]
                        for inp in form.find_all("input"):
                            name = inp.get("name")
                            if name:
                                params.append(f"{name}=1")

                        if params:
                            full_url = action_url + "?" + "&".join(params)

                            if (
                                full_url not in self.visited
                                and full_url not in self.to_visit
                            ):
                                print(f"  + Form GET détecté : {full_url}")
                                self.to_visit.append(full_url)

            except Exception as e:
                print(f"Impossible d'accéder à {current} → {e}")

    def get_urls(self):
        """
        Return all URLs discovered by the crawler.
        Used by scanners (auth, sqli, etc.).
        """
        return self.urls
