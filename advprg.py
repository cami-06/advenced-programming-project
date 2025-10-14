import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def explore(liend, limite=30):
    # On garde la trace des liens vus
    dejavus = set()
    # Liste des liens à visiter
    avisiter = [liend]
    d = urlparse(liend).netloc

    # Tant qu il y a tjr des liens a visiter
    while avisiter and len(dejavus) < limite:
        lcourant = avisiter.pop(0)
        if lcourant in dejavus:
            continue

        print(f"→ Visite de : {lcourant}")
        dejavus.add(lcourant)

        try:
            # On recupere le contenu HTML
            page = requests.get(lcourant, timeout=6)
            contenu = BeautifulSoup(page.text, "html.parser")

            # On parcourt les balises <a> pour trouver d'autres liens
            for a in contenu.find_all("a", href=True):
                nouveau = urljoin(lcourant, a["href"])
                domaine = urlparse(nouveau).netloc

                # On ne garde que les liens internes au meme domaine
                if domaine == d and nouveau not in dejavus and nouveau not in avisiter:
                    avisiter.append(nouveau)

        except Exception as err:
            print(f"Impo {lcourant} → {err}")

if __name__ == "__main__":
    lien = input("Entrez adr de depart ").strip()
    explore(lien)
