import requests
import time
from urllib.parse import urlparse
from utils.target_extractor import extract_urls
from bs4 import BeautifulSoup

MAX_PAGES = 20
CRAWL_DELAY = 0.5

def extract_forms(url, html):
    soup = BeautifulSoup(html, "lxml")
    forms = []

    for form in soup.find_all("form"):
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = []

        # input'lar (type belirtilmese bile alınır)
        for input_tag in form.find_all("input"):
            name = input_tag.get("name")
            if name:
                inputs.append({
                    "name": name,
                    "type": input_tag.get("type", "text")
                })

        # textarea'lar
        for textarea in form.find_all("textarea"):
            name = textarea.get("name")
            if name:
                inputs.append({
                    "name": name,
                    "type": "textarea"
                })

        # select'ler
        for select in form.find_all("select"):
            name = select.get("name")
            if name:
                inputs.append({
                    "name": name,
                    "type": "select"
                })

        # button (eğer name varsa veri taşır)
        for button in form.find_all("button"):
            name = button.get("name")
            if name:
                inputs.append({
                    "name": name,
                    "type": "button"
                })

        forms.append({
            "url": url,
            "action": action,
            "method": method,
            "inputs": inputs
        })

    return forms


def crawl_targets(start_url):
    visited = set()
    to_visit = [start_url]
    found_forms = []
    found_get_urls = []

    print(f"[+] Tarama başlatıldı: {start_url}")

    while to_visit and len(visited) < MAX_PAGES:
        current_url = to_visit.pop(0)
        if current_url in visited:
            continue

        try:
            response = requests.get(current_url, timeout=10, verify=False)  # DÜZENLENDİ
            html = response.text
        except Exception as e:
            print(f"[!] {current_url} erişim hatası: {e}")
            visited.add(current_url)
            continue

        print(f"[•] Sayfa: {current_url}")
        visited.add(current_url)

        # Formları topla
        forms = extract_forms(current_url, html)
        found_forms.extend(forms)

        # Yeni URL'leri sıraya ekle
        new_urls = extract_urls(current_url, html)
        for url in new_urls:
            if url not in visited and url not in to_visit:
                to_visit.append(url)

            if "?" in url:
                found_get_urls.append(url)

        time.sleep(CRAWL_DELAY)

    return {
        "forms": found_forms,
        "get_urls": list(set(found_get_urls))
    }
