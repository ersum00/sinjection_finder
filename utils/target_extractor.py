from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def extract_urls(base_url, html):
    soup = BeautifulSoup(html, "lxml")
    elements = []

    # Potansiyel URL içeren HTML özellikleri
    attrs = [
        ("a", "href"),
        ("form", "action"),
        ("script", "src"),
        ("iframe", "src"),
        ("link", "href")
    ]

    for tag, attr in attrs:
        for element in soup.find_all(tag):
            url = element.get(attr)
            if url:
                full_url = urljoin(base_url, url.split("#")[0])
                if is_same_domain(base_url, full_url):
                    elements.append(full_url)

    return list(set(elements))  # tekrarları kaldır

def is_same_domain(base, target):
    return urlparse(base).netloc == urlparse(target).netloc
