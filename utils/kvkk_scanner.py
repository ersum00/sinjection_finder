import requests
import re
import time
import os
import json
from bs4 import BeautifulSoup
from urllib.parse import quote
from tqdm import tqdm
from datetime import datetime

# -------------------------------
# Duyarlılık desenleri ve skorlar
# -------------------------------
SENSITIVE_PATTERNS = {
    "T.C. Kimlik No": r"\b[1-9][0-9]{10}\b",
    "Telefon": r"\b0\s?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{2}[\s.-]?\d{2}\b",
    "E-posta": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "Adres": r"\b(mahallesi|sokak|cadde|no:|daire|apartman|blok|site|bina|kat)\b",
    "Ad Soyad": r"\b[A-ZÇĞİÖŞÜ][a-zçğıöşü]+\s+[A-ZÇĞİÖŞÜ][a-zçğıöşü]+\b",
    "Dahili Numara": r"\b\d{4}\b",
    "Vergi No": r"\b\d{10}\b",
    "IBAN": r"\bTR\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b"
}

PATTERN_SCORES = {
    "T.C. Kimlik No": 5,
    "Telefon": 3,
    "E-posta": 2,
    "Adres": 2,
    "Ad Soyad": 1,
    "Dahili Numara": 1,
    "Vergi No": 4,
    "IBAN": 5
}

# -------------------------------
# Google Dork ile URL toplama
# -------------------------------
def google_dork_search(domain, filetypes=None, max_pages=2):
    filetypes = filetypes or ["xml", "doc", "docx", "xls", "xlsx"]
    headers = {"User-Agent": "Mozilla/5.0"}
    results = []

    for filetype in filetypes:
        for page in range(0, max_pages * 10, 10):
            query = f"site:{domain} filetype:{filetype}"
            url = f"https://www.google.com/search?q={quote(query)}&start={page}"
            print(f"[•] Google Dork: {url}")
            try:
                res = requests.get(url, headers=headers, timeout=10)
                soup = BeautifulSoup(res.text, "html.parser")
                for link in soup.find_all("a"):
                    href = link.get("href")
                    if href and href.startswith("/url?q="):
                        real_url = href.split("/url?q=")[1].split("&")[0]
                        if domain in real_url:
                            results.append(real_url)
            except Exception as e:
                print(f"[!] Hata: {e}")
            time.sleep(1)
    return list(set(results))

# -------------------------------
# Her dosya URL’sini analiz et
# -------------------------------
def fetch_and_analyze_file(url):
    try:
        r = requests.get(url, timeout=10)
        content = r.text
        findings = []
        total_score = 0

        for name, pattern in SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append({"type": name, "matches": list(set(matches))[:5]})
                total_score += PATTERN_SCORES.get(name, 1) * len(matches[:5])
        return {"url": url, "findings": findings, "risk_score": total_score}
    except Exception as e:
        print(f"[!] Dosya erişim hatası: {e}")
        return {"url": url, "findings": [], "risk_score": 0}

# -------------------------------
# HTML raporu üret
# -------------------------------
def generate_html_report(domain, results):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"kvkk_report_{domain.replace('.', '_')}_{timestamp}.html"

    html = f"""<html>
<head>
    <meta charset="utf-8">
    <title>KVKK Raporu - {domain}</title>
    <style>
        body {{ font-family: Arial; padding: 20px; }}
        h2 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; }}
        td, th {{ border: 1px solid #ccc; padding: 8px; }}
        th {{ background-color: #f4f4f4; }}
        .danger {{ background-color: #ffe0e0; }}
        .score {{ font-weight: bold; color: #b00; }}
    </style>
</head>
<body>
    <h2>KVKK Açık Dosyalar Raporu - {domain}</h2>
    <p>Toplam incelenen dosya: {len(results)}</p>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Dosya URL</th>
                <th>Risk Skoru</th>
                <th>İçerik Bulguları</th>
            </tr>
        </thead>
        <tbody>
"""

    for i, item in enumerate(results, 1):
        row_class = "danger" if item["risk_score"] >= 5 else ""
        findings_html = "<br>".join([f"<b>{f['type']}:</b> {', '.join(f['matches'])}" for f in item["findings"]])
        html += f"""
            <tr class="{row_class}">
                <td>{i}</td>
                <td><a href="{item['url']}" target="_blank">{item['url']}</a></td>
                <td class="score">{item['risk_score']}</td>
                <td>{findings_html}</td>
            </tr>
        """

    html += """
        </tbody>
    </table>
</body>
</html>
"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[✓] HTML raporu oluşturuldu: {filename}")

# -------------------------------
# Ana fonksiyon
# -------------------------------


def run_dork_scan(domain):
    print(f"[+] Google Dork taraması başlatıldı: {domain}\n")
    urls = google_dork_search(domain)

    if not urls:
        print("[-] Hiçbir sonuç bulunamadı.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    report_dir = f"kvkk_reports/{domain.replace('.', '_')}_{timestamp}"
    os.makedirs(report_dir, exist_ok=True)

    with open(os.path.join(report_dir, "dork_results.json"), "w", encoding="utf-8") as f:
        json.dump(urls, f, indent=2, ensure_ascii=False)
    print(f"[✓] Dork sonuçları kaydedildi.\n")

    results = []
    print(f"[→] {len(urls)} dosya indirilecek ve analiz edilecek...\n")
    for url in tqdm(urls, desc="KVKK Analiz", unit="dosya"):
        result = fetch_and_analyze_file(url)
        results.append(result)
        time.sleep(1)  # Sunucuyu yormamak için

    with open(os.path.join(report_dir, "kvkk_findings.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    generate_html_report(domain, results, save_dir=report_dir)
