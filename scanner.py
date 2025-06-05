import argparse
import os
from urllib.parse import urlparse

from utils.crawler import crawl_targets
from utils.tester import test_targets
from utils.reporter import print_report
from utils.html_reporter import generate_html_report
from utils.xss_tester import test_xss, test_open_redirect, test_cors_misconfig
from utils.kvkk_scanner import run_dork_scan

def check_system():
    print("[*] Sistem kontrolü yapılıyor...")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    payloads_json = os.path.join(base_dir, "payloads.json")
    payloads_txt = os.path.join(base_dir, "payloads.txt")

    if os.path.exists(payloads_json):
        print("[✓] payloads.json bulundu.")
    elif os.path.exists(payloads_txt):
        print("[!] payloads.json yok, payloads.txt kullanılacak.")
    else:
        print("[!] Uyarı: payloads.json ve payloads.txt yok. Varsayılan payloadlar ile devam edilecek.")

    print("[✓] Sistem kontrolü tamamlandı.\n")

def safe_run(func, *args, test_type="Test"):
    try:
        return func(*args)
    except Exception as e:
        print(f"[!] {test_type} sırasında hata oluştu: {e}")
        return []

def main():
    check_system()

    parser = argparse.ArgumentParser(description="SQL Injection, XSS, Open Redirect, CORS ve KVKK Scanner")
    parser.add_argument('--url', required=True, help='Hedef URL (örn: https://example.com)')
    parser.add_argument('--kvkk', action='store_true', help='Google Dork ile KVKK taraması yap')
    args = parser.parse_args()

    url = args.url.strip()
    print(f"[+] Hedef: {url}")

    try:
        targets = crawl_targets(url)
    except Exception as e:
        print(f"[!] Tarama hatası: {e}")
        return

    form_sayisi = len(targets.get("forms", []))
    get_url_sayisi = len(targets.get("get_urls", []))
    print(f"[✓] {form_sayisi} form ve {get_url_sayisi} GET URL bulundu. Testler başlatılıyor...\n")

    # SQL Injection Testi
    print("[*] SQL Injection testleri başlıyor...\n")
    sql_results = safe_run(test_targets, targets, test_type="SQL Injection")
    print_report(sql_results, test_type="SQL Injection")
    generate_html_report(sql_results, filename="sql_report.html")

    # XSS Testi
    print("\n[*] XSS testleri başlıyor...\n")
    xss_results = safe_run(test_xss, targets, test_type="XSS")
    print_report(xss_results, test_type="XSS")
    generate_html_report(xss_results, filename="xss_report.html")

    # Open Redirect Testi
    print("\n[*] Open Redirect testleri başlıyor...\n")
    redirect_results = safe_run(test_open_redirect, targets.get("get_urls", []), test_type="Open Redirect")
    print_report(redirect_results, test_type="Open Redirect")
    generate_html_report(redirect_results, filename="redirect_report.html")

    # CORS Misconfiguration Testi
    print("\n[*] CORS testleri başlıyor...\n")
    cors_results = safe_run(test_cors_misconfig, targets.get("get_urls", []), test_type="CORS")
    print_report(cors_results, test_type="CORS")
    generate_html_report(cors_results, filename="cors_report.html")

    # KVKK Tarama
    if args.kvkk:
        print("\n[*] KVKK / Kişisel Veri içerikli açık dosya taraması başlıyor...\n")
        try:
            domain = urlparse(url).netloc
            run_dork_scan(domain)
        except Exception as e:
            print(f"[!] KVKK tarama hatası: {e}")

if __name__ == "__main__":
    main()
