import requests
import os
import time
from urllib.parse import urlencode, urljoin, urlparse, parse_qs, urlunparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def load_xss_payloads():
    base = os.path.dirname(os.path.abspath(__file__))
    txt_path = os.path.join(base, "..", "xss_payloads.txt")

    if os.path.exists(txt_path):
        with open(txt_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    print("[!] xss_payloads.txt bulunamadı. Varsayılan payloadlar kullanılacak.")
    return [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "\"'><script>alert(1)</script>",
        "<iframe src='javascript:alert(1)'>",
        "<body onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<input autofocus onfocus=alert(1)>"
    ]

def test_xss(targets):
    payloads = load_xss_payloads()
    results = []

    # FORM tabanlı XSS
    for form in targets.get("forms", []):
        action = form.get("action")
        method = form.get("method", "get")
        inputs = form.get("inputs", [])

        if not action:
            continue

        for payload in payloads:
            for field in inputs:
                data = {i["name"]: "" for i in inputs if i.get("name")}
                if not field.get("name"):
                    continue
                data[field["name"]] = payload

                try:
                    if method.lower() == "post":
                        r = requests.post(action, data=data, timeout=10, verify=False)
                    else:
                        r = requests.get(action, params=data, timeout=10, verify=False)
                except Exception as e:
                    print(f"[XSS-Test] {action} bağlantı hatası: {e}")
                    continue

                if payload in r.text or payload.replace('<', '&lt;').replace('>', '&gt;') in r.text:
                    results.append({
                        "url": action,
                        "method": method.upper(),
                        "type": "form",
                        "input": field["name"],
                        "payload": payload,
                        "data": data
                    })

    # GET tabanlı XSS
    for url in targets.get("get_urls", []):
        if not url:
            continue

        for payload in payloads:
            try:
                param_url = inject_payload_into_url(url, payload)
                r = requests.get(param_url, timeout=10, verify=False)

                if payload in r.text or payload.replace('<', '&lt;').replace('>', '&gt;') in r.text:
                    results.append({
                        "url": param_url,
                        "method": "GET",
                        "type": "url",
                        "input": "query",
                        "payload": payload
                    })

            except Exception as e:
                print(f"[XSS-Test] {url} bağlantı hatası: {e}")
                continue

    return results

def inject_payload_into_url(url, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    modified = {k: payload for k in query}

    new_query = urlencode(modified, doseq=True)
    return urlunparse(parsed._replace(query=new_query))

def test_open_redirect(urls):
    payloads = [
        "https://evil.com",
        "//evil.com",
        "///evil.com",
        "\\evil.com",
        "http://evil.com/%2e%2e"
    ]

    results = []
    for url in urls:
        for payload in payloads:
            try:
                test_url = inject_payload_into_url(url, payload)
                r = requests.get(test_url, timeout=10, verify=False, allow_redirects=False)
                if r.status_code in [301, 302, 303, 307, 308] and "evil.com" in r.headers.get("Location", ""):
                    results.append({
                        "url": test_url,
                        "vulnerability": "Open Redirect",
                        "redirect_to": r.headers.get("Location")
                    })
            except Exception as e:
                print(f"[Redirect-Test] {url} hata: {e}")
                continue

    return results

def test_cors_misconfig(urls):
    results = []
    for url in urls:
        try:
            headers = {
                "Origin": "https://evil.com"
            }
            r = requests.get(url, headers=headers, timeout=10, verify=False)
            if "Access-Control-Allow-Origin" in r.headers and "evil.com" in r.headers["Access-Control-Allow-Origin"]:
                results.append({
                    "url": url,
                    "vulnerability": "CORS Misconfiguration",
                    "details": r.headers["Access-Control-Allow-Origin"]
                })
        except Exception as e:
            print(f"[CORS-Test] {url} hata: {e}")
            continue
    return results
