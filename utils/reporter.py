from colorama import init, Fore, Style

# Windows için renk desteği
init(autoreset=True)

def print_report(results, test_type=""):
    if not results:
        print(Fore.GREEN + f"[✓] {test_type} zafiyeti bulunamadı.\n")
        return

    print(Fore.RED + f"[!] {len(results)} potansiyel {test_type} zafiyeti bulundu:\n")

    for idx, r in enumerate(results, start=1):
        url = r.get("target") or r.get("url") or "-"
        status = r.get("status", "-")
        color = Fore.RED if status == "vulnerable" else (Fore.YELLOW if status == "error" else Fore.GREEN)

        print(color + f"[{idx}] {r.get('method', 'GET')} {url}")
        print(f"     Tür       : {test_type or r.get('type', '-')}")
        print(f"     Param     : {r.get('param', '-')}")
        print(f"     Payload   : {r.get('payload', '-')}")
        print(f"     Durum     : {status}")
        print(f"     Açıklama  : {r.get('message', '-')}")
        if 'data' in r:
            print(f"     Veriler   : {r['data']}")
        print("-" * 60)

    print(Fore.YELLOW + "\n[!] Lütfen manuel doğrulama ile teyit ediniz.\n")
