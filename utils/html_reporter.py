import os

def generate_html_report(results, filename="report.html"):
    html = f"""
    <html>
    <head>
        <meta charset="utf-8">
        <title>Tarama Raporu</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }}
            th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
            th {{ background-color: #ddd; }}
            tr.vulnerable {{ background-color: #ffcccc; }}
            tr.clean {{ background-color: #ccffcc; }}
            tr.error {{ background-color: #ffe0b3; }}
            h1 {{ color: #333; }}
        </style>
    </head>
    <body>
        <h1>Tarama Raporu</h1>
        <p><strong>{len(results)}</strong> test sonucu bulundu.</p>
        <table>
            <tr>
                <th>#</th>
                <th>Test Türü</th>
                <th>URL</th>
                <th>Yöntem</th>
                <th>Parametre</th>
                <th>Payload</th>
                <th>Durum</th>
                <th>Açıklama</th>
                <th>Gerekçe</th>
            </tr>
    """

    for idx, r in enumerate(results, 1):
        row_class = r.get("status", "").lower()
        html += f"""
            <tr class="{row_class}">
                <td>{idx}</td>
                <td>{r.get("test", "-")}</td>
                <td>{r.get("target", "-")}</td>
                <td>{r.get("method", "-")}</td>
                <td>{r.get("param", "-")}</td>
                <td><code>{r.get("payload", "-")}</code></td>
                <td>{r.get("status", "-")}</td>
                <td>{r.get("message", "-")}</td>
                <td>{r.get("reason", "-")}</td>
            </tr>
        """

    html += """
        </table>
    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] HTML raporu oluşturuldu: {filename}")
