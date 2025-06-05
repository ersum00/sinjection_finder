# 🔍 sinjection_finder

Kendi web sitenizi temel güvenlik açıklarına karşı test edebileceğiniz bir Python aracıdır.

## 🚀 Özellikler

- ✅ SQL Injection Tespiti
- ✅ CORS (Cross-Origin Resource Sharing) Zafiyet Taraması
- ✅ Open Redirect Açığı Taraması
- ✅ Google Dork ile KVKK Riskli Dosya Tespiti

## ⚠️ Uyarı

**Bu araç yalnızca kişisel test amaçlıdır.** Yalnızca kendi sitenizi veya açık izniniz olan sistemleri taramak için kullanınız. Başka siteleri izinsiz taramak KVKK ve benzeri yasalarca suç teşkil edebilir.

> ❗️Bu aracı kullanarak başkalarının sitelerine zarar vermekten doğabilecek hiçbir yasal sorumluluğu kabul etmiyorum.

## 🔧 Kurulum

```bash
git clone https://github.com/kullaniciadi/sinjection_finder.git
cd sinjection_finder
pip install -r requirements.txt

🛠 Kullanım
bash
Kopyala
Düzenle
python scanner.py --url http://example.com