cat << 'EOF' > requirements.txt
httpx
EOF

cat << 'EOF' > Dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY arayuz_ajan.py .

ENV PORT=8080
CMD ["python", "arayuz_ajan.py"]
EOF

cat << 'EOF' > arayuz_ajan.py
import base64
import html
import json
import os
import re
import threading
import time
import webbrowser
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import httpx

CVE_KALIBI = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
TARIH_KALIBI = re.compile(r"\b(20\d{2}-\d{2}-\d{2})\b")

KATEGORI_KURALLARI = {
    "Firewall": [
        "firewall", "fortigate", "fortinet", "palo alto", "pan-os", "checkpoint",
        "check point", "asa", "ftd", "netscreen", "waf", "web application firewall",
        "ips", "ids", "ngfw"
    ],
    "Load Balancer (LB)": [
        "load balancer", "f5", "big-ip", "bigip", "ltm", "gtm", "netscaler",
        "citrix adc", "haproxy", "envoy", "ingress", "reverse proxy", "traffic management"
    ],
    "Endpoint / VPN": [
        "vpn", "forticlient", "ems", "ssl vpn", "globalprotect", "anyconnect",
        "endpoint", "edr", "mdr", "antivirus", "windows", "linux", "macos", "rdp", "ssh"
    ],
    "Siber Sızıntı / Leak": [
        "leak", "ransomware", "dump", "breach", "database", "exfiltrat",
        "stealer", "infostealer", "sızıntı", "fidye", "veri tabanı"
    ],
}

TR_SOZLUK = [
    ("Critical vulnerability", "Kritik zafiyet"),
    ("Remote code execution", "Uzaktan kod çalıştırma (RCE)"),
    ("Privilege escalation", "Yetki yükseltme"),
    ("Denial of service", "Hizmet dışı bırakma (DoS)"),
    ("SQL injection", "SQL enjeksiyonu"),
    ("Authentication bypass", "Kimlik doğrulama atlatma"),
    ("Exploited in wild", "Aktif olarak istismar ediliyor"),
    ("Active exploitation", "Aktif istismar tespit edildi"),
    ("Database leak", "Veritabanı sızıntısı"),
    ("Ransomware group", "Fidye yazılımı grubu"),
    ("Known exploited vulnerability", "Bilinen aktif istismar edilen zafiyet"),
    ("High risk", "Yüksek risk"),
    ("Low risk", "Düşük risk"),
]

OTOMATIK_CEKIM_SANIYE = 900
KAYIT_DOSYASI = os.getenv("CTI_DATA_FILE", "sonuclar.json")
CTI_USER = os.getenv("CTI_USER", "").strip()
CTI_PASS = os.getenv("CTI_PASS", "").strip()

KILIT = threading.Lock()
KAYITLI_SONUCLAR: list[dict] = []
GORULEN_ANAHTARLAR: set[str] = set()
SON_GUNCELLEME: str = "Henüz çekilmedi"
SON_DURUM_MESAJI: str = "Başlatılıyor..."


def kayit_anahtari_uret(kayit: dict) -> str:
    cveler = sorted({x.get("cve", "").upper() for x in kayit.get("nvd", []) if x.get("cve")})
    if cveler:
        return "|".join(cveler)
    return kayit.get("en_metin", "").lower()[:160]


def diskten_yukle() -> None:
    if not os.path.exists(KAYIT_DOSYASI):
        return
    try:
        with open(KAYIT_DOSYASI, "r", encoding="utf-8") as f:
            veri = json.load(f)
        if isinstance(veri, list):
            with KILIT:
                for item in veri:
                    if isinstance(item, dict) and item.get("en_metin"):
                        KAYITLI_SONUCLAR.append(item)
                        GORULEN_ANAHTARLAR.add(kayit_anahtari_uret(item))
    except Exception:
        pass


def diske_kaydet() -> None:
    try:
        with KILIT:
            kopya = list(KAYITLI_SONUCLAR)
        with open(KAYIT_DOSYASI, "w", encoding="utf-8") as f:
            json.dump(kopya, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def turkce_ozet_uret(ingilizce_metin: str, nvd_listesi: list[dict], kategori: str) -> str:
    ceviri = ingilizce_metin
    for en, tr in TR_SOZLUK:
        ceviri = re.sub(re.escape(en), tr, ceviri, flags=re.IGNORECASE)

    nvd_ek = ""
    if nvd_listesi:
        parcalar = [f"{x['cve']} (CVSS {x['skor']})" for x in nvd_listesi]
        nvd_ek = " | NVD: " + ", ".join(parcalar)

    return f"[{kategori}] {ceviri}{nvd_ek}"


def kategori_belirle(metin: str, nvd_listesi: list[dict]) -> str:
    birlesik = (
        metin.lower()
        + " "
        + " ".join(item.get("ozet", "").lower() for item in nvd_listesi)
    )
    for kat, kelimeler in KATEGORI_KURALLARI.items():
        if any(k in birlesik for k in kelimeler):
            return kat
    return "Genel / Diğer"


def cve_detay_getir(cve_kodu: str) -> dict:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    try:
        resp = httpx.get(url, params={"cveId": cve_kodu}, timeout=10.0)
        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {"cve": cve_kodu, "skor": "-", "ozet": "NVD kaydı bulunamadı."}

        cve_obj = vulns[0].get("cve", {})
        aciklamalar = cve_obj.get("descriptions", [])
        desc = next((d["value"] for d in aciklamalar if d["lang"] == "en"), "Açıklama yok")

        metrics = cve_obj.get("metrics", {})
        skor = "-"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            liste = metrics.get(key)
            if liste:
                skor = str(liste[0].get("cvssData", {}).get("baseScore", "-"))
                break

        return {
            "cve": cve_kodu,
            "skor": skor,
            "ozet": desc[:200] + ("..." if len(desc) > 200 else ""),
        }
    except Exception as e:
        return {"cve": cve_kodu, "skor": "Hata", "ozet": f"NVD sorgu hatası: {e}"}


def kayit_ekle_guvenli(metin: str, tarih_str: str = "", kaynak: str = "Manuel", on_nvd: dict | None = None) -> bool:
    temiz_metin = " ".join(metin.strip().split())
    if not temiz_metin:
        return False

    if not tarih_str:
        eslesme = TARIH_KALIBI.search(temiz_metin)
        tarih_str = eslesme.group(1) if eslesme else datetime.now(timezone.utc).strftime("%Y-%m-%d")

    try:
        datetime.strptime(tarih_str, "%Y-%m-%d")
    except ValueError:
        tarih_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    cveler = sorted({m.group(0).upper() for m in CVE_KALIBI.finditer(temiz_metin)})
    anahtar = "|".join(cveler) if cveler else temiz_metin.lower()[:160]

    with KILIT:
        if anahtar in GORULEN_ANAHTARLAR:
            return False

    nvd_bilgileri = [on_nvd] if on_nvd is not None else [cve_detay_getir(cve) for cve in cveler]
    kategori = kategori_belirle(temiz_metin, nvd_bilgileri)
    tr_metin = turkce_ozet_uret(temiz_metin, nvd_bilgileri, kategori)

    yeni_kayit = {
        "tarih": tarih_str,
        "kaynak": kaynak,
        "kategori": kategori,
        "en_metin": temiz_metin,
        "tr_metin": tr_metin,
        "nvd": nvd_bilgileri,
    }

    with KILIT:
        if anahtar in GORULEN_ANAHTARLAR:
            return False
        GORULEN_ANAHTARLAR.add(anahtar)
        KAYITLI_SONUCLAR.append(yeni_kayit)

    diske_kaydet()
    return True


def dis_kaynaklardan_cek() -> int:
    eklenen = 0
    simdi = datetime.now(timezone.utc)
    baslangic = (simdi - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00.000")
    bitis = simdi.strftime("%Y-%m-%dT23:59:59.999")

    try:
        resp = httpx.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"pubStartDate": baslangic, "pubEndDate": bitis, "resultsPerPage": 25},
            timeout=15.0,
        )
        resp.raise_for_status()
        for item in resp.json().get("vulnerabilities", []):
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id", "")
            pub_tarih = (cve_obj.get("published") or simdi.strftime("%Y-%m-%d"))[:10]
            aciklamalar = cve_obj.get("descriptions", [])
            desc = next((d["value"] for d in aciklamalar if d["lang"] == "en"), "Açıklama yok")

            metrics = cve_obj.get("metrics", {})
            skor = "-"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                liste = metrics.get(key)
                if liste:
                    skor = str(liste[0].get("cvssData", {}).get("baseScore", "-"))
                    break

            nvd_dict = {"cve": cve_id, "skor": skor, "ozet": desc[:200] + ("..." if len(desc) > 200 else "")}
            if kayit_ekle_guvenli(f"{cve_id}: {desc}", pub_tarih, kaynak="NVD", on_nvd=nvd_dict):
                eklenen += 1
    except Exception:
        pass

    try:
        resp = httpx.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=15.0,
        )
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        sinir_90 = (simdi - timedelta(days=90)).strftime("%Y-%m-%d")

        for v in reversed(vulns):
            tarih = v.get("dateAdded", simdi.strftime("%Y-%m-%d"))
            if tarih < sinir_90:
                continue
            cve_id = v.get("cveID", "")
            vendor = v.get("vendorProject", "")
            product = v.get("product", "")
            short_desc = v.get("shortDescription", "")
            nvd_dict = {"cve": cve_id, "skor": "KEV", "ozet": short_desc[:200]}
            if kayit_ekle_guvenli(
                f"Known exploited vulnerability {cve_id} in {vendor} {product}: {short_desc}",
                tarih,
                kaynak="CISA KEV",
                on_nvd=nvd_dict,
            ):
                eklenen += 1
            if eklenen >= 40:
                break
    except Exception:
        pass

    rss_url = os.getenv("X_RSS_URL", "").strip()
    if rss_url:
        try:
            resp = httpx.get(rss_url, timeout=12.0)
            resp.raise_for_status()
            temiz = " ".join(re.sub(r"<[^>]+>", " ", resp.text).split())
            if temiz and kayit_ekle_guvenli(temiz[:500], simdi.strftime("%Y-%m-%d"), kaynak="X/RSS"):
                eklenen += 1
        except Exception:
            pass

    return eklenen


def tetikle_guncelleme() -> int:
    global SON_GUNCELLEME, SON_DURUM_MESAJI
    yeni_adet = dis_kaynaklardan_cek()
    with KILIT:
        SON_GUNCELLEME = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        SON_DURUM_MESAJI = f"Son taramada {yeni_adet} yeni kayıt eklendi."
    return yeni_adet


def arka_plan_dongusu() -> None:
    while True:
        try:
            tetikle_guncelleme()
        except Exception:
            pass
        time.sleep(OTOMATIK_CEKIM_SANIYE)


def son_uc_ay_icinde_mi(tarih_str: str) -> bool:
    try:
        dt = datetime.strptime(tarih_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return dt >= (datetime.now(timezone.utc) - timedelta(days=90))
    except ValueError:
        return True


def html_uret(secili_kategori: str = "Tümü", donem: str = "3ay", oto_yenile: bool = True) -> str:
    with KILIT:
        anlik_kayitlar = list(reversed(KAYITLI_SONUCLAR))
        son_gunc = SON_GUNCELLEME
        durum_msg = SON_DURUM_MESAJI

    filtreli = [
        item for item in anlik_kayitlar
        if not (donem == "3ay" and not son_uc_ay_icinde_mi(item["tarih"]))
        and not (secili_kategori != "Tümü" and item["kategori"] != secili_kategori)
    ]

    kategoriler = [
        "Tümü", "Firewall", "Load Balancer (LB)",
        "Endpoint / VPN", "Siber Sızıntı / Leak", "Genel / Diğer"
    ]
    kat_secenekleri = "".join(
        f'<option value="{html.escape(k)}" {"selected" if k == secili_kategori else ""}>{html.escape(k)}</option>'
        for k in kategoriler
    )

    satirlar_html = ""
    for item in filtreli:
        nvd_html = ""
        if item["nvd"]:
            for n in item["nvd"]:
                nvd_html += (
                    f"<div class='nvd-box'>"
                    f"<strong>{html.escape(n['cve'])}</strong> "
                    f"<span class='cvss'>CVSS/Durum: {html.escape(n['skor'])}</span><br>"
                    f"<span>{html.escape(n['ozet'])}</span>"
                    f"</div>"
                )
        else:
            nvd_html = "<span class='muted'>CVE yok</span>"

        satirlar_html += f"""
        <tr>
            <td>
                <strong>{html.escape(item['tarih'])}</strong><br>
                <span class="kaynak">{html.escape(item['kaynak'])}</span>
            </td>
            <td><span class="badge">{html.escape(item['kategori'])}</span></td>
            <td>
                <div class="lang-box"><strong>EN:</strong> {html.escape(item['en_metin'])}</div>
                <div class="lang-box tr"><strong>TR:</strong> {html.escape(item['tr_metin'])}</div>
            </td>
            <td>{nvd_html}</td>
        </tr>
        """

    if not satirlar_html:
        satirlar_html = "<tr><td colspan='4' class='empty'>Seçili filtreye uygun kayıt bulunamadı.</td></tr>"

    bugun = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    refresh_meta = '<meta http-equiv="refresh" content="60">' if oto_yenile else ""

    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
{refresh_meta}
<title>Canlı CTI & CVE İzleme Arayüzü</title>
<style>
  * {{ color: #22c55e; }}
  body {{ font-family: "JetBrains Mono", "Fira Code", Menlo, Consolas, monospace; background: #000000; color: #22c55e; margin: 0; padding: 24px; }}
  .container {{ max-width: 1240px; margin: 0 auto; }}
  h1 {{ margin: 0 0 6px 0; font-size: 24px; color: #4ade80; }}
  .status-bar {{ background: #050505; border: 1px solid #15803d; color: #22c55e; padding: 10px 14px; border-radius: 8px; margin-bottom: 16px; font-size: 13px; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 10px; }}
  .panel {{ background: #050505; border: 1px solid #166534; border-radius: 10px; padding: 16px; margin-bottom: 16px; }}
  .row {{ display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }}
  textarea {{ width: 100%; height: 65px; background: #000000; color: #22c55e; border: 1px solid #166534; border-radius: 8px; padding: 10px; font-size: 13px; box-sizing: border-box; margin-bottom: 10px; }}
  input, select {{ background: #000000; color: #22c55e; border: 1px solid #166534; border-radius: 8px; padding: 8px 10px; font-size: 13px; }}
  button {{ background: #000000; color: #4ade80; border: 1px solid #22c55e; padding: 9px 15px; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 13px; }}
  button:hover {{ background: #14532d; color: #86efac; }}
  button.secondary {{ background: #052e16; border-color: #4ade80; }}
  button.secondary:hover {{ background: #166534; }}
  table {{ width: 100%; border-collapse: collapse; background: #000000; border-radius: 10px; overflow: hidden; border: 1px solid #166534; }}
  th, td {{ padding: 11px; text-align: left; border-bottom: 1px solid #14532d; vertical-align: top; font-size: 13px; color: #22c55e; }}
  th {{ background: #050505; color: #4ade80; font-size: 12px; text-transform: uppercase; }}
  .badge {{ display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; background: #052e16; color: #4ade80; border: 1px solid #22c55e; }}
  .kaynak {{ display: inline-block; margin-top: 4px; font-size: 11px; color: #16a34a; }}
  .lang-box {{ background: #000000; border: 1px solid #14532d; border-radius: 6px; padding: 7px 9px; margin-bottom: 6px; color: #22c55e; }}
  .lang-box.tr {{ border-color: #22c55e; background: #051408; color: #4ade80; }}
  .nvd-box {{ background: #000000; border: 1px solid #14532d; border-radius: 6px; padding: 7px; margin-bottom: 6px; font-size: 12px; color: #22c55e; }}
  .cvss {{ background: #052e16; color: #86efac; border: 1px solid #22c55e; padding: 2px 6px; border-radius: 4px; font-size: 11px; margin-left: 4px; }}
  .muted {{ color: #16a34a; font-size: 12px; }}
  .empty {{ text-align: center; color: #22c55e; padding: 24px; }}
</style>
</head>
<body>
<div class="container">
  <h1>Canlı CTI Ürün & CVE İzleme Arayüzü</h1>

  <div class="status-bar">
    <div><strong>Otomatik Mod:</strong> Her 15 dk arka planda veri çeker | Sayfa 60 sn'de bir yenilenir</div>
    <div><strong>Son Güncelleme:</strong> {html.escape(son_gunc)} — <em>{html.escape(durum_msg)}</em></div>
  </div>

  <div class="panel">
    <form method="POST" action="/ekle">
      <textarea name="metin" placeholder="İstersen buraya manuel kayıt da ekleyebilirsin (Örn: CVE-2025-11111 in F5 BIG-IP or FortiGate firewall...)"></textarea>
      <div class="row">
        <label>Tarih: <input type="text" name="tarih" value="{bugun}" size="12"></label>
        <button type="submit">Manuel Kayıt Ekle</button>
      </div>
    </form>
  </div>

  <div class="panel">
    <form method="GET" action="/" class="row">
      <label>Dönem:
        <select name="donem">
          <option value="3ay" {"selected" if donem == "3ay" else ""}>Son 3 Ay</option>
          <option value="tumu" {"selected" if donem == "tumu" else ""}>Tüm Zamanlar</option>
        </select>
      </label>
      <label>Ürün / Kategori:
        <select name="kategori">
          {kat_secenekleri}
        </select>
      </label>
      <label>Oto-Yenileme:
        <select name="oto">
          <option value="1" {"selected" if oto_yenile else ""}>Açık (60 sn)</option>
          <option value="0" {"selected" if not oto_yenile else ""}>Kapalı</option>
        </select>
      </label>
      <button type="submit">Filtrele</button>
      <button type="submit" name="simdi_cek" value="1" class="secondary">Şimdi Veri Çek</button>
      <span class="muted">Gösterilen kayıt: <strong>{len(filtreli)}</strong></span>
    </form>
  </div>

  <table>
    <thead>
      <tr>
        <th>Tarih / Kaynak</th>
        <th>Kategori</th>
        <th>İngilizce (EN) & Türkçe (TR)</th>
        <th>CVE & Detay</th>
      </tr>
    </thead>
    <tbody>
      {satirlar_html}
    </tbody>
  </table>
</div>
</body>
</html>"""


class ArayuzHandler(BaseHTTPRequestHandler):
    def yetkili_mi(self) -> bool:
        if not CTI_USER or not CTI_PASS:
            return True
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return False
        try:
            cozulmus = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
            kullanici, parola = cozulmus.split(":", 1)
            return kullanici == CTI_USER and parola == CTI_PASS
        except Exception:
            return False

    def yetki_iste(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="CTI Arayuz"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write("Kimlik dogrulamasi gerekli.".encode("utf-8"))

    def do_GET(self):
        if not self.yetkili_mi():
            self.yetki_iste()
            return

        parsed = urlparse(self.path)
        if parsed.path == "/api/sonuclar":
            with KILIT:
                body = json.dumps(KAYITLI_SONUCLAR, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        qs = parse_qs(parsed.query)
        kategori = qs.get("kategori", ["Tümü"])[0]
        donem = qs.get("donem", ["3ay"])[0]
        oto_yenile = qs.get("oto", ["1"])[0] != "0"

        if qs.get("simdi_cek", ["0"])[0] == "1":
            tetikle_guncelleme()

        body = html_uret(secili_kategori=kategori, donem=donem, oto_yenile=oto_yenile).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not self.yetkili_mi():
            self.yetki_iste()
            return

        if self.path == "/ekle":
            uzunluk = int(self.headers.get("Content-Length", "0"))
            ham_veri = self.rfile.read(uzunluk).decode("utf-8", errors="replace")
            form = parse_qs(ham_veri)
            metin = form.get("metin", [""])[0].strip()
            tarih = form.get("tarih", [""])[0].strip()
            if metin:
                kayit_ekle_guvenli(metin, tarih, kaynak="Manuel")

        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    diskten_yukle()
    tetikle_guncelleme()
    worker = threading.Thread(target=arka_plan_dongusu, daemon=True)
    worker.start()

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8080"))
    sunucu = ThreadingHTTPServer((host, port), ArayuzHandler)
    url = f"http://127.0.0.1:{port}"
    print(f"Canlı erişime hazır arayüz dinlemede -> {host}:{port} (Yerel: {url})")
    try:
        webbrowser.open(url)
    except Exception:
        pass

    try:
        sunucu.serve_forever()
    except KeyboardInterrupt:
        print("\nSunucu kapatıldı.")
EOF
