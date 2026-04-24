# VultronScanner

<div align="center">

```
██╗   ██╗██╗   ██╗██╗  ████████╗██████╗  ██████╗ ███╗   ██╗
██║   ██║██║   ██║██║  ╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║
██║   ██║██║   ██║██║     ██║   ██████╔╝██║   ██║██╔██╗ ██║
╚██╗ ██╔╝██║   ██║██║     ██║   ██╔══██╗██║   ██║██║╚██╗██║
 ╚████╔╝ ╚██████╔╝███████╗██║   ██║  ██║╚██████╔╝██║ ╚████║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
```

**Modüler Saldırı Yüzeyi Yöneticisi & Sızma Testi Platformu**

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)
![Lisans](https://img.shields.io/badge/Lisans-MIT-green?style=flat-square)
![Durum](https://img.shields.io/badge/Durum-Aktif_Geliştirme-orange?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square)

</div>

---

## Hakkında

**VultronScanner**, üç temel aşamadan oluşan modüler bir sızma testi platformudur: **Keşif (Discovery)**, **Analiz (Intelligence)** ve **Aksiyon (Action)**. Basit bir Nmap arayüzünün ötesine geçerek; ağ tarama, zafiyet analizi ve otomatik raporlamayı tek bir Attack Surface Manager çatısı altında birleştirir.

---

## Mimari

```
Keşif → Analiz → Aksiyon → Rapor
```

| Katman | Modüller | Açıklama |
|--------|---------|----------|
| **Keşif** | NetworkScanner, HostDiscovery, PortAnalyzer | Ağ keşfi ve port analizi |
| **Analiz** | VulnerabilityEngine, WebAnalyzer, ThreatScorer | CVE analizi ve risk puanlama |
| **Aksiyon** | ExploitSuggester, BruteForceEngine | Aktif test ve exploit önerileri |
| **Raporlar** | HTML, Markdown, JSON | Otomatik rapor üretimi |

---

## Kurulum

```bash
# Repoyu klonla
git clone https://github.com/iremysv/VultronScanner.git
cd VultronScanner

# Sanal ortam oluştur
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS

# Bağımlılıkları yükle
pip install -r requirements.txt

# API anahtarlarını yapılandır
cp .env.example .env
# .env dosyasını düzenle: NVD_API_KEY ekle
```

---

## Kullanım

```bash
# Hızlı tarama (en hızlı seçenek)
python main.py scan --target <HEDEF> --profile quick

# Kapsamlı tarama (tüm portlar + zafiyet analizi)
python main.py scan --target <HEDEF> --profile full

# Web odaklı tarama (HTTP/HTTPS güvenlik analizi)
python main.py scan --target <HEDEF> --profile web

# Gizli tarama (IDS/IPS tetiklememek için)
python main.py scan --target <HEDEF> --profile stealth

# Kimlik doğrulama testi (yalnızca izinli sistemlerde!)
python main.py scan --target <HEDEF> --profile auth

# HTML rapor ile tarama
python main.py scan --target <HEDEF> --report html --output ./Reports/Output/
```

> `<HEDEF>` yerine hedef IP adresi, IP bloğu (CIDR) veya domain adı yazınız.

---

## Tarama Profilleri

| Profil | Süre | Açıklama |
|--------|------|----------|
| `quick` | 1–3 dk | En yaygın 100 port, hızlı keşif |
| `full` | 15–45 dk | Tüm portlar, CVE analizi, kapsamlı rapor |
| `stealth` | 30–90 dk | Yavaş ve sessiz, IDS/IPS farkındalığı düşük |
| `web` | 2–10 dk | HTTP/HTTPS servisleri ve güvenlik başlıkları |
| `auth` | 5–20 dk | SSH, FTP, RDP gibi servislerde kimlik doğrulama testi |

---

## Proje Yapısı

```
VultronScanner/
├── Core/             # Async orkestratör, EventBus, SessionManager
├── Modules/
│   ├── Discovery/    # Nmap, HostDiscovery, PortAnalyzer
│   ├── Intelligence/ # CVE/NVD, CVSS, WebAnalyzer
│   └── Action/       # ExploitSuggester, BruteForce
├── Utils/            # Logger, Validator, NetworkUtils, CvssCalculator
├── Reports/          # HTML, Markdown, JSON rapor motorları
├── Config/           # YAML tabanlı konfigürasyon & profiller
└── Tests/            # pytest tabanlı unit test suite
```

---

## Yasal Uyarı

> Bu araç **yalnızca eğitim amaçlı** olup yalnızca **açık izin alınmış sistemler** üzerinde kullanılmak üzere tasarlanmıştır. İzinsiz kullanım yürürlükteki yasalar kapsamında suç teşkil edebilir. Geliştirici, herhangi bir kötüye kullanımdan sorumlu tutulamaz.

---

## Lisans

[MIT](LICENSE)
