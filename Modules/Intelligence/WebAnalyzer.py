"""
Modules.Intelligence.WebAnalyzer
================================

Hedefin web kök dizininde yer alan varsayılan ve kritik dosyaları
(robots.txt, sitemap.xml, security.txt, /.git vb.) tespit ederek
bilgi ifşası (Information Disclosure) zafiyetlerini kontrol eder.

Yazar   : VultronScanner Team
Sürüm   : 1.0.0
Ders    : BGT006 Sızma Testi — İstinye Üniversitesi
"""

import requests
from urllib.parse import urljoin

from Core.Models import Finding, Severity


class WebAnalyzer:
    """
    Hedef web uygulamasının temel dosya ve dizin kontrollerini yapar.

    Attributes:
        base_url (str): Hedefin kök adresi (ör. https://example.com)
        timeout (int): HTTP istekleri için zaman aşımı süresi
    """

    # Kontrol edilecek yollar ve özellikleri
    TARGET_PATHS = {
        "/robots.txt": {
            "title": "Robots.txt Bilgi İfşası",
            "desc": "Robots.txt dosyası bulundu. Özel dizinleri sızdırıyor olabilir.",
            "severity": Severity.INFO,
        },
        "/sitemap.xml": {
            "title": "Sitemap XML Erişimi",
            "desc": "Site haritası genel erişime açık, uygulama yapısını sızdırabilir.",
            "severity": Severity.INFO,
        },
        "/.well-known/security.txt": {
            "title": "Security.txt Dosyası (Güvenlik Politikası)",
            "desc": "Güvenlik araştırmacıları için policy dosyası bulundu.",
            "severity": Severity.INFO,
        },
        "/.git/config": {
            "title": "Git Konfigürasyon Dosyası İfşası (.git/config)",
            "desc": "Uygulamanın kaynak kod deposu bilgileri ve muhtemelen kendisi genel erişime açık! Bu kritik bir zafiyettir.",
            "severity": Severity.CRITICAL,
            "cve": "CWE-538",
        },
        "/.env": {
            "title": "Çevresel Değişken İfşası (.env)",
            "desc": "Uygulamanın veritabanı şifreleri ve gizli anahtarları ifşa olmuş olabilir.",
            "severity": Severity.CRITICAL,
            "cve": "CWE-538",
        }
    }

    def __init__(self, base_url: str, timeout: int = 10) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.headers = {"User-Agent": "VultronScanner/1.0 (BGT006 Sizma Testi)"}

    def scan(self) -> list[Finding]:
        """
        Tanımlı hedef yollara HTTP GET isteği gönderir ve bulguları toplar.

        Returns:
            list[Finding]: Tespit edilen bulgular listesi.
        """
        findings: list[Finding] = []

        for path, meta in self.TARGET_PATHS.items():
            url = urljoin(self.base_url + "/", path.lstrip("/"))
            try:
                # SSL uyarılarını bastırmak için verify=False kullanılabilir ancak gerçek projede dikkat edilmeli
                # requests uyarısını bastır:
                requests.packages.urllib3.disable_warnings()
                
                response = requests.get(
                    url, 
                    headers=self.headers, 
                    timeout=self.timeout, 
                    verify=False,
                    allow_redirects=False
                )

                if response.status_code == 200:
                    # Sadece geçerli içerik döndüğünde bulgu ekle (bazen WAF 200 döndürüp boş sayfa verebilir)
                    if len(response.text.strip()) > 0:
                        content_sample = response.text[:200] + ("..." if len(response.text) > 200 else "")
                        findings.append(
                            Finding(
                                title=meta["title"],
                                severity=meta["severity"],
                                description=meta["desc"],
                                recommendation="İlgili dosyanın/dizinin dış erişime açık olmasını inceleyin ve gerekirse web sunucusu konfigürasyonundan engelleyin.",
                                module="WebAnalyzer",
                                target=url,
                                evidence=f"Status: {response.status_code}\n\n{content_sample}",
                                cve=meta.get("cve", ""),
                            )
                        )
            except requests.RequestException:
                # Hedefe erişilemedi veya timeout oluştu, bu yolu atla
                continue

        return findings
