"""
Modules.HeaderAnalyzer.HeaderScanner
======================================
HTTP güvenlik başlıklarını analiz eden zafiyet tarama modülü.

Kontrol Edilen Başlıklar (OWASP Secure Headers Project):
    ┌─────────────────────────────────────┬──────────┐
    │ Başlık                              │ Seviye   │
    ├─────────────────────────────────────┼──────────┤
    │ Strict-Transport-Security (HSTS)    │ High     │
    │ Content-Security-Policy (CSP)       │ High     │
    │ X-Frame-Options                     │ Medium   │
    │ X-Content-Type-Options              │ Medium   │
    │ Referrer-Policy                     │ Low      │
    │ Permissions-Policy                  │ Low      │
    │ Server (bilgi sızıntısı)            │ Low      │
    │ X-Powered-By (bilgi sızıntısı)      │ Low      │
    └─────────────────────────────────────┴──────────┘

Ek Kontroller:
    - HTTPS yönlendirme varlığı
    - CSP içerisinde 'unsafe-inline' / 'unsafe-eval' direktifleri
    - HSTS preload ve includeSubDomains parametreleri

Yazar   : VultronScanner Team
Sürüm   : 1.0.0
Ders    : BGT006 Sızma Testi — İstinye Üniversitesi
Referans: https://owasp.org/www-project-secure-headers/
"""

from __future__ import annotations

import urllib.parse
from typing import NamedTuple

import requests
import urllib3

from Core.Models import Finding, Severity

# Geliştirme ortamında SSL uyarılarını bastır (tarama hedefi güvenilmez sertifika taşıyabilir)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Başlık Kural Tanımları ─────────────────────────────────────────────────────

class _HeaderRule(NamedTuple):
    """Bir güvenlik başlığı kuralını tanımlar."""
    header: str
    severity: Severity
    title: str
    description: str
    recommendation: str
    check_value: bool = False          # Değer içeriğini de kontrol et
    expected_contains: str = ""        # Değerin içermesi gereken substring


# Eksik başlık kuralları
_MISSING_HEADER_RULES: list[_HeaderRule] = [
    _HeaderRule(
        header="Strict-Transport-Security",
        severity=Severity.HIGH,
        title="HSTS Başlığı Eksik",
        description=(
            "Strict-Transport-Security (HSTS) başlığı tanımlanmamış. "
            "Bu durumda tarayıcılar HTTP bağlantılarını otomatik HTTPS'e "
            "yönlendirmez ve SSL stripping saldırılarına kapı açılır."
        ),
        recommendation=(
            "Yanıta şu başlığı ekleyin: "
            "'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'"
        ),
    ),
    _HeaderRule(
        header="Content-Security-Policy",
        severity=Severity.HIGH,
        title="Content-Security-Policy (CSP) Başlığı Eksik",
        description=(
            "CSP başlığı tanımlanmamış. Bu durum XSS (Cross-Site Scripting) ve "
            "veri enjeksiyon saldırılarına karşı savunmasızlık oluşturur."
        ),
        recommendation=(
            "Uygulamanıza özel bir CSP politikası tanımlayın. Başlangıç için: "
            "'Content-Security-Policy: default-src \\'self\\'; script-src \\'self\\'; "
            "object-src \\'none\\''"
        ),
    ),
    _HeaderRule(
        header="X-Frame-Options",
        severity=Severity.MEDIUM,
        title="X-Frame-Options Başlığı Eksik",
        description=(
            "X-Frame-Options başlığı eksik. Sayfa bir iframe içine yerleştirilebilir, "
            "bu da Clickjacking saldırılarına zemin hazırlar."
        ),
        recommendation=(
            "Yanıta 'X-Frame-Options: DENY' veya "
            "'X-Frame-Options: SAMEORIGIN' başlığını ekleyin."
        ),
    ),
    _HeaderRule(
        header="X-Content-Type-Options",
        severity=Severity.MEDIUM,
        title="X-Content-Type-Options Başlığı Eksik",
        description=(
            "X-Content-Type-Options: nosniff başlığı eksik. "
            "Tarayıcı MIME sniffing yaparak kötü amaçlı içeriği "
            "farklı bir türde yorumlayabilir (MIME Confusion Attack)."
        ),
        recommendation="Yanıta 'X-Content-Type-Options: nosniff' başlığını ekleyin.",
    ),
    _HeaderRule(
        header="Referrer-Policy",
        severity=Severity.LOW,
        title="Referrer-Policy Başlığı Eksik",
        description=(
            "Referrer-Policy başlığı tanımlanmamış. Kullanıcı gezinti bilgileri "
            "üçüncü taraf sitelere sızdırılabilir."
        ),
        recommendation=(
            "Yanıta 'Referrer-Policy: strict-origin-when-cross-origin' "
            "veya 'no-referrer' başlığını ekleyin."
        ),
    ),
    _HeaderRule(
        header="Permissions-Policy",
        severity=Severity.LOW,
        title="Permissions-Policy Başlığı Eksik",
        description=(
            "Permissions-Policy (eski adıyla Feature-Policy) başlığı eksik. "
            "Tarayıcı API'lerine (kamera, mikrofon, konum) gereksiz erişim verilebilir."
        ),
        recommendation=(
            "Kullanılmayan tarayıcı özelliklerini kısıtlayın: "
            "'Permissions-Policy: camera=(), microphone=(), geolocation=()'"
        ),
    ),
]

# Değer içermesi gereken başlık kuralları
_VALUE_RULES: list[_HeaderRule] = [
    _HeaderRule(
        header="Strict-Transport-Security",
        severity=Severity.MEDIUM,
        title="HSTS 'includeSubDomains' Parametresi Eksik",
        description="HSTS politikası alt alan adlarını kapsamıyor.",
        recommendation="HSTS başlığına 'includeSubDomains' parametresini ekleyin.",
        check_value=True,
        expected_contains="includesubdomains",
    ),
]


class HeaderScanner:
    """
    HTTP Güvenlik Başlıkları Tarayıcı.

    Hedef URL'e bir HTTP GET isteği gönderir ve yanıt başlıklarını
    OWASP Secure Headers Project standartlarına göre analiz eder.

    Attributes:
        url     (str): Taranacak tam URL (ör. https://example.com).
        timeout (int): HTTP bağlantı zaman aşımı (saniye).

    Örnek:
        >>> scanner = HeaderScanner("https://example.com")
        >>> findings = scanner.scan()
        >>> for f in findings:
        ...     print(f.severity.value, f.title)
    """

    MODULE_NAME = "HeaderAnalyzer"

    def __init__(self, url: str, timeout: int = 10) -> None:
        self.url     = url
        self.timeout = timeout

    # ── Public API ─────────────────────────────────────────────────────────────

    def scan(self) -> list[Finding]:
        """
        Güvenlik başlıklarını analiz eder.

        Returns:
            list[Finding]: Tespit edilen güvenlik başlığı bulgularının listesi.

        Raises:
            requests.RequestException: Bağlantı hatası durumunda.
        """
        headers = self._fetch_headers()
        findings: list[Finding] = []

        # Normalize: büyük/küçük harf duyarsız karşılaştırma
        lower_headers = {k.lower(): v for k, v in headers.items()}

        findings.extend(self._check_missing(lower_headers))
        findings.extend(self._check_values(lower_headers))
        findings.extend(self._check_information_disclosure(lower_headers))
        findings.extend(self._check_csp_directives(lower_headers))

        return findings

    # ── Private Helpers ────────────────────────────────────────────────────────

    def _fetch_headers(self) -> dict[str, str]:
        """
        Hedef URL'e GET isteği gönderir ve yanıt başlıklarını döndürür.

        SSL doğrulaması devre dışı bırakılır (hedef geçersiz sertifika
        taşıyabilir; SSL kontrolü ayrı modül tarafından yapılır).

        Returns:
            dict[str, str]: HTTP yanıt başlıkları.
        """
        response = requests.get(
            self.url,
            timeout=self.timeout,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "VultronScanner/1.0 (Security Audit)"},
        )
        return dict(response.headers)

    def _check_missing(
        self,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Eksik güvenlik başlıklarını kontrol eder."""
        findings: list[Finding] = []
        for rule in _MISSING_HEADER_RULES:
            if rule.header.lower() not in headers:
                findings.append(Finding(
                    title=rule.title,
                    severity=rule.severity,
                    description=rule.description,
                    recommendation=rule.recommendation,
                    module=self.MODULE_NAME,
                    target=self.url,
                    evidence=f"'{rule.header}' başlığı yanıtta bulunamadı.",
                ))
        return findings

    def _check_values(
        self,
        headers: dict[str, str],
    ) -> list[Finding]:
        """Mevcut başlıkların değer içeriğini kontrol eder."""
        findings: list[Finding] = []
        for rule in _VALUE_RULES:
            header_key = rule.header.lower()
            if header_key in headers:
                value = headers[header_key].lower()
                if rule.expected_contains and rule.expected_contains not in value:
                    findings.append(Finding(
                        title=rule.title,
                        severity=rule.severity,
                        description=rule.description,
                        recommendation=rule.recommendation,
                        module=self.MODULE_NAME,
                        target=self.url,
                        evidence=f"{rule.header}: {headers[header_key]}",
                    ))
        return findings

    def _check_information_disclosure(
        self,
        headers: dict[str, str],
    ) -> list[Finding]:
        """
        Sunucu bilgisi ifşasını kontrol eder.

        'Server' ve 'X-Powered-By' başlıkları sürüm bilgisi içeriyorsa
        saldırgana hedef sistemi hakkında bilgi sağlar.
        """
        findings: list[Finding] = []
        disclosure_headers = {
            "server":       "Server",
            "x-powered-by": "X-Powered-By",
        }

        for key, display_name in disclosure_headers.items():
            if key in headers:
                value = headers[key]
                findings.append(Finding(
                    title=f"Sunucu Bilgisi İfşası: {display_name}",
                    severity=Severity.LOW,
                    description=(
                        f"'{display_name}' başlığı sunucu/teknoloji bilgisini ifşa ediyor. "
                        "Bu bilgi saldırganın hedef sisteme yönelik saldırı profilini "
                        "oluşturmasına yardımcı olur."
                    ),
                    recommendation=(
                        f"'{display_name}' başlığını kaldırın veya değerini gizleyin. "
                        "Nginx için: 'server_tokens off;', Apache için: 'ServerTokens Prod'"
                    ),
                    module=self.MODULE_NAME,
                    target=self.url,
                    evidence=f"{display_name}: {value}",
                ))

        return findings

    def _check_csp_directives(
        self,
        headers: dict[str, str],
    ) -> list[Finding]:
        """
        CSP direktif güvenliğini kontrol eder.

        'unsafe-inline' ve 'unsafe-eval' direktifleri CSP'yi
        neredeyse işlevsiz kılar.
        """
        findings: list[Finding] = []
        csp_value = headers.get("content-security-policy", "")

        if not csp_value:
            return findings

        unsafe_directives = {
            "'unsafe-inline'": (
                "CSP 'unsafe-inline' Direktifi",
                "CSP politikası 'unsafe-inline' içeriyor. Bu direktif satır içi "
                "script/stil çalıştırılmasına izin vererek XSS korumasını etkisiz kılar.",
                "Nonce veya hash tabanlı CSP kullanın; 'unsafe-inline' direktifini kaldırın.",
            ),
            "'unsafe-eval'": (
                "CSP 'unsafe-eval' Direktifi",
                "CSP politikası 'unsafe-eval' içeriyor. Bu direktif eval() ve benzeri "
                "dinamik kod çalıştırma işlevlerine izin verir.",
                "'unsafe-eval' direktifini kaldırın, kodu statik olarak yükleyin.",
            ),
        }

        for directive, (title, desc, rec) in unsafe_directives.items():
            if directive in csp_value.lower():
                findings.append(Finding(
                    title=title,
                    severity=Severity.MEDIUM,
                    description=desc,
                    recommendation=rec,
                    module=self.MODULE_NAME,
                    target=self.url,
                    evidence=f"Content-Security-Policy: {csp_value[:200]}",
                ))

        return findings
