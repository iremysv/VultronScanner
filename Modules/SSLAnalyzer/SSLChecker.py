"""
Modules.SSLAnalyzer.SSLChecker
================================
SSL/TLS sertifika ve protokol güvenlik denetim modülü.

NIST SP 800-52 Rev. 2 ve BSI TR-02102-2 yönergelerine uygun olarak
aşağıdaki kontrolleri gerçekleştirir:

    ┌────────────────────────────────────────────┬──────────┐
    │ Kontrol                                    │ Seviye   │
    ├────────────────────────────────────────────┼──────────┤
    │ Sertifika süresi dolmuş                    │ Critical │
    │ Self-signed (kendi imzalı) sertifika       │ High     │
    │ Sertifika 30 gün içinde sona eriyor        │ High     │
    │ TLS 1.0 / TLS 1.1 protokolü aktif          │ High     │
    │ Sertifika alan adı uyuşmazlığı             │ High     │
    │ Sertifika 90 gün içinde sona eriyor        │ Medium   │
    │ Zayıf şifreleme (RC4, MD5, DES, 3DES)     │ Medium   │
    └────────────────────────────────────────────┴──────────┘

Yazar   : VultronScanner Team
Sürüm   : 1.0.0
Ders    : BGT006 Sızma Testi — İstinye Üniversitesi
Referans: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from Core.Models import Finding, Severity

# ── Sabitler ──────────────────────────────────────────────────────────────────

_HTTPS_PORT = 443
_WARN_DAYS_HIGH   = 30   # Bu kadar günden az kaldıysa High
_WARN_DAYS_MEDIUM = 90   # Bu kadar günden az kaldıysa Medium

_DEPRECATED_PROTOCOLS = {
    ssl.TLSVersion.TLSv1:   "TLS 1.0",
    ssl.TLSVersion.TLSv1_1: "TLS 1.1",
}

_WEAK_CIPHERS = {"RC4", "MD5", "DES", "3DES", "NULL", "EXPORT", "ADH", "AECDH"}


class SSLChecker:
    """
    SSL/TLS sertifika ve protokol güvenlik denetçisi.

    Hedef sunucuya gerçek bir TLS el sıkışması (handshake) yaparak
    sertifika ve protokol bilgilerini toplar; NIST standartlarına
    göre güvenlik açıklarını raporlar.

    Attributes:
        host    (str): Denetlenecek sunucu adresi (IP veya FQDN).
        port    (int): TLS portu (varsayılan: 443).
        timeout (int): Bağlantı zaman aşımı (saniye).

    Örnek:
        >>> checker = SSLChecker("example.com")
        >>> findings = checker.scan()
        >>> for f in findings:
        ...     print(f.severity.label, f.title)
    """

    MODULE_NAME = "SSLAnalyzer"

    def __init__(
        self,
        host: str,
        port: int = _HTTPS_PORT,
        timeout: int = 10,
    ) -> None:
        self.host    = host
        self.port    = port
        self.timeout = timeout

    # ── Public API ─────────────────────────────────────────────────────────────

    def scan(self) -> list[Finding]:
        """
        SSL/TLS denetimini gerçekleştirir.

        Sertifika bilgilerini ve TLS el sıkışma verilerini toplar,
        güvenlik açıklarını Finding nesneleri olarak döndürür.

        Returns:
            list[Finding]: Tespit edilen SSL/TLS bulgularının listesi.
        """
        findings: list[Finding] = []

        try:
            cert_info, tls_info = self._fetch_tls_info()
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as exc:
            findings.append(Finding(
                title="SSL/TLS Bağlantısı Kurulamadı",
                severity=Severity.HIGH,
                description=(
                    f"Hedefe TLS bağlantısı kurulamadı: {exc}\n"
                    "Bu durum sunucunun SSL'i desteklemediğine veya "
                    "güvenlik duvarı kurallarına işaret edebilir."
                ),
                recommendation="Sunucunun TLS 1.2 veya TLS 1.3 desteklediğini doğrulayın.",
                module=self.MODULE_NAME,
                target=f"{self.host}:{self.port}",
                evidence=str(exc),
            ))
            return findings

        findings.extend(self._check_expiry(cert_info))
        findings.extend(self._check_self_signed(cert_info))
        findings.extend(self._check_hostname(cert_info))
        findings.extend(self._check_protocol(tls_info))
        findings.extend(self._check_cipher(tls_info))

        return findings

    # ── Bağlantı ──────────────────────────────────────────────────────────────

    def _fetch_tls_info(self) -> tuple[dict[str, Any], dict[str, Any]]:
        """
        Hedefe TLS bağlantısı kurarak sertifika ve protokol bilgilerini toplar.

        Returns:
            tuple: (cert_info, tls_info)
                - cert_info: ssl.SSLSocket.getpeercert() çıktısı
                - tls_info : {'protocol': str, 'cipher': str, 'cipher_bits': int}

        Raises:
            ssl.SSLError          : TLS el sıkışma hatası.
            socket.timeout        : Bağlantı zaman aşımı.
            ConnectionRefusedError: Bağlantı reddedildi.
            OSError               : Genel ağ hatası.
        """
        context = ssl.create_default_context()
        # Süresi dolmuş veya self-signed sertifikaları da yakalamak için
        # doğrulamayı devre dışı bırakıyoruz; hatayı kendimiz raporluyoruz.
        context.check_hostname = False
        context.verify_mode    = ssl.CERT_NONE

        with socket.create_connection(
            (self.host, self.port), timeout=self.timeout
        ) as sock:
            with context.wrap_socket(sock, server_hostname=self.host) as tls_sock:
                cert    = tls_sock.getpeercert()
                cipher  = tls_sock.cipher()          # (name, protocol, bits)
                version = tls_sock.version()         # ör. "TLSv1.3"

        cert_info: dict[str, Any] = cert or {}
        tls_info: dict[str, Any] = {
            "protocol":    version or "Unknown",
            "cipher":      cipher[0] if cipher else "Unknown",
            "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else 0,
        }
        return cert_info, tls_info

    # ── Kontrol Metodları ──────────────────────────────────────────────────────

    def _check_expiry(self, cert: dict[str, Any]) -> list[Finding]:
        """
        Sertifika geçerlilik tarihini kontrol eder.

        - Süresi dolmuşsa    → Critical
        - 30 gün içindeyse   → High
        - 90 gün içindeyse   → Medium
        """
        findings: list[Finding] = []
        not_after_str = cert.get("notAfter", "")
        if not not_after_str:
            return findings

        try:
            not_after = datetime.strptime(
                not_after_str, "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            return findings

        now        = datetime.now(tz=timezone.utc)
        days_left  = (not_after - now).days
        target_str = f"{self.host}:{self.port}"

        if days_left < 0:
            findings.append(Finding(
                title="SSL Sertifikası Süresi Dolmuş",
                severity=Severity.CRITICAL,
                description=(
                    f"Sertifikanın geçerlilik süresi {abs(days_left)} gün önce dolmuş. "
                    "Tarayıcılar bu siteye güvensiz olarak işaret eder ve "
                    "MITM saldırılarına kapı açılır."
                ),
                recommendation=(
                    "Sertifikayı derhal yenileyin. Let's Encrypt (certbot) veya "
                    "CA'nızdan yeni sertifika alın."
                ),
                module=self.MODULE_NAME,
                target=target_str,
                evidence=f"Sertifika bitiş tarihi: {not_after_str} | Kalan gün: {days_left}",
                cvss_score=9.1,
            ))
        elif days_left <= _WARN_DAYS_HIGH:
            findings.append(Finding(
                title=f"SSL Sertifikası Yakında Sona Eriyor ({days_left} gün)",
                severity=Severity.HIGH,
                description=(
                    f"Sertifika {days_left} gün içinde sona eriyor ({not_after_str}). "
                    "Süresi dolan sertifika servis kesintisine neden olur."
                ),
                recommendation="Sertifikayı en kısa sürede yenileyin.",
                module=self.MODULE_NAME,
                target=target_str,
                evidence=f"Sertifika bitiş tarihi: {not_after_str}",
            ))
        elif days_left <= _WARN_DAYS_MEDIUM:
            findings.append(Finding(
                title=f"SSL Sertifikası 90 Gün İçinde Sona Eriyor ({days_left} gün)",
                severity=Severity.MEDIUM,
                description=(
                    f"Sertifika {days_left} gün içinde sona eriyor ({not_after_str}). "
                    "Yenileme planı yapılmalıdır."
                ),
                recommendation="Sertifika yenileme sürecini başlatın veya otomatik yenileme kurun.",
                module=self.MODULE_NAME,
                target=target_str,
                evidence=f"Sertifika bitiş tarihi: {not_after_str}",
            ))

        return findings

    def _check_self_signed(self, cert: dict[str, Any]) -> list[Finding]:
        """
        Sertifikanın kendi imzalı (self-signed) olup olmadığını kontrol eder.

        Issuer == Subject ise sertifika kendi imzalıdır.
        """
        findings: list[Finding] = []
        issuer  = dict(x[0] for x in cert.get("issuer",  []))
        subject = dict(x[0] for x in cert.get("subject", []))

        issuer_cn  = issuer.get("commonName",  "")
        subject_cn = subject.get("commonName", "")

        if issuer_cn and subject_cn and issuer_cn == subject_cn:
            findings.append(Finding(
                title="Self-Signed (Kendi İmzalı) Sertifika",
                severity=Severity.HIGH,
                description=(
                    "Sertifika güvenilir bir Sertifika Otoritesi (CA) tarafından "
                    "değil, sunucunun kendisi tarafından imzalanmış. "
                    "Tarayıcılar bu siteyi güvensiz olarak işaretler ve "
                    "MITM saldırılarına karşı koruma sağlamaz."
                ),
                recommendation=(
                    "Let's Encrypt (ücretsiz), DigiCert, GlobalSign gibi güvenilir "
                    "bir CA'dan sertifika alın."
                ),
                module=self.MODULE_NAME,
                target=f"{self.host}:{self.port}",
                evidence=f"Issuer CN: {issuer_cn} | Subject CN: {subject_cn}",
                cvss_score=7.4,
            ))

        return findings

    def _check_hostname(self, cert: dict[str, Any]) -> list[Finding]:
        """
        Sertifikadaki alan adının hedef host ile eşleşip eşleşmediğini kontrol eder.

        SubjectAltName (SAN) veya commonName kullanılır.
        """
        findings: list[Finding] = []
        try:
            ssl.match_hostname(cert, self.host)  # type: ignore[attr-defined]
        except ssl.CertificateError as exc:
            findings.append(Finding(
                title="SSL Sertifikası Alan Adı Uyuşmazlığı",
                severity=Severity.HIGH,
                description=(
                    f"Sertifika '{self.host}' alan adı için geçerli değil. "
                    "Bu durum MITM (Man-in-the-Middle) saldırısına işaret edebilir."
                ),
                recommendation=(
                    "Doğru alan adı için geçerli bir sertifika edinin. "
                    "Wildcard sertifika veya SAN sertifikası kullanılabilir."
                ),
                module=self.MODULE_NAME,
                target=f"{self.host}:{self.port}",
                evidence=str(exc),
                cvss_score=7.5,
            ))
        except AttributeError:
            # Python 3.12+ match_hostname kaldırıldı; geç
            pass

        return findings

    def _check_protocol(self, tls_info: dict[str, Any]) -> list[Finding]:
        """
        TLS protokol sürümünü kontrol eder.

        TLS 1.0 ve TLS 1.1 NIST SP 800-52 Rev. 2 kapsamında kullanımdan
        kaldırılmıştır; High bulgu olarak raporlanır.
        """
        findings: list[Finding] = []
        protocol = tls_info.get("protocol", "")

        deprecated = {
            "TLSv1":   "TLS 1.0",
            "TLSv1.1": "TLS 1.1",
        }

        for proto_key, proto_name in deprecated.items():
            if proto_key in protocol:
                findings.append(Finding(
                    title=f"Kullanımdan Kaldırılmış Protokol: {proto_name}",
                    severity=Severity.HIGH,
                    description=(
                        f"Sunucu {proto_name} protokolünü destekliyor. "
                        "Bu protokol POODLE, BEAST gibi bilinen saldırılara karşı "
                        "savunmasızdır ve NIST SP 800-52 Rev. 2 ile yasaklanmıştır."
                    ),
                    recommendation=(
                        f"{proto_name} protokolünü devre dışı bırakın. "
                        "Yalnızca TLS 1.2 ve TLS 1.3'ü etkinleştirin. "
                        "Nginx için: 'ssl_protocols TLSv1.2 TLSv1.3;'"
                    ),
                    module=self.MODULE_NAME,
                    target=f"{self.host}:{self.port}",
                    evidence=f"Aktif protokol: {protocol}",
                    cve="CVE-2014-3566",  # POODLE
                    cvss_score=7.4,
                ))

        return findings

    def _check_cipher(self, tls_info: dict[str, Any]) -> list[Finding]:
        """
        Aktif şifre takımını (cipher suite) kontrol eder.

        RC4, DES, 3DES, MD5, NULL, EXPORT cipher'ları zayıf kabul edilir.
        """
        findings: list[Finding] = []
        cipher     = tls_info.get("cipher", "").upper()
        cipher_bits = tls_info.get("cipher_bits", 0)

        for weak in _WEAK_CIPHERS:
            if weak in cipher:
                findings.append(Finding(
                    title=f"Zayıf Şifre Takımı Kullanılıyor: {weak}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Aktif TLS bağlantısında zayıf '{weak}' şifreleme algoritması "
                        "kullanılıyor. Bu algoritma kriptografik saldırılara karşı "
                        "savunmasızdır."
                    ),
                    recommendation=(
                        "Zayıf cipher suite'leri devre dışı bırakın. "
                        "Yalnızca AES-GCM, ChaCha20-Poly1305 gibi modern algoritmaları kullanın. "
                        "Nginx için: 'ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:...'"
                    ),
                    module=self.MODULE_NAME,
                    target=f"{self.host}:{self.port}",
                    evidence=f"Aktif cipher: {tls_info.get('cipher')} ({cipher_bits} bit)",
                ))
                break  # Aynı bağlantı için tek bulgu yeterli

        return findings
