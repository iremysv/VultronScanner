"""
Modules.SSLAnalyzer Package
=============================
SSL/TLS sertifika ve protokol denetim modülü.

NIST SP 800-52 Rev. 2 ve BSI TR-02102-2 yönergelerine uygun olarak
aşağıdaki güvenlik kontrollerini gerçekleştirir:

    - Sertifika geçerlilik süresi (dolmuş / yakında dolacak)
    - Self-signed sertifika tespiti
    - Alan adı (hostname) uyuşmazlığı
    - Kullanımdan kaldırılmış protokoller (TLS 1.0, TLS 1.1)
    - Zayıf şifre takımları (RC4, DES, 3DES, MD5)

Hızlı Kullanım:
    >>> from Modules.SSLAnalyzer import SSLChecker
    >>> findings = SSLChecker("example.com").scan()
"""

from Modules.SSLAnalyzer.SSLChecker import SSLChecker

__all__ = ["SSLChecker"]
