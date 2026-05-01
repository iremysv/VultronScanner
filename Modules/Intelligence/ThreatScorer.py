"""
Modules.Intelligence.ThreatScorer
=================================

Tarama sonucunda elde edilen tüm bulguları değerlendirip,
eksik CVSS puanlarını varsayılan değerlerle atar ve 
genel sistem risk durumunu iyileştirir.

Yazar   : VultronScanner Team
Sürüm   : 1.0.0
Ders    : BGT006 Sızma Testi — İstinye Üniversitesi
"""

from Core.Models import ScanResult


class ThreatScorer:
    """
    Tüm bulguları gözden geçirerek puanlama yapan ve 
    risk analizini standartlaştıran motor.
    """

    # Eğer CVSS skoru yoksa, ciddiyete (severity) göre varsayılan ağırlıklar
    DEFAULT_SCORES = {
        "Critical": 9.5,
        "High": 8.0,
        "Medium": 5.5,
        "Low": 2.5,
        "Info": 0.0,
    }

    def __init__(self, result: ScanResult) -> None:
        self.result = result

    def evaluate(self) -> None:
        """
        ScanResult içerisindeki findings dizisini yerinde (in-place) günceller.
        Eksik CVSS puanlarını tamamlar.
        """
        for finding in self.result.findings:
            if finding.cvss_score is None:
                finding.cvss_score = self.DEFAULT_SCORES.get(finding.severity.value, 0.0)

        # Gelecekte burada korelasyonlar da eklenebilir.
        # Örneğin: Hem OpenSSH zafiyeti hem de XSS varsa, puanı %10 artır vb.
