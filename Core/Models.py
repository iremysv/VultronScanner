"""
Core.Models
============
VultronScanner genelinde kullanılan veri modellerini ve zafiyet
ciddiyet sınıflandırmasını tanımlar.

Sınıflar:
    Severity        : Zafiyet seviyesi enum'u (Critical → Info)
    Finding         : Tek bir zafiyet bulgusu
    ScanResult      : Tarama oturumunun tüm bulgularını taşır
    TargetConfig    : Hedef bilgisi (host, port, protokol)

Kullanım:
    >>> from Core.Models import Finding, Severity
    >>> f = Finding(
    ...     title="HSTS Eksik",
    ...     severity=Severity.HIGH,
    ...     description="...",
    ...     recommendation="...",
    ... )

Yazar   : VultronScanner Team
Sürüm   : 1.0.0
Ders    : BGT006 Sızma Testi — İstinye Üniversitesi
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


# ── Severity Enum ──────────────────────────────────────────────────────────────

class Severity(str, Enum):
    """
    Zafiyet ciddiyet seviyesi.

    CVSS v3.1 metodolojisine dayalı beş kademeli sınıflandırma:
        CRITICAL : CVSS 9.0-10.0  — Hemen müdahale gerektirir
        HIGH     : CVSS 7.0-8.9   — Kısa sürede giderilmeli
        MEDIUM   : CVSS 4.0-6.9   — Planlı güncelleme ile giderilmeli
        LOW      : CVSS 0.1-3.9   — İzlenebilir, düşük öncelikli
        INFO     : CVSS 0.0        — Bilgilendirme amaçlı
    """

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    # Seviyeyi emoji ile renklendirilmiş string'e dönüştür (rapor için)
    @property
    def label(self) -> str:
        """Markdown raporunda kullanılacak emoji'li etiket."""
        labels = {
            "Critical": "🔴 Critical",
            "High":     "🟠 High",
            "Medium":   "🟡 Medium",
            "Low":      "🟢 Low",
            "Info":     "🔵 Info",
        }
        return labels[self.value]

    @property
    def sort_key(self) -> int:
        """Raporlarda sıralamak için sayısal ağırlık (yüksek = daha kritik)."""
        weights = {
            "Critical": 5,
            "High":     4,
            "Medium":   3,
            "Low":      2,
            "Info":     1,
        }
        return weights[self.value]


# ── Finding Dataclass ──────────────────────────────────────────────────────────

@dataclass
class Finding:
    """
    Tek bir zafiyet bulgusunu temsil eder.

    Attributes:
        finding_id    : Otomatik oluşturulan benzersiz UUID.
        title         : Kısa ve açıklayıcı bulgu başlığı.
        severity      : Ciddiyet seviyesi (Severity enum).
        description   : Detaylı teknik açıklama.
        recommendation: Giderme önerisi.
        module        : Bulguyu tespit eden modül adı.
        target        : Etkilenen hedef (URL, IP, port vb.).
        evidence      : Kanıt verisi (ham HTTP başlığı, sertifika bilgisi vb.).
        cve           : İlgili CVE numarası (varsa).
        cvss_score    : Sayısal CVSS puanı (0.0-10.0, isteğe bağlı).
        timestamp     : Bulgunun tespit edildiği zaman damgası.
    """

    title: str
    severity: Severity
    description: str
    recommendation: str
    module: str = "Unknown"
    target: str = ""
    evidence: str = ""
    cve: str = ""
    cvss_score: float | None = None
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> dict[str, Any]:
        """JSON serileştirme için sözlük gösterimi döndürür."""
        return {
            "finding_id":     self.finding_id,
            "title":          self.title,
            "severity":       self.severity.value,
            "module":         self.module,
            "target":         self.target,
            "description":    self.description,
            "recommendation": self.recommendation,
            "evidence":       self.evidence,
            "cve":            self.cve if self.cve else None,
            "cvss_score":     self.cvss_score,
            "timestamp":      self.timestamp,
        }


# ── TargetConfig Dataclass ─────────────────────────────────────────────────────

@dataclass
class TargetConfig:
    """
    Taranacak hedef bilgilerini taşır.

    Attributes:
        host     : IP adresi veya alan adı.
        ports    : Taranacak port aralığı (ör. "22-1024", "80,443,8080").
        scheme   : Protokol (http veya https).
        timeout  : Bağlantı zaman aşımı (saniye).
    """

    host: str
    ports: str = "1-1024"
    scheme: str = "https"
    timeout: int = 10

    @property
    def base_url(self) -> str:
        """Tam URL döndürür: scheme://host"""
        return f"{self.scheme}://{self.host}"


# ── ScanResult Dataclass ───────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """
    Bir tarama oturumunun tüm sonuçlarını taşır.

    Attributes:
        target         : Taranan hedef konfigürasyonu.
        findings       : Tespit edilen tüm bulgular listesi.
        scan_start     : Tarama başlangıç zamanı (ISO-8601).
        scan_end       : Tarama bitiş zamanı (ISO-8601).
        scanner_version: VultronScanner sürüm numarası.
    """

    target: TargetConfig
    findings: list[Finding] = field(default_factory=list)
    scan_start: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    scan_end: str = ""
    scanner_version: str = "1.0.0"

    # ── Yardımcı metodlar ──────────────────────────────────────────────────────

    def add_finding(self, finding: Finding) -> None:
        """Listeye yeni bulgu ekler."""
        self.findings.append(finding)

    def add_findings(self, findings: list[Finding]) -> None:
        """Toplu bulgu ekler."""
        self.findings.extend(findings)

    def sorted_findings(self) -> list[Finding]:
        """Bulguları severity'ye göre büyükten küçüğe sıralar."""
        return sorted(self.findings, key=lambda f: f.severity.sort_key, reverse=True)

    def summary(self) -> dict[str, int]:
        """Severity düzeyine göre bulgu sayısını özetler."""
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """JSON serileştirme için tam sözlük gösterimi."""
        return {
            "scanner":  "VultronScanner",
            "version":  self.scanner_version,
            "target": {
                "host":   self.target.host,
                "ports":  self.target.ports,
                "scheme": self.target.scheme,
            },
            "scan_start":  self.scan_start,
            "scan_end":    self.scan_end,
            "summary":     self.summary(),
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
