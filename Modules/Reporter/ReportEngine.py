"""
Modules.Reporter.ReportEngine
=============================

Tarama sonuçlarını işleyerek Markdown ve JSON formatlarında
çıktı üretilmesini sağlayan rapor motoru.

Yazar   : VultronScanner Team
Sürüm   : 1.0.0
Ders    : BGT006 Sızma Testi — İstinye Üniversitesi
"""

import json
from pathlib import Path

from Core.Models import ScanResult


class ReportEngine:
    """
    Tarama sonuçlarını dışa aktarmak için motor sınıfı.

    Attributes:
        result (ScanResult): Raporlanacak tarama sonucu nesnesi.
    """

    def __init__(self, result: ScanResult) -> None:
        self.result = result

    def save_json(self, path: Path | str) -> None:
        """
        Tarama sonucunu JSON dosyası olarak kaydeder.

        Args:
            path: Kaydedilecek dosya yolu.
        """
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = self.result.to_dict()
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

    def save_markdown(self, path: Path | str) -> None:
        """
        Tarama sonucunu Markdown formatında kullanıcı okunaklı
        bir rapor olarak kaydeder.

        Args:
            path: Kaydedilecek dosya yolu.
        """
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        lines = [
            f"# 🛡️ VultronScanner Tarama Raporu: {self.result.target.host}",
            "",
            "## 📊 Genel Özet",
            f"- **Hedef:** `{self.result.target.base_url}`",
            f"- **Taranan Portlar:** `{self.result.target.ports}`",
            f"- **Başlangıç:** `{self.result.scan_start}`",
            f"- **Bitiş:** `{self.result.scan_end}`",
            f"- **Toplam Bulgu:** `{len(self.result.findings)}`",
            "",
            "### Ciddiyet Dağılımı",
        ]

        summary = self.result.summary()
        for severity, count in summary.items():
            lines.append(f"- **{severity}**: {count}")
        lines.append("\n---\n")

        lines.append("## 🔍 Detaylı Bulgular")
        
        if not self.result.findings:
            lines.append("Hiçbir zafiyet veya bulgu tespit edilemedi. 🎉")
        else:
            for idx, finding in enumerate(self.result.sorted_findings(), start=1):
                lines.extend([
                    f"### {idx}. {finding.severity.label} - {finding.title}",
                    "",
                    f"- **Bulgu ID:** `{finding.finding_id}`",
                    f"- **Modül:** `{finding.module}`",
                ])

                if finding.cve:
                    lines.append(f"- **CVE:** `{finding.cve}`")
                if finding.cvss_score:
                    lines.append(f"- **CVSS Puanı:** `{finding.cvss_score}`")

                lines.extend([
                    "",
                    "#### Açıklama",
                    f"{finding.description}",
                    "",
                    "#### Öneri",
                    f"{finding.recommendation}",
                    "",
                ])

                if finding.evidence:
                    lines.extend([
                        "#### Kanıt (Evidence)",
                        "```text",
                        finding.evidence,
                        "```",
                        "",
                    ])
                lines.append("---\n")

        with output_path.open("w", encoding="utf-8") as f:
            f.write("\n".join(lines))
