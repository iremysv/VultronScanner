"""
Core.Orchestrator
==================
Tarama iş akışını koordine eder; modülleri sırayla çalıştırır,
bulguları birleştirir ve raporlama motorunu tetikler.

İş akışı:
    1. Konfigürasyondan hedefleri oku
    2. Her hedef için sırayla çalıştır:
       a. Nmap Port Tarama   (Modules.ViseNmap)
       b. Security Headers   (Modules.HeaderAnalyzer)
       c. SSL/TLS Kontrolü   (Modules.SSLAnalyzer)
    3. Bulguları ScanResult'a topla
    4. Markdown + JSON raporlarını üret

Kullanım:
    >>> from Core.Orchestrator import Orchestrator
    >>> orch = Orchestrator("config.yaml")
    >>> orch.run()

Yazar   : VultronScanner Team
Sürüm   : 1.0.0
Ders    : BGT006 Sızma Testi — İstinye Üniversitesi
"""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

from Core.ConfigLoader import ConfigLoader
from Core.Models import ScanResult, TargetConfig
from Modules.HeaderAnalyzer.HeaderScanner import HeaderScanner
from Modules.Reporter.ReportEngine import ReportEngine
from Modules.SSLAnalyzer.SSLChecker import SSLChecker
from Modules.ViseNmap.NmapScannerTool import NmapScannerTool


class Orchestrator:
    """
    VultronScanner tarama orkestratörü.

    Tüm tarama modüllerini sırayla çalıştırır, bulguları birleştirir
    ve rapor motorunu tetikler.

    Attributes:
        config_path (str | Path): Konfigürasyon dosyası yolu.
        output_dir  (Path)      : Rapor çıktı klasörü.
        config      (dict)      : Yüklenen konfigürasyon.
    """

    def __init__(
        self,
        config_path: str | Path = "config.yaml",
        output_dir: str | Path = "Reports",
    ) -> None:
        self.config_path = config_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        loader = ConfigLoader(config_path)
        self.config = loader.load()

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        """
        Tüm hedefler için taramayı başlatır.

        Her hedef için bağımsız bir ScanResult oluşturur,
        modülleri çalıştırır ve raporları kaydeder.
        """
        targets = self.config.get("targets", [])
        scan_settings = self.config.get("scan_settings", {})

        print("\n" + "═" * 60)
        print("  🔍 VultronScanner — BGT006 Final Projesi")
        print("  📚 İstinye Üniversitesi — Sızma Testi")
        print("═" * 60)
        print(f"  Toplam hedef : {len(targets)}")
        print(f"  Çıktı klasörü: {self.output_dir.resolve()}")
        print("═" * 60 + "\n")

        for idx, target_cfg in enumerate(targets, start=1):
            target = TargetConfig(
                host=target_cfg["host"],
                ports=target_cfg.get("ports", scan_settings.get("default_ports", "1-1024")),
                scheme=target_cfg.get("scheme", "https"),
                timeout=target_cfg.get("timeout", scan_settings.get("timeout", 10)),
            )

            print(f"[{idx}/{len(targets)}] 🎯 Hedef: {target.base_url}")
            result = self._scan_target(target, scan_settings)
            self._save_reports(result, target)

        print("\n✅ Tüm taramalar tamamlandı.\n")

    # ── Private Helpers ────────────────────────────────────────────────────────

    def _scan_target(
        self,
        target: TargetConfig,
        settings: dict,
    ) -> ScanResult:
        """
        Tek bir hedef için tüm modülleri çalıştırır.

        Args:
            target  : Taranacak hedef konfigürasyonu.
            settings: Genel tarama ayarları.

        Returns:
            ScanResult: Tüm bulguları içeren tarama sonucu.
        """
        result = ScanResult(target=target)
        enabled = settings.get("modules", {})

        # ── 1. Nmap Port Tarama ────────────────────────────────────────────────
        if enabled.get("nmap", True):
            print(f"    ├─ [Nmap]   Port taraması başlıyor → {target.ports}")
            try:
                nmap = NmapScannerTool(
                    target=target.host,
                    ports=target.ports,
                    timeout=target.timeout,
                )
                findings = nmap.scan()
                result.add_findings(findings)
                print(f"    │   └─ {len(findings)} bulgu")
            except Exception as exc:  # noqa: BLE001
                print(f"    │   └─ ⚠️  Nmap hatası: {exc}")

        # ── 2. Security Headers ────────────────────────────────────────────────
        if enabled.get("headers", True):
            print(f"    ├─ [Headers] Güvenlik başlıkları analiz ediliyor...")
            try:
                header_scanner = HeaderScanner(
                    url=target.base_url,
                    timeout=target.timeout,
                )
                findings = header_scanner.scan()
                result.add_findings(findings)
                print(f"    │   └─ {len(findings)} bulgu")
            except Exception as exc:  # noqa: BLE001
                print(f"    │   └─ ⚠️  Header hatası: {exc}")

        # ── 3. SSL/TLS Kontrolü ────────────────────────────────────────────────
        if enabled.get("ssl", True) and target.scheme == "https":
            print(f"    ├─ [SSL]    Sertifika ve TLS kontrolü...")
            try:
                ssl_checker = SSLChecker(
                    host=target.host,
                    timeout=target.timeout,
                )
                findings = ssl_checker.scan()
                result.add_findings(findings)
                print(f"    │   └─ {len(findings)} bulgu")
            except Exception as exc:  # noqa: BLE001
                print(f"    │   └─ ⚠️  SSL hatası: {exc}")

        result.scan_end = datetime.utcnow().isoformat() + "Z"
        summary = result.summary()
        print(
            f"    └─ 📊 Özet → "
            f"Critical:{summary['Critical']} | "
            f"High:{summary['High']} | "
            f"Medium:{summary['Medium']} | "
            f"Low:{summary['Low']}\n"
        )
        return result

    def _save_reports(self, result: ScanResult, target: TargetConfig) -> None:
        """
        Raporları diske kaydeder.

        Dosya adları: rapor_<host>.md ve sonuc_<host>.json

        Args:
            result: Kaydedilecek tarama sonucu.
            target: Raporlanacak hedef.
        """
        safe_host = target.host.replace(".", "_").replace(":", "_")
        md_path   = self.output_dir / f"rapor_{safe_host}.md"
        json_path = self.output_dir / f"sonuc_{safe_host}.json"

        reporter = ReportEngine(result)
        reporter.save_markdown(md_path)
        reporter.save_json(json_path)

        print(f"    📄 Markdown : {md_path}")
        print(f"    📄 JSON     : {json_path}")
