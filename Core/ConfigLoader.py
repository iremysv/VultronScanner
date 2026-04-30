"""
Core.ConfigLoader
==================
config.yaml veya config.toml dosyasından tarama konfigürasyonunu
yükler ve doğrular.

Desteklenen formatlar:
    - YAML (.yaml / .yml)  — PyYAML kütüphanesi kullanılır.
    - TOML (.toml)         — Python 3.11+ tomllib, önceki sürümlerde tomli.

Kullanım:
    >>> from Core.ConfigLoader import ConfigLoader
    >>> cfg = ConfigLoader("config.yaml").load()
    >>> print(cfg["targets"])

Yazar   : VultronScanner Team
Sürüm   : 1.0.0
Ders    : BGT006 Sızma Testi — İstinye Üniversitesi
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

# Python 3.11+ built-in tomllib; önceki sürümler için tomli paketini dene
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


class ConfigLoader:
    """
    Konfigürasyon dosyası yükleyicisi.

    Desteklenen formatlar YAML ve TOML'dur. Dosya uzantısına
    bakılarak otomatik olarak doğru parser seçilir.

    Attributes:
        config_path (Path): Konfigürasyon dosyasının tam yolu.

    Raises:
        FileNotFoundError : Belirtilen dosya bulunamazsa.
        ValueError        : Desteklenmeyen uzantı veya eksik alan.
        RuntimeError      : TOML desteği yüklü değilse.
    """

    REQUIRED_KEYS = ("targets",)

    def __init__(self, config_path: str | Path = "config.yaml") -> None:
        self.config_path = Path(config_path)
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Konfigürasyon dosyası bulunamadı: {self.config_path}\n"
                "Lütfen config.yaml veya config.toml dosyası oluşturun."
            )

    # ── Public API ─────────────────────────────────────────────────────────────

    def load(self) -> dict[str, Any]:
        """
        Konfigürasyon dosyasını yükler ve doğrular.

        Returns:
            dict: Doğrulanmış konfigürasyon sözlüğü.

        Raises:
            ValueError: Gerekli alanlar eksikse.
        """
        suffix = self.config_path.suffix.lower()

        if suffix in {".yaml", ".yml"}:
            config = self._load_yaml()
        elif suffix == ".toml":
            config = self._load_toml()
        else:
            raise ValueError(
                f"Desteklenmeyen konfigürasyon formatı: '{suffix}'. "
                "Lütfen .yaml veya .toml kullanın."
            )

        self._validate(config)
        return config

    # ── Private Helpers ────────────────────────────────────────────────────────

    def _load_yaml(self) -> dict[str, Any]:
        """YAML dosyasını okur ve Python sözlüğüne dönüştürür."""
        with self.config_path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return data or {}

    def _load_toml(self) -> dict[str, Any]:
        """TOML dosyasını okur ve Python sözlüğüne dönüştürür."""
        if tomllib is None:
            raise RuntimeError(
                "TOML desteği için Python 3.11+ veya 'tomli' paketi gereklidir.\n"
                "Kurulum: pip install tomli"
            )
        with self.config_path.open("rb") as fh:
            return tomllib.load(fh)

    def _validate(self, config: dict[str, Any]) -> None:
        """
        Zorunlu alanların varlığını kontrol eder.

        Args:
            config: Yüklenen konfigürasyon sözlüğü.

        Raises:
            ValueError: Eksik zorunlu alan varsa.
        """
        for key in self.REQUIRED_KEYS:
            if key not in config:
                raise ValueError(
                    f"Konfigürasyon dosyasında '{key}' alanı eksik.\n"
                    f"Gerekli alanlar: {', '.join(self.REQUIRED_KEYS)}"
                )

        # Her hedefte en az 'host' alanı olmalı
        targets = config.get("targets", [])
        if not isinstance(targets, list) or len(targets) == 0:
            raise ValueError("'targets' alanı en az bir hedef içermelidir.")

        for i, target in enumerate(targets):
            if "host" not in target:
                raise ValueError(
                    f"targets[{i}] için 'host' alanı eksik."
                )
