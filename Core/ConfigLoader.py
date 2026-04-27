"""
VultronScanner — Core/ConfigLoader.py
=======================================
YAML-based configuration loader with pydantic v2 validation and profile merging.

Responsibilities
----------------
1. Load ``Config/DefaultConfig.yaml`` (platform-wide defaults)
2. Load ``Config/ScanProfiles.yaml`` (per-profile module toggles)
3. Merge a selected profile's settings on top of defaults
4. Validate the merged config via pydantic models
5. Provide typed accessor properties for each config section

Usage
-----
    loader = ConfigLoader()
    cfg = loader.load(profile="quick")

    print(cfg.profile_name)          # "Quick Scan"
    print(cfg.nmap.arguments)        # "-F -T4 -sV"
    print(cfg.async_cfg.max_workers) # 25
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field, field_validator

from Utils.Logger import get_logger

log = get_logger("config")

# ---------------------------------------------------------------------------
# Pydantic config models
# ---------------------------------------------------------------------------


class AsyncConfig(BaseModel):
    max_concurrent_tasks: int = 25
    task_timeout_seconds: int = 120
    connection_timeout_seconds: int = 10
    retry_attempts: int = 3
    retry_delay_seconds: float = 2.0


class LoggingConfig(BaseModel):
    level: str = "INFO"
    enable_file_logging: bool = True
    log_directory: str = "logs/"
    log_filename: str = "vultron.log"
    max_log_size_mb: int = 10
    backup_count: int = 5
    rich_console: bool = True


class NetworkConfig(BaseModel):
    dns_servers: List[str] = ["8.8.8.8", "1.1.1.1"]
    resolve_hostnames: bool = True
    enable_ipv6: bool = False
    max_ping_count: int = 3
    ping_timeout_ms: int = 1000


class NmapConfig(BaseModel):
    binary_path: str = "nmap"
    arguments: str = "-sV -sC"
    timing_template: int = 3
    max_retries: int = 2
    host_timeout: str = "10m"
    port_range: Optional[str] = None

    @field_validator("timing_template")
    @classmethod
    def validate_timing(cls, v: int) -> int:
        if not 0 <= v <= 5:
            raise ValueError(f"timing_template must be 0-5, got {v}")
        return v


class WebConfig(BaseModel):
    user_agent: str = "VultronScanner/1.0 (Security Research)"
    request_timeout_seconds: int = 15
    follow_redirects: bool = True
    max_redirects: int = 5
    verify_ssl: bool = False
    check_headers: List[str] = Field(
        default_factory=lambda: [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
    )


class CveConfig(BaseModel):
    api_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key_env_var: str = "NVD_API_KEY"
    results_per_page: int = 20
    request_delay_seconds: float = 0.6
    cache_results: bool = True
    cache_ttl_hours: int = 24

    @property
    def api_key(self) -> Optional[str]:
        """Read API key from environment at call time."""
        return os.getenv(self.api_key_env_var)


class CvssThresholds(BaseModel):
    critical: float = 9.0
    high: float = 7.0
    medium: float = 4.0
    low: float = 0.1
    none: float = 0.0


class CvssConfig(BaseModel):
    thresholds: CvssThresholds = Field(default_factory=CvssThresholds)


class ReportsConfig(BaseModel):
    output_directory: str = "Reports/Output/"
    default_format: str = "html"
    include_raw_nmap: bool = False
    include_executive_summary: bool = True
    company_name: str = "VultronScanner"
    report_title_prefix: str = "VultronScanner Security Report"


class ModuleToggles(BaseModel):
    host_discovery: bool = True
    port_analyzer: bool = True
    network_scanner: bool = True
    service_fingerprint: bool = True
    web_analyzer: bool = False
    vulnerability_engine: bool = False
    threat_scorer: bool = True
    exploit_suggester: bool = False
    brute_force: bool = False


class ReportOptions(BaseModel):
    format: str = "markdown"
    include_executive_summary: bool = False
    verbosity: str = "summary"


class VultronConfig(BaseModel):
    """Merged, validated configuration object handed to the Orchestrator."""

    profile_key: str = "quick"
    profile_name: str = "Quick Scan"
    estimated_duration: str = "unknown"

    async_cfg: AsyncConfig = Field(default_factory=AsyncConfig)
    logging_cfg: LoggingConfig = Field(default_factory=LoggingConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    nmap: NmapConfig = Field(default_factory=NmapConfig)
    web: WebConfig = Field(default_factory=WebConfig)
    cve: CveConfig = Field(default_factory=CveConfig)
    cvss: CvssConfig = Field(default_factory=CvssConfig)
    reports: ReportsConfig = Field(default_factory=ReportsConfig)
    modules: ModuleToggles = Field(default_factory=ModuleToggles)
    report_opts: ReportOptions = Field(default_factory=ReportOptions)


# ---------------------------------------------------------------------------
# ConfigLoader
# ---------------------------------------------------------------------------


class ConfigLoader:
    """
    Loads and merges YAML configuration files.

    Parameters
    ----------
    config_dir : Path
        Directory containing ``DefaultConfig.yaml`` and ``ScanProfiles.yaml``.
        Defaults to ``<project_root>/Config/``.
    """

    DEFAULT_CONFIG = "DefaultConfig.yaml"
    PROFILES_CONFIG = "ScanProfiles.yaml"

    def __init__(self, config_dir: Optional[Path] = None) -> None:
        if config_dir is None:
            # Resolve relative to this file's location (Core/ → project root)
            config_dir = Path(__file__).parent.parent / "Config"
        self._config_dir = config_dir
        log.debug("ConfigLoader initialised", config_dir=str(config_dir))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self, profile: str = "quick") -> VultronConfig:
        """
        Load and validate configuration for *profile*.

        Returns a fully validated :class:`VultronConfig` instance.
        """
        defaults = self._load_yaml(self.DEFAULT_CONFIG)
        profiles = self._load_yaml(self.PROFILES_CONFIG)

        if "profiles" not in profiles:
            raise ValueError("ScanProfiles.yaml is missing 'profiles' top-level key")

        available = list(profiles["profiles"].keys())
        if profile not in profiles["profiles"]:
            log.warning(
                "Unknown profile requested, falling back to 'quick'",
                requested=profile,
                available=available,
            )
            profile = "quick"

        profile_data = profiles["profiles"][profile]
        merged = self._merge(defaults, profile_data)
        config = self._build_config(merged, profile, profile_data)

        log.info(
            "Configuration loaded",
            profile=profile,
            name=config.profile_name,
            duration=config.estimated_duration,
        )
        return config

    def available_profiles(self) -> List[str]:
        """Return a list of all profile keys defined in ScanProfiles.yaml."""
        profiles = self._load_yaml(self.PROFILES_CONFIG)
        return list(profiles.get("profiles", {}).keys())

    def get_profiles_data(self) -> Dict[str, Any]:
        """Return the full profiles dict from ScanProfiles.yaml."""
        raw = self._load_yaml(self.PROFILES_CONFIG)
        return raw.get("profiles", {})

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_yaml(self, filename: str) -> Dict[str, Any]:
        path = self._config_dir / filename
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        log.debug("YAML loaded", file=filename)
        return data or {}

    @staticmethod
    def _merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Deep-merge *override* on top of *base* (non-destructive copy)."""
        result = copy.deepcopy(base)
        for key, value in override.items():
            if isinstance(value, dict) and isinstance(result.get(key), dict):
                result[key] = ConfigLoader._merge(result[key], value)
            else:
                result[key] = value
        return result

    def _build_config(
        self,
        merged: Dict[str, Any],
        profile_key: str,
        profile_data: Dict[str, Any],
    ) -> VultronConfig:
        """Translate raw merged dict into a typed VultronConfig."""

        def _get(section: str) -> Dict[str, Any]:
            return merged.get(section, {})

        # Nmap settings — profile can override arguments / timing / port_range
        nmap_base = dict(_get("nmap"))
        nmap_override = profile_data.get("nmap", {})
        nmap_merged = {**nmap_base, **nmap_override}

        # Module toggles (nested under profile_data.modules.*)
        p_modules = profile_data.get("modules", {})
        disc = p_modules.get("discovery", {})
        intel = p_modules.get("intelligence", {})
        act = p_modules.get("action", {})

        modules = ModuleToggles(
            host_discovery=disc.get("host_discovery", True),
            port_analyzer=disc.get("port_analyzer", True),
            network_scanner=disc.get("network_scanner", True),
            service_fingerprint=intel.get("service_fingerprint", True),
            web_analyzer=intel.get("web_analyzer", False),
            vulnerability_engine=intel.get("vulnerability_engine", False),
            threat_scorer=intel.get("threat_scorer", True),
            exploit_suggester=act.get("exploit_suggester", False),
            brute_force=act.get("brute_force", False),
        )

        # Report options
        p_report = profile_data.get("report", {})
        report_opts = ReportOptions(
            format=p_report.get("format", "markdown"),
            include_executive_summary=p_report.get("include_executive_summary", False),
            verbosity=p_report.get("verbosity", "summary"),
        )

        async_raw = _get("async")
        return VultronConfig(
            profile_key=profile_key,
            profile_name=profile_data.get("name", profile_key),
            estimated_duration=profile_data.get("estimated_duration", "unknown"),
            async_cfg=AsyncConfig(**async_raw) if async_raw else AsyncConfig(),
            logging_cfg=LoggingConfig(**_get("logging")) if _get("logging") else LoggingConfig(),
            network=NetworkConfig(**_get("network")) if _get("network") else NetworkConfig(),
            nmap=NmapConfig(**nmap_merged),
            web=WebConfig(**_get("web")) if _get("web") else WebConfig(),
            cve=CveConfig(**_get("cve")) if _get("cve") else CveConfig(),
            cvss=(
                CvssConfig(thresholds=CvssThresholds(**_get("cvss").get("thresholds", {})))
                if _get("cvss")
                else CvssConfig()
            ),
            reports=ReportsConfig(**_get("reports")) if _get("reports") else ReportsConfig(),
            modules=modules,
            report_opts=report_opts,
        )
