"""
Tests/test_ConfigLoader.py
============================
Unit tests for Core/ConfigLoader.

Tests cover:
- YAML file loading (DefaultConfig + ScanProfiles)
- Profile merging (quick, full, stealth, web, auth)
- Module toggle values per profile
- Nmap argument inheritance and override
- Unknown profile fallback to 'quick'
- available_profiles() listing
- Pydantic validation (timing_template bounds)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from Core.ConfigLoader import ConfigLoader, VultronConfig

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def loader():
    return ConfigLoader()


# ---------------------------------------------------------------------------
# Basic loading
# ---------------------------------------------------------------------------


class TestBasicLoading:
    def test_load_quick_returns_config(self, loader):
        cfg = loader.load(profile="quick")
        assert isinstance(cfg, VultronConfig)

    def test_profile_key_set(self, loader):
        cfg = loader.load(profile="quick")
        assert cfg.profile_key == "quick"

    def test_profile_name_set(self, loader):
        cfg = loader.load(profile="quick")
        assert cfg.profile_name == "Quick Scan"

    def test_available_profiles_contains_expected(self, loader):
        profiles = loader.available_profiles()
        for expected in ["quick", "full", "stealth", "web", "auth"]:
            assert expected in profiles


# ---------------------------------------------------------------------------
# Async config
# ---------------------------------------------------------------------------


class TestAsyncConfig:
    def test_max_concurrent_tasks_positive(self, loader):
        cfg = loader.load("quick")
        assert cfg.async_cfg.max_concurrent_tasks > 0

    def test_task_timeout_positive(self, loader):
        cfg = loader.load("quick")
        assert cfg.async_cfg.task_timeout_seconds > 0


# ---------------------------------------------------------------------------
# Module toggles per profile
# ---------------------------------------------------------------------------


class TestModuleToggles:
    def test_quick_web_analyzer_off(self, loader):
        cfg = loader.load("quick")
        assert cfg.modules.web_analyzer is False

    def test_quick_vulnerability_engine_off(self, loader):
        cfg = loader.load("quick")
        assert cfg.modules.vulnerability_engine is False

    def test_full_web_analyzer_on(self, loader):
        cfg = loader.load("full")
        assert cfg.modules.web_analyzer is True

    def test_full_vulnerability_engine_on(self, loader):
        cfg = loader.load("full")
        assert cfg.modules.vulnerability_engine is True

    def test_full_brute_force_off(self, loader):
        cfg = loader.load("full")
        assert cfg.modules.brute_force is False

    def test_auth_brute_force_on(self, loader):
        cfg = loader.load("auth")
        assert cfg.modules.brute_force is True

    def test_host_discovery_always_on(self, loader):
        for profile in ["quick", "full", "stealth", "web"]:
            cfg = loader.load(profile)
            assert cfg.modules.host_discovery is True, f"host_discovery should be on for {profile}"

    def test_stealth_web_analyzer_off(self, loader):
        cfg = loader.load("stealth")
        assert cfg.modules.web_analyzer is False

    def test_web_profile_web_analyzer_on(self, loader):
        cfg = loader.load("web")
        assert cfg.modules.web_analyzer is True


# ---------------------------------------------------------------------------
# Nmap config
# ---------------------------------------------------------------------------


class TestNmapConfig:
    def test_quick_uses_fast_flag(self, loader):
        cfg = loader.load("quick")
        assert "-F" in cfg.nmap.arguments

    def test_full_scans_all_ports(self, loader):
        cfg = loader.load("full")
        assert cfg.nmap.port_range == "1-65535"

    def test_quick_no_port_range(self, loader):
        cfg = loader.load("quick")
        assert cfg.nmap.port_range is None

    def test_quick_timing_4(self, loader):
        cfg = loader.load("quick")
        assert cfg.nmap.timing_template == 4

    def test_stealth_timing_1(self, loader):
        cfg = loader.load("stealth")
        assert cfg.nmap.timing_template == 1


# ---------------------------------------------------------------------------
# Report config
# ---------------------------------------------------------------------------


class TestReportConfig:
    def test_quick_markdown_format(self, loader):
        cfg = loader.load("quick")
        assert cfg.report_opts.format == "markdown"

    def test_full_html_format(self, loader):
        cfg = loader.load("full")
        assert cfg.report_opts.format == "html"

    def test_full_executive_summary(self, loader):
        cfg = loader.load("full")
        assert cfg.report_opts.include_executive_summary is True

    def test_quick_no_executive_summary(self, loader):
        cfg = loader.load("quick")
        assert cfg.report_opts.include_executive_summary is False


# ---------------------------------------------------------------------------
# CVE config
# ---------------------------------------------------------------------------


class TestCveConfig:
    def test_api_url_set(self, loader):
        cfg = loader.load("quick")
        assert "nvd.nist.gov" in cfg.cve.api_base_url

    def test_cache_enabled(self, loader):
        cfg = loader.load("quick")
        assert cfg.cve.cache_results is True


# ---------------------------------------------------------------------------
# Unknown profile fallback
# ---------------------------------------------------------------------------


class TestUnknownProfileFallback:
    def test_unknown_profile_falls_back_to_quick(self, loader):
        cfg = loader.load(profile="nonexistent_profile_xyz")
        assert cfg.profile_key == "quick"


# ---------------------------------------------------------------------------
# Pydantic validation
# ---------------------------------------------------------------------------


class TestPydanticValidation:
    def test_timing_template_out_of_range_raises(self):
        from Core.ConfigLoader import NmapConfig

        with pytest.raises(Exception):
            NmapConfig(arguments="-sV", timing_template=6)

    def test_timing_template_zero_ok(self):
        from Core.ConfigLoader import NmapConfig

        cfg = NmapConfig(timing_template=0)
        assert cfg.timing_template == 0
