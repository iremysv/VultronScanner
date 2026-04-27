"""
Tests/test_web_analyzer.py
==========================
Unit tests for Modules/Intelligence/WebAnalyzer.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from Core.ConfigLoader import VultronConfig
from Core.EventBus import EventBus
from Core.Models import HostResult, RiskLevel
from Modules.Intelligence.WebAnalyzer import SECURITY_HEADERS, WebAnalyzer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config() -> VultronConfig:
    return VultronConfig()


def _make_host(ip: str = "127.0.0.1") -> HostResult:
    return HostResult(ip=ip, is_alive=True)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestWebAnalyzerDryRun:
    """WebAnalyzer in dry_run mode must not make real HTTP calls."""

    @pytest.mark.asyncio
    async def test_dry_run_injects_mock_result(self):
        bus = EventBus()
        cfg = _make_config()
        analyzer = WebAnalyzer(bus=bus, config=cfg, dry_run=True)
        host = _make_host()

        await analyzer.analyze_host(host, session_id="test-session")

        assert "web" in host.metadata
        web = host.metadata["web"]
        assert isinstance(web["missing_headers"], list)
        assert isinstance(web["present_headers"], list)
        assert "highest_risk" in web

    @pytest.mark.asyncio
    async def test_dry_run_url_uses_host_ip(self):
        bus = EventBus()
        cfg = _make_config()
        analyzer = WebAnalyzer(bus=bus, config=cfg, dry_run=True)
        host = _make_host(ip="10.0.0.1")

        await analyzer.analyze_host(host, session_id="test-session")

        assert host.metadata["web"]["url"] == "http://10.0.0.1"

    @pytest.mark.asyncio
    async def test_dry_run_escalates_host_risk(self):
        bus = EventBus()
        cfg = _make_config()
        analyzer = WebAnalyzer(bus=bus, config=cfg, dry_run=True)
        host = _make_host()
        # Default host risk is INFORMATIONAL — web findings should escalate it
        assert host.risk == RiskLevel.INFORMATIONAL

        await analyzer.analyze_host(host, session_id="test-session")

        # Mock result has MEDIUM highest_risk — host risk must be >= MEDIUM
        risk_order = list(RiskLevel)
        assert risk_order.index(host.risk) >= risk_order.index(RiskLevel.MEDIUM)

    @pytest.mark.asyncio
    async def test_analyze_all_skips_dead_hosts(self):
        bus = EventBus()
        cfg = _make_config()
        analyzer = WebAnalyzer(bus=bus, config=cfg, dry_run=True)
        alive = _make_host("192.168.1.1")
        dead = HostResult(ip="192.168.1.2", is_alive=False)

        await analyzer.analyze_all([alive, dead], session_id="sess")

        assert "web" in alive.metadata
        assert "web" not in dead.metadata


class TestWebAnalyzerHeaderParsing:
    """Test the _parse_headers static method in isolation."""

    def test_all_headers_missing(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html"}

        result = WebAnalyzer._parse_headers("http://test.local", mock_response)

        assert len(result["missing_headers"]) == len(SECURITY_HEADERS)
        assert result["present_headers"] == []
        assert result["highest_risk"] == RiskLevel.HIGH.value  # HSTS missing = HIGH

    def test_all_headers_present(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {h.lower(): "value" for h in SECURITY_HEADERS}

        result = WebAnalyzer._parse_headers("http://test.local", mock_response)

        assert result["missing_headers"] == []
        assert len(result["present_headers"]) == len(SECURITY_HEADERS)
        assert result["highest_risk"] == RiskLevel.INFORMATIONAL.value

    def test_partial_headers(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "strict-transport-security": "max-age=31536000",
            "x-frame-options": "DENY",
        }

        result = WebAnalyzer._parse_headers("https://test.local", mock_response)

        present_headers = [h.lower() for h in result["present_headers"]]
        assert "Strict-Transport-Security".lower() in present_headers
        # CSP missing → risk should be at least MEDIUM
        risk_order = list(RiskLevel)
        assert risk_order.index(RiskLevel(result["highest_risk"])) >= risk_order.index(
            RiskLevel.MEDIUM
        )
