"""
Tests/test_PortAnalyzer.py
===========================
Unit tests for Modules/Discovery/PortAnalyzer.

Tests cover:
- Known risky port detection (Telnet, FTP, RDP, Redis, etc.)
- Safe port detection (HTTPS, IMAPS, etc.)
- Port category assignment (WELL_KNOWN / REGISTERED / DYNAMIC)
- Heuristic fallback for unknown ports
- Host-level risk aggregation
- OPEN-only annotation (CLOSED ports should remain INFORMATIONAL)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from Core.ConfigLoader import ConfigLoader
from Core.Models import (
    HostResult,
    PortCategory,
    PortResult,
    PortState,
    RiskLevel,
)
from Modules.Discovery.PortAnalyzer import PortAnalyzer

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def config():
    return ConfigLoader().load(profile="quick")


@pytest.fixture
def analyzer(config):
    return PortAnalyzer(config=config)


def make_port(port: int, state: PortState = PortState.OPEN, service: str = "unknown") -> PortResult:
    return PortResult(port=port, state=state, service=service)


def make_host(*ports: PortResult, ip: str = "192.168.1.1") -> HostResult:
    return HostResult(ip=ip, is_alive=True, ports=list(ports))


# ---------------------------------------------------------------------------
# Port category assignment
# ---------------------------------------------------------------------------


class TestPortCategory:
    """PortResult.__post_init__ should auto-assign IANA category."""

    def test_well_known(self):
        p = make_port(80)
        assert p.category == PortCategory.WELL_KNOWN

    def test_well_known_boundary(self):
        p = make_port(1023)
        assert p.category == PortCategory.WELL_KNOWN

    def test_registered_lower(self):
        p = make_port(1024)
        assert p.category == PortCategory.REGISTERED

    def test_registered_upper(self):
        p = make_port(49151)
        assert p.category == PortCategory.REGISTERED

    def test_dynamic(self):
        p = make_port(49152)
        assert p.category == PortCategory.DYNAMIC

    def test_dynamic_high(self):
        p = make_port(65535)
        assert p.category == PortCategory.DYNAMIC


# ---------------------------------------------------------------------------
# CRITICAL risk ports
# ---------------------------------------------------------------------------


class TestCriticalPorts:
    """Ports that must always be flagged as CRITICAL."""

    @pytest.mark.parametrize("port", [23, 512, 513, 514])
    def test_critical_detection(self, analyzer, port):
        host = make_host(make_port(port))
        analyzer.analyze(host)
        result = host.ports[0]
        assert result.risk == RiskLevel.CRITICAL, f"Port {port} should be CRITICAL"

    def test_telnet_has_note(self, analyzer):
        host = make_host(make_port(23))
        analyzer.analyze(host)
        notes_text = " ".join(host.ports[0].notes)
        assert "Telnet" in notes_text

    def test_telnet_has_remediation(self, analyzer):
        host = make_host(make_port(23))
        analyzer.analyze(host)
        notes_text = " ".join(host.ports[0].notes)
        assert "SSH" in notes_text


# ---------------------------------------------------------------------------
# HIGH risk ports
# ---------------------------------------------------------------------------


class TestHighRiskPorts:
    """Ports that must be flagged as HIGH."""

    @pytest.mark.parametrize("port", [21, 445, 3389, 5900, 6379, 27017])
    def test_high_detection(self, analyzer, port):
        host = make_host(make_port(port))
        analyzer.analyze(host)
        assert host.ports[0].risk == RiskLevel.HIGH, f"Port {port} should be HIGH"

    def test_rdp_note_mentions_nla(self, analyzer):
        host = make_host(make_port(3389))
        analyzer.analyze(host)
        notes_text = " ".join(host.ports[0].notes)
        assert "NLA" in notes_text or "VPN" in notes_text

    def test_redis_unauthenticated_note(self, analyzer):
        host = make_host(make_port(6379))
        analyzer.analyze(host)
        notes_text = " ".join(host.ports[0].notes)
        assert "requirepass" in notes_text or "unauthenticated" in notes_text.lower()


# ---------------------------------------------------------------------------
# MEDIUM risk ports
# ---------------------------------------------------------------------------


class TestMediumRiskPorts:
    @pytest.mark.parametrize("port", [22, 3306, 5432, 8080])
    def test_medium_detection(self, analyzer, port):
        host = make_host(make_port(port))
        analyzer.analyze(host)
        assert host.ports[0].risk == RiskLevel.MEDIUM, f"Port {port} should be MEDIUM"


# ---------------------------------------------------------------------------
# LOW risk ports
# ---------------------------------------------------------------------------


class TestLowRiskPorts:
    @pytest.mark.parametrize("port", [80])
    def test_low_detection(self, analyzer, port):
        host = make_host(make_port(port))
        analyzer.analyze(host)
        assert host.ports[0].risk == RiskLevel.LOW, f"Port {port} should be LOW"


# ---------------------------------------------------------------------------
# Safe / INFORMATIONAL ports
# ---------------------------------------------------------------------------


class TestSafePorts:
    """Known safe ports should remain INFORMATIONAL."""

    @pytest.mark.parametrize("port", [443, 993, 995, 465])
    def test_safe_port_informational(self, analyzer, port):
        host = make_host(make_port(port))
        analyzer.analyze(host)
        assert host.ports[0].risk == RiskLevel.INFORMATIONAL, f"Port {port} should be INFORMATIONAL"


# ---------------------------------------------------------------------------
# Closed ports should NOT be annotated
# ---------------------------------------------------------------------------


class TestClosedPortsSkipped:
    def test_closed_port_stays_informational(self, analyzer):
        port = make_port(23, state=PortState.CLOSED)  # Telnet but CLOSED
        host = make_host(port)
        analyzer.analyze(host)
        assert host.ports[0].risk == RiskLevel.INFORMATIONAL

    def test_filtered_port_stays_informational(self, analyzer):
        port = make_port(3389, state=PortState.FILTERED)  # RDP but FILTERED
        host = make_host(port)
        analyzer.analyze(host)
        assert host.ports[0].risk == RiskLevel.INFORMATIONAL


# ---------------------------------------------------------------------------
# Host risk aggregation
# ---------------------------------------------------------------------------


class TestHostRiskAggregation:
    def test_host_risk_matches_highest_port(self, analyzer):
        host = make_host(
            make_port(443),  # INFORMATIONAL
            make_port(80),  # LOW
            make_port(3389),  # HIGH
        )
        analyzer.analyze(host)
        assert host.risk == RiskLevel.HIGH

    def test_host_with_critical_port(self, analyzer):
        host = make_host(
            make_port(443),
            make_port(23),  # CRITICAL
        )
        analyzer.analyze(host)
        assert host.risk == RiskLevel.CRITICAL

    def test_empty_host_stays_informational(self, analyzer):
        host = make_host()  # no ports
        analyzer.analyze(host)
        assert host.risk == RiskLevel.INFORMATIONAL

    def test_all_closed_ports(self, analyzer):
        host = make_host(
            make_port(23, state=PortState.CLOSED),
            make_port(3389, state=PortState.CLOSED),
        )
        analyzer.analyze(host)
        assert host.risk == RiskLevel.INFORMATIONAL


# ---------------------------------------------------------------------------
# Heuristic fallback
# ---------------------------------------------------------------------------


class TestHeuristicFallback:
    def test_dynamic_unknown_port_informational(self, analyzer):
        host = make_host(make_port(60000, service="unknown"))
        analyzer.analyze(host)
        assert host.ports[0].risk == RiskLevel.INFORMATIONAL

    def test_registered_unknown_port_low(self, analyzer):
        host = make_host(make_port(12345, service="unknown"))
        analyzer.analyze(host)
        assert host.ports[0].risk == RiskLevel.LOW

    def test_admin_keyword_in_service_flags_high(self, analyzer):
        host = make_host(make_port(12345, service="admin-panel"))
        analyzer.analyze(host)
        assert host.ports[0].risk == RiskLevel.HIGH

    def test_debug_keyword_in_service_flags_high(self, analyzer):
        host = make_host(make_port(9000, service="debug-interface"))
        analyzer.analyze(host)
        assert host.ports[0].risk == RiskLevel.HIGH
