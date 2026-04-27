"""
Tests/test_threat_scorer.py
============================
Unit tests for Modules/Intelligence/ThreatScorer.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from Core.ConfigLoader import VultronConfig
from Core.Models import (
    HostResult,
    PortResult,
    PortState,
    RiskLevel,
    ScanSession,
    SessionState,
)
from Modules.Intelligence.ThreatScorer import ThreatScorer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config() -> VultronConfig:
    return VultronConfig()


def _make_port(risk: RiskLevel) -> PortResult:
    p = PortResult(port=80, state=PortState.OPEN, service="http")
    p.risk = risk
    return p


def _make_host(ip: str, *port_risks: RiskLevel) -> HostResult:
    host = HostResult(ip=ip, is_alive=True)
    host.ports = [_make_port(r) for r in port_risks]
    return host


def _make_session(*hosts: HostResult) -> ScanSession:
    session = ScanSession(target="192.168.1.0/24", profile="quick")
    session.hosts = list(hosts)
    session.state = SessionState.COMPLETED
    return session


# ---------------------------------------------------------------------------
# Tests: RiskLevel.from_cvss (via ThreatScorer.risk_from_cvss)
# ---------------------------------------------------------------------------


class TestRiskFromCvss:
    """CVSS → RiskLevel mapping boundary tests."""

    @pytest.mark.parametrize(
        "score,expected",
        [
            (0.0, RiskLevel.INFORMATIONAL),
            (0.1, RiskLevel.LOW),
            (3.9, RiskLevel.LOW),
            (4.0, RiskLevel.MEDIUM),
            (6.9, RiskLevel.MEDIUM),
            (7.0, RiskLevel.HIGH),
            (8.9, RiskLevel.HIGH),
            (9.0, RiskLevel.CRITICAL),
            (10.0, RiskLevel.CRITICAL),
        ],
    )
    def test_boundary_scores(self, score: float, expected: RiskLevel):
        assert ThreatScorer.risk_from_cvss(score) == expected


# ---------------------------------------------------------------------------
# Tests: ThreatScorer.score_host
# ---------------------------------------------------------------------------


class TestScoreHost:
    """score_host must return the maximum risk across ports and web findings."""

    def test_no_ports_returns_informational(self):
        scorer = ThreatScorer(config=_make_config())
        host = HostResult(ip="1.2.3.4", is_alive=True)
        assert scorer.score_host(host) == RiskLevel.INFORMATIONAL

    def test_single_port_propagates_risk(self):
        scorer = ThreatScorer(config=_make_config())
        host = _make_host("1.2.3.4", RiskLevel.HIGH)
        assert scorer.score_host(host) == RiskLevel.HIGH

    def test_max_across_multiple_ports(self):
        scorer = ThreatScorer(config=_make_config())
        host = _make_host("1.2.3.4", RiskLevel.LOW, RiskLevel.CRITICAL, RiskLevel.MEDIUM)
        assert scorer.score_host(host) == RiskLevel.CRITICAL

    def test_web_metadata_included_in_scoring(self):
        scorer = ThreatScorer(config=_make_config())
        host = _make_host("1.2.3.4", RiskLevel.LOW)
        host.metadata["web"] = {"highest_risk": RiskLevel.HIGH.value}
        assert scorer.score_host(host) == RiskLevel.HIGH

    def test_invalid_web_risk_ignored(self):
        scorer = ThreatScorer(config=_make_config())
        host = _make_host("1.2.3.4", RiskLevel.MEDIUM)
        host.metadata["web"] = {"highest_risk": "INVALID_LEVEL"}
        # Should not raise; port risk (MEDIUM) should still be returned
        assert scorer.score_host(host) == RiskLevel.MEDIUM


# ---------------------------------------------------------------------------
# Tests: ThreatScorer.score_session
# ---------------------------------------------------------------------------


class TestScoreSession:
    """score_session must return a complete breakdown dict and update host risks."""

    def test_empty_session_returns_zero_counts(self):
        scorer = ThreatScorer(config=_make_config())
        session = _make_session()
        breakdown = scorer.score_session(session)
        for level in RiskLevel:
            assert breakdown[level.value] == 0

    def test_breakdown_counts_hosts_correctly(self):
        scorer = ThreatScorer(config=_make_config())
        h1 = _make_host("1.1.1.1", RiskLevel.CRITICAL)
        h2 = _make_host("1.1.1.2", RiskLevel.HIGH)
        h3 = _make_host("1.1.1.3", RiskLevel.MEDIUM)
        h4 = HostResult(ip="1.1.1.4", is_alive=True)  # no ports → INFO

        session = _make_session(h1, h2, h3, h4)
        breakdown = scorer.score_session(session)

        assert breakdown[RiskLevel.CRITICAL.value] == 1
        assert breakdown[RiskLevel.HIGH.value] == 1
        assert breakdown[RiskLevel.MEDIUM.value] == 1
        assert breakdown[RiskLevel.INFORMATIONAL.value] == 1

    def test_host_risk_updated_in_place(self):
        scorer = ThreatScorer(config=_make_config())
        host = _make_host("1.1.1.1", RiskLevel.CRITICAL)
        host.risk = RiskLevel.INFORMATIONAL  # intentionally wrong starting value

        session = _make_session(host)
        scorer.score_session(session)

        assert host.risk == RiskLevel.CRITICAL

    def test_breakdown_has_all_risk_levels(self):
        scorer = ThreatScorer(config=_make_config())
        session = _make_session()
        breakdown = scorer.score_session(session)
        for level in RiskLevel:
            assert level.value in breakdown
