"""
Tests/test_report_markdown.py
==============================
Unit tests for Reports/Engine/MarkdownReport.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from Core.Models import (
    HostResult,
    PortResult,
    PortState,
    RiskLevel,
    ScanSession,
    SessionState,
)
from Reports.Engine.MarkdownReport import MarkdownReport


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_session() -> ScanSession:
    """Build a realistic dummy ScanSession for testing."""
    session = ScanSession(target="192.168.1.100", profile="web")
    session.state = SessionState.COMPLETED
    session.started_at = datetime(2026, 4, 27, 9, 0, 0, tzinfo=timezone.utc)
    session.completed_at = datetime(2026, 4, 27, 9, 0, 45, tzinfo=timezone.utc)

    host = HostResult(
        ip="192.168.1.100",
        hostname="target.local",
        is_alive=True,
        os_guess="Linux 5.x",
    )
    port_ssh = PortResult(port=22, state=PortState.OPEN, service="ssh", version="OpenSSH 8.9")
    port_ssh.risk = RiskLevel.HIGH
    port_ssh.notes = ["CVE-2023-38408 (CVSS: 9.8 — CRITICAL)"]

    port_http = PortResult(port=80, state=PortState.OPEN, service="http", version="nginx 1.22")
    port_http.risk = RiskLevel.MEDIUM

    host.ports = [port_ssh, port_http]
    host.risk = RiskLevel.HIGH
    host.metadata["web"] = {
        "url": "http://192.168.1.100",
        "status_code": 200,
        "server": "nginx/1.22",
        "missing_headers": [
            {
                "header": "Content-Security-Policy",
                "risk": RiskLevel.MEDIUM.value,
                "description": "CSP mitigates XSS attacks.",
            }
        ],
        "present_headers": ["Strict-Transport-Security", "X-Frame-Options"],
        "highest_risk": RiskLevel.MEDIUM.value,
    }

    session.hosts = [host]
    return session


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMarkdownReportGenerate:
    """MarkdownReport.generate() must create a valid markdown file."""

    def test_file_is_created(self, tmp_path: Path):
        report = MarkdownReport()
        session = _build_session()
        out = report.generate(session, tmp_path / "scan.md")

        assert out.exists()
        assert out.suffix == ".md"

    def test_file_contains_target(self, tmp_path: Path):
        report = MarkdownReport()
        session = _build_session()
        out = report.generate(session, tmp_path / "scan.md")

        content = out.read_text(encoding="utf-8")
        assert "192.168.1.100" in content

    def test_file_contains_host_ip(self, tmp_path: Path):
        report = MarkdownReport()
        session = _build_session()
        out = report.generate(session, tmp_path / "scan.md")

        content = out.read_text(encoding="utf-8")
        assert "192.168.1.100" in content

    def test_file_contains_port_info(self, tmp_path: Path):
        report = MarkdownReport()
        session = _build_session()
        out = report.generate(session, tmp_path / "scan.md")

        content = out.read_text(encoding="utf-8")
        assert "ssh" in content
        assert "OpenSSH" in content

    def test_file_contains_cve_notes(self, tmp_path: Path):
        report = MarkdownReport()
        session = _build_session()
        out = report.generate(session, tmp_path / "scan.md")

        content = out.read_text(encoding="utf-8")
        assert "CVE-2023-38408" in content

    def test_file_contains_web_findings(self, tmp_path: Path):
        report = MarkdownReport()
        session = _build_session()
        out = report.generate(session, tmp_path / "scan.md")

        content = out.read_text(encoding="utf-8")
        assert "Content-Security-Policy" in content

    def test_executive_summary_included_when_requested(self, tmp_path: Path):
        report = MarkdownReport(include_executive_summary=True)
        session = _build_session()
        out = report.generate(session, tmp_path / "scan.md")

        content = out.read_text(encoding="utf-8")
        assert "Executive Summary" in content

    def test_executive_summary_excluded_by_default(self, tmp_path: Path):
        report = MarkdownReport(include_executive_summary=False)
        session = _build_session()
        out = report.generate(session, tmp_path / "scan.md")

        content = out.read_text(encoding="utf-8")
        assert "Executive Summary" not in content

    def test_parent_dir_created_automatically(self, tmp_path: Path):
        report = MarkdownReport()
        session = _build_session()
        nested = tmp_path / "deep" / "nested" / "scan.md"

        out = report.generate(session, nested)
        assert out.exists()

    def test_risk_breakdown_section_present(self, tmp_path: Path):
        report = MarkdownReport()
        session = _build_session()
        out = report.generate(session, tmp_path / "scan.md")

        content = out.read_text(encoding="utf-8")
        assert "Risk Breakdown" in content

    def test_returns_absolute_path(self, tmp_path: Path):
        report = MarkdownReport()
        session = _build_session()
        out = report.generate(session, tmp_path / "scan.md")

        assert out.is_absolute()
