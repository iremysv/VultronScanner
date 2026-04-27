"""
VultronScanner — Reports/Engine/MarkdownReport.py
=================================================
Git-friendly Markdown security report generator.

Sections
--------
1. Executive Summary (optional — based on profile)
2. Risk Breakdown table
3. Host inventory table
4. Per-host port detail tables
5. Web security findings (if WebAnalyzer ran)
6. Footer (scan metadata)

Usage
-----
    report = MarkdownReport(include_executive_summary=True)
    out = report.generate(session, Path("Reports/Output/scan.md"))
"""

from __future__ import annotations

import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from Core.Models import HostResult, RiskLevel, ScanSession
from Reports.Engine.BaseReport import BaseReport
from Utils.Logger import get_logger

log = get_logger("markdown_report")

# Emoji badges per risk level
_RISK_BADGE: dict[str, str] = {
    RiskLevel.CRITICAL.value: "🔴 CRITICAL",
    RiskLevel.HIGH.value: "🟠 HIGH",
    RiskLevel.MEDIUM.value: "🟡 MEDIUM",
    RiskLevel.LOW.value: "🟢 LOW",
    RiskLevel.INFORMATIONAL.value: "⚪ INFO",
}


class MarkdownReport(BaseReport):
    """
    Produce a structured Markdown security report from a ScanSession.

    Parameters
    ----------
    include_executive_summary :
        If ``True``, prepend a plain-language summary paragraph.
        Defaults to ``False``.
    """

    EXTENSION = ".md"

    def __init__(self, include_executive_summary: bool = False) -> None:
        self._exec_summary = include_executive_summary

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, session: ScanSession, output_path: Path) -> Path:
        """
        Render Markdown and write to *output_path*.

        Returns
        -------
        Path
            Absolute path of the written file.
        """
        self._ensure_parent(output_path)
        lines: List[str] = []

        lines += self._header(session)

        if self._exec_summary:
            lines += self._executive_summary(session)

        lines += self._risk_breakdown(session)
        lines += self._host_inventory(session)

        for host in session.hosts:
            if host.is_alive:
                lines += self._host_detail(host)

        lines += self._footer(session)

        content = "\n".join(lines) + "\n"
        output_path.write_text(content, encoding="utf-8")

        log.info(
            "Markdown report written",
            path=str(output_path),
            hosts=len(session.hosts),
            lines=len(lines),
        )
        return output_path.resolve()

    # ------------------------------------------------------------------
    # Section builders
    # ------------------------------------------------------------------

    @staticmethod
    def _header(session: ScanSession) -> List[str]:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return [
            "# VultronScanner Security Report",
            "",
            f"> **Target:** `{session.target}`  ",
            f"> **Profile:** `{session.profile}`  ",
            f"> **Session:** `{session.session_id}`  ",
            f"> **Generated:** {ts}  ",
            "",
            "---",
            "",
        ]

    @staticmethod
    def _executive_summary(session: ScanSession) -> List[str]:
        alive = len([h for h in session.hosts if h.is_alive])
        open_p = sum(len(h.open_ports()) for h in session.hosts)
        elapsed = session.elapsed_seconds() or 0

        risk_counts = {r.value: 0 for r in RiskLevel}
        for h in session.hosts:
            risk_counts[h.risk.value] += 1

        critical = risk_counts[RiskLevel.CRITICAL.value]
        high = risk_counts[RiskLevel.HIGH.value]

        severity_line = (
            f"The scan identified **{critical} CRITICAL** and **{high} HIGH** severity findings "
            f"that require immediate attention."
            if (critical + high) > 0
            else "No critical or high severity findings were identified."
        )

        return [
            "## Executive Summary",
            "",
            textwrap.dedent(f"""\
                A security assessment was performed against `{session.target}` using the
                `{session.profile}` scan profile. The scan completed in {elapsed:.0f} seconds,
                discovering **{alive} active host(s)** with **{open_p} open port(s)**.
                {severity_line}
            """),
            "---",
            "",
        ]

    @staticmethod
    def _risk_breakdown(session: ScanSession) -> List[str]:
        counts = {r.value: 0 for r in RiskLevel}
        for h in session.hosts:
            counts[h.risk.value] += 1

        lines = [
            "## Risk Breakdown",
            "",
            "| Severity | Hosts |",
            "|----------|-------|",
        ]
        for level in reversed(list(RiskLevel)):
            badge = _RISK_BADGE[level.value]
            lines.append(f"| {badge} | {counts[level.value]} |")

        lines += ["", "---", ""]
        return lines

    @staticmethod
    def _host_inventory(session: ScanSession) -> List[str]:
        lines = [
            "## Host Inventory",
            "",
            "| IP Address | Hostname | OS | Open Ports | Highest Risk |",
            "|------------|----------|----|-----------|--------------|",
        ]
        for host in session.hosts:
            hostname = host.hostname or "—"
            os_guess = host.os_guess or "—"
            open_count = len(host.open_ports())
            badge = _RISK_BADGE[host.risk.value]
            lines.append(f"| `{host.ip}` | {hostname} | {os_guess} | {open_count} | {badge} |")

        lines += ["", "---", ""]
        return lines

    @staticmethod
    def _host_detail(host: HostResult) -> List[str]:
        badge = _RISK_BADGE[host.risk.value]
        lines = [
            f"## Host: `{host.ip}` — {badge}",
            "",
        ]

        if host.hostname:
            lines.append(f"**Hostname:** {host.hostname}  ")
        if host.os_guess:
            lines.append(f"**OS:** {host.os_guess}  ")
        lines.append("")

        # Port table
        if host.ports:
            lines += [
                "### Open Ports",
                "",
                "| Port | Protocol | Service | Version | Risk | Notes |",
                "|------|----------|---------|---------|------|-------|",
            ]
            for p in host.open_ports():
                notes = "; ".join(p.notes[:3]) if p.notes else "—"
                if len(p.notes) > 3:
                    notes += f" *(+{len(p.notes) - 3} more)*"
                lines.append(
                    f"| {p.port} | {p.protocol} | {p.service} | {p.version or '—'} "
                    f"| {_RISK_BADGE[p.risk.value]} | {notes} |"
                )
            lines.append("")

        # Web analysis findings
        web = host.metadata.get("web")
        if web:
            lines += _MarkdownReport_web_section(web)

        lines += ["---", ""]
        return lines

    @staticmethod
    def _footer(session: ScanSession) -> List[str]:
        elapsed = session.elapsed_seconds() or 0
        errors = session.errors
        lines = [
            "## Scan Metadata",
            "",
            "| Key | Value |",
            "|-----|-------|",
            f"| Session ID | `{session.session_id}` |",
            f"| Target | `{session.target}` |",
            f"| Profile | `{session.profile}` |",
            f"| Duration | {elapsed:.1f} seconds |",
            f"| Status | {session.state.value} |",
            f"| Errors | {len(errors)} |",
        ]
        if errors:
            lines += ["", "### Errors", ""]
            for err in errors:
                lines.append(f"- {err}")
        lines += [
            "",
            "---",
            "",
            "*Report generated by [VultronScanner](https://github.com) "
            "· İstinye Üniversitesi · Bilgisayar Mühendisliği*",
        ]
        return lines


# ---------------------------------------------------------------------------
# Module-level helper (avoids nested method name clash)
# ---------------------------------------------------------------------------


def _MarkdownReport_web_section(web: dict) -> List[str]:
    """Render the web security header findings block."""
    lines = [
        "### Web Security Headers",
        "",
        f"**URL:** `{web.get('url', '—')}`  ",
        f"**HTTP Status:** {web.get('status_code', '—')}  ",
        f"**Server:** {web.get('server', '—')}  ",
        "",
    ]

    missing = web.get("missing_headers", [])
    present = web.get("present_headers", [])

    if missing:
        lines += [
            "#### ⚠ Missing Security Headers",
            "",
            "| Header | Risk | Impact |",
            "|--------|------|--------|",
        ]
        for m in missing:
            badge = _RISK_BADGE.get(m["risk"], m["risk"])
            desc = m.get("description", "—")[:80]
            lines.append(f"| `{m['header']}` | {badge} | {desc} |")
        lines.append("")

    if present:
        lines.append("#### ✔ Present Headers: " + ", ".join(f"`{h}`" for h in present))
        lines.append("")

    return lines
