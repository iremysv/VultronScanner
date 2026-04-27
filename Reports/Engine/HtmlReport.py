"""
VultronScanner — Reports/Engine/HtmlReport.py
=============================================
Executive-facing visual HTML security report.

Features
--------
- Inline CSS (no external dependencies — works offline)
- Risk severity badge cards (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Color-coded host and port tables
- Web security header findings panel
- Dark-themed, professional layout

Usage
-----
    report = HtmlReport()
    out = report.generate(session, Path("Reports/Output/scan.html"))
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

from Core.Models import HostResult, RiskLevel, ScanSession
from Reports.Engine.BaseReport import BaseReport
from Utils.Logger import get_logger

log = get_logger("html_report")

# ---------------------------------------------------------------------------
# Risk color palette
# ---------------------------------------------------------------------------

_RISK_COLORS: dict[str, dict[str, str]] = {
    RiskLevel.CRITICAL.value: {"bg": "#7c0909", "text": "#fff", "border": "#ff2d2d"},
    RiskLevel.HIGH.value: {"bg": "#8b3a00", "text": "#fff", "border": "#ff6b00"},
    RiskLevel.MEDIUM.value: {"bg": "#7a6200", "text": "#fff", "border": "#ffd000"},
    RiskLevel.LOW.value: {"bg": "#1a4d1a", "text": "#fff", "border": "#4caf50"},
    RiskLevel.INFORMATIONAL.value: {"bg": "#1a2a3a", "text": "#ccc", "border": "#4a8ab5"},
}

_CSS = """
:root {
  --bg: #0d1117;
  --surface: #161b22;
  --surface2: #21262d;
  --border: #30363d;
  --text: #e6edf3;
  --text-muted: #8b949e;
  --accent: #58a6ff;
  --font: 'Segoe UI', system-ui, -apple-system, sans-serif;
  --mono: 'Cascadia Code', 'Fira Code', monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: var(--font);
       line-height: 1.6; padding: 2rem; }
.container { max-width: 1100px; margin: 0 auto; }
header { border-bottom: 2px solid var(--accent); padding-bottom: 1.5rem; margin-bottom: 2rem; }
h1 { font-size: 2rem; color: var(--accent); margin-bottom: .5rem; }
h2 { font-size: 1.25rem; color: var(--accent); margin: 2rem 0 1rem; border-left: 4px solid var(--accent);
     padding-left: .75rem; }
h3 { font-size: 1rem; color: var(--text-muted); margin: 1rem 0 .5rem; }
.meta { font-size: .85rem; color: var(--text-muted); }
.meta span { color: var(--text); }
.cards { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
.card { flex: 1; min-width: 120px; border-radius: 8px; padding: 1rem 1.25rem;
        border: 1px solid; text-align: center; }
.card .count { font-size: 2rem; font-weight: 700; }
.card .label { font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; margin-top: .25rem; }
table { width: 100%; border-collapse: collapse; font-size: .875rem; margin-bottom: 1.5rem; }
th { background: var(--surface2); color: var(--text-muted); text-align: left;
     padding: .6rem .8rem; font-weight: 600; border-bottom: 1px solid var(--border); }
td { padding: .55rem .8rem; border-bottom: 1px solid var(--border); vertical-align: top; }
tr:hover td { background: var(--surface2); }
.badge { display: inline-block; border-radius: 4px; padding: .15rem .5rem;
         font-size: .75rem; font-weight: 600; }
code { font-family: var(--mono); background: var(--surface2); padding: .1rem .35rem;
       border-radius: 3px; font-size: .85em; color: var(--accent); }
.host-block { background: var(--surface); border: 1px solid var(--border);
              border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
.present-headers { color: #4caf50; font-size: .85rem; }
footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border);
         font-size: .8rem; color: var(--text-muted); text-align: center; }
"""


class HtmlReport(BaseReport):
    """
    Generate a self-contained, dark-themed HTML security report.

    Parameters
    ----------
    include_executive_summary :
        Prepend a plain-language summary paragraph.
    """

    EXTENSION = ".html"

    def __init__(self, include_executive_summary: bool = True) -> None:
        self._exec_summary = include_executive_summary

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, session: ScanSession, output_path: Path) -> Path:
        """Write HTML report to *output_path* and return its absolute path."""
        self._ensure_parent(output_path)
        html = self._render(session)
        output_path.write_text(html, encoding="utf-8")
        log.info("HTML report written", path=str(output_path), hosts=len(session.hosts))
        return output_path.resolve()

    # ------------------------------------------------------------------
    # Renderer
    # ------------------------------------------------------------------

    def _render(self, session: ScanSession) -> str:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        elapsed = session.elapsed_seconds() or 0
        alive_hosts = [h for h in session.hosts if h.is_alive]
        open_ports_total = sum(len(h.open_ports()) for h in alive_hosts)

        # Risk counts
        risk_counts = {r.value: 0 for r in RiskLevel}
        for h in session.hosts:
            risk_counts[h.risk.value] += 1

        parts: List[str] = [
            "<!DOCTYPE html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="UTF-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1.0">',
            f"<title>VultronScanner — {session.target}</title>",
            f"<style>{_CSS}</style>",
            "</head>",
            '<body><div class="container">',
            self._header_block(session, ts, elapsed, alive_hosts, open_ports_total),
        ]

        if self._exec_summary:
            parts.append(self._exec_summary_block(session, alive_hosts, open_ports_total, elapsed))

        parts.append(self._risk_cards(risk_counts))
        parts.append(self._host_inventory_table(session))

        for host in alive_hosts:
            parts.append(self._host_block(host))

        parts.append(self._footer_block(session))
        parts.append("</div></body></html>")

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Section renderers
    # ------------------------------------------------------------------

    @staticmethod
    def _header_block(
        session: ScanSession,
        ts: str,
        elapsed: float,
        alive_hosts: list,
        open_ports: int,
    ) -> str:
        return f"""
<header>
  <h1>🔍 VultronScanner Security Report</h1>
  <div class="meta">
    <b>Target:</b> <code>{session.target}</code> &nbsp;|&nbsp;
    <b>Profile:</b> <code>{session.profile}</code> &nbsp;|&nbsp;
    <b>Session:</b> <code>{session.session_id[:16]}…</code><br>
    <b>Generated:</b> <span>{ts}</span> &nbsp;|&nbsp;
    <b>Duration:</b> <span>{elapsed:.1f}s</span> &nbsp;|&nbsp;
    <b>Alive Hosts:</b> <span>{len(alive_hosts)}</span> &nbsp;|&nbsp;
    <b>Open Ports:</b> <span>{open_ports}</span>
  </div>
</header>"""

    @staticmethod
    def _exec_summary_block(
        session: ScanSession,
        alive_hosts: list,
        open_ports: int,
        elapsed: float,
    ) -> str:
        risk_counts = {r.value: 0 for r in RiskLevel}
        for h in session.hosts:
            risk_counts[h.risk.value] += 1
        critical = risk_counts[RiskLevel.CRITICAL.value]
        high = risk_counts[RiskLevel.HIGH.value]

        severity_line = (
            f"<b>{critical} CRITICAL</b> and <b>{high} HIGH</b> severity findings require immediate attention."
            if (critical + high) > 0
            else "No critical or high severity findings were identified."
        )

        return f"""
<h2>Executive Summary</h2>
<p>A security assessment was performed against <code>{session.target}</code> using the
<code>{session.profile}</code> scan profile. The scan completed in <b>{elapsed:.0f} seconds</b>,
discovering <b>{len(alive_hosts)} active host(s)</b> with <b>{open_ports} open port(s)</b>.
{severity_line}</p>"""

    @staticmethod
    def _risk_cards(risk_counts: dict) -> str:
        cards = '<h2>Risk Breakdown</h2><div class="cards">'
        for level in reversed(list(RiskLevel)):
            c = _RISK_COLORS[level.value]
            count = risk_counts.get(level.value, 0)
            cards += (
                f'<div class="card" style="background:{c["bg"]};border-color:{c["border"]};color:{c["text"]}">'
                f'<div class="count">{count}</div>'
                f'<div class="label">{level.value}</div>'
                f"</div>"
            )
        cards += "</div>"
        return cards

    @staticmethod
    def _badge(risk_value: str) -> str:
        c = _RISK_COLORS.get(risk_value, _RISK_COLORS[RiskLevel.INFORMATIONAL.value])
        return (
            f'<span class="badge" style="background:{c["bg"]};color:{c["text"]};'
            f'border:1px solid {c["border"]}">{risk_value}</span>'
        )

    def _host_inventory_table(self, session: ScanSession) -> str:
        rows = ""
        for host in session.hosts:
            rows += (
                f"<tr><td><code>{host.ip}</code></td>"
                f"<td>{host.hostname or '—'}</td>"
                f"<td>{host.os_guess or '—'}</td>"
                f"<td>{len(host.open_ports())}</td>"
                f"<td>{'✔ Alive' if host.is_alive else '✗ Dead'}</td>"
                f"<td>{self._badge(host.risk.value)}</td></tr>"
            )
        return f"""
<h2>Host Inventory</h2>
<table>
  <tr><th>IP</th><th>Hostname</th><th>OS</th><th>Open Ports</th><th>State</th><th>Risk</th></tr>
  {rows}
</table>"""

    def _host_block(self, host: HostResult) -> str:
        port_rows = ""
        for p in host.open_ports():
            notes = "; ".join(p.notes[:3]) or "—"
            port_rows += (
                f"<tr><td>{p.port}/{p.protocol}</td>"
                f"<td>{p.service}</td>"
                f"<td>{p.version or '—'}</td>"
                f"<td>{self._badge(p.risk.value)}</td>"
                f"<td style='font-size:.8rem'>{notes}</td></tr>"
            )

        port_table = ""
        if port_rows:
            port_table = f"""
<h3>Open Ports</h3>
<table>
  <tr><th>Port</th><th>Service</th><th>Version</th><th>Risk</th><th>CVE Notes</th></tr>
  {port_rows}
</table>"""

        web_section = self._web_panel(host.metadata.get("web"))

        return f"""
<div class="host-block">
  <h2>Host: <code>{host.ip}</code> — {self._badge(host.risk.value)}</h2>
  {f'<div class="meta"><b>Hostname:</b> {host.hostname}</div>' if host.hostname else ''}
  {f'<div class="meta"><b>OS:</b> {host.os_guess}</div>' if host.os_guess else ''}
  {port_table}
  {web_section}
</div>"""

    def _web_panel(self, web: dict | None) -> str:
        if not web:
            return ""

        missing = web.get("missing_headers", [])
        present = web.get("present_headers", [])

        missing_rows = ""
        for m in missing:
            missing_rows += (
                f"<tr><td><code>{m['header']}</code></td>"
                f"<td>{self._badge(m['risk'])}</td>"
                f"<td style='font-size:.8rem'>{m.get('description','')[:90]}</td></tr>"
            )

        present_str = ", ".join(f"<code>{h}</code>" for h in present)

        missing_table = (
            f"""<h3>⚠ Missing Security Headers</h3>
<table>
  <tr><th>Header</th><th>Risk</th><th>Impact</th></tr>
  {missing_rows}
</table>"""
            if missing_rows
            else "<p>All checked security headers are present. ✔</p>"
        )

        return f"""
<h3>Web Security Analysis — <code>{web.get('url','')}</code></h3>
<div class="meta">HTTP {web.get('status_code','—')} · Server: {web.get('server','—')}</div>
{missing_table}
<p class="present-headers">✔ Present: {present_str}</p>"""

    @staticmethod
    def _footer_block(session: ScanSession) -> str:
        elapsed = session.elapsed_seconds() or 0
        errors_html = ""
        if session.errors:
            items = "".join(f"<li>{e}</li>" for e in session.errors)
            errors_html = f"<h2>Errors</h2><ul>{items}</ul>"
        return f"""
{errors_html}
<footer>
  VultronScanner · İstinye Üniversitesi · Bilgisayar Mühendisliği &nbsp;|&nbsp;
  Session: <code>{session.session_id}</code> &nbsp;|&nbsp;
  Duration: {elapsed:.1f}s &nbsp;|&nbsp; Status: {session.state.value}
</footer>"""
