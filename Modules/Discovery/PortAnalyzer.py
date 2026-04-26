"""
VultronScanner — Modules/Discovery/PortAnalyzer.py
====================================================
Risk categorization and annotation of discovered ports.

Responsibilities
----------------
- Assign ``PortCategory`` (WELL_KNOWN / REGISTERED / DYNAMIC) to each port
- Detect risky services (Telnet, FTP, RDP, unauth databases, etc.)
- Assign ``RiskLevel`` to each port based on service risk + port number
- Add human-readable ``notes`` explaining why a port is risky
- Update ``HostResult.risk`` to reflect the highest port-level risk
- Operates in-place on ``HostResult`` objects after NetworkScanner finishes

Risk Scoring Logic
------------------
CRITICAL:       Port in CRITICAL_RISK_PORTS set
HIGH:           Port in HIGH_RISK_PORTS set
MEDIUM:         Common registered port (database, monitoring, etc.)
LOW:            Known but not high-risk service
INFORMATIONAL:  Everything else (HTTPS, well-configured SSH, etc.)

Usage
-----
    pa = PortAnalyzer(config=cfg)
    pa.analyze(host_result)
    # host_result.ports now have .risk and .notes populated
"""

from __future__ import annotations

from typing import Dict, List, Set, Tuple

from Core.ConfigLoader import VultronConfig
from Core.Models import HostResult, PortCategory, PortResult, PortState, RiskLevel
from Utils.Logger import get_logger

log = get_logger("port_analyzer")

# ---------------------------------------------------------------------------
# Risk port tables
# ---------------------------------------------------------------------------

# Port → (RiskLevel, description, remediation_hint)
_PORT_RISK_DB: Dict[int, Tuple[RiskLevel, str, str]] = {
    # ── CRITICAL ──────────────────────────────────────────────────────────
    23:    (RiskLevel.CRITICAL, "Telnet — plaintext credential transmission",
            "Disable Telnet immediately; replace with SSH."),
    512:   (RiskLevel.CRITICAL, "rexec — legacy remote execution (no encryption)",
            "Block port 512. Use SSH for remote execution."),
    513:   (RiskLevel.CRITICAL, "rlogin — legacy remote login (no encryption)",
            "Block port 513. Migrate to SSH."),
    514:   (RiskLevel.CRITICAL, "rsh — remote shell (no authentication/encryption)",
            "Block port 514. Use SSH with key-based auth."),
    # ── HIGH ──────────────────────────────────────────────────────────────
    21:    (RiskLevel.HIGH, "FTP — plaintext file transfer",
            "Upgrade to SFTP or FTPS; disable anonymous FTP."),
    25:    (RiskLevel.HIGH, "SMTP without AUTH — potential open relay",
            "Require SMTP AUTH; disable unauthenticated relay."),
    53:    (RiskLevel.HIGH, "DNS — exposed to enumeration / amplification",
            "Restrict recursive queries; implement DNSSEC."),
    111:   (RiskLevel.HIGH, "RPCbind — exposes RPC services",
            "Block port 111 externally; disable unnecessary RPC services."),
    135:   (RiskLevel.HIGH, "MS-RPC endpoint mapper",
            "Block port 135 at perimeter firewall."),
    137:   (RiskLevel.HIGH, "NetBIOS Name Service",
            "Disable NetBIOS over TCP/IP if not required."),
    139:   (RiskLevel.HIGH, "NetBIOS Session Service",
            "Disable NetBIOS; use SMB over port 445 only with signing enforced."),
    445:   (RiskLevel.HIGH, "SMB — high-value ransomware target (EternalBlue, WannaCry)",
            "Apply all patches; enforce SMB signing; block externally."),
    2049:  (RiskLevel.HIGH, "NFS — potential unauthenticated filesystem access",
            "Restrict exports to known IPs; use NFSv4 with Kerberos."),
    3389:  (RiskLevel.HIGH, "RDP — brute-force and BlueKeep exposure",
            "Disable if unused; set NLA; restrict to VPN only."),
    5900:  (RiskLevel.HIGH, "VNC — often unauthenticated or weakly secured",
            "Require strong passwords; tunnel over SSH; disable if unused."),
    6379:  (RiskLevel.HIGH, "Redis — often unauthenticated in default config",
            "Enable requirepass; bind to 127.0.0.1; add firewall rules."),
    27017: (RiskLevel.HIGH, "MongoDB — unauthenticated access in default config",
            "Enable authentication; bind to localhost; update to latest version."),
    # ── MEDIUM ────────────────────────────────────────────────────────────
    22:    (RiskLevel.MEDIUM, "SSH — brute-force risk if password auth enabled",
            "Enforce key-based auth; disable PasswordAuthentication."),
    110:   (RiskLevel.MEDIUM, "POP3 — plaintext email retrieval",
            "Enforce POP3S (port 995); disable plain POP3."),
    143:   (RiskLevel.MEDIUM, "IMAP — plaintext email retrieval",
            "Enforce IMAPS (port 993); disable plain IMAP."),
    161:   (RiskLevel.MEDIUM, "SNMP v1/v2c — community string exposure",
            "Upgrade to SNMPv3 with authentication and privacy."),
    1433:  (RiskLevel.MEDIUM, "MSSQL — exposed database port",
            "Block externally; use Windows Authentication; apply patches."),
    1521:  (RiskLevel.MEDIUM, "Oracle DB — exposed database port",
            "Block externally; enforce strong passwords; apply patches."),
    3306:  (RiskLevel.MEDIUM, "MySQL — exposed database port",
            "Bind to 127.0.0.1 unless remote access needed; use strong creds."),
    5432:  (RiskLevel.MEDIUM, "PostgreSQL — exposed database port",
            "Restrict pg_hba.conf; bind to localhost; use SSL."),
    8080:  (RiskLevel.MEDIUM, "HTTP alternate — potential dev/admin interface",
            "Remove or secure; ensure no admin panel is exposed."),
    8443:  (RiskLevel.MEDIUM, "HTTPS alternate — potential admin interface",
            "Restrict access; verify certificate validity."),
    # ── LOW ───────────────────────────────────────────────────────────────
    80:    (RiskLevel.LOW, "HTTP — unencrypted web traffic",
            "Redirect all HTTP to HTTPS; implement HSTS."),
    8000:  (RiskLevel.LOW, "HTTP dev server — possibly exposed development environment",
            "Ensure not exposed in production."),
    8888:  (RiskLevel.LOW, "HTTP alternate / Jupyter Notebook",
            "Secure Jupyter with password/token; never expose publicly."),
}

# Ports that are generally safe (INFORMATIONAL)
_SAFE_PORTS: Set[int] = {443, 993, 995, 465, 587, 636, 5061}


class PortAnalyzer:
    """
    Annotates PortResult objects with risk levels and remediation notes.

    Parameters
    ----------
    config :
        VultronConfig (used for CVSS thresholds in future scoring extension).
    """

    def __init__(self, config: VultronConfig) -> None:
        self._cfg = config

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, host: HostResult) -> HostResult:
        """
        Annotate all ports on *host* in-place.

        Returns the same HostResult for chaining.
        """
        for port in host.ports:
            if port.state != PortState.OPEN:
                continue
            self._annotate_port(port)

        # Lift host risk to the highest port risk
        host.risk = host.highest_risk()

        open_ports = host.open_ports()
        log.debug(
            "Host analyzed",
            ip         = host.ip,
            open_ports = len(open_ports),
            host_risk  = host.risk.value,
        )
        return host

    def analyze_many(self, hosts: List[HostResult]) -> List[HostResult]:
        """Convenience wrapper to analyze a list of hosts."""
        for host in hosts:
            self.analyze(host)
        return hosts

    # ------------------------------------------------------------------
    # Port annotation
    # ------------------------------------------------------------------

    def _annotate_port(self, port: PortResult) -> None:
        """Assign risk level and notes to a single open PortResult."""
        if port.port in _PORT_RISK_DB:
            risk_level, reason, remediation = _PORT_RISK_DB[port.port]
            port.risk = risk_level
            if reason not in port.notes:
                port.notes.append(f"⚠ {reason}")
            if remediation not in port.notes:
                port.notes.append(f"💡 {remediation}")

        elif port.port in _SAFE_PORTS:
            port.risk = RiskLevel.INFORMATIONAL

        else:
            # Unknown port — apply heuristic based on category
            port.risk = self._heuristic_risk(port)

        log.trace(
            "Port annotated",
            port    = port.port,
            service = port.service,
            risk    = port.risk.value,
        )

    @staticmethod
    def _heuristic_risk(port: PortResult) -> RiskLevel:
        """
        Fallback heuristic for ports not in the database.

        Logic:
        - Dynamic ports (>49151) with unknown service → INFORMATIONAL
        - Registered ports (1024-49151) → LOW unless service name suggests DB/admin
        - Well-known ports (0-1023) not in DB → LOW (anomalous)
        """
        high_signal_keywords = {
            "admin", "mgmt", "management", "backdoor",
            "debug", "shell", "exec", "telnet",
        }
        service_lower = port.service.lower()

        if any(kw in service_lower for kw in high_signal_keywords):
            note = f"⚠ Service name '{port.service}' suggests elevated risk"
            if note not in port.notes:
                port.notes.append(note)
            return RiskLevel.HIGH

        if port.category == PortCategory.DYNAMIC:
            return RiskLevel.INFORMATIONAL

        if port.category == PortCategory.REGISTERED:
            return RiskLevel.LOW

        # WELL_KNOWN but not in DB → unexpected, flag as LOW
        return RiskLevel.LOW
