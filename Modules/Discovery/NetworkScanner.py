"""
VultronScanner — Modules/Discovery/NetworkScanner.py
======================================================
python-nmap wrapper for port and service enumeration.

Design
------
- Wraps ``python-nmap`` (``nmap.PortScanner``) behind an async interface
  via ``loop.run_in_executor`` so the blocking scan doesn't stall the event loop
- Reads arguments, timing template, and port range from ``VultronConfig``
- Converts raw nmap XML output → VultronScanner ``HostResult`` / ``PortResult``
- Adds hosts directly to ``SessionManager`` (no duplicate publish needed)
- Publishes ``PORT_DISCOVERED`` events for each open port
- Dry-run mode returns a pre-built mock result (no nmap required)

Usage
-----
    ns = NetworkScanner(bus=bus, config=cfg)
    await ns.run(target="192.168.1.1", session=sm)
"""

from __future__ import annotations

import asyncio
from typing import List, Optional

from Core.ConfigLoader import VultronConfig
from Core.EventBus import EventBus
from Core.Models import (
    EventTopic,
    HostResult,
    PortResult,
    PortState,
    RiskLevel,
    ScanEvent,
)
from Core.SessionManager import SessionManager
from Utils.Logger import get_logger

log = get_logger("network_scanner")

# ---------------------------------------------------------------------------
# Mock scan result for dry-run / testing
# ---------------------------------------------------------------------------

_MOCK_NMAP_DATA = {
    "127.0.0.1": {
        "hostname": "localhost",
        "state":    "up",
        "ports": [
            {"port": 22,  "state": "open",   "name": "ssh",   "version": "OpenSSH 8.9", "cpe": ["cpe:/a:openbsd:openssh:8.9"]},
            {"port": 80,  "state": "open",   "name": "http",  "version": "nginx 1.22",  "cpe": []},
            {"port": 443, "state": "open",   "name": "https", "version": "nginx 1.22",  "cpe": []},
            {"port": 8080,"state": "closed", "name": "http-alt","version": "",           "cpe": []},
        ],
        "os": "Linux 5.x",
    }
}


class NetworkScanner:
    """
    Async wrapper around python-nmap for port/service discovery.

    Parameters
    ----------
    bus :
        EventBus for publishing PORT_DISCOVERED events.
    config :
        Validated VultronConfig (uses nmap section).
    dry_run :
        Return mock data without executing real nmap.
    """

    MODULE_NAME = "NetworkScanner"

    def __init__(
        self,
        bus:     EventBus,
        config:  VultronConfig,
        dry_run: bool = False,
    ) -> None:
        self._bus     = bus
        self._cfg     = config
        self._dry_run = dry_run

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self, target: str, session: SessionManager) -> List[HostResult]:
        """
        Scan *target* and populate *session* with findings.

        Parameters
        ----------
        target :
            IP address, CIDR, or hostname.
        session :
            SessionManager to which HostResult objects are added.

        Returns
        -------
        List[HostResult]
            All discovered host results.
        """
        log.info(
            "Network scan started",
            target   = target,
            profile  = self._cfg.profile_key,
            args     = self._cfg.nmap.arguments,
            dry_run  = self._dry_run,
        )

        if self._dry_run:
            raw_data = _MOCK_NMAP_DATA
        else:
            raw_data = await self._run_nmap(target)

        hosts = []
        for ip, data in raw_data.items():
            host = self._parse_host(ip, data)
            session.add_host(host)
            hosts.append(host)

            # Publish an event per open port
            for port in host.open_ports():
                await self._publish_port(port, ip, session.session_id)

        log.info(
            "Network scan complete",
            hosts_found = len(hosts),
            total_open  = sum(len(h.open_ports()) for h in hosts),
        )
        return hosts

    # ------------------------------------------------------------------
    # Nmap execution
    # ------------------------------------------------------------------

    async def _run_nmap(self, target: str) -> dict:
        """Execute nmap in a thread executor and return parsed dict."""
        try:
            import nmap  # type: ignore
        except ImportError:
            log.error("python-nmap not installed. Install with: pip install python-nmap")
            return {}

        loop     = asyncio.get_event_loop()
        cfg      = self._cfg.nmap
        args     = cfg.arguments
        if cfg.port_range:
            args = f"-p {cfg.port_range} {args}"

        def _scan() -> dict:
            scanner = nmap.PortScanner()
            scanner.scan(hosts=target, arguments=args)
            return self._nmap_to_dict(scanner)

        try:
            raw = await asyncio.wait_for(
                loop.run_in_executor(None, _scan),
                timeout=self._cfg.async_cfg.task_timeout_seconds,
            )
        except asyncio.TimeoutError:
            log.error("Nmap scan timed out", target=target)
            return {}
        except Exception as exc:  # noqa: BLE001
            log.error("Nmap scan failed", target=target, error=str(exc))
            return {}

        return raw

    @staticmethod
    def _nmap_to_dict(scanner) -> dict:
        """Convert nmap.PortScanner object → internal dict format."""
        result: dict = {}
        for host in scanner.all_hosts():
            info = scanner[host]
            ports = []
            for proto in info.all_protocols():
                for port_num in sorted(info[proto].keys()):
                    p = info[proto][port_num]
                    cpe_list = []
                    if "cpe" in p and p["cpe"]:
                        cpe_list = [c for c in p["cpe"].split() if c]
                    ports.append({
                        "port":    port_num,
                        "state":   p.get("state",   "unknown"),
                        "name":    p.get("name",    "unknown"),
                        "version": f"{p.get('product','')} {p.get('version','')}".strip(),
                        "cpe":     cpe_list,
                    })

            hostname = ""
            if info.hostname():
                hostname = info.hostname()

            os_guess = ""
            if "osmatch" in info and info["osmatch"]:
                os_guess = info["osmatch"][0].get("name", "")

            result[host] = {
                "hostname": hostname,
                "state":    info.state(),
                "ports":    ports,
                "os":       os_guess,
            }
        return result

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_host(ip: str, data: dict) -> HostResult:
        """Translate raw scan dict into a HostResult."""
        port_results: List[PortResult] = []
        for p in data.get("ports", []):
            state_str = p.get("state", "closed")
            try:
                state = PortState(state_str)
            except ValueError:
                state = PortState.CLOSED

            pr = PortResult(
                port     = int(p["port"]),
                state    = state,
                service  = p.get("name",    "unknown"),
                version  = p.get("version", ""),
                cpe      = p.get("cpe",     []),
            )
            port_results.append(pr)

        host = HostResult(
            ip       = ip,
            hostname = data.get("hostname") or None,
            is_alive = data.get("state", "") == "up",
            os_guess = data.get("os") or None,
            ports    = port_results,
        )
        host.risk = host.highest_risk()
        return host

    # ------------------------------------------------------------------
    # EventBus publishing
    # ------------------------------------------------------------------

    async def _publish_port(
        self,
        port:       PortResult,
        ip:         str,
        session_id: str,
    ) -> None:
        event = ScanEvent(
            topic      = EventTopic.PORT_DISCOVERED,
            session_id = session_id,
            source     = self.MODULE_NAME,
            payload    = {
                "ip":      ip,
                "port":    port.port,
                "service": port.service,
                "version": port.version,
                "state":   port.state.value,
            },
        )
        await self._bus.publish(event)
        log.debug(
            "Port discovered",
            ip      = ip,
            port    = port.port,
            service = port.service,
            state   = port.state.value,
        )
