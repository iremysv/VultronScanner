"""
VultronScanner — Modules/Discovery/HostDiscovery.py
=====================================================
ICMP ping sweep to determine which hosts are alive.

Design
------
- Uses ``asyncio.create_subprocess_exec`` to run system ping
  → no root privilege required for ICMP echo on macOS/Linux with ping binary
- Sweeps all hosts in a CIDR range or single IP concurrently
- Respects ``config.async_cfg.max_concurrent_tasks`` semaphore
- Publishes ``HOST_ALIVE`` or ``HOST_DEAD`` events to EventBus
- Dry-run mode skips real network calls (for testing)

Usage
-----
    hd = HostDiscovery(bus=bus, config=cfg)
    await hd.run("192.168.1.0/24")
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import List, Optional

from Core.ConfigLoader import VultronConfig
from Core.EventBus import EventBus
from Core.Models import EventTopic, ScanEvent
from Utils.Logger import get_logger

log = get_logger("host_discovery")

# Riskli servisler — PortAnalyzer tarafından da kullanılır
RISKY_SERVICES: dict[int, str] = {
    21:   "FTP",
    23:   "Telnet",
    25:   "SMTP (unauthenticated)",
    111:  "RPCbind",
    135:  "MS-RPC",
    137:  "NetBIOS",
    139:  "NetBIOS",
    445:  "SMB",
    512:  "rexec",
    513:  "rlogin",
    514:  "rsh",
    1433: "MSSQL",
    1521: "Oracle DB",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis (unauthenticated)",
    27017:"MongoDB (unauthenticated)",
}


class HostDiscovery:
    """
    Concurrent ICMP ping sweep over a target range.

    Parameters
    ----------
    bus :
        EventBus instance for publishing results.
    config :
        Validated VultronConfig (uses network + async sections).
    dry_run :
        Skip real pings; treat 127.0.0.1 as alive for testing.
    """

    MODULE_NAME = "HostDiscovery"

    def __init__(
        self,
        bus:     EventBus,
        config:  VultronConfig,
        dry_run: bool = False,
    ) -> None:
        self._bus     = bus
        self._cfg     = config
        self._dry_run = dry_run
        self._sem     = asyncio.Semaphore(config.async_cfg.max_concurrent_tasks)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self, target: str) -> List[str]:
        """
        Sweep *target* (single IP or CIDR) and return list of alive IPs.

        Parameters
        ----------
        target :
            e.g. ``"192.168.1.0/24"``, ``"10.0.0.1"``, ``"scanme.nmap.org"``
        """
        hosts = self._expand_target(target)
        log.info("Host discovery started", target=target, host_count=len(hosts))

        tasks   = [asyncio.create_task(self._ping_host(ip)) for ip in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        alive = [ip for ip, ok in zip(hosts, results) if ok is True]
        log.info(
            "Host discovery complete",
            total=len(hosts),
            alive=len(alive),
            dead=len(hosts) - len(alive),
        )
        return alive

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _ping_host(self, ip: str) -> bool:
        """Return True if host responds to ICMP ping."""
        async with self._sem:
            if self._dry_run:
                # In dry-run, only 127.0.0.1 is "alive"
                result = ip in ("127.0.0.1", "::1")
                topic  = EventTopic.HOST_ALIVE if result else EventTopic.HOST_DEAD
                await self._publish(topic, ip)
                return result

            try:
                alive = await self._icmp_ping(ip)
            except Exception as exc:  # noqa: BLE001
                log.debug("Ping error", ip=ip, error=str(exc))
                await self._publish(EventTopic.HOST_DEAD, ip)
                return False

            topic = EventTopic.HOST_ALIVE if alive else EventTopic.HOST_DEAD
            await self._publish(topic, ip)
            return alive

    async def _icmp_ping(self, ip: str) -> bool:
        """Execute a system ping and return True on success."""
        ping_count = str(self._cfg.network.max_ping_count)
        timeout_s  = str(self._cfg.network.ping_timeout_ms // 1000 or 1)

        import platform
        if platform.system() == "Windows":
            cmd = ["ping", "-n", ping_count, "-w", str(self._cfg.network.ping_timeout_ms), ip]
        else:
            # macOS/Linux: -c count, -W timeout_seconds, -q quiet
            cmd = ["ping", "-c", ping_count, "-W", timeout_s, "-q", ip]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(
                proc.communicate(),
                timeout=self._cfg.async_cfg.connection_timeout_seconds,
            )
            return proc.returncode == 0
        except asyncio.TimeoutError:
            log.debug("Ping timed out", ip=ip)
            return False

    async def _publish(self, topic: EventTopic, ip: str) -> None:
        """Publish a HOST_ALIVE or HOST_DEAD event."""
        hostname: Optional[str] = None
        if self._cfg.network.resolve_hostnames and topic == EventTopic.HOST_ALIVE:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                pass

        event = ScanEvent(
            topic      = topic,
            session_id = "",          # filled by Orchestrator via SessionManager
            source     = self.MODULE_NAME,
            payload    = {"ip": ip, "hostname": hostname},
        )
        await self._bus.publish(event)

        if topic == EventTopic.HOST_ALIVE:
            log.info("Host alive", ip=ip, hostname=hostname or "—")
        else:
            log.debug("Host dead", ip=ip)

    @staticmethod
    def _expand_target(target: str) -> List[str]:
        """
        Expand *target* to a flat list of IP strings.

        Accepts:
        - Single IP: ``"192.168.1.1"``
        - CIDR:      ``"192.168.1.0/24"``
        - Hostname:  ``"scanme.nmap.org"`` → resolved to IP
        """
        try:
            network = ipaddress.ip_network(target, strict=False)
            # For /32 or host addresses, just return that one IP
            return [str(ip) for ip in network.hosts()] or [str(network.network_address)]
        except ValueError:
            # Treat as hostname → resolve
            try:
                ip = socket.gethostbyname(target)
                log.debug("Hostname resolved", hostname=target, ip=ip)
                return [ip]
            except socket.gaierror:
                log.error("Cannot resolve target", target=target)
                return []
