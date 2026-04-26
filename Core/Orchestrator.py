"""
VultronScanner — Core/Orchestrator.py
=======================================
Async pipeline runner that coordinates all scan modules.

Responsibilities
----------------
- Accept a :class:`~Core.ConfigLoader.VultronConfig` + target
- Spin up an :class:`~Core.EventBus.EventBus` and :class:`~Core.SessionManager.SessionManager`
- Instantiate and run enabled modules in the correct pipeline order
- Collect :class:`~Core.Models.HostResult` objects via EventBus subscriptions
- Hand off to the Report Engine (stub for Day 5)
- Return a completed :class:`~Core.Models.ScanSession`

Pipeline Order
--------------
Phase 1 — Discovery  : HostDiscovery → NetworkScanner → PortAnalyzer
Phase 2 — Intelligence: WebAnalyzer, VulnerabilityEngine, ThreatScorer  (Day 5)
Phase 3 — Action     : ExploitSuggester, BruteForce                     (Day 6)
Phase 4 — Reporting                                                       (Day 5)

Usage
-----
    cfg = ConfigLoader().load(profile="quick")
    orc = Orchestrator(cfg)
    session = await orc.run(target="192.168.1.1")
"""

from __future__ import annotations

import asyncio

from Core.ConfigLoader import VultronConfig
from Core.EventBus import EventBus
from Core.Models import EventTopic, HostResult, ScanEvent
from Core.SessionManager import SessionManager
from Modules.Discovery.HostDiscovery import HostDiscovery
from Modules.Discovery.NetworkScanner import NetworkScanner
from Modules.Discovery.PortAnalyzer import PortAnalyzer
from Utils.Logger import VultronLogger, get_logger

log = get_logger("orchestrator")


class Orchestrator:
    """
    Masters the end-to-end scan pipeline.

    Parameters
    ----------
    config : VultronConfig
        Merged, validated configuration (output of ConfigLoader.load()).
    """

    def __init__(self, config: VultronConfig) -> None:
        self._cfg = config

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(
        self,
        target: str,
        dry_run: bool = False,
    ) -> SessionManager:
        """
        Execute the full scan pipeline for *target*.

        Parameters
        ----------
        target :
            IP address, CIDR range, or hostname to scan.
        dry_run :
            If ``True``, modules skip real network calls (for testing).

        Returns
        -------
        SessionManager
            Completed session containing all findings.
        """
        bus = EventBus()
        sm = SessionManager(target=target, profile=self._cfg.profile_key)
        logger = get_logger("orchestrator", session_id=sm.session_id)

        # Log startup banner
        logger.banner(
            title=f"VultronScanner — {self._cfg.profile_name}",
            subtitle=f"Target: {target}  |  Profile: {self._cfg.profile_key}  |  Session: {sm.session_id[:8]}",
        )

        # Wire up EventBus → SessionManager
        bus.subscribe(EventTopic.HOST_ALIVE, self._on_host_alive(sm))
        bus.subscribe(EventTopic.MODULE_ERROR, self._on_module_error(sm))

        sm.start()

        try:
            # ── Phase 1: Discovery ────────────────────────────────────────
            logger.section("Phase 1 — Discovery")
            await self._run_discovery(target, bus, sm, logger, dry_run)

            # ── Phase 2: Intelligence (stub — Day 5) ───────────────────────
            logger.section("Phase 2 — Intelligence (scheduled Day 5)")
            logger.info("Intelligence modules not yet implemented — skipping")

            # ── Phase 3: Action (stub — Day 6) ────────────────────────────
            # logger.section("Phase 3 — Action (scheduled Day 6)")

            sm.complete()

        except asyncio.CancelledError:
            sm.abort()
            raise

        except Exception as exc:  # noqa: BLE001
            logger.failure(f"Pipeline error: {exc}")
            sm.fail(reason=str(exc))

        finally:
            await bus.shutdown()
            self._print_summary(sm, logger)

        return sm

    # ------------------------------------------------------------------
    # Discovery phase
    # ------------------------------------------------------------------

    async def _run_discovery(
        self,
        target: str,
        bus: EventBus,
        sm: SessionManager,
        logger: VultronLogger,
        dry_run: bool,
    ) -> None:
        cfg = self._cfg

        tasks = []

        if cfg.modules.host_discovery:
            hd = HostDiscovery(bus=bus, config=cfg, dry_run=dry_run)
            tasks.append(hd.run(target))

        if cfg.modules.network_scanner:
            ns = NetworkScanner(bus=bus, config=cfg, dry_run=dry_run)
            tasks.append(ns.run(target, sm))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        else:
            logger.warning("All discovery modules are disabled for this profile")

        # PortAnalyzer runs post-scan to annotate already-collected ports
        if cfg.modules.port_analyzer:
            pa = PortAnalyzer(config=cfg)
            for host in sm.session.hosts:
                pa.analyze(host)
            logger.info("PortAnalyzer completed", hosts=len(sm.session.hosts))

    # ------------------------------------------------------------------
    # EventBus handlers (returned as coroutines via closures)
    # ------------------------------------------------------------------

    @staticmethod
    def _on_host_alive(sm: SessionManager):
        async def _handler(event: ScanEvent) -> None:
            # HostDiscovery publishes payload={ip, hostname}
            # NetworkScanner publishes full HostResult via add_host directly
            payload = event.payload
            if "ip" in payload and event.source == "HostDiscovery":
                # Minimal alive record — NetworkScanner will enrich it later
                host = HostResult(
                    ip=payload["ip"],
                    hostname=payload.get("hostname"),
                    is_alive=True,
                )
                sm.add_host(host)

        return _handler

    @staticmethod
    def _on_module_error(sm: SessionManager):
        async def _handler(event: ScanEvent) -> None:
            msg = event.payload.get("message", "unknown error")
            sm.add_error(f"[{event.source}] {msg}")

        return _handler

    # ------------------------------------------------------------------
    # Final summary
    # ------------------------------------------------------------------

    @staticmethod
    def _print_summary(sm: SessionManager, logger: VultronLogger) -> None:
        s = sm.summary()
        logger.section("Scan Summary")
        logger.info(
            "Results",
            alive_hosts=s["alive_hosts"],
            open_ports=s["open_ports"],
            errors=s["errors"],
            elapsed_sec=f"{s['elapsed_sec'] or 0:.1f}",
        )
        risk = s.get("risk_breakdown", {})
        if any(risk.values()):
            logger.info(
                "Risk breakdown",
                critical=risk.get("CRITICAL", 0),
                high=risk.get("HIGH", 0),
                medium=risk.get("MEDIUM", 0),
                low=risk.get("LOW", 0),
                informational=risk.get("INFORMATIONAL", 0),
            )
