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
- Hand off to the Report Engine
- Return a completed :class:`~Core.Models.ScanSession`

Pipeline Order
--------------
Phase 1 — Discovery  : HostDiscovery → NetworkScanner → PortAnalyzer
Phase 2 — Intelligence: WebAnalyzer, VulnerabilityEngine, ThreatScorer
Phase 3 — Action     : ExploitSuggester, BruteForce                     (Day 6)
Phase 4 — Reporting  : MarkdownReport / HtmlReport / JsonReport

Usage
-----
    cfg = ConfigLoader().load(profile="quick")
    orc = Orchestrator(cfg)
    session = await orc.run(target="192.168.1.1")
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from Core.ConfigLoader import VultronConfig
from Core.EventBus import EventBus
from Core.Models import EventTopic, HostResult, ScanEvent
from Core.SessionManager import SessionManager
from Modules.Discovery.HostDiscovery import HostDiscovery
from Modules.Discovery.NetworkScanner import NetworkScanner
from Modules.Discovery.PortAnalyzer import PortAnalyzer
from Modules.Intelligence.ThreatScorer import ThreatScorer
from Modules.Intelligence.VulnerabilityEngine import VulnerabilityEngine
from Modules.Intelligence.WebAnalyzer import WebAnalyzer
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

            # ── Phase 2: Intelligence ─────────────────────────────────────
            logger.section("Phase 2 — Intelligence")
            await self._run_intelligence(bus, sm, logger, dry_run)

            # ── Phase 3: Action (stub — Day 6) ────────────────────────────
            # logger.section("Phase 3 — Action (scheduled Day 6)")

            sm.complete()

            # ── Phase 4: Reporting ────────────────────────────────────────
            logger.section("Phase 4 — Reporting")
            await self._run_reporting(sm, logger)

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
    # Intelligence phase
    # ------------------------------------------------------------------

    async def _run_intelligence(
        self,
        bus: EventBus,
        sm: SessionManager,
        logger: VultronLogger,
        dry_run: bool,
    ) -> None:
        cfg = self._cfg
        hosts = sm.session.hosts
        alive = [h for h in hosts if h.is_alive]

        if not alive:
            logger.warning("No alive hosts — skipping Intelligence phase")
            return

        # ── WebAnalyzer ─────────────────────────────────────────────────
        if cfg.modules.web_analyzer:
            logger.info("WebAnalyzer starting", hosts=len(alive))
            web = WebAnalyzer(bus=bus, config=cfg, dry_run=dry_run)
            await web.analyze_all(alive, sm.session_id)
            logger.info("WebAnalyzer completed")
        else:
            logger.info("WebAnalyzer disabled for this profile — skipping")

        # ── VulnerabilityEngine ─────────────────────────────────────────
        if cfg.modules.vulnerability_engine:
            logger.info("VulnerabilityEngine starting", hosts=len(alive))
            vuln = VulnerabilityEngine(bus=bus, config=cfg, dry_run=dry_run)
            await vuln.enrich_all(alive, sm.session_id)
            logger.info("VulnerabilityEngine completed")
        else:
            logger.info("VulnerabilityEngine disabled for this profile — skipping")

        # ── ThreatScorer (always runs if any intelligence ran) ──────────
        if cfg.modules.threat_scorer:
            logger.info("ThreatScorer scoring session")
            scorer = ThreatScorer(config=cfg)
            breakdown = scorer.score_session(sm.session)
            sm.session.metadata["risk_breakdown"] = breakdown
            logger.info("ThreatScorer completed", breakdown=breakdown)

    # ------------------------------------------------------------------
    # Reporting phase
    # ------------------------------------------------------------------

    async def _run_reporting(self, sm: SessionManager, logger: VultronLogger) -> None:
        """Select and run the appropriate report generator based on profile config."""
        fmt = self._cfg.report_opts.format.lower()
        output_dir = Path(self._cfg.reports.output_directory)
        exec_summary = self._cfg.report_opts.include_executive_summary

        # Build output filename from session_id prefix + target slug
        target_slug = sm.session.target.replace("/", "_").replace(".", "-")
        stem = f"scan_{target_slug}_{sm.session_id[:8]}"

        try:
            if fmt == "html":
                from Reports.Engine.HtmlReport import HtmlReport

                report = HtmlReport(include_executive_summary=exec_summary)
                out = report.generate(sm.session, output_dir / f"{stem}.html")

            elif fmt == "json":
                from Reports.Engine.JsonReport import JsonReport

                report = JsonReport()
                out = report.generate(sm.session, output_dir / f"{stem}.json")

            else:  # default: markdown
                from Reports.Engine.MarkdownReport import MarkdownReport

                report = MarkdownReport(include_executive_summary=exec_summary)
                out = report.generate(sm.session, output_dir / f"{stem}.md")

            logger.info("Report generated", format=fmt, path=str(out))
            sm.session.metadata["report_path"] = str(out)

        except Exception as exc:  # noqa: BLE001
            logger.failure(f"Report generation failed: {exc}")
            sm.add_error(f"[Reporting] {exc}")

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
        report_path = sm.session.metadata.get("report_path")
        if report_path:
            logger.info("Report saved", path=report_path)
