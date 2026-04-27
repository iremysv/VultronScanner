"""
VultronScanner — Modules/Intelligence/ThreatScorer.py
======================================================
CVSS v3.1 aligned risk aggregation engine.

Responsibilities
----------------
- Walk every HostResult in a ScanSession and re-compute host-level risk
  as the maximum risk across all ports
- Produce a session-level ``risk_breakdown`` dict counting hosts per level
- Optionally apply custom CVSS thresholds from ``VultronConfig.cvss``

This module is intentionally synchronous (no async I/O) so it can be
called inline in the Orchestrator pipeline without ``await``.

Usage
-----
    scorer = ThreatScorer(config=cfg)
    breakdown = scorer.score_session(session)
    # breakdown = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 0, "INFORMATIONAL": 3}
"""

from __future__ import annotations

from collections import Counter
from typing import Dict

from Core.ConfigLoader import VultronConfig
from Core.Models import HostResult, RiskLevel, ScanSession
from Utils.Logger import get_logger

log = get_logger("threat_scorer")

# Full ordered list (lowest → highest)
_RISK_ORDER = [
    RiskLevel.INFORMATIONAL,
    RiskLevel.LOW,
    RiskLevel.MEDIUM,
    RiskLevel.HIGH,
    RiskLevel.CRITICAL,
]


class ThreatScorer:
    """
    Synchronous CVSS-based risk aggregation for hosts and sessions.

    Parameters
    ----------
    config :
        Validated VultronConfig (uses ``cvss.thresholds`` section).
    """

    MODULE_NAME = "ThreatScorer"

    def __init__(self, config: VultronConfig) -> None:
        self._cfg = config

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score_session(self, session: ScanSession) -> Dict[str, int]:
        """
        Re-compute risk for every host in *session* and return a breakdown.

        Parameters
        ----------
        session :
            Completed (or in-progress) ScanSession.

        Returns
        -------
        dict
            Keys are RiskLevel names; values are host counts.
            Example: ``{"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, ...}``
        """
        counter: Counter = Counter({r.value: 0 for r in RiskLevel})

        for host in session.hosts:
            scored_risk = self.score_host(host)
            host.risk = scored_risk
            counter[scored_risk.value] += 1

        breakdown = dict(counter)
        log.info(
            "ThreatScorer session scored",
            total_hosts=len(session.hosts),
            breakdown=breakdown,
        )
        return breakdown

    def score_host(self, host: HostResult) -> RiskLevel:
        """
        Compute the effective RiskLevel for a single *host*.

        Logic
        -----
        1. Collect all port risks.
        2. Check ``host.metadata["web"]["highest_risk"]`` if present.
        3. Return the maximum.
        """
        risks: list[RiskLevel] = [p.risk for p in host.ports]

        # Include web analysis findings
        web_risk_str: str | None = host.metadata.get("web", {}).get("highest_risk")
        if web_risk_str:
            try:
                risks.append(RiskLevel(web_risk_str))
            except ValueError:
                pass

        if not risks:
            return RiskLevel.INFORMATIONAL

        return max(risks, key=lambda r: _RISK_ORDER.index(r))

    @staticmethod
    def risk_from_cvss(score: float) -> RiskLevel:
        """
        Map a raw CVSS v3.1 base score to a ``RiskLevel``.

        Thresholds follow NIST NVD conventions:
        - 9.0–10.0 → CRITICAL
        - 7.0–8.9  → HIGH
        - 4.0–6.9  → MEDIUM
        - 0.1–3.9  → LOW
        - 0.0      → INFORMATIONAL
        """
        return RiskLevel.from_cvss(score)
