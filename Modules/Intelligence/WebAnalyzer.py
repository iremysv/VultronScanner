"""
VultronScanner — Modules/Intelligence/WebAnalyzer.py
=====================================================
Async HTTP/HTTPS security header analyzer.

Responsibilities
----------------
- Fetch the target URL (http + https) using ``httpx.AsyncClient``
- Check for the presence of critical security response headers
- Assign a ``RiskLevel`` to each missing header
- Write findings into ``HostResult.metadata["web"]``
- Publish an ``INTEL_COMPLETE`` event per analyzed host

Header → Risk Mapping
---------------------
+----------------------------+----------+
| Header                     | Risk     |
+============================+==========+
| Strict-Transport-Security  | HIGH     |
| Content-Security-Policy    | MEDIUM   |
| X-Frame-Options            | MEDIUM   |
| X-Content-Type-Options     | LOW      |
| Referrer-Policy            | LOW      |
| Permissions-Policy         | LOW      |
+----------------------------+----------+

Dry-run
-------
When ``dry_run=True`` no real HTTP requests are made.  A pre-built
mock result is returned so tests/CI can run without network access.

Usage
-----
    analyzer = WebAnalyzer(bus=bus, config=cfg, dry_run=False)
    await analyzer.analyze_host(host, session_id)
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from Core.ConfigLoader import VultronConfig
from Core.EventBus import EventBus
from Core.Models import EventTopic, HostResult, RiskLevel, ScanEvent
from Utils.Logger import get_logger

log = get_logger("web_analyzer")

# ---------------------------------------------------------------------------
# Risk ordering (lowest → highest) — must match ThreatScorer._RISK_ORDER
# ---------------------------------------------------------------------------

_RISK_ORDER: list[RiskLevel] = [
    RiskLevel.INFORMATIONAL,
    RiskLevel.LOW,
    RiskLevel.MEDIUM,
    RiskLevel.HIGH,
    RiskLevel.CRITICAL,
]

# ---------------------------------------------------------------------------
# Header definitions
# ---------------------------------------------------------------------------

#: Maps header name → (description, RiskLevel if missing)
SECURITY_HEADERS: Dict[str, tuple[str, RiskLevel]] = {
    "Strict-Transport-Security": (
        "HSTS enforces HTTPS connections; absence allows downgrade attacks.",
        RiskLevel.HIGH,
    ),
    "Content-Security-Policy": (
        "CSP mitigates XSS; absence allows script injection.",
        RiskLevel.MEDIUM,
    ),
    "X-Frame-Options": (
        "Prevents clickjacking by restricting framing.",
        RiskLevel.MEDIUM,
    ),
    "X-Content-Type-Options": (
        "Prevents MIME-type sniffing attacks.",
        RiskLevel.LOW,
    ),
    "Referrer-Policy": (
        "Controls referrer information leakage.",
        RiskLevel.LOW,
    ),
    "Permissions-Policy": (
        "Restricts browser feature access (camera, mic, geolocation).",
        RiskLevel.LOW,
    ),
}

# ---------------------------------------------------------------------------
# Mock result for dry-run / testing
# ---------------------------------------------------------------------------

_MOCK_WEB_RESULT: Dict[str, Any] = {
    "url": "http://127.0.0.1",
    "status_code": 200,
    "server": "nginx/1.22",
    "missing_headers": [
        {
            "header": "Content-Security-Policy",
            "risk": RiskLevel.MEDIUM.value,
            "description": "CSP mitigates XSS; absence allows script injection.",
        },
        {
            "header": "Permissions-Policy",
            "risk": RiskLevel.LOW.value,
            "description": "Restricts browser feature access (camera, mic, geolocation).",
        },
    ],
    "present_headers": [
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ],
    "highest_risk": RiskLevel.MEDIUM.value,
}


class WebAnalyzer:
    """
    Async HTTP security header analyzer.

    Parameters
    ----------
    bus :
        EventBus for publishing ``INTEL_COMPLETE`` events.
    config :
        Validated VultronConfig (uses ``web`` and ``async_cfg`` sections).
    dry_run :
        Skip real HTTP calls; return pre-built mock data.
    """

    MODULE_NAME = "WebAnalyzer"

    def __init__(
        self,
        bus: EventBus,
        config: VultronConfig,
        dry_run: bool = False,
    ) -> None:
        self._bus = bus
        self._cfg = config
        self._dry_run = dry_run

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze_host(self, host: HostResult, session_id: str) -> None:
        """
        Analyze HTTP security headers for *host* and store findings in
        ``host.metadata["web"]``.

        Attempts both ``http://`` and ``https://``; uses the first
        successful response.
        """
        log.info(
            "WebAnalyzer starting",
            ip=host.ip,
            dry_run=self._dry_run,
        )

        if self._dry_run:
            result = _MOCK_WEB_RESULT.copy()
            result["url"] = f"http://{host.ip}"
        else:
            result = await self._fetch_headers(host.ip)

        host.metadata["web"] = result

        # Escalate host risk if web findings are worse
        if result.get("highest_risk"):
            web_risk = RiskLevel(result["highest_risk"])
            if _RISK_ORDER.index(web_risk) > _RISK_ORDER.index(host.risk):
                host.risk = web_risk

        log.info(
            "WebAnalyzer complete",
            ip=host.ip,
            missing=len(result.get("missing_headers", [])),
            highest_risk=result.get("highest_risk"),
        )

        await self._publish(host.ip, session_id, result)

    async def analyze_all(
        self,
        hosts: List[HostResult],
        session_id: str,
        concurrency: int = 5,
    ) -> None:
        """Analyze all *hosts* concurrently (bounded by *concurrency*)."""
        sem = asyncio.Semaphore(concurrency)

        async def _bounded(h: HostResult) -> None:
            async with sem:
                try:
                    await self.analyze_host(h, session_id)
                except Exception as exc:  # noqa: BLE001
                    log.warning("WebAnalyzer failed for host", ip=h.ip, error=str(exc))

        await asyncio.gather(*[_bounded(h) for h in hosts if h.is_alive])

    # ------------------------------------------------------------------
    # Internal: HTTP fetch
    # ------------------------------------------------------------------

    async def _fetch_headers(self, ip: str) -> Dict[str, Any]:
        """Try http:// then https://, return analysis dict."""
        try:
            import httpx  # type: ignore
        except ImportError:
            log.error("httpx not installed — pip install httpx")
            return self._empty_result(f"http://{ip}")

        web_cfg = self._cfg.web
        timeout = web_cfg.request_timeout_seconds

        for scheme in ("https", "http"):
            url = f"{scheme}://{ip}"
            try:
                async with httpx.AsyncClient(
                    verify=web_cfg.verify_ssl,
                    follow_redirects=web_cfg.follow_redirects,
                    max_redirects=web_cfg.max_redirects,
                    headers={"User-Agent": web_cfg.user_agent},
                    timeout=timeout,
                ) as client:
                    response = await client.get(url)
                    return self._parse_headers(url, response)
            except Exception as exc:  # noqa: BLE001
                log.debug("HTTP fetch failed", url=url, error=str(exc))
                continue

        return self._empty_result(f"http://{ip}")

    @staticmethod
    def _parse_headers(url: str, response: Any) -> Dict[str, Any]:
        """Build analysis dict from an httpx Response."""
        headers = {k.lower(): v for k, v in response.headers.items()}

        missing: List[Dict[str, str]] = []
        present: List[str] = []

        highest_risk: Optional[RiskLevel] = None

        for header_name, (description, risk) in SECURITY_HEADERS.items():
            if header_name.lower() in headers:
                present.append(header_name)
            else:
                missing.append(
                    {
                        "header": header_name,
                        "risk": risk.value,
                        "description": description,
                    }
                )
                if highest_risk is None or _RISK_ORDER.index(risk) > _RISK_ORDER.index(
                    highest_risk
                ):
                    highest_risk = risk

        return {
            "url": url,
            "status_code": response.status_code,
            "server": headers.get("server", ""),
            "missing_headers": missing,
            "present_headers": present,
            "highest_risk": highest_risk.value if highest_risk else RiskLevel.INFORMATIONAL.value,
        }

    @staticmethod
    def _empty_result(url: str) -> Dict[str, Any]:
        return {
            "url": url,
            "status_code": None,
            "server": "",
            "missing_headers": [],
            "present_headers": [],
            "highest_risk": RiskLevel.INFORMATIONAL.value,
            "error": "Could not connect to target",
        }

    # ------------------------------------------------------------------
    # EventBus
    # ------------------------------------------------------------------

    async def _publish(self, ip: str, session_id: str, result: Dict[str, Any]) -> None:
        event = ScanEvent(
            topic=EventTopic.INTEL_COMPLETE,
            session_id=session_id,
            source=self.MODULE_NAME,
            payload={"ip": ip, "web": result},
        )
        await self._bus.publish(event)
