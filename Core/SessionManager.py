"""
VultronScanner — Core/SessionManager.py
=========================================
Scan session lifecycle manager.

Responsibilities
----------------
- Generate and own the session UUID
- Track session state machine: INITIALISED → RUNNING → COMPLETED / FAILED
- Measure elapsed time with sub-second precision
- Accumulate HostResult objects as modules report findings
- Persist session snapshot to JSON after completion
- Provide summary metrics for CLI progress display

Usage
-----
    sm = SessionManager(target="192.168.1.0/24", profile="quick")
    sm.start()

    sm.add_host(host_result)
    sm.add_error("module X failed: ...")

    sm.complete()
    sm.save(output_dir=Path("Reports/Output"))
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from Core.Models import HostResult, RiskLevel, ScanSession, SessionState
from Utils.Logger import get_logger

log = get_logger("session")


class SessionManager:
    """
    Manages the lifecycle of a single VultronScanner scan session.

    Thread-safe: ``add_host`` and ``add_error`` may be called from
    concurrent asyncio tasks running in threadpool executors.
    """

    def __init__(self, target: str, profile: str) -> None:
        self._session = ScanSession(target=target, profile=profile)
        self._lock = threading.Lock()
        log.info(
            "Session initialised",
            session_id=self._session.session_id,
            target=target,
            profile=profile,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Transition to RUNNING and record start time."""
        with self._lock:
            if self._session.state != SessionState.INITIALISED:
                log.warning("Session already started", state=self._session.state.value)
                return
            self._session.state = SessionState.RUNNING
            self._session.started_at = datetime.now(tz=timezone.utc)
        log.info("Session started", session_id=self.session_id)

    def complete(self) -> None:
        """Transition to COMPLETED and record end time."""
        with self._lock:
            self._session.state = SessionState.COMPLETED
            self._session.completed_at = datetime.now(tz=timezone.utc)
        elapsed = self._session.elapsed_seconds() or 0
        log.info(
            "Session completed",
            session_id=self.session_id,
            elapsed_sec=f"{elapsed:.1f}",
            hosts_found=len(self._session.hosts),
        )

    def fail(self, reason: str = "") -> None:
        """Transition to FAILED."""
        with self._lock:
            self._session.state = SessionState.FAILED
            self._session.completed_at = datetime.now(tz=timezone.utc)
            if reason:
                self._session.errors.append(f"[FATAL] {reason}")
        log.error("Session failed", session_id=self.session_id, reason=reason)

    def abort(self) -> None:
        """Transition to ABORTED (user-initiated cancel)."""
        with self._lock:
            self._session.state = SessionState.ABORTED
            self._session.completed_at = datetime.now(tz=timezone.utc)
        log.warning("Session aborted", session_id=self.session_id)

    # ------------------------------------------------------------------
    # Data accumulation
    # ------------------------------------------------------------------

    def add_host(self, host: HostResult) -> None:
        """Append a discovered host to the session results."""
        with self._lock:
            # Deduplicate by IP
            existing_ips = {h.ip for h in self._session.hosts}
            if host.ip in existing_ips:
                log.debug("Duplicate host skipped", ip=host.ip)
                return
            self._session.hosts.append(host)
        log.debug("Host added", ip=host.ip, open_ports=len(host.open_ports()))

    def add_error(self, message: str) -> None:
        """Record a non-fatal error message."""
        with self._lock:
            self._session.errors.append(message)
        log.warning("Session error recorded", message=message)

    def set_metadata(self, key: str, value: object) -> None:
        """Store arbitrary metadata key/value pairs."""
        with self._lock:
            self._session.metadata[key] = value

    # ------------------------------------------------------------------
    # Metrics / Summary
    # ------------------------------------------------------------------

    @property
    def session_id(self) -> str:
        return self._session.session_id

    @property
    def state(self) -> SessionState:
        with self._lock:
            return self._session.state

    def summary(self) -> dict:
        """Return a snapshot of key session metrics."""
        with self._lock:
            s = self._session
            alive = s.alive_hosts()
            all_ports = [p for h in alive for p in h.open_ports()]
            risk_counts: dict = {r.value: 0 for r in RiskLevel}
            for p in all_ports:
                risk_counts[p.risk.value] += 1
            return {
                "session_id": s.session_id,
                "state": s.state.value,
                "target": s.target,
                "profile": s.profile,
                "elapsed_sec": s.elapsed_seconds(),
                "total_hosts": len(s.hosts),
                "alive_hosts": len(alive),
                "open_ports": len(all_ports),
                "errors": len(s.errors),
                "risk_breakdown": risk_counts,
            }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, output_dir: Optional[Path] = None) -> Path:
        """
        Persist session as a JSON snapshot.

        Parameters
        ----------
        output_dir :
            Target directory. Defaults to ``Reports/Output/``.

        Returns
        -------
        Path
            Path to the written JSON file.
        """
        if output_dir is None:
            output_dir = Path("Reports") / "Output"
        output_dir.mkdir(parents=True, exist_ok=True)

        filename = (
            f"session_{self._session.session_id[:8]}_"
            f"{datetime.now(tz=timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        )
        out_path = output_dir / filename

        with self._lock:
            data = self._session.to_dict()

        with out_path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

        log.success("Session saved", path=str(out_path))
        return out_path

    # ------------------------------------------------------------------
    # Raw access (read-only snapshot)
    # ------------------------------------------------------------------

    @property
    def session(self) -> ScanSession:
        """Return a shallow copy of the current ScanSession."""
        with self._lock:
            return self._session

    def __repr__(self) -> str:  # pragma: no cover
        s = self.summary()
        return (
            f"SessionManager("
            f"id={s['session_id'][:8]}, "
            f"state={s['state']}, "
            f"hosts={s['alive_hosts']}/{s['total_hosts']})"
        )
