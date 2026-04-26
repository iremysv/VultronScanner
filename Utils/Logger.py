"""
VultronScanner — Utils/Logger.py
=================================
Async-aware, Rich-powered structured logging system.

Features:
  - 6-level severity hierarchy  (TRACE → DEBUG → INFO → WARNING → ERROR → CRITICAL)
  - Rich Console with markup and emoji panel headers
  - Optional JSON-line file sink for machine-readable audit trails
  - asyncio-safe non-blocking write via run_in_executor
  - Named child loggers (e.g. "discovery", "intelligence") with shared config
  - Context tags injected per-message  (session_id, module, target)
  - Thread-safe singleton factory via get_logger()

Usage:
    from Utils.Logger import get_logger

    log = get_logger("discovery")
    log.info("Scan started", target="192.168.1.0/24", session="abc123")
    await log.async_info("Host alive", host="192.168.1.5")
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme

# ---------------------------------------------------------------------------
# Custom severity levels
# ---------------------------------------------------------------------------

TRACE_LEVEL = 5
logging.addLevelName(TRACE_LEVEL, "TRACE")


class LogLevel(IntEnum):
    TRACE = TRACE_LEVEL
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


# ---------------------------------------------------------------------------
# VultronScanner Rich theme
# ---------------------------------------------------------------------------

VULTRON_THEME = Theme(
    {
        "log.trace": "dim cyan",
        "log.debug": "bright_cyan",
        "log.info": "bright_green",
        "log.warning": "bright_yellow",
        "log.error": "bright_red",
        "log.critical": "bold bright_red on dark_red",
        "log.time": "dim white",
        "log.module": "magenta",
        "log.tag": "dim blue",
        "log.target": "bold cyan",
        "log.session": "dim yellow",
        "banner.border": "bright_cyan",
        "banner.title": "bold bright_white",
    }
)

# Shared Rich console — one instance used across all loggers
_console = Console(theme=VULTRON_THEME, highlight=True, markup=True)

# Level → (icon, style) mapping for Rich output
_LEVEL_META: Dict[int, tuple[str, str]] = {
    TRACE_LEVEL: ("󰜏 ", "log.trace"),
    logging.DEBUG: ("󰃤 ", "log.debug"),
    logging.INFO: (" ", "log.info"),
    logging.WARNING: (" ", "log.warning"),
    logging.ERROR: (" ", "log.error"),
    logging.CRITICAL: ("󰚑 ", "log.critical"),
}


# ---------------------------------------------------------------------------
# JSON file handler (async-safe)
# ---------------------------------------------------------------------------


class _JsonFileHandler(logging.Handler):
    """Writes structured JSON-line records to a rotating log file."""

    def __init__(self, log_path: Path) -> None:
        super().__init__()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._path = log_path
        self._lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        entry = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "module": record.name,
            "msg": record.getMessage(),
            **getattr(record, "ctx", {}),
        }
        line = json.dumps(entry, ensure_ascii=False)
        with self._lock:
            try:
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError:
                self.handleError(record)


# ---------------------------------------------------------------------------
# Core logger class
# ---------------------------------------------------------------------------


class VultronLogger:
    """
    Rich-powered structured logger for VultronScanner modules.

    Parameters
    ----------
    name : str
        Module name displayed in every log line (e.g. ``"discovery"``).
    level : LogLevel
        Minimum severity to emit. Defaults to INFO.
    log_dir : Path | None
        Directory for JSON log files. Pass ``None`` to disable file logging.
    session_id : str | None
        Optional session identifier injected into every record.
    """

    _instances: Dict[str, "VultronLogger"] = {}
    _lock = threading.Lock()

    def __init__(
        self,
        name: str = "vultron",
        level: LogLevel = LogLevel.INFO,
        log_dir: Optional[Path] = None,
        session_id: Optional[str] = None,
    ) -> None:
        self.name = name
        self.session_id = session_id
        self._level = level

        # Build stdlib logger
        self._logger = logging.getLogger(f"vultron.{name}")
        self._logger.setLevel(int(level))
        self._logger.propagate = False

        # Avoid duplicate handlers on re-instantiation
        if not self._logger.handlers:
            rich_handler = RichHandler(
                console=_console,
                show_time=True,
                show_path=False,
                markup=True,
                rich_tracebacks=True,
                tracebacks_show_locals=True,
                log_time_format="[%H:%M:%S]",
            )
            rich_handler.setLevel(int(level))
            self._logger.addHandler(rich_handler)

            if log_dir is not None:
                log_file = log_dir / f"{name}.jsonl"
                file_handler = _JsonFileHandler(log_file)
                file_handler.setLevel(logging.DEBUG)
                self._logger.addHandler(file_handler)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_extra(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Merge session_id into context kwargs."""
        merged: Dict[str, Any] = {}
        if self.session_id:
            merged["session"] = self.session_id
        merged.update(ctx)
        return merged

    def _log(self, level: int, msg: str, **ctx: Any) -> None:
        extra = {"ctx": self._build_extra(ctx)}
        # Append key=value tags to message for Rich display
        if ctx:
            tags = "  ".join(f"[log.tag]{k}[/]=[log.target]{v}[/]" for k, v in ctx.items())
            msg = f"{msg}  {tags}"
        self._logger.log(level, msg, extra=extra, stacklevel=3)

    # ------------------------------------------------------------------
    # Sync logging API
    # ------------------------------------------------------------------

    def trace(self, msg: str, **ctx: Any) -> None:
        """Granular trace output — disabled in production."""
        self._log(TRACE_LEVEL, msg, **ctx)

    def debug(self, msg: str, **ctx: Any) -> None:
        self._log(logging.DEBUG, msg, **ctx)

    def info(self, msg: str, **ctx: Any) -> None:
        self._log(logging.INFO, msg, **ctx)

    def warning(self, msg: str, **ctx: Any) -> None:
        self._log(logging.WARNING, msg, **ctx)

    def error(self, msg: str, **ctx: Any) -> None:
        self._log(logging.ERROR, msg, **ctx)

    def critical(self, msg: str, **ctx: Any) -> None:
        self._log(logging.CRITICAL, msg, **ctx)

    # ------------------------------------------------------------------
    # Async logging API (non-blocking)
    # ------------------------------------------------------------------

    async def async_trace(self, msg: str, **ctx: Any) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: self.trace(msg, **ctx))

    async def async_debug(self, msg: str, **ctx: Any) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: self.debug(msg, **ctx))

    async def async_info(self, msg: str, **ctx: Any) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: self.info(msg, **ctx))

    async def async_warning(self, msg: str, **ctx: Any) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: self.warning(msg, **ctx))

    async def async_error(self, msg: str, **ctx: Any) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: self.error(msg, **ctx))

    async def async_critical(self, msg: str, **ctx: Any) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: self.critical(msg, **ctx))

    # ------------------------------------------------------------------
    # Rich panel helpers
    # ------------------------------------------------------------------

    def banner(self, title: str, subtitle: str = "") -> None:
        """Print a styled startup/section banner to console."""
        content = Text()
        content.append(f"{title}\n", style="banner.title")
        if subtitle:
            content.append(subtitle, style="dim white")
        _console.print(
            Panel(
                content,
                border_style="banner.border",
                expand=False,
                padding=(0, 2),
            )
        )

    def section(self, title: str) -> None:
        """Print a visual section separator."""
        _console.rule(f"[bold cyan]{title}[/bold cyan]", style="bright_cyan")

    def success(self, msg: str, **ctx: Any) -> None:
        """Semantic alias for INFO with a distinct success icon."""
        icon = "✔ "
        self._log(logging.INFO, f"[bold green]{icon}{msg}[/bold green]", **ctx)

    def failure(self, msg: str, **ctx: Any) -> None:
        """Semantic alias for ERROR with a distinct failure icon."""
        icon = "✘ "
        self._log(logging.ERROR, f"[bold red]{icon}{msg}[/bold red]", **ctx)

    # ------------------------------------------------------------------
    # Child logger
    # ------------------------------------------------------------------

    def child(self, name: str) -> "VultronLogger":
        """Return a child logger sharing the same session and log_dir."""
        child_name = f"{self.name}.{name}"
        with VultronLogger._lock:
            if child_name not in VultronLogger._instances:
                inst = VultronLogger.__new__(VultronLogger)
                inst.name = child_name
                inst.session_id = self.session_id
                inst._level = self._level
                inst._logger = logging.getLogger(f"vultron.{child_name}")
                inst._logger.setLevel(int(self._level))
                inst._logger.propagate = True  # inherit parent handlers
                VultronLogger._instances[child_name] = inst
            return VultronLogger._instances[child_name]

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"VultronLogger(name={self.name!r}, "
            f"level={LogLevel(self._level).name}, "
            f"session={self.session_id!r})"
        )


# ---------------------------------------------------------------------------
# Singleton factory
# ---------------------------------------------------------------------------

_root_logger: Optional[VultronLogger] = None
_factory_lock = threading.Lock()


def get_logger(
    name: str = "vultron",
    level: LogLevel = LogLevel.INFO,
    log_dir: Optional[Path] = None,
    session_id: Optional[str] = None,
) -> VultronLogger:
    """
    Return a named VultronLogger instance (singleton per name).

    First call with a given ``name`` creates the instance; subsequent
    calls return the cached object regardless of other parameters.

    Parameters
    ----------
    name : str
        Logical module name, e.g. ``"discovery"``, ``"intelligence"``.
    level : LogLevel
        Minimum log severity. Only applied on first creation.
    log_dir : Path | None
        Write JSON audit log to this directory. Only applied on first creation.
    session_id : str | None
        Optional scan session UUID. Only applied on first creation.
    """
    with _factory_lock:
        if name not in VultronLogger._instances:
            VultronLogger._instances[name] = VultronLogger(
                name=name,
                level=level,
                log_dir=log_dir,
                session_id=session_id,
            )
        return VultronLogger._instances[name]


def configure_root(
    level: LogLevel = LogLevel.INFO,
    log_dir: Optional[Path] = None,
    session_id: Optional[str] = None,
) -> VultronLogger:
    """
    Configure the root ``"vultron"`` logger.

    Call this once from ``main.py`` before importing any module logger.
    """
    global _root_logger
    with _factory_lock:
        _root_logger = VultronLogger(
            name="vultron",
            level=level,
            log_dir=log_dir,
            session_id=session_id,
        )
        VultronLogger._instances["vultron"] = _root_logger
    return _root_logger
