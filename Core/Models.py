"""
VultronScanner — Core/Models.py
================================
Shared data models (dataclasses) used across all VultronScanner modules.

All models are immutable-by-convention: fill them at creation time and
treat them as read-only value objects.

Hierarchy
---------
ScanSession
  └── HostResult (many)
        └── PortResult (many)
EventBus messages: ScanEvent
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class RiskLevel(str, Enum):
    """CVSS-aligned severity categories."""

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_cvss(cls, score: float) -> "RiskLevel":
        """Map a CVSS v3.1 base score to a RiskLevel."""
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0.0:
            return cls.LOW
        return cls.INFORMATIONAL


class PortCategory(str, Enum):
    """Standard IANA port range categories."""

    WELL_KNOWN = "WELL_KNOWN"  # 0-1023
    REGISTERED = "REGISTERED"  # 1024-49151
    DYNAMIC = "DYNAMIC"  # 49152-65535


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class EventTopic(str, Enum):
    """EventBus channel identifiers."""

    HOST_ALIVE = "host.alive"
    HOST_DEAD = "host.dead"
    PORT_DISCOVERED = "port.discovered"
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    MODULE_ERROR = "module.error"
    INTEL_COMPLETE = "intel.complete"  # WebAnalyzer / VulnerabilityEngine


class SessionState(str, Enum):
    INITIALISED = "initialised"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


# ---------------------------------------------------------------------------
# Core data models
# ---------------------------------------------------------------------------


@dataclass
class PortResult:
    """Represents a single scanned port with service information."""

    port: int
    state: PortState
    protocol: str = "tcp"
    service: str = "unknown"
    version: str = ""
    banner: str = ""
    category: PortCategory = PortCategory.WELL_KNOWN
    risk: RiskLevel = RiskLevel.INFORMATIONAL
    cpe: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Auto-assign IANA category if not explicitly set
        if self.port <= 1023:
            self.category = PortCategory.WELL_KNOWN
        elif self.port <= 49151:
            self.category = PortCategory.REGISTERED
        else:
            self.category = PortCategory.DYNAMIC

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "state": self.state.value,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
            "category": self.category.value,
            "risk": self.risk.value,
            "cpe": self.cpe,
            "notes": self.notes,
        }


@dataclass
class HostResult:
    """Represents a scanned host with aggregated port/service findings."""

    ip: str
    hostname: Optional[str] = None
    is_alive: bool = False
    os_guess: Optional[str] = None
    ports: List[PortResult] = field(default_factory=list)
    risk: RiskLevel = RiskLevel.INFORMATIONAL
    scan_time: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def open_ports(self) -> List[PortResult]:
        """Return only OPEN ports."""
        return [p for p in self.ports if p.state == PortState.OPEN]

    def highest_risk(self) -> RiskLevel:
        """Return the highest risk level across all ports."""
        if not self.ports:
            return RiskLevel.INFORMATIONAL
        order = list(RiskLevel)
        return max(self.ports, key=lambda p: order.index(p.risk)).risk

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "is_alive": self.is_alive,
            "os_guess": self.os_guess,
            "risk": self.risk.value,
            "ports": [p.to_dict() for p in self.ports],
            "scan_time": self.scan_time.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class ScanEvent:
    """
    EventBus message envelope.

    Every module publishes a ScanEvent to notify listeners of a
    discovery, error, or lifecycle change.
    """

    topic: EventTopic
    session_id: str
    source: str  # module name, e.g. "HostDiscovery"
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "topic": self.topic.value,
            "session_id": self.session_id,
            "source": self.source,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ScanSession:
    """Tracks the full lifecycle of a scan session."""

    target: str
    profile: str
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    state: SessionState = SessionState.INITIALISED
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    hosts: List[HostResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def elapsed_seconds(self) -> Optional[float]:
        if self.started_at is None:
            return None
        end = self.completed_at or datetime.now(tz=timezone.utc)
        return (end - self.started_at).total_seconds()

    def alive_hosts(self) -> List[HostResult]:
        return [h for h in self.hosts if h.is_alive]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target": self.target,
            "profile": self.profile,
            "state": self.state.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "elapsed_sec": self.elapsed_seconds(),
            "hosts": [h.to_dict() for h in self.hosts],
            "errors": self.errors,
            "metadata": self.metadata,
        }
