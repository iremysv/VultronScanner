"""
Tests/test_SessionManager.py
=============================
Unit tests for Core/SessionManager.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from Core.Models import HostResult, PortResult, PortState, RiskLevel, SessionState
from Core.SessionManager import SessionManager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sm(target: str = "192.168.1.0/24", profile: str = "quick") -> SessionManager:
    return SessionManager(target=target, profile=profile)


def _make_host(ip: str, alive: bool = True) -> HostResult:
    return HostResult(ip=ip, is_alive=alive)


def _make_open_port(port: int = 80, risk: RiskLevel = RiskLevel.LOW) -> PortResult:
    p = PortResult(port=port, state=PortState.OPEN, service="http")
    p.risk = risk
    return p


# ---------------------------------------------------------------------------
# Tests: Lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    """SessionManager state machine transitions."""

    def test_initial_state_is_initialised(self):
        sm = _make_sm()
        assert sm.state == SessionState.INITIALISED

    def test_start_transitions_to_running(self):
        sm = _make_sm()
        sm.start()
        assert sm.state == SessionState.RUNNING

    def test_complete_transitions_to_completed(self):
        sm = _make_sm()
        sm.start()
        sm.complete()
        assert sm.state == SessionState.COMPLETED

    def test_fail_transitions_to_failed(self):
        sm = _make_sm()
        sm.start()
        sm.fail(reason="nmap error")
        assert sm.state == SessionState.FAILED

    def test_abort_transitions_to_aborted(self):
        sm = _make_sm()
        sm.start()
        sm.abort()
        assert sm.state == SessionState.ABORTED

    def test_fail_records_reason_as_error(self):
        sm = _make_sm()
        sm.fail(reason="disk full")
        assert any("disk full" in e for e in sm.session.errors)

    def test_double_start_does_not_crash(self):
        sm = _make_sm()
        sm.start()
        sm.start()  # second call should be a no-op
        assert sm.state == SessionState.RUNNING

    def test_completed_at_set_after_complete(self):
        sm = _make_sm()
        sm.start()
        sm.complete()
        assert sm.session.completed_at is not None

    def test_elapsed_seconds_positive_after_complete(self):
        sm = _make_sm()
        sm.start()
        sm.complete()
        elapsed = sm.session.elapsed_seconds()
        assert elapsed is not None
        assert elapsed >= 0


# ---------------------------------------------------------------------------
# Tests: Data accumulation
# ---------------------------------------------------------------------------


class TestDataAccumulation:
    """add_host / add_error / set_metadata behaviour."""

    def test_add_host_increases_host_count(self):
        sm = _make_sm()
        sm.add_host(_make_host("1.2.3.4"))
        assert len(sm.session.hosts) == 1

    def test_add_host_deduplicates_by_ip(self):
        sm = _make_sm()
        sm.add_host(_make_host("1.2.3.4"))
        sm.add_host(_make_host("1.2.3.4"))  # duplicate
        assert len(sm.session.hosts) == 1

    def test_add_two_different_hosts(self):
        sm = _make_sm()
        sm.add_host(_make_host("1.2.3.4"))
        sm.add_host(_make_host("1.2.3.5"))
        assert len(sm.session.hosts) == 2

    def test_add_error_records_message(self):
        sm = _make_sm()
        sm.add_error("timeout on host")
        assert "timeout on host" in sm.session.errors

    def test_add_multiple_errors(self):
        sm = _make_sm()
        sm.add_error("err1")
        sm.add_error("err2")
        assert len(sm.session.errors) == 2

    def test_set_metadata_stores_value(self):
        sm = _make_sm()
        sm.set_metadata("custom_key", 42)
        assert sm.session.metadata["custom_key"] == 42


# ---------------------------------------------------------------------------
# Tests: Summary metrics
# ---------------------------------------------------------------------------


class TestSummary:
    """summary() must return correct aggregated metrics."""

    def test_summary_has_required_keys(self):
        sm = _make_sm()
        s = sm.summary()
        for key in ("session_id", "state", "target", "profile", "total_hosts", "alive_hosts"):
            assert key in s

    def test_summary_total_hosts(self):
        sm = _make_sm()
        sm.add_host(_make_host("1.1.1.1"))
        sm.add_host(_make_host("1.1.1.2"))
        assert sm.summary()["total_hosts"] == 2

    def test_summary_alive_hosts(self):
        sm = _make_sm()
        sm.add_host(_make_host("1.1.1.1", alive=True))
        sm.add_host(_make_host("1.1.1.2", alive=False))
        assert sm.summary()["alive_hosts"] == 1

    def test_summary_open_ports(self):
        sm = _make_sm()
        host = _make_host("1.1.1.1", alive=True)
        host.ports = [_make_open_port(80), _make_open_port(443)]
        sm.add_host(host)
        assert sm.summary()["open_ports"] == 2

    def test_summary_error_count(self):
        sm = _make_sm()
        sm.add_error("e1")
        sm.add_error("e2")
        assert sm.summary()["errors"] == 2

    def test_summary_target_matches(self):
        sm = _make_sm(target="10.0.0.1")
        assert sm.summary()["target"] == "10.0.0.1"

    def test_summary_risk_breakdown_keys(self):
        sm = _make_sm()
        breakdown = sm.summary()["risk_breakdown"]
        for level in RiskLevel:
            assert level.value in breakdown

    def test_session_id_property(self):
        sm = _make_sm()
        assert len(sm.session_id) == 36  # UUID format


# ---------------------------------------------------------------------------
# Tests: Persistence
# ---------------------------------------------------------------------------


class TestPersistence:
    """save() must write a valid JSON file."""

    def test_save_creates_file(self, tmp_path: Path):
        sm = _make_sm()
        sm.start()
        sm.complete()
        out = sm.save(output_dir=tmp_path)
        assert out.exists()
        assert out.suffix == ".json"

    def test_save_json_is_valid(self, tmp_path: Path):
        import json

        sm = _make_sm()
        sm.start()
        sm.complete()
        out = sm.save(output_dir=tmp_path)
        data = json.loads(out.read_text())
        assert "session_id" in data
        assert "target" in data

    def test_save_creates_output_dir_if_missing(self, tmp_path: Path):
        sm = _make_sm()
        nested = tmp_path / "deep" / "output"
        sm.save(output_dir=nested)
        assert nested.exists()
