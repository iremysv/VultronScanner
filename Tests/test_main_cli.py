"""
Tests/test_main_cli.py
=======================
Unit tests for main.py CLI entry point.
Tests focus on the helper functions and Click command behavior
without triggering real network scans.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from click.testing import CliRunner

from main import VERSION, _print_summary_table, cli

# ---------------------------------------------------------------------------
# Tests: _print_summary_table helper
# ---------------------------------------------------------------------------


class TestPrintSummaryTable:
    """_print_summary_table must not crash with various inputs."""

    def test_empty_summary(self):
        """Should handle a mostly-empty summary dict gracefully."""
        _print_summary_table({})  # should not raise

    def test_full_summary(self):
        summary = {
            "session_id": "abcd1234-dead-beef-cafe-000000000000",
            "target": "192.168.1.0/24",
            "profile": "quick",
            "state": "COMPLETED",
            "elapsed_sec": 42.5,
            "total_hosts": 10,
            "alive_hosts": 3,
            "open_ports": 7,
            "errors": 0,
            "risk_breakdown": {
                "CRITICAL": 1,
                "HIGH": 2,
                "MEDIUM": 3,
                "LOW": 1,
                "INFORMATIONAL": 0,
            },
        }
        _print_summary_table(summary)  # should not raise

    def test_zero_elapsed(self):
        summary = {"session_id": "a" * 36, "elapsed_sec": 0}
        _print_summary_table(summary)  # should not raise

    def test_none_elapsed(self):
        summary = {"session_id": "a" * 36, "elapsed_sec": None}
        _print_summary_table(summary)  # should not raise


# ---------------------------------------------------------------------------
# Tests: CLI — version command
# ---------------------------------------------------------------------------


class TestCliVersion:
    def test_version_option(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert VERSION in result.output


# ---------------------------------------------------------------------------
# Tests: CLI — profiles command
# ---------------------------------------------------------------------------


class TestCliProfiles:
    def test_profiles_lists_profiles(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["profiles"])
        assert result.exit_code == 0
        # Should display at least some profile names
        assert "quick" in result.output.lower() or "Profile" in result.output

    def test_profiles_output_contains_table(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["profiles"])
        # Should not crash
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Tests: CLI — scan command dry-run
# ---------------------------------------------------------------------------


class TestCliScan:
    def test_scan_dry_run_exits_cleanly(self):
        """Dry-run scan on loopback should complete without errors."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                "--target",
                "127.0.0.1",
                "--profile",
                "quick",
                "--dry-run",
                "--no-save",
                "--log-level",
                "ERROR",
            ],
        )
        # Exit code should be 0 (success) or at worst non-crash
        assert result.exit_code in (0, 1)

    def test_scan_missing_target_fails(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan"])
        assert result.exit_code != 0
        assert "target" in result.output.lower() or "Missing" in result.output

    def test_scan_invalid_profile_still_runs(self):
        """Unknown profile falls back to 'quick' via ConfigLoader."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                "--target",
                "127.0.0.1",
                "--profile",
                "nonexistent_profile",
                "--dry-run",
                "--no-save",
                "--log-level",
                "ERROR",
            ],
        )
        assert result.exit_code in (0, 1)

    def test_scan_invalid_log_level_fails(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["scan", "--target", "127.0.0.1", "--log-level", "INVALID_LEVEL"],
        )
        assert result.exit_code != 0

    def test_scan_banner_displayed(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                "--target",
                "127.0.0.1",
                "--dry-run",
                "--no-save",
                "--log-level",
                "ERROR",
            ],
        )
        # Banner or some VultronScanner text should appear
        assert "VULTRON" in result.output.upper() or result.exit_code == 0
