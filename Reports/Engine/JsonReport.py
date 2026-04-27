"""
VultronScanner — Reports/Engine/JsonReport.py
=============================================
Machine-readable JSON report for SIEM/pipeline integration.

Writes the full ``ScanSession.to_dict()`` payload to a UTF-8
encoded JSON file with 2-space indentation.

Usage
-----
    report = JsonReport()
    out = report.generate(session, Path("Reports/Output/scan.json"))
"""

from __future__ import annotations

import json
from pathlib import Path

from Core.Models import ScanSession
from Reports.Engine.BaseReport import BaseReport
from Utils.Logger import get_logger

log = get_logger("json_report")


class JsonReport(BaseReport):
    """
    Serialise a completed ScanSession to a JSON file.

    The output is the direct serialisation of
    ``ScanSession.to_dict()``; it can be ingested by any SIEM,
    Elastic, or custom pipeline without additional transformation.
    """

    EXTENSION = ".json"

    def generate(self, session: ScanSession, output_path: Path) -> Path:
        """
        Write JSON report to *output_path*.

        Returns
        -------
        Path
            Absolute path of the written file.
        """
        self._ensure_parent(output_path)
        data = session.to_dict()

        with output_path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False, default=str)

        log.info(
            "JSON report written",
            path=str(output_path),
            hosts=len(session.hosts),
        )
        return output_path.resolve()
