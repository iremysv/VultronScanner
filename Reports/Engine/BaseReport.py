"""
VultronScanner — Reports/Engine/BaseReport.py
=============================================
Abstract base class for all report format implementations.

Every concrete report (Markdown, JSON, HTML) must subclass
``BaseReport`` and implement ``generate()``.

Usage
-----
    class MarkdownReport(BaseReport):
        def generate(self, session: ScanSession, output_path: Path) -> Path:
            ...
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from Core.Models import ScanSession


class BaseReport(ABC):
    """
    Abstract base for VultronScanner report generators.

    Subclasses must implement :meth:`generate`.
    """

    #: File extension produced by this report format (e.g. ``".md"``).
    EXTENSION: str = ""

    @abstractmethod
    def generate(self, session: ScanSession, output_path: Path) -> Path:
        """
        Render *session* findings and write to *output_path*.

        Parameters
        ----------
        session :
            Completed ScanSession with all host/port/CVE data.
        output_path :
            Destination file path.  The parent directory is created
            automatically if it does not exist.

        Returns
        -------
        Path
            The absolute path of the written report file.
        """

    @staticmethod
    def _ensure_parent(path: Path) -> None:
        """Create parent directories if they do not exist."""
        path.parent.mkdir(parents=True, exist_ok=True)
