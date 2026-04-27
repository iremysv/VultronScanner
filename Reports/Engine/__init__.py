"""
VultronScanner — Reports/Engine/__init__.py
============================================
Report Engine package: converts completed ScanSession objects
into human- and machine-readable output formats.

Formats
-------
MarkdownReport  — Git-friendly developer report
JsonReport      — Machine-readable SIEM/pipeline output
HtmlReport      — Executive-facing visual report with severity badges
"""

from Reports.Engine.HtmlReport import HtmlReport
from Reports.Engine.JsonReport import JsonReport
from Reports.Engine.MarkdownReport import MarkdownReport

__all__ = [
    "MarkdownReport",
    "JsonReport",
    "HtmlReport",
]
