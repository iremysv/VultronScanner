"""
VultronScanner — Modules/Intelligence/__init__.py
==================================================
Intelligence layer package: enriches raw Discovery findings with
CVE data, web security analysis, and CVSS-based risk scoring.

Modules
-------
WebAnalyzer        — HTTP/HTTPS security header analysis
VulnerabilityEngine — NVD CVE API queries per discovered service
ThreatScorer       — CVSS v3.1 host/session risk aggregation
"""

from Modules.Intelligence.ThreatScorer import ThreatScorer
from Modules.Intelligence.VulnerabilityEngine import VulnerabilityEngine
from Modules.Intelligence.WebAnalyzer import WebAnalyzer

__all__ = [
    "WebAnalyzer",
    "VulnerabilityEngine",
    "ThreatScorer",
]
