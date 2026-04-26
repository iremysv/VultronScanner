"""
VultronScanner — Modules/Discovery Package
============================================
Phase 1 of the scan pipeline.

Modules
-------
HostDiscovery  : ICMP ping sweep — determines which hosts are alive
NetworkScanner : python-nmap wrapper — port/service enumeration
PortAnalyzer   : risk categorization and annotation of discovered ports
"""

from Modules.Discovery.HostDiscovery import HostDiscovery
from Modules.Discovery.NetworkScanner import NetworkScanner
from Modules.Discovery.PortAnalyzer import PortAnalyzer

__all__ = ["HostDiscovery", "NetworkScanner", "PortAnalyzer"]
