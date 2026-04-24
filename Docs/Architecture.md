# VultronScanner — Architecture

## System Overview

VultronScanner follows a modular, layered pipeline architecture inspired by professional penetration testing frameworks. Each layer has a single responsibility and communicates via an internal EventBus.

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Layer                           │
│               (Click-based command interface)               │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                    Core Orchestrator                        │
│         (Async pipeline, EventBus, SessionManager)          │
└──────┬──────────────────┬──────────────────┬────────────────┘
       │                  │                  │
┌──────▼──────┐  ┌────────▼────────┐  ┌──────▼──────┐
│  Discovery  │  │  Intelligence   │  │   Action    │
│─────────────│  │─────────────────│  │─────────────│
│NetworkScanner│ │VulnerabilityEng │  │ExploitSugge │
│HostDiscovery│  │  WebAnalyzer    │  │BruteForce   │
│PortAnalyzer │  │  ThreatScorer   │  │             │
└──────┬──────┘  └────────┬────────┘  └──────┬──────┘
       └──────────────────┴──────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                    Report Engine                            │
│              HTML  │  Markdown  │  JSON                     │
└─────────────────────────────────────────────────────────────┘
```

---

## Module Descriptions

### Core

| Module | Responsibility |
|--------|---------------|
| `CoreOrchestrator` | Manages async pipeline execution, profile loading, session lifecycle |
| `EventBus` | Pub/sub message broker between modules |
| `SessionManager` | Tracks scan state, elapsed time, result aggregation |

### Discovery Layer

| Module | Responsibility |
|--------|---------------|
| `NetworkScanner` | Wraps `python-nmap`; executes port and service scans |
| `HostDiscovery` | ICMP ping sweep, ARP discovery on local segments |
| `PortAnalyzer` | Categorizes ports (well-known, registered, dynamic), flags risky services |

### Intelligence Layer

| Module | Responsibility |
|--------|---------------|
| `VulnerabilityEngine` | Queries NVD/CVE API for discovered service CVEs |
| `WebAnalyzer` | Checks HTTP security headers (CSP, HSTS, X-Frame-Options, etc.) |
| `ThreatScorer` | Calculates CVSS v3.1 base scores, maps to risk level |

### Action Layer

| Module | Responsibility |
|--------|---------------|
| `ExploitSuggester` | Maps discovered CVEs to known exploit databases |
| `BruteForceEngine` | Dictionary attacks on SSH, FTP, RDP (requires explicit profile) |

### Report Engine

| Format | Use Case |
|--------|---------|
| HTML | Executive report with charts and severity breakdown |
| Markdown | Developer-friendly, version-control friendly |
| JSON | Machine-readable for SIEM/pipeline integration |

---

## Data Flow

```
1. CLI receives: target + profile
2. CoreOrchestrator loads profile from Config/ScanProfiles.yaml
3. Discovery modules run concurrently via asyncio.gather()
4. Results published to EventBus as ScanEvent objects
5. Intelligence modules consume ScanEvents, enrich with CVE/CVSS data
6. Action modules execute if enabled in profile
7. Report Engine aggregates all findings → output file
```

---

## Configuration System

```
Config/
├── DefaultConfig.yaml     # Global platform settings (async, logging, CVSS thresholds)
└── ScanProfiles.yaml      # Per-profile module toggles and nmap arguments
```

Profile selection at runtime:
```bash
python main.py scan --target <HEDEF> --profile full
```

---

## Security Design Decisions

| Decision | Rationale |
|----------|-----------|
| Non-root Docker user | Principle of least privilege |
| Brute force OFF by default | Prevent accidental unauthorized testing |
| `.env` excluded from git | API keys never committed |
| Scan outputs excluded from git | Prevent sensitive target data leaks |
| `--no-commit-to-branch=main` hook | Enforces PR-based workflow |
