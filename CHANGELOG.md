# Changelog

All notable changes to VultronScanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Modular project scaffold with Core, Modules, Utils, Reports, Config, Tests directories
- YAML-based scan profile system (quick, full, stealth, web, auth)
- Default platform configuration with async engine, logging, and CVSS threshold settings
- Pinned dependency manifest for reproducible builds
- `.gitignore` configured to exclude sensitive scan outputs and API keys
- `.dockerignore` to keep Docker images lean
- `.editorconfig` for consistent code style across editors
- `.gitattributes` for line ending normalization
- `.pre-commit-config.yaml` with Black, isort, flake8, mypy, Bandit hooks
- `CITATION.cff` for academic reference
- `CODE_OF_CONDUCT.md` based on Contributor Covenant 2.1
- `CONTRIBUTING.md` with branch strategy and commit convention
- `SECURITY.md` with responsible disclosure guidelines
- `LICENSE` (MIT)
- ISU logo asset (`Isu_logo.svg`)

### Changed
- *(nothing yet)*

### Fixed
- *(nothing yet)*

---

## [0.1.0] — Planned

### Planned
- `CoreOrchestrator` with async pipeline management
- `NetworkScanner` wrapping python-nmap
- `HostDiscovery` and `PortAnalyzer` modules
- `VulnerabilityEngine` with NVD/CVE API integration
- `WebAnalyzer` for HTTP security header analysis
- `ThreatScorer` with CVSS v3.1 scoring
- `ExploitSuggester` module
- HTML, Markdown, and JSON report generators
- Full pytest test suite
- Docker image and docker-compose setup
- CI/CD pipeline via GitHub Actions

---

[Unreleased]: https://github.com/iremysv/VultronScanner/compare/HEAD...HEAD
