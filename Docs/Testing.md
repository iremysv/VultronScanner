# VultronScanner — Testing Guide

## Overview

VultronScanner uses **pytest** as the primary test framework, with `pytest-asyncio` for async module testing and `pytest-cov` for coverage reporting.

---

## Running Tests

```bash
# Activate virtual environment first
source .venv/bin/activate

# Run all tests with coverage
pytest Tests/ -v --cov=. --cov-report=term-missing

# Run a specific test file
pytest Tests/Discovery/test_port_analyzer.py -v

# Run a specific test function
pytest Tests/Discovery/test_port_analyzer.py::test_risky_port_detection -v

# Run with HTML coverage report
pytest Tests/ --cov=. --cov-report=html
open htmlcov/index.html
```

---

## Test Structure

```
Tests/
├── conftest.py                  # Shared fixtures and mock setup
├── Discovery/
│   ├── test_network_scanner.py
│   ├── test_host_discovery.py
│   └── test_port_analyzer.py
├── Intelligence/
│   ├── test_vulnerability_engine.py
│   ├── test_web_analyzer.py
│   └── test_threat_scorer.py
├── Action/
│   ├── test_exploit_suggester.py
│   └── test_brute_force_engine.py
├── Core/
│   ├── test_orchestrator.py
│   └── test_event_bus.py
└── Reports/
    ├── test_html_reporter.py
    └── test_markdown_reporter.py
```

---

## Coverage Requirements

| Component | Minimum Coverage |
|-----------|----------------|
| Core | 90% |
| Discovery | 85% |
| Intelligence | 85% |
| Reports | 80% |
| Overall | **80%** |

Coverage below 80% will cause CI to fail.

---

## Writing Tests

### Async Test Example

```python
import pytest
from Modules.Discovery.PortAnalyzer import PortAnalyzer

@pytest.mark.asyncio
async def test_risky_port_detection():
    analyzer = PortAnalyzer()
    result = await analyzer.analyze([22, 23, 3389])
    assert result.risky_ports == [23, 3389]
```

### Using Fixtures

```python
# conftest.py adds:
@pytest.fixture
def mock_scan_result():
    return {"host": "test-host", "ports": [80, 443, 22]}

# In your test:
def test_something(mock_scan_result):
    assert mock_scan_result["ports"] == [80, 443, 22]
```

---

## Mocking External Services

All external API calls (NVD, CVE APIs) must be mocked in tests:

```python
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_vulnerability_lookup():
    with patch("Modules.Intelligence.VulnerabilityEngine.fetch_cve") as mock_fetch:
        mock_fetch.return_value = AsyncMock(return_value={"CVE-2024-1234": {"cvss": 9.8}})
        # ... rest of test
```

---

## CI Integration

Tests run automatically on every push and pull request via GitHub Actions (`.github/workflows/ci.yml`). Pull requests are blocked if tests fail or coverage drops below threshold.
