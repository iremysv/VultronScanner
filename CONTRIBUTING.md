# Contributing to VultronScanner

Thank you for considering contributing to VultronScanner! This document outlines guidelines for contributing to the project.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Branch Strategy](#branch-strategy)
- [Commit Convention](#commit-convention)
- [Code Style](#code-style)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)

---

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone git@github.com:<your-username>/VultronScanner.git`
3. Set up the development environment (see below)
4. Create a feature branch and make your changes
5. Submit a pull request

---

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install pre-commit
pre-commit install
```

---

## Branch Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Stable, production-ready code |
| `dev` | Active development integration |
| `feat/<name>` | New features |
| `fix/<name>` | Bug fixes |
| `docs/<name>` | Documentation updates |

> **Do not commit directly to `main`.**

---

## Commit Convention

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>
```

**Types:** `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `perf`

**Examples:**
```
feat(scanner): add async port scanning with semaphore control
fix(reporter): handle empty CVE list in HTML template
docs(readme): update installation steps
```

---

## Code Style

- Follow **PEP 8** (enforced by `flake8`)
- Format with **Black** (`--line-length=100`)
- Sort imports with **isort** (`--profile=black`)
- Use **type hints** everywhere
- Use **PascalCase** for class names, **snake_case** for functions/variables

---

## Testing

```bash
pytest Tests/ -v --cov=. --cov-report=term-missing
```

- All new features must include unit tests
- Maintain test coverage above **80%**
- Place tests under `Tests/` mirroring the source structure

---

## Pull Request Process

1. Ensure all pre-commit hooks pass
2. Ensure all tests pass
3. Update `CHANGELOG.md` under `[Unreleased]`
4. Reference related issues in the PR description
5. Request a review and wait for approval before merging

---

## Security Issues

**Do not open public issues for security vulnerabilities.**  
Please refer to [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.
