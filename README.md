# 🛡️ PySentinel

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://python.org)
[![SARIF: 2.1.0](https://img.shields.io/badge/SARIF-2.1.0%20Compliant-purple.svg)](https://sarifweb.azurewebsites.net)
[![Dependencies: 0](https://img.shields.io/badge/Dependencies-Zero-orange.svg)](pyproject.toml)
[![GitHub Code Scanning](https://img.shields.io/badge/GitHub-Code%20Scanning%20Ready-success.svg)](#-github-actions-integration)

> **Zero-dependency, high-precision Python security linter with first-class SARIF 2.1.0 support.**

PySentinel is built on a simple philosophy: **fewer rules, zero false-positive fatigue, and actionable remediation**. It leverages Python's native Abstract Syntax Tree (`ast`) to detect dangerous API usages and security anti-patterns with deterministic accuracy.

---

## 🌟 Key Highlights

- ⚡ **Zero External Dependencies**: Pure Python standard library (`ast`, `argparse`, `json`, `pathlib`). Installs in milliseconds and runs anywhere.
- 🎯 **High-Confidence Rule Engine**: Targets specific syntactic anti-patterns with zero false-positive noise.
- 📊 **OASIS SARIF 2.1.0 Standard**: Ingest scan results directly into GitHub's **Security -> Code Scanning Alerts** tab.
- 🔇 **Line-Level Suppressions**: Inline comment ignore syntax (`# pysentinel: ignore[PYSEC-001]` and `# nosec`).
- 📁 **Baseline Suppressions**: Suppress legacy technical debt and fail CI only on newly introduced vulnerabilities (`--baseline`).
- 📖 **Built-in Security Guides**: Run `pysentinel explain <RULE_ID>` for clear vulnerability mechanics and safe remediation examples.
- 🚀 **Standard Exit Codes**: Clean `0` for safe code, `1` for detected security vulnerabilities.

---

## 📋 Rule Catalog (v0.1)

| Rule ID | Title | CWE | Severity | Target Pattern |
|:---:|:---|:---:|:---:|:---|
| **`PYSEC-001`** | **Command Injection** | CWE-78 | High | `os.system()`, `os.popen()`, `subprocess.*(shell=True)` |
| **`PYSEC-002`** | **Insecure Deserialization** | CWE-502 | Critical | `pickle.load()`, `pickle.loads()`, `_pickle` |
| **`PYSEC-003`** | **Dynamic Execution** | CWE-95 | Critical | `eval()`, `exec()`, dynamic runtime `compile()` |
| **`PYSEC-004`** | **SQL Query Interpolation** | CWE-89 | High | Query strings constructed via f-strings, `%`, or `+` |
| **`PYSEC-005`** | **Insecure Temp File** | CWE-377 | Medium | Race-condition prone `tempfile.mktemp()` |
| **`PYSEC-006`** | **Broken Cryptographic Hash** | CWE-328 | Medium | `hashlib.md5()`, `hashlib.sha1()` in security contexts |
| **`PYSEC-007`** | **Insecure Debug Binding** | CWE-489 | High | Web apps started with `debug=True` or `host="0.0.0.0"` |

---

## 🚀 Installation

```bash
pip install pysentinel
```

Or run directly with `uvx` / `pipx`:

```bash
uvx pysentinel scan .
```

---

## 💻 CLI Usage

### 1. Scan a Project / Directory
```bash
# Scan current directory
pysentinel scan .

# Scan specific files or directories
pysentinel scan src/ app/main.py

# Filter by minimum severity
pysentinel scan src/ --min-severity high
```

### 2. Export to SARIF (GitHub Code Scanning)
```bash
pysentinel scan . -f sarif -o results.sarif
```

### 3. Export to JSON (Automation / Pipelines)
```bash
pysentinel scan . -f json -o security-report.json
```

### 4. Baseline Filtering (Legacy Codebases)
```bash
# 1. Generate baseline for existing issues:
pysentinel scan . --generate-baseline .pysentinel-baseline.json

# 2. In CI, only fail on NEW issues:
pysentinel scan . --baseline .pysentinel-baseline.json
```

### 5. Educational Explanations
```bash
# Explain a specific vulnerability and safe fix pattern:
pysentinel explain PYSEC-001

# List all registered rules:
pysentinel explain
```

---

## 🔕 Suppressing Findings

### Line-Level Specific Rule Suppression:
```python
import os
os.system("clear")  # pysentinel: ignore[PYSEC-001]
```

### General Suppression:
```python
import tempfile
path = tempfile.mktemp()  # pysentinel: ignore
# or Bandit-compatible:
path = tempfile.mktemp()  # nosec
```

### Whole-File Suppression:
Add this comment at the top of your file:
```python
# pysentinel: ignore-file
```

---

## 🤖 GitHub Actions Integration

Upload security alerts directly to GitHub's **Code Scanning** tab:

```yaml
name: "PySentinel Security Scan"
on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  security-audit:
    name: PySentinel AST Audit
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install PySentinel
        run: pip install pysentinel

      - name: Run PySentinel Security Audit
        run: pysentinel scan . --format sarif -o pysentinel-results.sarif --exit-zero

      - name: Upload SARIF report to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pysentinel-results.sarif
```

---

## 📄 License

MIT License &copy; 2026 Umut Güngör
