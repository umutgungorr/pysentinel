"""Integration tests for PySentinel CLI."""

import json
from pathlib import Path
from pysentinel.cli import main


def test_cli_scan_clean(tmp_path: Path):
    clean_file = tmp_path / "safe.py"
    clean_file.write_text("def hello():\n    return 'clean code'\n")

    code = main(["scan", str(clean_file)])
    assert code == 0


def test_cli_scan_vulnerable(tmp_path: Path):
    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text("import os\nos.system('whoami')\n")

    code = main(["scan", str(vuln_file)])
    assert code == 1


def test_cli_scan_exit_zero(tmp_path: Path):
    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text("import os\nos.system('whoami')\n")

    code = main(["scan", str(vuln_file), "--exit-zero"])
    assert code == 0


def test_cli_scan_output_json(tmp_path: Path):
    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text("import pickle\npickle.loads(b'payload')\n")
    out_json = tmp_path / "report.json"

    code = main(["scan", str(vuln_file), "-f", "json", "-o", str(out_json)])
    assert code == 1
    assert out_json.exists()

    data = json.loads(out_json.read_text())
    assert data["summary"]["total_findings"] == 1
    assert data["findings"][0]["rule_id"] == "PYSEC-002"


def test_cli_scan_output_sarif(tmp_path: Path):
    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text("import tempfile\ntempfile.mktemp()\n")
    out_sarif = tmp_path / "report.sarif"

    code = main(["scan", str(vuln_file), "-f", "sarif", "-o", str(out_sarif)])
    assert code == 1
    assert out_sarif.exists()

    data = json.loads(out_sarif.read_text())
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 1


def test_cli_explain_specific(capsys):
    code = main(["explain", "PYSEC-001"])
    assert code == 0
    captured = capsys.readouterr().out
    assert "OS Command & Shell Injection" in captured
    assert "CWE-78" in captured


def test_cli_explain_list(capsys):
    code = main(["explain"])
    assert code == 0
    captured = capsys.readouterr().out
    assert "PYSEC-001" in captured
    assert "PYSEC-007" in captured
