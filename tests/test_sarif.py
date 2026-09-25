"""Unit tests verifying OASIS SARIF 2.1.0 specification compliance."""

import json
from pysentinel.engine import Engine
from pysentinel.formatters.sarif import format_sarif


def test_sarif_output_schema():
    engine = Engine()
    code = """
import os
import pickle

os.system("ls")
pickle.loads(b"data")
"""
    findings, _ = engine.scan_source(code, file_path="app/vulnerable.py")
    assert len(findings) == 2

    sarif_str = format_sarif(findings)
    doc = json.loads(sarif_str)

    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert len(doc["runs"]) == 1

    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "PySentinel"
    assert len(run["tool"]["driver"]["rules"]) >= 7

    results = run["results"]
    assert len(results) == 2

    rule_ids = {r["ruleId"] for r in results}
    assert "PYSEC-001" in rule_ids
    assert "PYSEC-002" in rule_ids

    # Location check
    first_res = results[0]
    loc = first_res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app/vulnerable.py"
    assert loc["region"]["startLine"] > 0
