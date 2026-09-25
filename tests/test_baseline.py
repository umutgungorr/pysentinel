"""Unit tests for baseline suppression."""

import json
from pathlib import Path
from pysentinel.cli import load_baseline
from pysentinel.engine import Engine


def test_baseline_suppression(tmp_path: Path):
    engine = Engine()

    code1 = """
import os
os.system("old_command")
"""
    findings1, _ = engine.scan_source(code1, file_path="script.py")
    assert len(findings1) == 1

    # Save baseline file
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(json.dumps([findings1[0].fingerprint]))

    # Now load baseline and scan again
    fingerprints = load_baseline(str(baseline_file))
    assert findings1[0].fingerprint in fingerprints

    engine_with_baseline = Engine(baseline_fingerprints=fingerprints)

    code2 = """
import os
os.system("old_command")
os.system("new_vulnerability")
"""
    findings2, _ = engine_with_baseline.scan_source(code2, file_path="script.py")
    # Only the new vulnerability should be flagged
    assert len(findings2) == 1
    assert "new_vulnerability" in findings2[0].code_snippet
