"""Tests for line-level and file-level suppression mechanisms."""

from pysentinel.engine import Engine


def test_line_suppression_specific_rule():
    engine = Engine()

    code = """
import os

os.system("ls")  # pysentinel: ignore[PYSEC-001]
os.system("whoami")  # Unsuppressed
"""
    findings, _ = engine.scan_source(code)
    assert len(findings) == 1
    assert findings[0].line_number == 5


def test_line_suppression_general():
    engine = Engine()

    code = """
import os

os.system("ls")  # pysentinel: ignore
"""
    findings, _ = engine.scan_source(code)
    assert len(findings) == 0


def test_line_suppression_nosec():
    engine = Engine()

    code = """
import os

os.system("ls")  # nosec
"""
    findings, _ = engine.scan_source(code)
    assert len(findings) == 0


def test_whole_file_suppression():
    engine = Engine()

    code = """# pysentinel: ignore-file
import os
import pickle

os.system("cat /etc/passwd")
data = pickle.loads(b"exploit")
"""
    findings, _ = engine.scan_source(code)
    assert len(findings) == 0
