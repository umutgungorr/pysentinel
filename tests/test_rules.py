"""Unit tests verifying high-precision detection and zero false positives across all 7 rules."""

from pysentinel.engine import Engine


def test_pysec_001_command_injection_positive():
    engine = Engine()

    code = """
import os
import subprocess

os.system("ls -la " + path)
os.popen("whoami")
subprocess.Popen("rm -rf " + target, shell=True)
subprocess.run(f"echo {msg}", shell=True)
"""
    findings, errors = engine.scan_source(code)
    assert not errors
    assert len(findings) == 4
    assert all(f.rule_id == "PYSEC-001" for f in findings)


def test_pysec_001_command_injection_negative():
    engine = Engine()

    # Safe subprocess execution with list and shell=False
    code = """
import subprocess

subprocess.run(["ls", "-la", "/tmp"], check=True)
subprocess.Popen(["git", "status"], shell=False)
subprocess.check_output(["whoami"])
"""
    findings, errors = engine.scan_source(code)
    assert not errors
    assert len(findings) == 0, f"Expected 0 false positives, got {findings}"


def test_pysec_002_deserialization_positive():
    engine = Engine()

    code = """
import pickle
import _pickle

data = pickle.loads(raw_stream)
obj = pickle.load(fp)
fast = _pickle.loads(payload)
"""
    findings, errors = engine.scan_source(code)
    assert not errors
    assert len(findings) == 3
    assert all(f.rule_id == "PYSEC-002" for f in findings)


def test_pysec_002_deserialization_negative():
    engine = Engine()

    code = """
import json

data = json.loads(user_json)
obj = json.load(fp)
"""
    findings, errors = engine.scan_source(code)
    assert not errors
    assert len(findings) == 0


def test_pysec_003_dynamic_exec_positive():
    engine = Engine()

    code = """
eval("2 + 2")
exec("import os; os.system('sh')")
"""
    findings, errors = engine.scan_source(code)
    assert not errors
    assert len(findings) == 2
    assert all(f.rule_id == "PYSEC-003" for f in findings)


def test_pysec_003_dynamic_exec_negative():
    engine = Engine()

    # ast.literal_eval is the safe standard
    code = """
import ast

data = ast.literal_eval("{'user': 'alice', 'role': 'admin'}")
"""
    findings, errors = engine.scan_source(code)
    assert not errors
    assert len(findings) == 0


def test_pysec_004_sql_interpolation_positive():
    engine = Engine()

    code = """
cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
cursor.execute("SELECT * FROM accounts WHERE name = '%s'" % username)
db.execute("SELECT * FROM logs WHERE tag = " + tag)
cursor.execute("SELECT * FROM items WHERE id = {}".format(item_id))
"""
    findings, errors = engine.scan_source(code)
    assert not errors
    assert len(findings) == 4
    assert all(f.rule_id == "PYSEC-004" for f in findings)


def test_pysec_004_sql_interpolation_negative():
    engine = Engine()

    # Parameterized queries are safe
    code = """
cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))
cursor.execute("SELECT * FROM accounts WHERE name = %s AND active = %s", (name, True))
"""
    findings, errors = engine.scan_source(code)
    assert not errors
    assert len(findings) == 0


def test_pysec_005_tempfile_positive():
    engine = Engine()

    code = """
import tempfile

path = tempfile.mktemp()
"""
    findings, errors = engine.scan_source(code)
    assert not errors
    assert len(findings) == 1
    assert findings[0].rule_id == "PYSEC-005"


def test_pysec_005_tempfile_negative():
    engine = Engine()

    code = """
import tempfile

with tempfile.NamedTemporaryFile(delete=True) as tmp:
    tmp.write(b"safe")
"""
    findings, errors = engine.scan_source(code)
    assert not errors
    assert len(findings) == 0


def test_pysec_006_weak_crypto_positive():
    engine = Engine()

    code = """
import hashlib

h1 = hashlib.md5(b"secret").hexdigest()
h2 = hashlib.sha1(b"token").hexdigest()
h3 = hashlib.new("md5")
"""
    findings, errors = engine.scan_source(code)
    assert not errors
    assert len(findings) == 3
    assert all(f.rule_id == "PYSEC-006" for f in findings)


def test_pysec_006_weak_crypto_negative():
    engine = Engine()

    # SHA256 or explicit usedforsecurity=False
    code = """
import hashlib

h_secure = hashlib.sha256(b"secret").hexdigest()
cache_key = hashlib.md5(b"non-security-cache", usedforsecurity=False).hexdigest()
"""
    findings, errors = engine.scan_source(code)
    assert not errors
    assert len(findings) == 0


def test_pysec_007_debug_binding_positive():
    engine = Engine()

    code = """
app.run(debug=True, port=8000)
server.run(host="0.0.0.0", port=5000)
"""
    findings, errors = engine.scan_source(code)
    assert not errors
    assert len(findings) == 2
    assert all(f.rule_id == "PYSEC-007" for f in findings)


def test_pysec_007_debug_binding_negative():
    engine = Engine()

    code = """
app.run(debug=False, host="127.0.0.1", port=8000)
"""
    findings, errors = engine.scan_source(code)
    assert not errors
    assert len(findings) == 0
