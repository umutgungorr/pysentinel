"""PYSEC-005: Insecure Temporary File Creation via tempfile.mktemp."""

import ast
from pysentinel.models import Confidence, Finding, RuleMetadata, Severity
from pysentinel.rules.base import BaseRule


class InsecureTempfileRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="PYSEC-005",
        cwe_id="CWE-377",
        title="Insecure Temporary File Creation via tempfile.mktemp",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        description=(
            "tempfile.mktemp() is deprecated and vulnerable to race conditions (TOCTOU). "
            "Between generating the path and opening the file, an attacker can create a symlink "
            "pointing to a sensitive location."
        ),
        remediation=(
            "Use tempfile.NamedTemporaryFile() or tempfile.mkstemp(), which atomically create "
            "and open the file with secure permissions."
        ),
        unsafe_example='import tempfile\ntmp_path = tempfile.mktemp()',
        safe_example='import tempfile\nwith tempfile.NamedTemporaryFile(delete=True) as tmp:\n    tmp.write(b"data")',
    )

    def check(self, node: ast.AST, file_path: str, lines: list[str]) -> list[Finding]:
        if not isinstance(node, ast.Call):
            return []

        call_name = self.get_call_name(node)
        if call_name in ("tempfile.mktemp", "mktemp"):
            return [
                Finding(
                    rule_id=self.metadata.rule_id,
                    cwe_id=self.metadata.cwe_id,
                    title=self.metadata.title,
                    severity=self.metadata.severity,
                    confidence=self.metadata.confidence,
                    file_path=file_path,
                    line_number=node.lineno,
                    column=node.col_offset,
                    code_snippet=self.get_snippet(lines, node.lineno),
                    message="Use of insecure 'tempfile.mktemp()' creates file race conditions (CWE-377).",
                    remediation_hint="Replace with tempfile.NamedTemporaryFile() or tempfile.mkstemp().",
                )
            ]

        return []
