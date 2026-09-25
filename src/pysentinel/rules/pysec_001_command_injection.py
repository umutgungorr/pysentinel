"""PYSEC-001: OS Command & Shell Injection."""

import ast
from pysentinel.models import Confidence, Finding, RuleMetadata, Severity
from pysentinel.rules.base import BaseRule


class CommandInjectionRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="PYSEC-001",
        cwe_id="CWE-78",
        title="OS Command & Shell Injection",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description=(
            "Direct invocation of system shells via os.system, os.popen, or subprocess functions "
            "with shell=True allows arbitrary command execution if input contains shell metacharacters."
        ),
        remediation=(
            "Use subprocess.run() with an argument sequence (e.g. ['ls', '-la']) and shell=False. "
            "Never concatenate untrusted user input into shell command strings."
        ),
        unsafe_example='import os\nos.system(f"ping {host}")\nsubprocess.run(f"echo {msg}", shell=True)',
        safe_example='import subprocess\nsubprocess.run(["ping", "-c", "1", host], check=True)',
    )

    SUBPROCESS_FUNCS = {
        "subprocess.Popen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "Popen",
        "run",
        "call",
        "check_call",
        "check_output",
    }

    def check(self, node: ast.AST, file_path: str, lines: list[str]) -> list[Finding]:
        if not isinstance(node, ast.Call):
            return []

        call_name = self.get_call_name(node)

        # 1. os.system or os.popen
        if call_name in ("os.system", "os.popen", "system", "popen"):
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
                    message=f"Dangerous system call '{call_name}()' invokes the underlying OS shell directly.",
                    remediation_hint="Replace with subprocess.run([...]) without shell=True.",
                )
            ]

        # 2. subprocess.* with shell=True
        if call_name in self.SUBPROCESS_FUNCS:
            shell_kw = self.get_keyword(node, "shell")
            if shell_kw and self.is_truthy(shell_kw.value):
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
                        message=f"Subprocess call '{call_name}' explicitly enabled shell=True, exposing shell injection.",
                        remediation_hint="Pass arguments as a list of strings and remove shell=True.",
                    )
                ]

        return []
