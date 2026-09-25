"""PYSEC-002: Insecure Deserialization via pickle."""

import ast
from pysentinel.models import Confidence, Finding, RuleMetadata, Severity
from pysentinel.rules.base import BaseRule


class DeserializationRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="PYSEC-002",
        cwe_id="CWE-502",
        title="Insecure Deserialization via Pickle",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description=(
            "The pickle module is inherently unsafe when processing untrusted input. "
            "Malicious serialized payloads can construct arbitrary Python objects and execute code during unpickling."
        ),
        remediation=(
            "Use safer serialization formats such as JSON, Protocol Buffers, or MessagePack. "
            "Never unpickle data from network streams, cookies, or untrusted users."
        ),
        unsafe_example='import pickle\ndata = pickle.loads(user_supplied_bytes)',
        safe_example='import json\ndata = json.loads(user_supplied_json_str)',
    )

    DANGEROUS_CALLS = {
        "pickle.load",
        "pickle.loads",
        "_pickle.load",
        "_pickle.loads",
        "cPickle.load",
        "cPickle.loads",
        "dill.load",
        "dill.loads",
    }

    def check(self, node: ast.AST, file_path: str, lines: list[str]) -> list[Finding]:
        if not isinstance(node, ast.Call):
            return []

        call_name = self.get_call_name(node)
        if call_name in self.DANGEROUS_CALLS or call_name in ("loads", "load"):
            # Check if likely unpickling
            if call_name in self.DANGEROUS_CALLS:
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
                        message=f"Insecure deserialization detected: '{call_name}()' executes arbitrary code if data is untrusted.",
                        remediation_hint="Replace pickle with json.loads() or another safe structured format.",
                    )
                ]

        return []
