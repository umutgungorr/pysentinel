"""PYSEC-003: Dangerous Dynamic Code Execution via eval/exec."""

import ast
from pysentinel.models import Confidence, Finding, RuleMetadata, Severity
from pysentinel.rules.base import BaseRule


class DynamicExecutionRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="PYSEC-003",
        cwe_id="CWE-95",
        title="Dangerous Dynamic Code Execution",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description=(
            "Direct invocation of eval() or exec() parses and evaluates arbitrary Python statements "
            "at runtime, leading to complete remote code execution if input is attacker-influenced."
        ),
        remediation=(
            "Avoid dynamic string evaluation. If parsing string literals or data structures, "
            "use ast.literal_eval() safely instead of eval()."
        ),
        unsafe_example='result = eval(user_expression)\nexec(dynamic_code_string)',
        safe_example='import ast\nsafe_val = ast.literal_eval(user_literal_string)',
    )

    DANGEROUS_FUNCS = {"eval", "exec"}

    def check(self, node: ast.AST, file_path: str, lines: list[str]) -> list[Finding]:
        if not isinstance(node, ast.Call):
            return []

        call_name = self.get_call_name(node)

        # Do NOT flag ast.literal_eval
        if call_name in ("ast.literal_eval", "literal_eval"):
            return []

        if call_name in self.DANGEROUS_FUNCS or call_name.endswith(".eval") or call_name.endswith(".exec"):
            # Ensure it's not a common method like dataframe.eval or tensorflow eval without context
            if call_name in self.DANGEROUS_FUNCS:
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
                        message=f"Dangerous dynamic execution: '{call_name}()' executes arbitrary Python code.",
                        remediation_hint="Refactor logic to avoid dynamic evaluation, or use ast.literal_eval() for data literals.",
                    )
                ]

        return []
