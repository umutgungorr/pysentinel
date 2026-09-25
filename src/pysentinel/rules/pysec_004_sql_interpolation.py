"""PYSEC-004: SQL Query String Interpolation."""

import ast
import re
from pysentinel.models import Confidence, Finding, RuleMetadata, Severity
from pysentinel.rules.base import BaseRule


class SqlInterpolationRule(BaseRule):
    metadata = RuleMetadata(
        rule_id="PYSEC-004",
        cwe_id="CWE-89",
        title="SQL Query String Interpolation",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description=(
            "Constructing SQL queries using f-strings, %, .format(), or string concatenation (+) "
            "exposes applications to SQL injection when dynamic variables are embedded."
        ),
        remediation=(
            "Use parameterized queries provided by your database driver (e.g. cursor.execute('SELECT ... WHERE id = ?', (val,)) "
            "or cursor.execute('SELECT ... WHERE id = %s', (val,))). Never interpolate variables directly into SQL syntax."
        ),
        unsafe_example='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\ncursor.execute("SELECT * FROM accounts WHERE name = \'%s\'" % name)',
        safe_example='cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
    )

    SQL_PATTERN = re.compile(
        r"\b(SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|WHERE\s+\w+)\b",
        re.IGNORECASE,
    )

    DB_EXEC_METHODS = {"execute", "executemany", "raw", "cursor.execute", "db.execute"}

    def check(self, node: ast.AST, file_path: str, lines: list[str]) -> list[Finding]:
        if not isinstance(node, ast.Call):
            return []

        call_name = self.get_call_name(node)
        is_exec = call_name in self.DB_EXEC_METHODS or call_name.endswith(".execute") or call_name.endswith(".raw")

        if not node.args:
            return []

        first_arg = node.args[0]
        finding_reason = None

        # Case 1: f-string (ast.JoinedStr) containing SQL keywords
        if isinstance(first_arg, ast.JoinedStr):
            text_parts = []
            has_expressions = False
            for val in first_arg.values:
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    text_parts.append(val.value)
                elif isinstance(val, ast.FormattedValue):
                    has_expressions = True

            combined = " ".join(text_parts)
            if has_expressions and (is_exec or self.SQL_PATTERN.search(combined)):
                finding_reason = "SQL query constructed with dynamic f-string interpolation."

        # Case 2: String formatting via % operator (ast.BinOp with ast.Mod)
        elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):
            if isinstance(first_arg.left, ast.Constant) and isinstance(first_arg.left.value, str):
                if is_exec or self.SQL_PATTERN.search(first_arg.left.value):
                    finding_reason = "SQL query formatted using '%' string interpolation."

        # Case 3: String concatenation via + operator (ast.BinOp with ast.Add)
        elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
            # Check if one of operands is SQL string
            left_str = (
                first_arg.left.value
                if isinstance(first_arg.left, ast.Constant) and isinstance(first_arg.left.value, str)
                else ""
            )
            right_str = (
                first_arg.right.value
                if isinstance(first_arg.right, ast.Constant) and isinstance(first_arg.right.value, str)
                else ""
            )
            if is_exec or self.SQL_PATTERN.search(left_str) or self.SQL_PATTERN.search(right_str):
                finding_reason = "SQL query constructed via dynamic string concatenation (+)."

        # Case 4: str.format() call
        elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute):
            if first_arg.func.attr == "format" and isinstance(first_arg.func.value, ast.Constant):
                if isinstance(first_arg.func.value.value, str) and (
                    is_exec or self.SQL_PATTERN.search(first_arg.func.value.value)
                ):
                    finding_reason = "SQL query formatted using .format() method."

        if finding_reason:
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
                    message=f"Possible SQL Injection (CWE-89): {finding_reason}",
                    remediation_hint="Use your database driver's parameterized query placeholders (e.g. '?' or '%s').",
                )
            ]

        return []
