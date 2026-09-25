"""Base rule interface and AST helper utilities for PySentinel rules."""

import ast
from typing import Optional
from pysentinel.models import Finding, RuleMetadata


class BaseRule:
    metadata: RuleMetadata

    def check(self, node: ast.AST, file_path: str, lines: list[str]) -> list[Finding]:
        """Inspects an AST node and returns any security findings."""
        raise NotImplementedError

    @staticmethod
    def get_snippet(lines: list[str], lineno: int) -> str:
        """Retrieves trimmed line content at lineno (1-indexed)."""
        if 1 <= lineno <= len(lines):
            return lines[lineno - 1].strip()
        return ""

    @staticmethod
    def get_call_name(node: ast.Call) -> str:
        """Resolves full call target name, e.g. 'os.system', 'pickle.loads', 'subprocess.Popen'."""
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute):
            parts = []
            curr: ast.AST = func
            while isinstance(curr, ast.Attribute):
                parts.append(curr.attr)
                curr = curr.value
            if isinstance(curr, ast.Name):
                parts.append(curr.id)
            parts.reverse()
            return ".".join(parts)
        return ""

    @staticmethod
    def get_keyword(node: ast.Call, name: str) -> Optional[ast.keyword]:
        """Finds a keyword argument by name in an ast.Call node."""
        for kw in node.keywords:
            if kw.arg == name:
                return kw
        return None

    @staticmethod
    def is_truthy(node: ast.AST) -> bool:
        """Checks if an AST literal evaluates to True."""
        if isinstance(node, ast.Constant):
            return bool(node.value)
        return False
