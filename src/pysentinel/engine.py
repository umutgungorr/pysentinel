"""AST scanning engine, suppression parser, and file discovery for PySentinel."""

import ast
from pathlib import Path
import re
from typing import Optional, Set
from pysentinel.models import Finding, Severity
from pysentinel.rules import ALL_RULES, BaseRule


IGNORED_DIRS = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "build",
    "dist",
    ".tox",
    ".pytest_cache",
    ".mypy_cache",
    "node_modules",
    ".eggs",
}

# Regex for line-level suppression
# Supports:
# # pysentinel: ignore
# # pysentinel: ignore[PYSEC-001]
# # pysentinel: ignore[PYSEC-001, PYSEC-004]
# # nosec
SUPPRESSION_REGEX = re.compile(
    r"#\s*(?:pysentinel:\s*ignore(?:\[([A-Z0-9,\s\-]+)\])?|nosec\b)",
    re.IGNORECASE,
)


class Engine:
    def __init__(
        self,
        rules: Optional[list[BaseRule]] = None,
        min_severity: Severity = Severity.LOW,
        baseline_fingerprints: Optional[Set[str]] = None,
    ):
        self.rules = rules or ALL_RULES
        self.min_severity = min_severity
        self.baseline_fingerprints = baseline_fingerprints or set()

    def discover_files(self, targets: list[str]) -> list[Path]:
        """Collects all Python files from given file/directory targets."""
        found_files: list[Path] = []
        for target in targets:
            path = Path(target)
            if path.is_file():
                if path.suffix == ".py":
                    found_files.append(path)
            elif path.is_dir():
                for item in path.rglob("*.py"):
                    # Check if any parent part matches ignored dirs
                    if not any(part in IGNORED_DIRS for part in item.parts):
                        found_files.append(item)
        return sorted(list(set(found_files)))

    def parse_suppressions(self, lines: list[str]) -> dict[int, Optional[set[str]]]:
        """
        Parses suppression comments per line number.
        Returns {line_no: set of rule_ids or None if all rules suppressed}.
        """
        suppressions: dict[int, Optional[set[str]]] = {}
        for lineno, line in enumerate(lines, start=1):
            match = SUPPRESSION_REGEX.search(line)
            if match:
                raw_rules = match.group(1)
                if raw_rules:
                    rules_set = {r.strip().upper() for r in raw_rules.split(",") if r.strip()}
                    suppressions[lineno] = rules_set
                else:
                    # Suppress all rules on this line
                    suppressions[lineno] = None
        return suppressions

    def scan_source(self, source: str, file_path: str = "<string>") -> tuple[list[Finding], list[str]]:
        """Scans a Python source string and returns (findings, syntax_errors)."""
        lines = source.splitlines()

        # Check for whole-file suppression
        if any("# pysentinel: ignore-file" in line.lower() for line in lines[:5]):
            return [], []

        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError as e:
            return [], [f"SyntaxError in {file_path}:{e.lineno}:{e.offset} - {e.msg}"]

        suppressions = self.parse_suppressions(lines)
        findings: list[Finding] = []

        # Traverse AST nodes
        for node in ast.walk(tree):
            for rule in self.rules:
                node_findings = rule.check(node, file_path=file_path, lines=lines)
                for f in node_findings:
                    # Check severity threshold
                    if f.severity.level_order < self.min_severity.level_order:
                        continue

                    # Check line-level suppression
                    if f.line_number in suppressions:
                        suppressed_rules = suppressions[f.line_number]
                        if suppressed_rules is None or f.rule_id.upper() in suppressed_rules:
                            continue

                    # Check baseline suppression
                    if f.fingerprint in self.baseline_fingerprints:
                        continue

                    findings.append(f)

        # Sort findings by line number, column
        findings.sort(key=lambda x: (x.line_number, x.column))
        return findings, []

    def scan_file(self, file_path: Path) -> tuple[list[Finding], list[str]]:
        """Reads and scans a single Python file."""
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return [], [f"Failed to read {file_path}: {e}"]

        return self.scan_source(source, file_path=str(file_path))

    def scan_paths(self, targets: list[str]) -> tuple[list[Finding], list[str], int]:
        """
        Scans all target paths.
        Returns (all_findings, all_errors, files_scanned_count).
        """
        files = self.discover_files(targets)
        all_findings: list[Finding] = []
        all_errors: list[str] = []

        for fpath in files:
            findings, errors = self.scan_file(fpath)
            all_findings.extend(findings)
            all_errors.extend(errors)

        return all_findings, all_errors, len(files)
