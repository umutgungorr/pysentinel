"""Data models for PySentinel security findings, rules, and severities."""

from dataclasses import dataclass
from enum import Enum
import hashlib
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def level_order(self) -> int:
        levels = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }
        return levels.get(self, 0)


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Finding:
    rule_id: str
    cwe_id: str
    title: str
    severity: Severity
    confidence: Confidence
    file_path: str
    line_number: int
    column: int
    code_snippet: str
    message: str
    remediation_hint: str

    @property
    def fingerprint(self) -> str:
        """Deterministic fingerprint for baseline comparison."""
        payload = f"{self.rule_id}:{self.file_path}:{self.code_snippet.strip()}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "cwe_id": self.cwe_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column": self.column,
            "code_snippet": self.code_snippet,
            "message": self.message,
            "remediation_hint": self.remediation_hint,
            "fingerprint": self.fingerprint,
        }


@dataclass
class RuleMetadata:
    rule_id: str
    cwe_id: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    remediation: str
    unsafe_example: str
    safe_example: str
