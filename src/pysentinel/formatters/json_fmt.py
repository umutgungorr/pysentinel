"""JSON output formatter for PySentinel."""

import json
from typing import Any
from pysentinel.models import Finding


def format_json(findings: list[Finding], errors: list[str], files_count: int) -> str:
    """Formats findings, errors, and statistics into structured JSON."""
    crit_count = sum(1 for f in findings if f.severity.value == "critical")
    high_count = sum(1 for f in findings if f.severity.value == "high")
    med_count = sum(1 for f in findings if f.severity.value == "medium")
    low_count = sum(1 for f in findings if f.severity.value == "low")

    payload: dict[str, Any] = {
        "version": "0.1.0",
        "scanner": "PySentinel",
        "summary": {
            "files_scanned": files_count,
            "total_findings": len(findings),
            "critical": crit_count,
            "high": high_count,
            "medium": med_count,
            "low": low_count,
        },
        "errors": errors,
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
