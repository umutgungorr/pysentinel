"""OASIS SARIF 2.1.0 JSON formatter for GitHub Code Scanning integration."""

import json
from typing import Any
from pysentinel.models import Finding, Severity
from pysentinel.rules import ALL_RULES


def _severity_to_sarif_level(sev: Severity) -> str:
    """Maps PySentinel Severity to SARIF level (error, warning, note)."""
    if sev in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    elif sev == Severity.MEDIUM:
        return "warning"
    else:
        return "note"


def format_sarif(findings: list[Finding]) -> str:
    """Formats findings into valid OASIS SARIF 2.1.0 JSON format."""
    rules_json = []
    for r in ALL_RULES:
        m = r.metadata
        rules_json.append({
            "id": m.rule_id,
            "name": m.rule_id.replace("-", ""),
            "shortDescription": {"text": m.title},
            "fullDescription": {"text": m.description},
            "help": {
                "text": f"{m.description}\n\nRemediation:\n{m.remediation}",
                "markdown": f"**{m.title}** ({m.cwe_id})\n\n{m.description}\n\n### Remediation\n{m.remediation}\n\n```python\n# Unsafe:\n{m.unsafe_example}\n\n# Safe:\n{m.safe_example}\n```",
            },
            "defaultConfiguration": {
                "level": _severity_to_sarif_level(m.severity)
            },
            "properties": {
                "tags": ["security", m.cwe_id],
                "precision": "high",
            },
        })

    results_json = []
    for f in findings:
        results_json.append({
            "ruleId": f.rule_id,
            "level": _severity_to_sarif_level(f.severity),
            "message": {
                "text": f"{f.message} Remediation: {f.remediation_hint}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file_path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": f.line_number,
                            "startColumn": max(1, f.column + 1),
                            "snippet": {
                                "text": f.code_snippet
                            }
                        }
                    }
                }
            ],
            "fingerprints": {
                "hash/v1": f.fingerprint
            }
        })

    sarif_doc: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PySentinel",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/umutgungorr/pysentinel",
                        "rules": rules_json,
                    }
                },
                "results": results_json,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2, ensure_ascii=False)
